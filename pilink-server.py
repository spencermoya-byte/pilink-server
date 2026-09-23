#!/usr/bin/env python3
# PiLink Server — direct TCP server on port 7788
# iPhone connects here directly. No relay. No middleman.
# Install: pip3 install psutil paramiko --break-system-packages

import urllib.request
import urllib.parse
import os, json, time, select, socket, ssl, threading, subprocess, secrets, shutil, stat, hashlib, re
import base64
import hmac
import sys
import traceback
import pty
from pathlib import Path
import psutil, paramiko

try:
    from zeroconf import ServiceInfo, Zeroconf
except ImportError:
    ServiceInfo = Zeroconf = None

CONFIG_DIR        = Path.home() / '.pilink'
CONFIG_FILE       = CONFIG_DIR / 'config.json'
SCHED_FILE        = CONFIG_DIR / 'schedules.json'
ADDR_FILE         = CONFIG_DIR / 'address.json'
EVENTS_LOG        = CONFIG_DIR / 'events.jsonl'
# Shared with pilink-agent.py (a separate process) — this server reads/writes
# the same files so Settings → Self-healing agent can control it without the
# agent needing its own TCP listener.
AGENT_CONFIG_FILE = CONFIG_DIR / 'agent_config.json'
AGENT_STATUS_FILE = CONFIG_DIR / 'agent_status.json'
DEFAULT_AGENT_CONFIG = {
    'autoRestartEnabled': True,
    'escalationThreshold': 3,
    'escalationCooldownMinutes': 15,
}
AGENT_STALE_MS = 30000  # no heartbeat in this long = treat the agent as not running
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
PORT = 7788

# ── Security constants ────────────────────────────────────────────────────────

# Auth rate limiting — block an IP after this many wrong keys within the window
AUTH_MAX_ATTEMPTS = 5
AUTH_WINDOW_SEC   = 60        # sliding window length
_AUTH_LOCK   = threading.Lock()
_AUDIT_LOCK  = threading.Lock()

# Allowed base directories for all file operations (path traversal guard)
# /tmp is scoped to /tmp/pilink/ to prevent clobbering other processes' temp files.
Path('/tmp/pilink').mkdir(parents=True, exist_ok=True)
ALLOWED_PATH_PREFIXES = tuple(
    p.resolve() for p in (
        Path.home(),
        Path('/tmp/pilink'),
        Path('/media'),
        Path('/mnt'),
    ) if p == Path('/tmp/pilink') or p.exists()
)

# ── Audit log & persistent rate limiter ──────────────────────────────────────
AUDIT_LOG        = CONFIG_DIR / 'audit.jsonl'
AUTH_FAILS_FILE  = CONFIG_DIR / 'auth_fails.json'
IP_LOCK_FILE     = CONFIG_DIR / 'ip_lock.json'
MAX_BUF_SIZE     = 64 * 1024 * 1024   # 64 MB per-connection receive buffer cap
MAX_UPLOAD_SIZE  = 20 * 1024 * 1024   # 20 MB max for uploads / downloads
IDLE_TIMEOUT_SEC = 7200               # 2 hours — disconnect silent authenticated sessions

def audit(event_type: str, detail: dict = None):
    """Append a line to ~/.pilink/audit.jsonl for every security-sensitive operation."""
    entry = {'ts': int(time.time() * 1000), 'event': event_type, **(detail or {})}
    with _AUDIT_LOCK:
        try:
            with open(AUDIT_LOG, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception:
            pass

ERRORS_LOG = CONFIG_DIR / 'errors.jsonl'

def error(where: str, exc: BaseException, detail: dict = None):
    """Report a server-side error: full traceback to stderr (captured by journald,
    so `journalctl -u pilink-server` shows it) plus a rolling errors.jsonl entry.
    The server's counterpart to the app's Sentry — failures become visible instead
    of vanishing into a broad except."""
    tb = ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(f'[pilink][error] {where}: {exc!r}\n{tb}', file=sys.stderr, flush=True)
    try:
        entry = {'ts': int(time.time() * 1000), 'where': where,
                 'error': f'{type(exc).__name__}: {exc}', **(detail or {})}
        with _AUDIT_LOCK:
            with open(ERRORS_LOG, 'a') as f:
                f.write(json.dumps(entry) + '\n')
    except Exception:
        pass

def _thread_excepthook(args):
    """Route uncaught exceptions from handler threads through error() so a crashing
    background handler is visible, not silent. Installed in serve()."""
    if args.exc_value is not None:
        error('thread', args.exc_value, {'thread': getattr(args.thread, 'name', '?')})

class StreamCoalescer:
    """Buffer text-stream chunks (terminal / SSH output) and flush them coalesced,
    so a flood of small reads becomes a few larger messages instead of a firehose
    that pins the app's JS thread. Flushes when the buffer passes max_bytes or
    max_delay_s since the first buffered chunk; the read loop also flush()es on
    idle so interactive output is never held longer than a select tick.

    Kept dependency-free and pure (time is injectable) so it stays trivial to
    reason about; the read loop's idle-flush is what preserves interactivity."""
    def __init__(self, send, max_bytes=16384, max_delay_s=0.03, time_fn=time.time):
        self._send = send
        self._buf = []
        self._size = 0
        self._first = 0.0
        self.max_bytes = max_bytes
        self.max_delay_s = max_delay_s
        self._now = time_fn

    def add(self, text):
        if not text:
            return
        if not self._buf:
            self._first = self._now()
        self._buf.append(text)
        self._size += len(text)
        if self._size >= self.max_bytes or (self._now() - self._first) >= self.max_delay_s:
            self.flush()

    def flush(self):
        if self._buf:
            self._send(''.join(self._buf))
            self._buf = []
            self._size = 0

def _load_auth_fails() -> dict:
    """Load persisted auth-failure timestamps from disk; prune expired entries."""
    if AUTH_FAILS_FILE.exists():
        try:
            raw = json.loads(AUTH_FAILS_FILE.read_text())
            now = time.time()
            return {ip: [ts for ts in times if now - ts < AUTH_WINDOW_SEC]
                    for ip, times in raw.items()}
        except Exception:
            pass
    return {}

def _save_auth_fails(fails: dict):
    """Persist auth-failure state so lockouts survive server restarts."""
    try:
        AUTH_FAILS_FILE.write_text(json.dumps(fails))
        AUTH_FAILS_FILE.chmod(0o600)
    except Exception:
        pass

_AUTH_FAILS: dict = _load_auth_fails()  # ip -> [timestamp, ...]  (restored from disk)

def load_ip_lock() -> dict:
    """Return the IP allowlist config: {enabled: bool, allowed: [str, ...]}."""
    if IP_LOCK_FILE.exists():
        try:
            return json.loads(IP_LOCK_FILE.read_text())
        except Exception:
            pass
    return {'enabled': False, 'allowed': []}

def save_ip_lock(cfg: dict):
    IP_LOCK_FILE.write_text(json.dumps(cfg))
    IP_LOCK_FILE.chmod(0o600)


# ── Managed services ─────────────────────────────────────────────────────────
# The user designates which systemd units are the "real" services they care
# about. Only units in this managed allowlist can be start/stop/restart/enable-
# controlled from the app; every other unit is read-only. Persisted so the set
# survives restarts.
MANAGED_SVC_FILE = CONFIG_DIR / 'managed_services.json'
_UNIT_RE = re.compile(r'^[A-Za-z0-9@:._-]+\.service$')

def _valid_unit(unit: str) -> bool:
    return bool(unit) and len(unit) <= 128 and bool(_UNIT_RE.match(unit))

def load_managed_units() -> list:
    if MANAGED_SVC_FILE.exists():
        try:
            data = json.loads(MANAGED_SVC_FILE.read_text())
            return [u for u in data.get('units', []) if _valid_unit(u)]
        except Exception:
            pass
    return []

def save_managed_units(units: list):
    clean = sorted({u for u in units if _valid_unit(u)})
    MANAGED_SVC_FILE.write_text(json.dumps({'units': clean}, indent=2))
    MANAGED_SVC_FILE.chmod(0o600)

def _svc_listening_ports() -> dict:
    """Map pid -> sorted list of TCP ports it is LISTENing on (best effort; a
    non-root server can't always see ports owned by other users)."""
    ports = {}
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.status == psutil.CONN_LISTEN and c.pid and c.laddr:
                ports.setdefault(c.pid, set()).add(c.laddr.port)
    except Exception:
        pass
    return {pid: sorted(p) for pid, p in ports.items()}

def _svc_port_for(pid, port_map: dict):
    """Listening port for pid, else the first listening port of a child proc."""
    if not pid:
        return None
    if port_map.get(pid):
        return port_map[pid][0]
    try:
        for child in psutil.Process(pid).children(recursive=True):
            if port_map.get(child.pid):
                return port_map[child.pid][0]
    except Exception:
        pass
    return None

def _svc_show(unit: str) -> dict:
    """systemctl show for one unit (read-only, no sudo)."""
    props = 'Description,ActiveState,SubState,UnitFileState,MainPID,MemoryCurrent,ActiveEnterTimestampMonotonic'
    out = {}
    try:
        r = subprocess.run(['systemctl', 'show', unit, '--no-pager', '-p', props],
                           capture_output=True, text=True, timeout=6)
        for line in r.stdout.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                out[k] = v
    except Exception:
        pass
    return out

def build_services() -> list:
    """All systemd .service units with basic status; managed units also get
    rich detail (main PID, memory, uptime, listening port)."""
    managed = set(load_managed_units())
    services = {}
    try:
        r = subprocess.run(['systemctl', 'list-units', '--type=service', '--all',
                            '--no-legend', '--no-pager', '--plain'],
                           capture_output=True, text=True, timeout=8)
        for line in r.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4 or not parts[0].endswith('.service'):
                continue
            unit = parts[0]
            services[unit] = {
                'unit': unit, 'name': unit[:-8],
                'description': parts[4] if len(parts) > 4 else '',
                'activeState': parts[2], 'subState': parts[3],
                'active': parts[2] == 'active', 'enabled': False,
                'managed': unit in managed,
                'mainPid': None, 'memMB': None, 'uptimeSec': None, 'port': None,
            }
    except Exception:
        pass
    try:
        r = subprocess.run(['systemctl', 'list-unit-files', '--type=service',
                            '--no-legend', '--no-pager', '--plain'],
                           capture_output=True, text=True, timeout=8)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in services:
                services[parts[0]]['enabled'] = parts[1] == 'enabled'
    except Exception:
        pass
    for unit in managed:
        services.setdefault(unit, {
            'unit': unit, 'name': unit[:-8], 'description': '',
            'activeState': 'unknown', 'subState': '', 'active': False,
            'enabled': False, 'managed': True,
            'mainPid': None, 'memMB': None, 'uptimeSec': None, 'port': None,
        })
    port_map = _svc_listening_ports()
    for unit in managed:
        s = services.get(unit)
        if not s:
            continue
        info = _svc_show(unit)
        if not info:
            continue
        s['activeState'] = info.get('ActiveState', s['activeState'])
        s['subState'] = info.get('SubState', s['subState'])
        s['active'] = s['activeState'] == 'active'
        s['description'] = info.get('Description') or s['description']
        ufs = info.get('UnitFileState', '')
        if ufs:
            s['enabled'] = ufs == 'enabled'
        try:
            pid = int(info.get('MainPID', '0') or '0')
        except ValueError:
            pid = 0
        s['mainPid'] = pid or None
        mem = info.get('MemoryCurrent', '')
        if mem.isdigit():
            m = int(mem)
            s['memMB'] = round(m / 1048576, 1) if m < 10**15 else None
        mono = info.get('ActiveEnterTimestampMonotonic', '')
        if mono.isdigit() and s['active']:
            up = time.monotonic() - int(mono) / 1_000_000
            s['uptimeSec'] = int(up) if up > 0 else None
        s['port'] = _svc_port_for(pid, port_map) if pid else None
    return sorted(services.values(), key=lambda x: (not x['managed'], x['name']))

# Map each app-facing action to systemctl verb(s). 'on'/'off' use --now so the
# unit is (dis)enabled for boot AND started/stopped in one shot -- that's what
# makes a toggled-off service stay off across reboots.
_SYSCTL_ARGS = {
    'start': ['start'], 'stop': ['stop'], 'restart': ['restart'],
    'enable': ['enable'], 'disable': ['disable'],
    'on': ['enable', '--now'], 'off': ['disable', '--now'],
}

# Stopping/disabling any of these would sever PiLink's own link to the Pi, so the
# toggle refuses to turn them off (start/restart/enable are still allowed).
_SELF_CRITICAL = {
    'pilink-server.service', 'pilink-agent.service', 'ssh.service', 'sshd.service',
    'NetworkManager.service', 'systemd-networkd.service', 'dhcpcd.service',
}

def _systemctl(action: str, unit: str):
    """Run systemctl for one action on one unit; try unprivileged first, then
    non-interactive sudo (system units need root/polkit). Returns (ok, error).
    Callers MUST validate `unit` and confirm it is managed before calling."""
    verb = _SYSCTL_ARGS.get(action)
    if not verb:
        return False, f'Unknown action: {action}'
    base = ['systemctl'] + verb + [unit]
    try:
        r = subprocess.run(base, capture_output=True, text=True, timeout=25)
        if r.returncode == 0:
            return True, ''
        r2 = subprocess.run(['sudo', '-n'] + base, capture_output=True, text=True, timeout=25)
        if r2.returncode == 0:
            return True, ''
        return False, (r2.stderr or r.stderr or 'systemctl failed').strip()
    except subprocess.TimeoutExpired:
        return False, 'systemctl timed out'
    except Exception as e:
        return False, str(e)

# ── Terminal escape-sequence sanitiser ───────────────────────────────────────
# Strip OSC 52 (clipboard write) and OSC 8 (hyperlinks) before forwarding
# PTY / SSH output to the app. These sequences could exfiltrate clipboard
# contents or silently open URLs in the renderer.
_DANGEROUS_OSC = re.compile(
    rb'\x1b\](?:52|8);.*?(?:\x07|\x1b\\)',
    re.DOTALL,
)

def _sanitise_pty(data: bytes) -> bytes:
    """Remove clipboard-write (OSC 52) and hyperlink (OSC 8) escape sequences."""
    return _DANGEROUS_OSC.sub(b'', data)

def safe_path(raw: str) -> Path:
    """Resolve *raw* and raise PermissionError if it escapes allowed dirs."""
    p = Path(raw).expanduser().resolve()
    if not any(p == prefix or p.is_relative_to(prefix) for prefix in ALLOWED_PATH_PREFIXES):
        raise PermissionError(f'Access denied: {p}')
    return p

# TLS certificate paths
TLS_CERT = CONFIG_DIR / 'tls_cert.pem'
TLS_KEY  = CONFIG_DIR / 'tls_key.pem'

def cert_fingerprint():
    """Canonical SHA-256 fingerprint of our certificate, colon-hex uppercase --
    identical to `openssl x509 -fingerprint -sha256`.

    Published in the mDNS TXT record so the app can learn the expected identity
    OUT OF BAND, before it has ever spoken to this Pi. That is what closes the
    trust-on-first-use window: the app can verify the certificate it is offered
    instead of simply believing the first one it sees.
    """
    try:
        der = ssl.PEM_cert_to_DER_cert(TLS_CERT.read_text())
        raw = hashlib.sha256(der).hexdigest().upper()
        return ':'.join(raw[i:i + 2] for i in range(0, len(raw), 2))
    except Exception:
        return ''

def ensure_tls_cert():
    """Generate a self-signed TLS certificate if one doesn't exist yet.
    Uses openssl (always available on Raspberry Pi OS).
    The cert is pinned on first connect by the iOS app (TOFU); the CN doesn't
    matter for validation since we skip chain-of-trust and check fingerprints."""
    if TLS_CERT.exists() and TLS_KEY.exists():
        return True
    try:
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', str(TLS_KEY),
            '-out',    str(TLS_CERT),
            '-days',   '3650',
            '-nodes',
            '-subj',   '/CN=pilink-local/O=PiLink',
        ], check=True, capture_output=True)
        TLS_KEY.chmod(0o600)
        TLS_CERT.chmod(0o644)
        print(f'[tls] Generated self-signed certificate → {TLS_CERT}')
        return True
    except Exception as e:
        print(f'[tls] WARNING: Could not generate certificate ({e}) — falling back to plaintext')
        return False

# ── Push notifications (APNs) ─────────────────────────────────────────────────
#
# The Pi talks to Apple directly. That's the only architecture that delivers when
# the app is closed, which is the entire point — an alert you only see once you've
# opened the app is just a list.
#
# Credentials live beside the other secrets in ~/.pilink/ (chmod 600):
#   apns_key.p8  — the APNs auth key downloaded from the Apple Developer portal
#   apns.json    — {"keyId": "...", "teamId": "...", "bundleId": "com.spencer.pilink"}
#
# NOTE ON WHAT THIS CANNOT DO: the Pi cannot tell you it went offline. If it's
# down it can't send anything. "Came back" is reported here on startup; detecting
# "went away" is the app's job (local notification) or needs a third party.
APNS_KEY_FILE    = CONFIG_DIR / 'apns_key.p8'
APNS_CONFIG_FILE = CONFIG_DIR / 'apns.json'
PUSH_TOKENS_FILE = CONFIG_DIR / 'push_tokens.json'
ALERTS_FILE      = CONFIG_DIR / 'alerts.json'
ALERTS_CAP       = 100      # rolling in-app alert history kept on the Pi

PUSH_CATEGORIES = ('service', 'schedule', 'threshold', 'presence')

_apns_jwt_cache = {'token': None, 'made': 0}
_push_cooldown  = {}          # (category, key) -> last sent timestamp
PUSH_COOLDOWN_SEC = 15 * 60   # don't repeat the same alert within this window


def load_push_tokens() -> dict:
    if PUSH_TOKENS_FILE.exists():
        try:
            return json.loads(PUSH_TOKENS_FILE.read_text())
        except Exception:
            pass
    return {}


def save_push_tokens(d: dict):
    PUSH_TOKENS_FILE.write_text(json.dumps(d, indent=2))
    PUSH_TOKENS_FILE.chmod(0o600)


def _apns_config():
    try:
        return json.loads(APNS_CONFIG_FILE.read_text())
    except Exception:
        return None


def _apns_jwt():
    """ES256 JWT for the APNs provider API, cached.

    Apple rejects tokens refreshed more often than every 20 minutes and expires
    them at 60, so we regenerate at 30.

    The subtle part is the signature encoding: `cryptography` emits DER, but JOSE
    requires the raw r||s pair. Skipping that conversion produces a token Apple
    rejects with a completely unhelpful 403.
    """
    cfg = _apns_config()
    if not cfg or not APNS_KEY_FILE.exists():
        return None
    now = time.time()
    if _apns_jwt_cache['token'] and now - _apns_jwt_cache['made'] < 1800:
        return _apns_jwt_cache['token']
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    except ImportError:
        print('[push] cryptography not available — push disabled')
        return None

    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b'=')

    try:
        key = serialization.load_pem_private_key(APNS_KEY_FILE.read_bytes(), password=None)
        header  = b64(json.dumps({'alg': 'ES256', 'kid': cfg['keyId']}, separators=(',', ':')).encode())
        payload = b64(json.dumps({'iss': cfg['teamId'], 'iat': int(now)}, separators=(',', ':')).encode())
        signing_input = header + b'.' + payload
        der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, sv = asym_utils.decode_dss_signature(der)
        raw_sig = r.to_bytes(32, 'big') + sv.to_bytes(32, 'big')
        token = (signing_input + b'.' + b64(raw_sig)).decode()
        _apns_jwt_cache.update({'token': token, 'made': now})
        return token
    except Exception as e:
        print(f'[push] could not build APNs JWT: {e}')
        return None


def _apns_post(client, host, device_token, jwt, topic, payload):
    return client.post(
        f'https://{host}/3/device/{device_token}',
        headers={
            'authorization':    f'bearer {jwt}',
            'apns-topic':       topic,
            'apns-push-type':   'alert',
            'apns-priority':    '10',
        },
        json=payload,
        timeout=10,
    )


def _friendly_unit(unit):
    """'streamcode.service' -> 'streamcode'. Notification text should read like a
    sentence, not like systemd output."""
    return (unit or 'A service').replace('.service', '').replace('.socket', '').replace('.timer', '')


def _plain_reason(detail):
    """Turn a raw command error into something a person can act on.

    Returns None when we can't say anything useful -- better to stay silent than
    to put 'sudo: a password is required' on someone's lock screen.
    """
    d = (detail or '').lower()
    if 'password is required' in d or 'not allowed' in d:
        return "PiLink doesn't have permission to do that on your Pi."
    if 'timed out' in d or 'timeout' in d:
        return 'It took too long, so it was stopped.'
    if 'no such file' in d or 'not found' in d:
        return "The command or script couldn't be found."
    if 'permission denied' in d:
        return 'Permission was denied.'
    if 'connection refused' in d or 'unreachable' in d:
        return "Something it needed wasn't reachable."
    return None


# ── In-app alert history ─────────────────────────────────────────────────────
#
# The Alerts screen in the app was fully built — UI, store, live handler — but
# nothing ever fed it: the server only pushed to APNs and broadcast agent events,
# never a `type: 'alert'` the screen consumes. So it was permanently empty. We now
# record every notable event (the same ones that would notify you) into a rolling
# history on the Pi, broadcast it live to connected apps, and serve it on connect.

_alerts_lock = threading.Lock()
_alerts_recent = {}     # (category, dedup-key) -> last ts (ms), to avoid pile-ups


def _load_alerts():
    try:
        return json.loads(ALERTS_FILE.read_text())
    except Exception:
        return []


def _save_alerts(items):
    try:
        ALERTS_FILE.write_text(json.dumps(items[-ALERTS_CAP:]))
        ALERTS_FILE.chmod(0o600)
    except Exception as e:
        print(f'[alerts] could not save: {e}')


def _alert_meta(category, title, body):
    """Map a notification into an in-app alert's (type, severity, message).
    `type` picks the icon; `severity` the colour; the message drops the
    "PiName: " prefix since the Alerts screen is already per-device."""
    text = (title or '').split(': ', 1)[-1] if ': ' in (title or '') else (title or body or 'Alert')
    low = f'{title} {body}'.lower()
    if category == 'presence':
        kind = 'reboot' if ('reboot' in low or 'restart' in low or 'came back' in low) else 'online'
        return kind, 'info', text
    if category == 'threshold':
        atype = ('overheat' if ('hot' in low or 'temp' in low) else
                 'disk' if ('disk' in low or 'full' in low or 'storage' in low) else 'custom')
        return atype, 'warning', text
    if category == 'schedule':
        return 'custom', 'warning', text
    # service
    sev = 'critical' if ('keeps stopping' in low or "couldn't start" in low or 'is down' in low) else 'warning'
    return 'custom', sev, text


def record_alert(category, title, body, key=None):
    """Append one alert to the rolling history and broadcast it to connected apps.
    Light-deduped (same event within 30s is one entry) so a flapping condition
    can't bury the list."""
    atype, severity, message = _alert_meta(category, title, body)
    now = int(time.time() * 1000)
    dedup = (category, key or message)
    with _alerts_lock:
        if now - _alerts_recent.get(dedup, 0) < 30000:
            return
        _alerts_recent[dedup] = now
        alert = {'id': f'al_{now}_{secrets.token_hex(3)}', 'type': atype,
                 'severity': severity, 'message': message, 'timestamp': now, 'read': False}
        items = _load_alerts()
        items.append(alert)
        _save_alerts(items)
    broadcast({'type': 'alert', 'data': alert})


def push_notify(category, title, body, key=None, extra=None, bypass_cooldown=False):
    # Returns {'sent': n, 'failed': n, 'errors': [...], 'skipped': reason|None}.
    # Callers that report to the user MUST use this rather than assuming success:
    # the old test handler claimed "sent" the moment a thread started, so every
    # delivery failure was invisible.
    """Send a push to every registered device that wants this category.

    `key` de-duplicates: the same (category, key) won't fire again inside the
    cooldown window. Four enabled categories is a lot of surface area, and a
    notification channel you mute is worth less than none at all.
    """
    result = {'sent': 0, 'failed': 0, 'errors': [], 'skipped': None}
    if category not in PUSH_CATEGORIES:
        result['skipped'] = f'unknown category {category!r}'
        return result
    # Record it in the in-app Alerts history regardless of whether a remote push
    # actually goes out (no registered devices, notifications off, cooldown…). A
    # test push isn't a real event, so those are skipped.
    if not bypass_cooldown:
        try:
            record_alert(category, title, body, key)
        except Exception as e:
            print(f'[alerts] {e}')
    tokens = load_push_tokens()
    if not tokens:
        result['skipped'] = 'no devices registered'
        return result
    cfg = _apns_config()
    jwt = _apns_jwt()
    if not cfg or not jwt:
        result['skipped'] = 'APNs credentials missing or unreadable'
        return result

    dedup = (category, key or title)
    now = time.time()
    # A test push must ALWAYS send. Otherwise pressing "Send test notification"
    # twice would silently do nothing the second time and look like a failure.
    if not bypass_cooldown:
        if now - _push_cooldown.get(dedup, 0) < PUSH_COOLDOWN_SEC:
            result['skipped'] = 'within cooldown'
            return result
        _push_cooldown[dedup] = now

    try:
        import httpx
    except ImportError:
        result['skipped'] = 'httpx not installed (pip3 install "httpx[http2]")'
        print('[push] ' + result['skipped'])
        return result

    payload = {
        'aps': {'alert': {'title': title, 'body': body}, 'sound': 'default'},
        'pilink': {'category': category, 'device': CONFIG['name'], **(extra or {})},
    }
    topic = cfg.get('bundleId', 'com.spencer.pilink')
    changed = False

    try:
        with httpx.Client(http2=True) as client:
            for token, meta in list(tokens.items()):
                if category not in (meta.get('categories') or list(PUSH_CATEGORIES)):
                    continue
                # A development build's token only exists in the sandbox and a
                # TestFlight one only in production, and we can't tell which we
                # were given. Try the remembered host first, then the other, and
                # remember what worked so it's one request from then on.
                hosts = ['api.push.apple.com', 'api.sandbox.push.apple.com']
                if meta.get('host') in hosts:
                    hosts.remove(meta['host'])
                    hosts.insert(0, meta['host'])
                before = result['sent'] + result['failed']
                for host in hosts:
                    try:
                        r = _apns_post(client, host, token, jwt, topic, payload)
                    except Exception as e:
                        print(f'[push] {host} error: {e}')
                        continue
                    if r.status_code == 200:
                        result['sent'] += 1
                        print(f'[push] delivered ({host}) {category}: {title}')
                        if meta.get('host') != host:
                            meta['host'] = host
                            changed = True
                        break
                    reason = ''
                    try:
                        reason = r.json().get('reason', '')
                    except Exception:
                        pass
                    if reason in ('BadDeviceToken', 'DeviceTokenNotForTopic'):
                        continue           # wrong environment — try the other host
                    if reason == 'Unregistered':
                        tokens.pop(token, None)   # app was uninstalled
                        changed = True
                        result['failed'] += 1
                        result['errors'].append('device no longer registered (app uninstalled?)')
                        break
                    result['failed'] += 1
                    result['errors'].append(f'{r.status_code} {reason}'.strip())
                    print(f'[push] {host} {r.status_code} {reason}')
                    break
                if result['sent'] + result['failed'] == before:
                    # Rejected by both environments with a retryable reason --
                    # previously this fell out of the loop counted as neither
                    # sent nor failed, which is how "sent" could be reported for
                    # a push that never went anywhere.
                    result['failed'] += 1
                    result['errors'].append('token rejected by both production and sandbox')
        if changed:
            save_push_tokens(tokens)
    except Exception as e:
        result['errors'].append(str(e))
        print(f'[push] send failed: {e}')
    return result


# ── Sentinel: pre-armed dead man's switch ────────────────────────────────────
#
# THE PROBLEM THIS EXISTS FOR: a device cannot report its own death. If this Pi
# loses power or crashes, nothing running here can tell anyone. Detection needs
# a third party that expects a signal and notices its absence -- which is
# precisely what Apple does for HomePods, and does not expose as an API.
#
# HOW THIS DIFFERS FROM A NORMAL UPTIME MONITOR: we don't just say "alive". We
# hand the watcher a fully-formed notification plus a deadline --
#
#     "If you don't hear from me by 14:32, send exactly this."
#
# and then keep pushing the deadline forward. So:
#
#   * The watcher never receives apns_key.p8. It gets a provider token valid for
#     at most an hour. Compromising the watcher lets someone replay OUR message
#     to OUR phone briefly, and mint nothing.
#   * The watcher composes nothing, so the text can be accurate about cause --
#     "your Daily reboot didn't come back" vs "nothing was scheduled".
#   * NOTHING IS PRE-FIRED. Before a scheduled reboot we arm a different payload
#     with a longer window; if the reboot works we come back and re-arm, and no
#     notification is ever sent. It only fires on genuine failure.
SENTINEL_CONFIG_FILE = CONFIG_DIR / 'sentinel.json'

SENTINEL_BEAT_SEC     = 120   # 720 beats/day
SENTINEL_GRACE_SEC    = 360   # 3 missed beats before we're considered dead
SENTINEL_REBOOT_GRACE = 600   # a reboot gets longer -- booting legitimately takes a while

# Why 120s is affordable now, when it wasn't before.
#
# The watcher used to spend one Cloudflare KV write per beat: 720/day against a
# free-tier ceiling of 1,000. That is 72% of a daily budget spent saying "still
# here", with nothing left for a restart, a redeploy, or anything else on the
# account -- and it ran out most days before the UTC reset. Worker v4 moves the
# deadline into a Durable Object alarm (100,000 row writes/day, so 720 is 0.7%)
# and falls back to a KV lease (~144 writes/day) where alarms aren't available.
# The beat rate is no longer what the budget is spent on, so it is chosen for
# detection latency alone.

# Cloudflare's edge blocks requests from known automation libraries with a 403
# (error 1010) BEFORE they reach the Worker -- the default `python-httpx/x.y`
# User-Agent is on that denylist, so a heartbeat sent without this header is
# silently rejected and the deadline is never set: Sentinel would look armed and
# fire nothing. Verified on the Pi: urllib/httpx defaults -> 403, any named UA
# (even curl's) -> 200. So we send an honest, non-denylisted identifier.
SENTINEL_UA = 'PiLink-Sentinel/1.0 (+https://github.com/spencermoya-byte/PiLink)'


def load_sentinel_config():
    """{'url': 'https://<worker>/beat', 'secret': '...', 'id': 'streaming-pi'}"""
    try:
        return json.loads(SENTINEL_CONFIG_FILE.read_text())
    except Exception:
        return None


def _sentinel_payload(kind='unexpected', label=''):
    """Author the notification NOW, for the watcher to send later if we vanish.

    Written here rather than in the watcher because only this Pi knows whether a
    disappearance was expected -- that context is exactly what makes the message
    useful instead of alarming.
    """
    name = CONFIG['name']
    if kind == 'scheduled-reboot':
        title = f'{name} hasn\'t come back'
        body  = (f'Your scheduled task "{label}" restarted it, but it hasn\'t reconnected. '
                 'It may have failed to boot.')
    elif kind == 'scheduled-shutdown':
        title = f'{name} hasn\'t come back'
        body  = f'Your scheduled task "{label}" shut it down and it hasn\'t returned.'
    elif kind == 'test':
        title = f'{name}: offline alerts are working'
        body  = ('This is the test you asked for. If your Pi ever goes offline for real, '
                 'this is how you\'ll hear about it.')
    else:
        title = f'{name} stopped responding'
        body  = ('No response for several minutes, and nothing was scheduled — '
                 'it may have lost power or dropped off the network.')
    return {'aps': {'alert': {'title': title, 'body': body}, 'sound': 'default'},
            'pilink': {'category': 'presence', 'device': name, 'sentinel': True, 'kind': kind}}


def sentinel_send(deadline_sec, kind='unexpected', label='', disarm=False):
    """Push the deadline forward (or stand the switch down entirely).

    Returns True if the watcher acknowledged. Failures are logged but never
    raised: the Sentinel is a safety net, and a net that crashes the thing it's
    protecting is worse than no net.
    """
    cfg = load_sentinel_config()
    if not cfg or not cfg.get('url') or not cfg.get('secret'):
        return False
    try:
        import httpx
    except ImportError:
        return False

    body = {
        'id':     cfg.get('id') or CONFIG['name'],
        'sentAt': int(time.time()),
        'disarm': bool(disarm),
    }
    if not disarm:
        jwt = _apns_jwt()
        acfg = _apns_config()
        toks = list(load_push_tokens().keys())
        if not (jwt and acfg and toks):
            return False          # nothing to arm it with
        body.update({
            # graceSec is what v4 watchers use: they own the clock, so they get
            # a duration rather than an instant and can decide how far ahead to
            # push their own deadline. `deadline` stays for a watcher deployed
            # before this change -- an absolute time it already knows how to
            # read. Sending both means a Pi and a watcher can be updated in
            # either order without a window where alerts silently stop arming.
            'graceSec':     deadline_sec,
            'deadline':     int(time.time()) + deadline_sec,
            'apnsJwt':      jwt,               # short-lived; the .p8 never leaves this Pi
            'topic':        acfg.get('bundleId', 'com.spencer.pilink'),
            'deviceTokens': toks,
            'payload':      _sentinel_payload(kind, label),
            'label':        kind,
        })

    raw = json.dumps(body, separators=(',', ':'))
    sig = hmac.new(cfg['secret'].encode(), raw.encode(), hashlib.sha256).hexdigest()
    try:
        r = httpx.post(cfg['url'], content=raw, timeout=10,
                       headers={'content-type': 'application/json',
                                'x-sentinel-hmac': sig,
                                'user-agent': SENTINEL_UA})
        if r.status_code != 200:
            print(f'[sentinel] watcher returned {r.status_code}: {r.text[:120]}')
            return False
        return True
    except Exception as e:
        print(f'[sentinel] could not reach watcher: {e}')
        return False


_SENTINEL_TEST_UNTIL = 0     # while set, the heartbeat pauses so a test can lapse
_SENTINEL_LAST_OK = False
_SENTINEL_LAST_AT = 0

# The end-to-end proof. Setup does not claim success until a real notification
# has actually landed on the phone, because every part of this chain has failed
# silently at least once: a worker that accepted heartbeats and never swept, a
# token that armed nothing, and an APNs push that Apple accepted and iOS dropped
# because notifications were switched off for the app.
_SENTINEL_VERIFY = {'active': False, 'startedAt': 0, 'confirmed': False}
SENTINEL_VERIFY_GRACE = 45    # deliberately short: we want to watch it fire
SENTINEL_VERIFY_WAIT = 165    # how long to wait for the phone to say it arrived


def _sentinel_health(cfg, device_id=None):
    """Ask the deployed worker about itself. Read-only, so it costs nothing."""
    if not cfg or not cfg.get('url'):
        return None
    url = cfg['url'].replace('/beat', '/health')
    if device_id:
        url += '?id=' + urllib.parse.quote(str(device_id))
    try:
        req = urllib.request.Request(url, headers={'user-agent': SENTINEL_UA})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def sentinel_status(verified=None):
    """What the app shows. Deliberately reports the truth, including 'configured
    but never actually reached the watcher' -- which otherwise looks identical to
    working right up until the day you need it."""
    cfg = load_sentinel_config()
    # 'alarm' means the deadline lives in a Durable Object alarm and an alert
    # arrives one grace period after the Pi goes quiet. 'kv-lease' is the
    # fallback for accounts that can't run Durable Objects: same alert, but it
    # can be up to twenty minutes late. Reported rather than hidden, because
    # those are different promises and the user should know which one they have.
    mode = (cfg or {}).get('mode', '')
    st = {
        'configured':  bool(cfg and cfg.get('url')),
        'url':         (cfg or {}).get('url', ''),
        'mode':        mode,
        'lastBeatOk':  _SENTINEL_LAST_OK,
        'lastBeatAt':  _SENTINEL_LAST_AT,
        'beatSeconds': SENTINEL_BEAT_SEC,
        'graceSeconds': SENTINEL_GRACE_SEC,
        'detectionSeconds': SENTINEL_GRACE_SEC if mode == 'alarm' else 1200,
        'pushReady':   bool(_apns_config() and APNS_KEY_FILE.exists() and load_push_tokens()),
        # When a real alert last actually landed on a phone. This is the only
        # honest answer to "is it working" -- everything else is a proxy for it.
        'verifiedAt':  int((cfg or {}).get('verifiedAt', 0)),
        'verifying':   bool(_SENTINEL_VERIFY['active']),
        'error':       '',
    }
    if verified is not None:
        st['lastBeatOk'] = verified
        if not verified:
            st['error'] = "Saved, but your Sentinel didn't answer. Check the address and the setup code match."
    return st


def sentinel_run_verification(emit, finish):
    """Let a real alert fire, and wait for the phone to confirm it arrived.

    Runs on its own thread. `emit(msg)` streams progress; `finish(ok, detail)`
    is called exactly once.

    WHY NOT JUST CHECK THE WORKER ANSWERS: because every failure this feature has
    ever had was downstream of that. The worker can be perfect and the alert
    still never arrives -- notifications off for the app, a device token from a
    build that no longer exists, a bundle id that puts the token in the other
    APNs environment. None of those are visible from the Pi. The only proof that
    the chain works is a notification that actually lands, so we make one.

    The diagnosis when it doesn't is the other half. Asking the worker whether it
    FIRED splits the two halves cleanly: fired-but-not-received is a phone
    problem, never-fired is a watcher problem, and they have nothing to do with
    each other. Guessing between them is what made this hard before.
    """
    global _SENTINEL_TEST_UNTIL
    cfg = load_sentinel_config()
    dev_id = (cfg or {}).get('id') or CONFIG['name']

    _SENTINEL_VERIFY.update({'active': True, 'startedAt': time.time(), 'confirmed': False})
    # Stop beating so the deadline genuinely lapses. Without this the heartbeat
    # keeps pushing it forward and nothing ever fires.
    _SENTINEL_TEST_UNTIL = time.time() + SENTINEL_VERIFY_GRACE + SENTINEL_VERIFY_WAIT

    if not sentinel_send(SENTINEL_VERIFY_GRACE, kind='test'):
        _SENTINEL_VERIFY['active'] = False
        _SENTINEL_TEST_UNTIL = 0
        finish(False, {'stage': 'arm',
                       'message': "Your Pi couldn't arm the test with the watcher."})
        return

    emit('Waiting for a real alert to arrive…')
    deadline = time.time() + SENTINEL_VERIFY_WAIT
    while time.time() < deadline:
        if _SENTINEL_VERIFY['confirmed']:
            break
        time.sleep(2)

    confirmed = _SENTINEL_VERIFY['confirmed']
    _SENTINEL_VERIFY['active'] = False
    _SENTINEL_TEST_UNTIL = 0
    sentinel_send(SENTINEL_GRACE_SEC)          # re-arm normally, whatever happened

    if confirmed:
        try:
            cfg = load_sentinel_config() or {}
            cfg['verifiedAt'] = int(time.time())
            SENTINEL_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
            SENTINEL_CONFIG_FILE.chmod(0o600)
        except Exception:
            pass
        finish(True, {})
        return

    # Nothing arrived. Ask the watcher whether it even fired -- that single fact
    # decides which half is broken, and the two need completely different fixes.
    health = _sentinel_health(cfg, dev_id)
    sw = (health or {}).get('switch') or {}
    if health and sw.get('firedAt'):
        finish(False, {'stage': 'delivery', 'fired': True,
                       'message': "The watcher noticed your Pi go quiet and sent the alert, "
                                  "but it never reached this phone. That's a notification "
                                  "problem, not a watcher problem: check notifications are "
                                  "allowed for PiLink, then run the test again."})
    elif health:
        finish(False, {'stage': 'fire', 'fired': False,
                       'message': "Your Pi stopped checking in, but the watcher never raised "
                                  "the alert. It is deployed and reachable, so this is worth "
                                  "setting up again."})
    else:
        finish(False, {'stage': 'unreachable',
                       'message': "Your Pi couldn't reach the watcher to find out what "
                                  "happened. Check the Pi still has internet."})


def sentinel_loop():
    """Keep the switch armed. Every beat pushes the deadline forward.

    Re-reads the config every cycle rather than once at startup, so a Sentinel
    set up from the app (or removed) takes effect within ~30s without a server
    restart -- the loop is always running and simply reacts to config appearing
    or disappearing.
    """
    ok_last = None
    note = None                 # last thing logged, so we log transitions only
    global _SENTINEL_LAST_OK, _SENTINEL_LAST_AT
    while True:
        cfg = load_sentinel_config()
        if not cfg or not cfg.get('url'):
            if note != 'off':
                print('[sentinel] not configured — offline detection is OFF '
                      '(set it up in the app; it is free)')
                note, ok_last, _SENTINEL_LAST_OK = 'off', None, False
            time.sleep(30)
            continue
        if note != cfg.get('url'):
            print(f'[sentinel] armed via {cfg.get("url")} — '
                  f'beat every {SENTINEL_BEAT_SEC}s, alert after {SENTINEL_GRACE_SEC}s of silence')
            note, ok_last = cfg.get('url'), None
        # During a self-test we deliberately stop beating so the deadline lapses
        # and a real alert arrives -- proving the whole chain without needing
        # anyone to pull the power out of their Pi.
        if time.time() < _SENTINEL_TEST_UNTIL:
            time.sleep(5)
            continue
        ok = sentinel_send(SENTINEL_GRACE_SEC)
        _SENTINEL_LAST_OK, _SENTINEL_LAST_AT = ok, int(time.time() * 1000)
        if ok != ok_last:      # only log transitions, not every two minutes
            print(f'[sentinel] {"armed" if ok else "NOT ARMED — alerts will not fire"}')
            ok_last = ok
        time.sleep(SENTINEL_BEAT_SEC)


# ── Sentinel one-tap deploy (the Pi provisions its own Cloudflare watcher) ────
#
# The worker source is embedded (base64) so it travels with the server through
# BOTH update paths -- deploy-pi.ps1 and GitHub self-update -- and needs no
# external fetch at deploy time, which also means it works for a user who never
# had the standalone repo.
#
# Generated from sentinel/worker.js. Regenerate on any change to that file:
#
#   python3 tools/embed-sentinel.py
#
# That is a script rather than a note because the note did not work: the worker
# was fixed in the repo and never redeployed, and Cloudflare ran the old build
# for months while the source read as correct and the version number said 3 in
# both. The script also stamps a build fingerprint the deployed worker reports
# at /health, so drift is one command to notice rather than an autopsy.
SENTINEL_WORKER_B64 = (
    "LyoqCiAqIFBpTGluayBTZW50aW5lbCDigJQgYSBwcmUtYXJtZWQgZGVhZCBtYW4ncyBzd2l0Y2guCiAqCiAqIFdIQVQgUFJPQkxF"
    "TSBUSElTIFNPTFZFUwogKgogKiBBIGRldmljZSBjYW5ub3QgcmVwb3J0IGl0cyBvd24gZGVhdGguIElmIHRoZSBQaSBsb3NlcyBw"
    "b3dlciwgY3Jhc2hlcywgb3IgdGhlCiAqIGhvdXNlIGludGVybmV0IGRyb3BzLCBub3RoaW5nIG9uIHRoZSBQaSBjYW4gdGVsbCB5"
    "b3Ug4oCUIGl0J3MgZ29uZS4gRGV0ZWN0aW9uCiAqIGZ1bmRhbWVudGFsbHkgcmVxdWlyZXMgYSB0aGlyZCBwYXJ0eSB0aGF0IGV4"
    "cGVjdHMgYSBzaWduYWwgYW5kIG5vdGljZXMgaXRzCiAqIGFic2VuY2UuIEFwcGxlIHNvbHZlcyB0aGlzIGZvciBIb21lUG9kcyBi"
    "eSBiZWluZyB0aGF0IHRoaXJkIHBhcnR5IHRoZW1zZWx2ZXM7CiAqIHRoZXkganVzdCBkb24ndCBleHBvc2UgaXQgYXMgYW4gQVBJ"
    "LgogKgogKiBUaGlzIFdvcmtlciBpcyB0aGF0IHRoaXJkIHBhcnR5LCBydW5uaW5nIGZyZWUgb24gQ2xvdWRmbGFyZSwgb3duZWQg"
    "YnkgeW91LgogKgogKiBXSFkgSVQgSVNOJ1QgSlVTVCBBIEhFQVJUQkVBVCBTRVJWSUNFCiAqCiAqIEEgbm9ybWFsIHVwdGltZSBt"
    "b25pdG9yIG5lZWRzIHlvdXIgY3JlZGVudGlhbHMgc28gaXQgY2FuIGFsZXJ0IHlvdSwgYW5kIGl0CiAqIGNvbXBvc2VzIHRoZSBt"
    "ZXNzYWdlIGl0c2VsZiDigJQgc28gaXQgY2FuJ3QgdGVsbCBhIGNyYXNoIGFwYXJ0IGZyb20gYSByZWJvb3QgeW91CiAqIHNjaGVk"
    "dWxlZC4gQm90aCBhcmUgYmFkLgogKgogKiBJbnN0ZWFkLCB0aGUgUGkgaGFuZHMgb3ZlciBhIGZ1bGx5LWZvcm1lZCBub3RpZmlj"
    "YXRpb24gYW5kIGEgZGVhZGxpbmU6CiAqCiAqICAgIklmIHlvdSBkb24ndCBoZWFyIGZyb20gbWUgYnkgMTQ6MzIsIHNlbmQgZXhh"
    "Y3RseSB0aGlzLCB1c2luZyB0aGlzIHRva2VuLiIKICoKICogVGhlIFBpIGtlZXBzIHB1c2hpbmcgdGhlIGRlYWRsaW5lIGZvcndh"
    "cmQuIENvbnNlcXVlbmNlczoKICoKICogICAtIFRoaXMgV29ya2VyIG5ldmVyIHNlZXMgdGhlIEFQTnMgc2lnbmluZyBrZXkgKC5w"
    "OCkuIEl0IG9ubHkgZXZlciBnZXRzIGEKICogICAgIHByb3ZpZGVyIHRva2VuIHZhbGlkIGZvciBhdCBtb3N0IGFuIGhvdXIuIEEg"
    "dG90YWwgY29tcHJvbWlzZSBvZiB0aGlzCiAqICAgICBXb3JrZXIgbGV0cyBhbiBhdHRhY2tlciByZXBsYXkgWU9VUiBub3RpZmlj"
    "YXRpb24gdG8gWU9VUiBwaG9uZSBmb3IgdW5kZXIKICogICAgIGFuIGhvdXIsIGFuZCBtaW50IG5vdGhpbmcuCiAqICAgLSBUaGlz"
    "IFdvcmtlciBoYXMgbm8gbWVzc2FnZSB0ZW1wbGF0ZXMgYW5kIG5vIGxvZ2ljIGFib3V0IHdoYXQgaGFwcGVuZWQuIEl0CiAqICAg"
    "ICBpcyBhIHJlbGF5IHdpdGggYSBzdG9wd2F0Y2guIFRoZSBQaSBhdXRob3JzIHRoZSB0ZXh0LCBzbyBpdCBjYW4gc2F5CiAqICAg"
    "ICAieW91ciBEYWlseSByZWJvb3QgZGlkbid0IGNvbWUgYmFjayIgdmVyc3VzICJub3RoaW5nIHdhcyBzY2hlZHVsZWQiLgogKiAg"
    "IC0gTm90aGluZyBpcyBldmVyIHByZS1maXJlZC4gQmVmb3JlIGEgc2NoZWR1bGVkIHJlYm9vdCB0aGUgUGkgYXJtcyBhCiAqICAg"
    "ICBkaWZmZXJlbnQgcGF5bG9hZCB3aXRoIGEgbG9uZ2VyIGRlYWRsaW5lOyBpZiB0aGUgcmVib290IHdvcmtzIHRoZSBQaQogKiAg"
    "ICAgcmV0dXJucyBhbmQgcmUtYXJtcywgYW5kIG5vIG5vdGlmaWNhdGlvbiBpcyBldmVyIHNlbnQuCiAqCiAqIOKUgOKUgOKUgOKU"
    "gOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKU"
    "gOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKU"
    "gOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgAogKiBX"
    "SFkgVEhJUyBGSUxFIFdBUyBSRVdSSVRURU4gKHY0KTogVEhFIEZSRUUgVElFUiBSQU4gT1VUIEVWRVJZIERBWQogKgogKiB2MyBz"
    "dG9yZWQgdGhlIGRlYWRsaW5lIGluIFdvcmtlcnMgS1YgYW5kIHJld3JvdGUgaXQgb24gZXZlcnkgaGVhcnRiZWF0LiBBdCBhCiAq"
    "IDItbWludXRlIGJlYXQgdGhhdCBpcyA3MjAgd3JpdGVzL2RheSBhZ2FpbnN0IGEgZnJlZS10aWVyIGNlaWxpbmcgb2YgMSwwMDAg"
    "4oCUCiAqIDcyJSBvZiB0aGUgZGFpbHkgYnVkZ2V0IGNvbnN1bWVkIGRvaW5nIG5vdGhpbmcgYnV0IHNheWluZyAic3RpbGwgaGVy"
    "ZSIsIHdpdGgKICogbm8gaGVhZHJvb20gZm9yIGEgcmVzdGFydCwgYSByZWRlcGxveSwgb3IgYW55dGhpbmcgZWxzZSBvbiB0aGUg"
    "YWNjb3VudC4gSXQgcmFuCiAqIG91dCBtb3N0IGRheXMgYmVmb3JlIHRoZSBVVEMgcmVzZXQuCiAqCiAqIFR3byBzZXBhcmF0ZSBw"
    "cm9ibGVtcywgYm90aCBmaXhlZCBoZXJlLgogKgogKiAxLiBUSEUgTEVBSy4gdjMncyBjcm9uIHJhbiBvbmNlIGEgbWludXRlIGFu"
    "ZCBkaWQ6CiAqCiAqICAgICAgICBpZiAoIShhd2FpdCBLVi5nZXQoJ2Nyb246c3RhcnRlZCcpKSkgYXdhaXQgS1YucHV0KCdjcm9u"
    "OnN0YXJ0ZWQnLCAuLi4pCiAqCiAqICAgIGludGVuZGVkIHRvIGNvc3Qgb25lIHdyaXRlIGV2ZXIuIEJ1dCBLViByZWFkcyBhcmUg"
    "c2VydmVkIGZyb20gYSBwZXItY29sbwogKiAgICBjYWNoZSB0aGF0IGFsc28gY2FjaGVzIE1JU1NFUywgYW5kIHRoZSBjcm9uIHJ1"
    "bnMgaW4gd2hpY2hldmVyIGNvbG8gcGlja3MgaXQKICogICAgdXAuIEV2ZXJ5IGNvbG8gdGhhdCByYW4gdGhlIHRpY2sgYmVmb3Jl"
    "IHRoYXQga2V5IGhhZCBwcm9wYWdhdGVkIHJlYWQgbnVsbAogKiAgICBhbmQgd3JvdGUgaXQgYWdhaW4uIHYzJ3Mgb3duIGNvbW1l"
    "bnRzIHJlY29yZCB0aGF0IGEgcGVyLXRpY2sgZ3VhcmQgaGFkCiAqICAgIGFscmVhZHkgYnVybmVkIHRoZSBxdW90YSBvbmNlIGFu"
    "ZCB3YXMgImZpeGVkIiBieSBtYWtpbmcgaXQgb25lLXNob3Qg4oCUIGJ1dAogKiAgICB0aGUgcmVhZC10aGVuLXdyaXRlLWlmLW1p"
    "c3Npbmcgc2hhcGUgaXMgdGhlIGxlYWssIG5vdCB0aGUgZnJlcXVlbmN5LiBJdCBpcwogKiAgICBnb25lIGVudGlyZWx5IG5vdzsg"
    "bm90aGluZyBwcm92ZXMgY3JvbiBsaXZlbmVzcyBieSBwYXlpbmcgZm9yIGEgd3JpdGUuCiAqCiAqIDIuIFRIRSBGTE9PUi4gRXZl"
    "biB3aXRoIHplcm8gbGVhaywgNzIwIHdyaXRlcy9kYXkgaXMgYSBmaXhlZCBjb3N0IHRoYXQgc2NhbGVzCiAqICAgIHdpdGggaG93"
    "IGZhc3QgeW91IHdhbnQgdG8gZGV0ZWN0IGRlYXRoLiBTaG9ydCBkZXRlY3Rpb24gcmVxdWlyZWQgZnJlcXVlbnQKICogICAgd3Jp"
    "dGVzIGJlY2F1c2UgdGhlIHN0b3B3YXRjaCBsaXZlZCBpbiBhIHN0b3JlIHRoYXQgY2hhcmdlcyBmb3IgdGlja2luZy4KICoKICog"
    "ICAgU28gdGhlIHN0b3B3YXRjaCBtb3ZlZC4gQSBEdXJhYmxlIE9iamVjdCBhbGFybSBJUyBhIGRlYWRsaW5lOiBzZXQgaXQsIGFu"
    "ZAogKiAgICB0aGUgcnVudGltZSB3YWtlcyB0aGUgb2JqZWN0IHdoZW4gaXQgcGFzc2VzLiBQdXNoaW5nIGFuIGFsYXJtIGZvcndh"
    "cmQgY29zdHMKICogICAgb25lIFNRTGl0ZSByb3cgd3JpdGUgYWdhaW5zdCBhIGZyZWUtdGllciBjZWlsaW5nIG9mIDEwMCwwMDAv"
    "ZGF5IOKAlCBhIGJ1ZGdldAogKiAgICAxMDB4IGxhcmdlciBmb3IgdGhlIHNhbWUgNzIwIGJlYXRzLiBUaGUgY3JvbiBkaXNhcHBl"
    "YXJzIHdpdGggaXQsIGJlY2F1c2UKICogICAgbm90aGluZyBuZWVkcyB0byBzd2VlcCBmb3IgZXhwaXJ5IGFueSBtb3JlLCBhbmQg"
    "ZGV0ZWN0aW9uIGxhdGVuY3kgZHJvcHMgdG8KICogICAgZXhhY3RseSB0aGUgZ3JhY2UgcGVyaW9kIGluc3RlYWQgb2YgdGhlIGdy"
    "YWNlIHBlcmlvZCBwbHVzIGEgY3JvbiB0aWNrLgogKgogKiBEdXJhYmxlIE9iamVjdHMgYXJlIG9uIHRoZSBXb3JrZXJzIEZyZWUg"
    "cGxhbiwgYnV0IE9OTFkgd2l0aCB0aGUgU1FMaXRlIHN0b3JhZ2UKICogYmFja2VuZCDigJQgaGVuY2UgdGhlIGBuZXdfc3FsaXRl"
    "X2NsYXNzZXNgIG1pZ3JhdGlvbiB0aGUgZGVwbG95IHNlbmRzLiBJZiB0aGF0CiAqIG1pZ3JhdGlvbiBjYW5ub3QgYmUgYXBwbGll"
    "ZCAoYW4gb2xkZXIgYWNjb3VudCwgYSB0b2tlbiB3aXRob3V0IHRoZSBwZXJtaXNzaW9uKQogKiB0aGUgV29ya2VyIHN0aWxsIHJ1"
    "bnMsIGZhbGxzIGJhY2sgdG8gS1YsIGFuZCBzd2l0Y2hlcyBLViBmcm9tIHJld3JpdGUtZXZlcnktCiAqIGJlYXQgdG8gYSBMRUFT"
    "RTogdGhlIHN0b3JlZCBkZWFkbGluZSBydW5zIHdlbGwgYWhlYWQgb2YgdGhlIGJlYXQgaW50ZXJ2YWwsIGFuZAogKiBhIGJlYXQg"
    "dGhhdCBjaGFuZ2VzIG5vdGhpbmcgbWF0ZXJpYWwgYW5kIHN0aWxsIGhhcyBsZWFzZSBsZWZ0IGNvc3RzIGEgcmVhZCBhbmQKICog"
    "bm8gd3JpdGUgYXQgYWxsLiBUaGF0IGlzIH4xNDQgd3JpdGVzL2RheSBpbnN0ZWFkIG9mIDcyMCwgYXQgdGhlIGNvc3Qgb2YgYQog"
    "KiBsb29zZXIgZGV0ZWN0aW9uIHdpbmRvdy4gYC9oZWFsdGhgIHJlcG9ydHMgd2hpY2ggbW9kZSBpcyBsaXZlLCBhbmQgc2F5cyBz"
    "bwogKiBwbGFpbmx5LCBiZWNhdXNlIGEgc2FmZXR5IG5ldCB0aGF0IHF1aWV0bHkgZGVncmFkZWQgaXMgdGhlIHRoaW5nIHdvcnRo"
    "IGtub3dpbmcuCiAqCiAqIEZSRUUgVElFUiBCVURHRVQKICoKICogICBhbGFybSBtb2RlIChwcmVmZXJyZWQpICAgfjcyMCBTUUxp"
    "dGUgcm93IHdyaXRlcy9kYXkgb2YgMTAwLDAwMCAgIDAuNyUKICogICAgICAgICAgICAgICAgICAgICAgICAgICAgfjcyMCByZXF1"
    "ZXN0cy9kYXkgb2YgMTAwLDAwMCAgICAgICAgICAgIDAuNyUKICogICAgICAgICAgICAgICAgICAgICAgICAgICAgbm8gY3JvbiB0"
    "cmlnZ2VyIGF0IGFsbAogKiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZXRlY3Rpb246IGV4YWN0bHkgdGhlIGdyYWNlIHBl"
    "cmlvZAogKgogKiAgIGt2LWxlYXNlIG1vZGUgKGZhbGxiYWNrKSB+MTQ0IEtWIHdyaXRlcy9kYXkgb2YgMSwwMDAgICAgICAgICAg"
    "ICAxNC40JQogKiAgICAgICAgICAgICAgICAgICAgICAgICAgICB+MiwxNjAgS1YgcmVhZHMvZGF5IG9mIDEwMCwwMDAKICogICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgMSBjcm9uIHRyaWdnZXIsIDEtbWludXRlIG1pbmltdW0KICogICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgZGV0ZWN0aW9uOiBncmFjZSwgdGhlbiAxMC0yMCBtaW4gb2YgbGVhc2UKICovCgovKioKICogRmluZ2VycHJp"
    "bnQgb2YgdGhpcyBmaWxlJ3Mgc291cmNlLCBzdGFtcGVkIGJ5IHRvb2xzL2VtYmVkLXNlbnRpbmVsLnB5LgogKgogKiBUaGlzIGV4"
    "aXN0cyBiZWNhdXNlIG9mIGEgcmVhbCBmYWlsdXJlOiB0aGUgZGVwbG95ZWQgV29ya2VyIHNpbGVudGx5IGRyaWZ0ZWQKICogZnJv"
    "bSB0aGUgcmVwby4gVGhlIEtWIGxlYWsgYWJvdmUgd2FzIGZvdW5kLCBmaXhlZCBhbmQgY29tbWl0dGVkIC0tIGFuZCBuZXZlcgog"
    "KiByZWRlcGxveWVkLiBDbG91ZGZsYXJlIGtlcHQgcnVubmluZyB0aGUgb2xkIGJ1aWxkIGZvciBtb250aHMgd2hpbGUgdGhlIHNv"
    "dXJjZQogKiByZWFkIGFzIGNvcnJlY3QsIGFuZCB0aGUgb25seSBjbHVlIHdhcyBhIGZpZWxkIG1pc3NpbmcgZnJvbSAvaGVhbHRo"
    "IHRoYXQKICogbm9ib2R5IGhhZCByZWFzb24gdG8gbG9vayBhdC4KICoKICogQSBoYW5kLW1haW50YWluZWQgYHZlcnNpb246IDNg"
    "IGNhbm5vdCBjYXRjaCB0aGF0OyBpdCB3YXMgMyBpbiBib3RoIGJ1aWxkcy4gQQogKiBoYXNoIG9mIHRoZSBzb3VyY2UgY2FuLCBi"
    "ZWNhdXNlIGl0IGNoYW5nZXMgd2hlbmV2ZXIgYW55dGhpbmcgZG9lcy4gQ29tcGFyZQogKiAvaGVhbHRoJ3MgYGJ1aWxkYCBhZ2Fp"
    "bnN0IHRoZSByZXBvIGFuZCBkcmlmdCBpcyBvbmUgY29tbWFuZCwgbm90IGFuIGF1dG9wc3kuCiAqLwpjb25zdCBCVUlMRCA9ICc3"
    "ODM4YmM3NWYyMTInOwoKY29uc3QgTUFYX1NLRVdfU0VDID0gMzAwOyAgICAgICAgLy8gcmVqZWN0IGhlYXJ0YmVhdHMgdGhpcyBm"
    "YXIgb3V0IG9mIHN0ZXAKY29uc3QgTUFYX0JPRFkgPSA4MTkyOyAgICAgICAgICAgLy8gYSBoZWFydGJlYXQgaXMgfjFLQjsgcmVm"
    "dXNlIGFueXRoaW5nIGFic3VyZAoKLy8gS1YgZmFsbGJhY2sgb25seS4gVGhlIGxlYXNlIHJ1bnMgYWhlYWQgb2YgdGhlIGJlYXQg"
    "c28gbW9zdCBiZWF0cyBjb3N0IG5vdGhpbmc7Ci8vIGEgd3JpdGUgaGFwcGVucyBvbmx5IG9uY2UgbGVzcyB0aGFuIFJFTkVXX01B"
    "UkdJTiBvZiBpdCByZW1haW5zLiBEZXRlY3Rpb24KLy8gdGhlcmVmb3JlIGxhbmRzIHNvbWV3aGVyZSBiZXR3ZWVuIFJFTkVXX01B"
    "UkdJTiBhbmQgTEVBU0VfU0VDIGFmdGVyIGRlYXRoIOKAlAovLyB0aGUgcHJpY2Ugb2Yga2VlcGluZyB0aGUgc3RvcHdhdGNoIGlu"
    "IGEgc3RvcmUgdGhhdCBjaGFyZ2VzIHRvIHRpY2sgaXQuCmNvbnN0IExFQVNFX1NFQyA9IDEyMDA7CmNvbnN0IFJFTkVXX01BUkdJ"
    "TiA9IDYwMDsKCi8qKgogKiBUaW1pbmdzLCBvdmVycmlkYWJsZSBPTkxZIGJ5IGVudiB2YXJzIHRoYXQgcHJvZHVjdGlvbiBuZXZl"
    "ciBzZXRzLgogKgogKiBUaGUgdmVyaWZpZXIgY29tcHJlc3NlcyB0aGUgY2xvY2sgdG8gc2Vjb25kcyBzbyBpdCBjYW4gd2F0Y2gg"
    "YSBsZWFzZSBhY3R1YWxseQogKiBleHBpcmUgYW5kIGFuIGFsZXJ0IGFjdHVhbGx5IGZpcmUuIFRoZSBhbHRlcm5hdGl2ZSBpcyBz"
    "ZWVkaW5nIHRoZSBLViBzdG9yZQogKiBiZWhpbmQgdGhlIFdvcmtlcidzIGJhY2ssIHdoaWNoIHRlc3RzIHRoZSBzdG9yZSByYXRo"
    "ZXIgdGhhbiB0aGUgV29ya2VyLgogKi8KZnVuY3Rpb24gdHVuaW5nKGVudikgewogIHJldHVybiB7CiAgICBsZWFzZTogTnVtYmVy"
    "KGVudiAmJiBlbnYuTEVBU0VfU0VDKSB8fCBMRUFTRV9TRUMsCiAgICBtYXJnaW46IE51bWJlcihlbnYgJiYgZW52LlJFTkVXX01B"
    "UkdJTikgfHwgUkVORVdfTUFSR0lOLAogICAgcmV0cnlTZWM6IE51bWJlcihlbnYgJiYgZW52LkFQTlNfUkVUUllfU0VDKSB8fCBB"
    "UE5TX1JFVFJZX1NFQywKICB9Owp9CgovKioKICogSG93IGxvbmcgdGhlIHN0b3JlZCBkZWFkbGluZSBydW5zIGFoZWFkLCBhbmQg"
    "d2hlbiBhIGJlYXQgaGFzIHRvIHBheSB0byByZW5ldyBpdC4KICoKICogYGhvbGRgIG5ldmVyIHVuZGVyY3V0cyB3aGF0IHRoZSBQ"
    "aSBhc2tlZCBmb3I6IGEgc2NoZWR1bGVkIHJlYm9vdCBhc2tzIGZvciBhCiAqIGxvbmdlciB3aW5kb3cgdGhhbiBhIG5vcm1hbCBi"
    "ZWF0IGFuZCBtdXN0IGdldCBpdC4gYHJlbmV3QXRgIGlzIGNhcHBlZCBhdCBoYWxmCiAqIHRoZSBob2xkIHNvIHRoZSB0d28gY2Fu"
    "IG5ldmVyIG1lZXQg4oCUIGlmIHRoZXkgZGlkLCBldmVyeSBiZWF0IHdvdWxkIHJlbmV3IGFuZAogKiB0aGUgbGVhc2Ugd291bGQg"
    "cXVpZXRseSB0dXJuIGJhY2sgaW50byB2MydzIHdyaXRlLXBlci1iZWF0IHdpdGhvdXQgYW55dGhpbmcKICogbG9va2luZyB3cm9u"
    "Zy4KICovCmZ1bmN0aW9uIHdpbmRvdyhncmFjZSwgdCkgewogIGNvbnN0IGhvbGQgPSBNYXRoLm1heChncmFjZSwgdC5sZWFzZSk7"
    "CiAgcmV0dXJuIHsgaG9sZCwgcmVuZXdBdDogTWF0aC5taW4odC5tYXJnaW4sIE1hdGguZmxvb3IoaG9sZCAvIDIpKSB9Owp9Cgpj"
    "b25zdCBERUZBVUxUX0dSQUNFX1NFQyA9IDM2MDsgICAvLyBpZiBhIFBpIHByZWRhdGVzIGBncmFjZVNlY2AgYW5kIHNlbmRzIG5v"
    "IGRlYWRsaW5lCmNvbnN0IE1BWF9HUkFDRV9TRUMgPSA4NjQwMDsgICAgIC8vIGEgZGVhZGxpbmUgZnVydGhlciBvdXQgdGhhbiB0"
    "aGlzIGlzIGEgYnVnLCBub3QgYSBwbGFuCgpjb25zdCBBUE5TX1JFVFJJRVMgPSAzOyAgICAgICAgICAvLyBhbGFybSByZS1hcm1z"
    "IHRoaXMgbWFueSB0aW1lcyBpZiBBUE5zIGlzIHVucmVhY2hhYmxlCmNvbnN0IEFQTlNfUkVUUllfU0VDID0gNjA7CgovKiogQ29u"
    "c3RhbnQtdGltZSBjb21wYXJlLCBzbyBhIGJhZCBITUFDIGNhbid0IGJlIGJydXRlLWZvcmNlZCBieSB0aW1pbmcuICovCmZ1bmN0"
    "aW9uIHRpbWluZ1NhZmVFcXVhbChhLCBiKSB7CiAgaWYgKGEubGVuZ3RoICE9PSBiLmxlbmd0aCkgcmV0dXJuIGZhbHNlOwogIGxl"
    "dCBkaWZmID0gMDsKICBmb3IgKGxldCBpID0gMDsgaSA8IGEubGVuZ3RoOyBpKyspIGRpZmYgfD0gYS5jaGFyQ29kZUF0KGkpIF4g"
    "Yi5jaGFyQ29kZUF0KGkpOwogIHJldHVybiBkaWZmID09PSAwOwp9CgpmdW5jdGlvbiB0b0hleChidWYpIHsKICByZXR1cm4gWy4u"
    "Lm5ldyBVaW50OEFycmF5KGJ1ZildLm1hcCgoYikgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7"
    "Cn0KCi8qKgogKiBWZXJpZnkgdGhlIGhlYXJ0YmVhdCByZWFsbHkgY2FtZSBmcm9tIHlvdXIgUGkuCiAqCiAqIFdpdGhvdXQgdGhp"
    "cywgYW55b25lIHdobyBsZWFybmVkIHlvdXIgV29ya2VyIFVSTCBjb3VsZCBwdXNoIHRoZSBkZWFkbGluZQogKiBmb3J3YXJkIGZv"
    "cmV2ZXIgYW5kIHBlcm1hbmVudGx5IHNpbGVuY2UgeW91ciBhbGVydHMg4oCUIHRoZSBmYWlsdXJlIG1vZGUgd2hlcmUKICogeW91"
    "IGJlbGlldmUgeW91J3JlIG1vbml0b3JlZCBhbmQgYXJlbid0LgogKi8KYXN5bmMgZnVuY3Rpb24gdmVyaWZ5SG1hYyhzZWNyZXQs"
    "IHJhd0JvZHksIHByb3ZpZGVkSGV4KSB7CiAgY29uc3Qga2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoCiAgICAn"
    "cmF3JywgbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHNlY3JldCksCiAgICB7IG5hbWU6ICdITUFDJywgaGFzaDogJ1NIQS0yNTYn"
    "IH0sIGZhbHNlLCBbJ3NpZ24nXSwKICApOwogIGNvbnN0IHNpZyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbignSE1BQycsIGtl"
    "eSwgbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHJhd0JvZHkpKTsKICByZXR1cm4gdGltaW5nU2FmZUVxdWFsKHRvSGV4KHNpZyks"
    "IChwcm92aWRlZEhleCB8fCAnJykudG9Mb3dlckNhc2UoKSk7Cn0KCmNvbnN0IEFQTlNfQkFTRVMgPSBbJ2h0dHBzOi8vYXBpLnB1"
    "c2guYXBwbGUuY29tJywgJ2h0dHBzOi8vYXBpLnNhbmRib3gucHVzaC5hcHBsZS5jb20nXTsKCi8qKgogKiBXaGVyZSBBcHBsZSBs"
    "aXZlcyDigJQgb3ZlcnJpZGFibGUgT05MWSBieSBhbiBlbnYgdmFyLCB3aGljaCBpcyBuZXZlciBzZXQgaW4KICogcHJvZHVjdGlv"
    "bi4KICoKICogVGhpcyBleGlzdHMgc28gdGhlIHZlcmlmaWVyIGNhbiBzdGFuZCBhIGZha2UgQVBOcyBpbiBmcm9udCBvZiBhIHJl"
    "YWwgV29ya2VyCiAqIGFuZCBhc3NlcnQgb24gdGhlIGV4YWN0IGJ5dGVzIHRoYXQgd291bGQgaGF2ZSByZWFjaGVkIEFwcGxlLiBU"
    "ZXN0aW5nIGEgZGVhZAogKiBtYW4ncyBzd2l0Y2ggYW55IG90aGVyIHdheSBtZWFucyBlaXRoZXIgbm90IHRlc3RpbmcgdGhlIGZp"
    "cmluZyBwYXRoIG9yCiAqIGdlbnVpbmVseSBwYWdpbmcgYSBwaG9uZSwgYW5kIHRoZSBmaXJpbmcgcGF0aCBpcyB0aGUgb25seSBw"
    "YXJ0IHRoYXQgbWF0dGVycy4KICovCmZ1bmN0aW9uIGFwbnNCYXNlcyhlbnYpIHsKICByZXR1cm4gZW52ICYmIGVudi5BUE5TX0JB"
    "U0VTID8gZW52LkFQTlNfQkFTRVMuc3BsaXQoJywnKSA6IEFQTlNfQkFTRVM7Cn0KCi8qKiBQT1NUIGEgcHJlLWFybWVkIHBheWxv"
    "YWQgdG8gQXBwbGUuIFRoZSB0b2tlbiB3YXMgbWludGVkIG9uIHRoZSBQaS4gKi8KYXN5bmMgZnVuY3Rpb24gc2VuZFRvQXBucyhl"
    "bnRyeSwgYmFzZXMgPSBBUE5TX0JBU0VTKSB7CiAgY29uc3QgcmVzdWx0cyA9IFtdOwogIGZvciAoY29uc3QgaG9zdCBvZiBiYXNl"
    "cykgewogICAgbGV0IGFueU9rID0gZmFsc2U7CiAgICBmb3IgKGNvbnN0IGRldmljZVRva2VuIG9mIGVudHJ5LmRldmljZVRva2Vu"
    "cyB8fCBbXSkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHIgPSBhd2FpdCBmZXRjaChgJHtob3N0fS8zL2RldmljZS8ke2Rl"
    "dmljZVRva2VufWAsIHsKICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICAgICAgaGVhZGVyczogewogICAgICAgICAgICBh"
    "dXRob3JpemF0aW9uOiBgYmVhcmVyICR7ZW50cnkuYXBuc0p3dH1gLAogICAgICAgICAgICAnYXBucy10b3BpYyc6IGVudHJ5LnRv"
    "cGljLAogICAgICAgICAgICAnYXBucy1wdXNoLXR5cGUnOiAnYWxlcnQnLAogICAgICAgICAgICAnYXBucy1wcmlvcml0eSc6ICcx"
    "MCcsCiAgICAgICAgICB9LAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoZW50cnkucGF5bG9hZCksCiAgICAgICAgfSk7"
    "CiAgICAgICAgY29uc3Qgb2sgPSByLnN0YXR1cyA9PT0gMjAwOwogICAgICAgIGFueU9rID0gYW55T2sgfHwgb2s7CiAgICAgICAg"
    "bGV0IHJlYXNvbiA9ICcnOwogICAgICAgIGlmICghb2spIHsgdHJ5IHsgcmVhc29uID0gKGF3YWl0IHIuanNvbigpKS5yZWFzb24g"
    "fHwgJyc7IH0gY2F0Y2ggeyAvKiBlbXB0eSBib2R5ICovIH0gfQogICAgICAgIHJlc3VsdHMucHVzaCh7IGhvc3QsIHN0YXR1czog"
    "ci5zdGF0dXMsIHJlYXNvbiB9KTsKICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgIHJlc3VsdHMucHVzaCh7IGhvc3QsIGVycm9y"
    "OiBTdHJpbmcoZSkgfSk7CiAgICAgIH0KICAgIH0KICAgIC8vIEEgZGV2ZWxvcG1lbnQgYnVpbGQncyB0b2tlbiBvbmx5IGV4aXN0"
    "cyBpbiBzYW5kYm94IGFuZCBhIFRlc3RGbGlnaHQgb25lCiAgICAvLyBvbmx5IGluIHByb2R1Y3Rpb24sIGFuZCB3ZSBjYW4ndCB0"
    "ZWxsIHdoaWNoIHdlIHdlcmUgZ2l2ZW4gLS0gc28gdHJ5IHRoZQogICAgLy8gb3RoZXIgaG9zdCBvbmx5IGlmIHByb2R1Y3Rpb24g"
    "cmVqZWN0ZWQgZXZlcnl0aGluZy4KICAgIGlmIChhbnlPaykgYnJlYWs7CiAgfQogIHJldHVybiByZXN1bHRzOwp9CgovKiogRGlk"
    "IGFueSBkZXZpY2UgYWNjZXB0IGl0PyBEcml2ZXMgdGhlIGFsYXJtJ3MgcmV0cnkgZGVjaXNpb24uICovCmZ1bmN0aW9uIGFueURl"
    "bGl2ZXJlZChyZXN1bHRzKSB7CiAgcmV0dXJuIHJlc3VsdHMuc29tZSgocikgPT4gci5zdGF0dXMgPT09IDIwMCk7Cn0KCi8qKgog"
    "KiBUaGUgbWF0ZXJpYWwgaGFsZiBvZiBhIGhlYXJ0YmVhdDogZXZlcnl0aGluZyBleGNlcHQgdGhlIGRlYWRsaW5lLgogKgogKiBC"
    "ZWF0cyBhcmUgb3ZlcndoZWxtaW5nbHkgaWRlbnRpY2FsIHRvIGVhY2ggb3RoZXIg4oCUIHRoZSBBUE5zIHRva2VuIGlzIGNhY2hl"
    "ZCBvbgogKiB0aGUgUGkgZm9yIDMwIG1pbnV0ZXMgYW5kIHRoZSBwYXlsb2FkIHRleHQgb25seSBjaGFuZ2VzIHdoZW4gdGhlIEtJ"
    "TkQgb2YKICogZGlzYXBwZWFyYW5jZSBjaGFuZ2VzLiBDb21wYXJpbmcgdGhpcyBsZXRzIGJvdGggc3RvcmFnZSBwYXRocyBza2lw"
    "IHRoZSB3cml0ZQogKiB3aGVuIGEgYmVhdCBzYXlzIG5vdGhpbmcgbmV3LCB3aGljaCBpcyB3aGF0IG1ha2VzIHRoZSBzdGVhZHkt"
    "c3RhdGUgY29zdCBhCiAqIHJvdW5kaW5nIGVycm9yIHJhdGhlciB0aGFuIGEgYnVkZ2V0LgogKi8KZnVuY3Rpb24gbWF0ZXJpYWwo"
    "Ym9keSkgewogIHJldHVybiBKU09OLnN0cmluZ2lmeShbYm9keS5hcG5zSnd0LCBib2R5LnRvcGljLCBib2R5LmRldmljZVRva2Vu"
    "cywgYm9keS5wYXlsb2FkLCBib2R5LmxhYmVsXSk7Cn0KCi8qKiBTZWNvbmRzIG9mIHNpbGVuY2UgdGhpcyBiZWF0IGlzIGFza2lu"
    "ZyB1cyB0byB0b2xlcmF0ZS4gKi8KZnVuY3Rpb24gZ3JhY2VPZihib2R5LCBub3cpIHsKICBsZXQgZyA9IE51bWJlcihib2R5Lmdy"
    "YWNlU2VjKSB8fCAwOwogIC8vIE9sZGVyIFBpIHNlcnZlcnMgc2VuZCBhbiBhYnNvbHV0ZSBkZWFkbGluZSBhbmQgbm8gZ3JhY2VT"
    "ZWMuCiAgaWYgKCFnICYmIGJvZHkuZGVhZGxpbmUpIGcgPSBOdW1iZXIoYm9keS5kZWFkbGluZSkgLSBub3c7CiAgaWYgKCFOdW1i"
    "ZXIuaXNGaW5pdGUoZykgfHwgZyA8PSAwKSBnID0gREVGQVVMVF9HUkFDRV9TRUM7CiAgcmV0dXJuIE1hdGgubWluKE1hdGgucm91"
    "bmQoZyksIE1BWF9HUkFDRV9TRUMpOwp9CgpmdW5jdGlvbiBqc29uKG9iaiwgc3RhdHVzID0gMjAwKSB7CiAgcmV0dXJuIG5ldyBS"
    "ZXNwb25zZShKU09OLnN0cmluZ2lmeShvYmopLCB7CiAgICBzdGF0dXMsIGhlYWRlcnM6IHsgJ2NvbnRlbnQtdHlwZSc6ICdhcHBs"
    "aWNhdGlvbi9qc29uJyB9LAogIH0pOwp9CgovLyDilIDilIAgRHVyYWJsZSBPYmplY3Q6IG9uZSBzd2l0Y2ggcGVyIGRldmljZSBp"
    "ZCDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDi"
    "lIDilIDilIDilIDilIDilIDilIDilIAKLy8KLy8gVGhlIGFsYXJtIGlzIHRoZSBkZWFkbGluZS4gVGhlcmUgaXMgbm8gc3dlZXAs"
    "IG5vIHBvbGxpbmcgYW5kIG5vIHN0b3JlZCBjbG9jazoKLy8gdGhlIHJ1bnRpbWUgd2FrZXMgdGhpcyBvYmplY3Qgd2hlbiB0aGUg"
    "ZGVhZGxpbmUgcGFzc2VzLCBhbmQgb25seSB0aGVuLgpleHBvcnQgY2xhc3MgU3dpdGNoIHsKICBjb25zdHJ1Y3RvcihzdGF0ZSwg"
    "ZW52KSB7CiAgICB0aGlzLnN0YXRlID0gc3RhdGU7CiAgICB0aGlzLmVudiA9IGVudjsKICAgIHRoaXMucm93cyA9IDA7ICAgICAg"
    "ICAgICAgICAgLy8gcm93IHdyaXRlcyBzaW5jZSB0aGlzIG9iamVjdCBsYXN0IHdva2UKICB9CgogIGFzeW5jIGZldGNoKHJlcXVl"
    "c3QpIHsKICAgIGNvbnN0IGJvZHkgPSBhd2FpdCByZXF1ZXN0Lmpzb24oKTsKICAgIGNvbnN0IG5vdyA9IE1hdGguZmxvb3IoRGF0"
    "ZS5ub3coKSAvIDEwMDApOwoKICAgIGlmIChib2R5LnN0YXR1cykgewogICAgICBjb25zdCByZWMgPSBhd2FpdCB0aGlzLnN0YXRl"
    "LnN0b3JhZ2UuZ2V0KCdyZWMnKTsKICAgICAgY29uc3QgYXQgPSBhd2FpdCB0aGlzLnN0YXRlLnN0b3JhZ2UuZ2V0QWxhcm0oKTsK"
    "ICAgICAgcmV0dXJuIGpzb24oewogICAgICAgIGFybWVkOiAhIShhdCAmJiByZWMgJiYgIXJlYy5maXJlZEF0KSwKICAgICAgICBk"
    "ZWFkbGluZTogYXQgPyBNYXRoLmZsb29yKGF0IC8gMTAwMCkgOiAwLAogICAgICAgIGZpcmVkQXQ6IChyZWMgJiYgcmVjLmZpcmVk"
    "QXQpIHx8IDAsCiAgICAgICAgbGFiZWw6IChyZWMgJiYgcmVjLmxhYmVsKSB8fCAnJywKICAgICAgICByb3dXcml0ZXM6IHRoaXMu"
    "cm93cywKICAgICAgfSk7CiAgICB9CgogICAgLy8gYGRpc2FybWAgaXMgaG93IGEgREVMSUJFUkFURSBzaHV0ZG93biBzdGF5cyBz"
    "aWxlbnQ6IHRoZSBQaSBzYXlzICJJJ20KICAgIC8vIGdvaW5nIGF3YXkgb24gcHVycG9zZSwgZG9uJ3QgYWxlcnQuIgogICAgaWYg"
    "KGJvZHkuZGlzYXJtKSB7CiAgICAgIGF3YWl0IHRoaXMuc3RhdGUuc3RvcmFnZS5kZWxldGVBbGFybSgpOwogICAgICBhd2FpdCB0"
    "aGlzLnN0YXRlLnN0b3JhZ2UuZGVsZXRlQWxsKCk7CiAgICAgIHRoaXMucm93cyArPSAyOwogICAgICByZXR1cm4ganNvbih7IG9r"
    "OiB0cnVlLCBkaXNhcm1lZDogdHJ1ZSB9KTsKICAgIH0KCiAgICBjb25zdCBkZWFkbGluZU1zID0gKG5vdyArIGdyYWNlT2YoYm9k"
    "eSwgbm93KSkgKiAxMDAwOwogICAgY29uc3QgcHJldiA9IGF3YWl0IHRoaXMuc3RhdGUuc3RvcmFnZS5nZXQoJ3JlYycpOwogICAg"
    "Y29uc3QgZnAgPSBtYXRlcmlhbChib2R5KTsKCiAgICAvLyBQdXNoIHRoZSBzdG9wd2F0Y2ggZm9yd2FyZC4gVGhpcyBhbHdheXMg"
    "aGFwcGVuczsgaXQgaXMgdGhlIHdob2xlIGpvYiwgYW5kCiAgICAvLyBpdCBpcyBvbmUgcm93IHdyaXRlLgogICAgYXdhaXQgdGhp"
    "cy5zdGF0ZS5zdG9yYWdlLnNldEFsYXJtKGRlYWRsaW5lTXMpOwogICAgdGhpcy5yb3dzKys7CgogICAgLy8gUmUtc3RvcmUgdGhl"
    "IG5vdGlmaWNhdGlvbiBvbmx5IHdoZW4gaXQgYWN0dWFsbHkgY2hhbmdlZCwgb3Igd2hlbiBhCiAgICAvLyBwcmV2aW91cyBhbGVy"
    "dCBuZWVkcyBjbGVhcmluZyBzbyByZWNvdmVyeSByZS1hcm1zLiBNb3N0IGJlYXRzIHNraXAgdGhpcy4KICAgIGlmICghcHJldiB8"
    "fCBwcmV2LmZwICE9PSBmcCB8fCBwcmV2LmZpcmVkQXQpIHsKICAgICAgYXdhaXQgdGhpcy5zdGF0ZS5zdG9yYWdlLnB1dCgncmVj"
    "JywgewogICAgICAgIGZwLAogICAgICAgIGFwbnNKd3Q6IGJvZHkuYXBuc0p3dCwKICAgICAgICB0b3BpYzogYm9keS50b3BpYywK"
    "ICAgICAgICBkZXZpY2VUb2tlbnM6IGJvZHkuZGV2aWNlVG9rZW5zLAogICAgICAgIHBheWxvYWQ6IGJvZHkucGF5bG9hZCwgICAg"
    "ICAgICAgLy8gdGhlIGV4YWN0IG5vdGlmaWNhdGlvbiwgYXV0aG9yZWQgYnkgdGhlIFBpCiAgICAgICAgbGFiZWw6IGJvZHkubGFi"
    "ZWwgfHwgJycsICAgICAgICAvLyBlLmcuICJzY2hlZHVsZWQtcmVib290IiAoZm9yIGxvZ3Mgb25seSkKICAgICAgICBmaXJlZEF0"
    "OiAwLCAgICAgICAgICAgICAgICAgICAgIC8vIGNsZWFyZWQgaGVyZSwgc28gcmVjb3ZlcnkgcmUtYXJtcwogICAgICAgIGF0dGVt"
    "cHRzOiAwLAogICAgICB9KTsKICAgICAgdGhpcy5yb3dzKys7CiAgICB9CgogICAgcmV0dXJuIGpzb24oeyBvazogdHJ1ZSwgZGVh"
    "ZGxpbmU6IE1hdGguZmxvb3IoZGVhZGxpbmVNcyAvIDEwMDApLCBtb2RlOiAnYWxhcm0nIH0pOwogIH0KCiAgLyoqCiAgICogVGhl"
    "IGRlYWRsaW5lIHBhc3NlZC4gU2VuZCBleGFjdGx5IHdoYXQgdGhlIFBpIGxlZnQgdXMuCiAgICoKICAgKiBFcnJvcnMgYXJlIHN3"
    "YWxsb3dlZCBkZWxpYmVyYXRlbHk6IGFuIHVuY2F1Z2h0IHRocm93IG1ha2VzIHRoZSBydW50aW1lIHJldHJ5CiAgICogdGhpcyBh"
    "bGFybSBvbiBpdHMgb3duIHNjaGVkdWxlLCB3aGljaCBhZ2FpbnN0IGEgZmxhcHBpbmcgQVBOcyBlbmRwb2ludCBpcyBhCiAgICog"
    "bm90aWZpY2F0aW9uIHN0b3JtLiBXZSByZXRyeSBhIGJvdW5kZWQgbnVtYmVyIG9mIHRpbWVzIG91cnNlbHZlcyBhbmQgdGhlbgog"
    "ICAqIHN0b3Ag4oCUIHRoZSBQaSdzIG5leHQgaGVhcnRiZWF0IHJlLWFybXMgZXZlcnl0aGluZyBhbnl3YXkuCiAgICovCiAgYXN5"
    "bmMgYWxhcm0oKSB7CiAgICBjb25zdCByZWMgPSBhd2FpdCB0aGlzLnN0YXRlLnN0b3JhZ2UuZ2V0KCdyZWMnKTsKICAgIGlmICgh"
    "cmVjIHx8IHJlYy5maXJlZEF0KSByZXR1cm47CgogICAgbGV0IHJlc3VsdHM7CiAgICB0cnkgeyByZXN1bHRzID0gYXdhaXQgc2Vu"
    "ZFRvQXBucyhyZWMsIGFwbnNCYXNlcyh0aGlzLmVudikpOyB9CiAgICBjYXRjaCAoZSkgeyByZXN1bHRzID0gW3sgZXJyb3I6IFN0"
    "cmluZyhlKSB9XTsgfQogICAgY29uc29sZS5sb2coYFtzZW50aW5lbF0gbGFwc2VkICgke3JlYy5sYWJlbCB8fCAndW5sYWJlbGxl"
    "ZCd9KSAtPmAsIEpTT04uc3RyaW5naWZ5KHJlc3VsdHMpKTsKCiAgICBpZiAoIWFueURlbGl2ZXJlZChyZXN1bHRzKSAmJiAocmVj"
    "LmF0dGVtcHRzIHx8IDApICsgMSA8IEFQTlNfUkVUUklFUykgewogICAgICByZWMuYXR0ZW1wdHMgPSAocmVjLmF0dGVtcHRzIHx8"
    "IDApICsgMTsKICAgICAgYXdhaXQgdGhpcy5zdGF0ZS5zdG9yYWdlLnB1dCgncmVjJywgcmVjKTsKICAgICAgYXdhaXQgdGhpcy5z"
    "dGF0ZS5zdG9yYWdlLnNldEFsYXJtKERhdGUubm93KCkgKyB0dW5pbmcodGhpcy5lbnYpLnJldHJ5U2VjICogMTAwMCk7CiAgICAg"
    "IHJldHVybjsKICAgIH0KCiAgICAvLyBNYXJrIGZpcmVkIHJhdGhlciB0aGFuIGRlbGV0aW5nOiB0aGUgcmVjb3JkIGRvY3VtZW50"
    "cyB3aGF0IGhhcHBlbmVkLCBhbmQKICAgIC8vIHRoZSBQaSdzIG5leHQgaGVhcnRiZWF0IGNsZWFycyBpdCBhdXRvbWF0aWNhbGx5"
    "IG9uIHJlY292ZXJ5LgogICAgcmVjLmZpcmVkQXQgPSBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxMDAwKTsKICAgIGF3YWl0IHRo"
    "aXMuc3RhdGUuc3RvcmFnZS5wdXQoJ3JlYycsIHJlYyk7CiAgfQp9CgovLyDilIDilIAgS1YgZmFsbGJhY2sg4pSA4pSA4pSA4pSA"
    "4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA"
    "4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA"
    "4pSA4pSA4pSA4pSA4pSA4pSA4pSACi8vCi8vIFVzZWQgb25seSB3aGVuIHRoZSBEdXJhYmxlIE9iamVjdCBtaWdyYXRpb24gY291"
    "bGQgbm90IGJlIGFwcGxpZWQuIEFsbCBhcm1lZAovLyBzd2l0Y2hlcyBsaXZlIHVuZGVyIE9ORSBrZXkgYXMgYSB7IFtpZF06IHJl"
    "Y29yZCB9IG1hcCwgc28gdGhlIGNyb24gR0VUcyBhCi8vIHNpbmdsZSBrZXkgaW5zdGVhZCBvZiBMSVNUaW5nLCBhbmQgd3JpdGVz"
    "IG9ubHkgd2hlbiBzb21ldGhpbmcgYWN0dWFsbHkgZmlyZXMuCmNvbnN0IEJFQVRTX0tFWSA9ICdiZWF0cyc7Cgphc3luYyBmdW5j"
    "dGlvbiByZWFkQmVhdHMoZW52KSB7CiAgLy8gUmV0dXJucyB0aGUgbWFwLCBvciB7fSBpZiB1bnNldC4gVGhyb3dzIG9ubHkgaWYg"
    "dGhlIEtWIGJpbmRpbmcgaXMgbWlzc2luZywKICAvLyB3aGljaCB0aGUgY2FsbGVyIHRyZWF0cyBhcyAidGhpcyB3b3JrZXIgY2Fu"
    "bm90IHN0b3JlIGFuZCBtdXN0IHNheSBzbyIuCiAgcmV0dXJuIChhd2FpdCBlbnYuU0VOVElORUwuZ2V0KEJFQVRTX0tFWSwgJ2pz"
    "b24nKSkgfHwge307Cn0KCi8qKgogKiBSZWNvcmQgdGhlIHdyaXRlIGluIHRoZSB2YWx1ZSB3ZSBhcmUgYWxyZWFkeSB3cml0aW5n"
    "LgogKgogKiB2MyBjb3VsZCBub3Qgc2F5IGhvdyBtdWNoIHF1b3RhIGl0IHdhcyB1c2luZywgc28gd2hlbiB0aGUgYnVkZ2V0IHJh"
    "biBvdXQgdGhlCiAqIG9ubHkgd2F5IHRvIHJlYXNvbiBhYm91dCBpdCB3YXMgYXJpdGhtZXRpYyBvbiB0aGUgc291cmNlIOKAlCB3"
    "aGljaCBpcyBob3cgYQogKiB3cml0ZSBub2JvZHkgaGFkIGNvdW50ZWQgd2VudCB1bm5vdGljZWQuIFRoaXMgY29zdHMgbm90aGlu"
    "ZzogaXQgcmlkZXMgaW5zaWRlCiAqIGEgcHV0IHRoYXQgd2FzIGhhcHBlbmluZyByZWdhcmRsZXNzLgogKi8KZnVuY3Rpb24gY291"
    "bnRXcml0ZShiZWF0cywgbm93KSB7CiAgY29uc3QgZGF5ID0gbmV3IERhdGUobm93ICogMTAwMCkudG9JU09TdHJpbmcoKS5zbGlj"
    "ZSgwLCAxMCk7CiAgY29uc3QgbSA9IGJlYXRzLl9fbWV0YSAmJiBiZWF0cy5fX21ldGEuZGF5ID09PSBkYXkgPyBiZWF0cy5fX21l"
    "dGEgOiB7IGRheSwgd3JpdGVzOiAwIH07CiAgbS53cml0ZXMrKzsKICBiZWF0cy5fX21ldGEgPSBtOwp9CgpmdW5jdGlvbiBzd2l0"
    "Y2hlcyhiZWF0cykgewogIHJldHVybiBPYmplY3QuZW50cmllcyhiZWF0cykuZmlsdGVyKChbaWRdKSA9PiBpZCAhPT0gJ19fbWV0"
    "YScpOwp9Cgphc3luYyBmdW5jdGlvbiBrdkJlYXQoZW52LCBib2R5LCBub3cpIHsKICBjb25zdCBiZWF0cyA9IGF3YWl0IHJlYWRC"
    "ZWF0cyhlbnYpOwogIGNvbnN0IHByZXYgPSBiZWF0c1tib2R5LmlkXTsKCiAgaWYgKGJvZHkuZGlzYXJtKSB7CiAgICBpZiAoIXBy"
    "ZXYpIHJldHVybiBqc29uKHsgb2s6IHRydWUsIGRpc2FybWVkOiB0cnVlLCB3cm90ZTogZmFsc2UgfSk7CiAgICBkZWxldGUgYmVh"
    "dHNbYm9keS5pZF07CiAgICBjb3VudFdyaXRlKGJlYXRzLCBub3cpOwogICAgYXdhaXQgZW52LlNFTlRJTkVMLnB1dChCRUFUU19L"
    "RVksIEpTT04uc3RyaW5naWZ5KGJlYXRzKSk7CiAgICByZXR1cm4ganNvbih7IG9rOiB0cnVlLCBkaXNhcm1lZDogdHJ1ZSwgd3Jv"
    "dGU6IHRydWUgfSk7CiAgfQoKICBjb25zdCBncmFjZSA9IGdyYWNlT2YoYm9keSwgbm93KTsKICBjb25zdCBmcCA9IG1hdGVyaWFs"
    "KGJvZHkpOwogIGNvbnN0IHcgPSB3aW5kb3coZ3JhY2UsIHR1bmluZyhlbnYpKTsKCiAgLy8gVGhlIGxlYXNlLiBBIGJlYXQgdGhh"
    "dCBzYXlzIG5vdGhpbmcgbmV3LCBvbiBhIHN3aXRjaCB3aXRoIGNvbWZvcnRhYmxlIHRpbWUKICAvLyBsZWZ0LCBpcyBhbnN3ZXJl"
    "ZCBmcm9tIHRoZSByZWFkIGFsb25lLiBUaGlzIGlzIHRoZSBlbnRpcmUgc2F2aW5nLgogIGlmIChwcmV2ICYmICFwcmV2LmZpcmVk"
    "QXQgJiYgcHJldi5mcCA9PT0gZnAgJiYgcHJldi5kZWFkbGluZSAtIG5vdyA+IHcucmVuZXdBdCkgewogICAgcmV0dXJuIGpzb24o"
    "eyBvazogdHJ1ZSwgZGVhZGxpbmU6IHByZXYuZGVhZGxpbmUsIHdyb3RlOiBmYWxzZSwgbW9kZTogJ2t2LWxlYXNlJyB9KTsKICB9"
    "CgogIGJlYXRzW2JvZHkuaWRdID0gewogICAgZGVhZGxpbmU6IG5vdyArIHcuaG9sZCwKICAgIGZwLAogICAgYXBuc0p3dDogYm9k"
    "eS5hcG5zSnd0LAogICAgdG9waWM6IGJvZHkudG9waWMsCiAgICBkZXZpY2VUb2tlbnM6IGJvZHkuZGV2aWNlVG9rZW5zLAogICAg"
    "cGF5bG9hZDogYm9keS5wYXlsb2FkLAogICAgbGFiZWw6IGJvZHkubGFiZWwgfHwgJycsCiAgICBmaXJlZEF0OiAwLAogICAgYXR0"
    "ZW1wdHM6IDAsCiAgICB1cGRhdGVkQXQ6IG5vdywKICB9OwogIGNvdW50V3JpdGUoYmVhdHMsIG5vdyk7CiAgYXdhaXQgZW52LlNF"
    "TlRJTkVMLnB1dChCRUFUU19LRVksIEpTT04uc3RyaW5naWZ5KGJlYXRzKSk7CiAgcmV0dXJuIGpzb24oeyBvazogdHJ1ZSwgZGVh"
    "ZGxpbmU6IGJlYXRzW2JvZHkuaWRdLmRlYWRsaW5lLCB3cm90ZTogdHJ1ZSwgbW9kZTogJ2t2LWxlYXNlJyB9KTsKfQoKZXhwb3J0"
    "IGRlZmF1bHQgewogIGFzeW5jIGZldGNoKHJlcXVlc3QsIGVudikgewogICAgY29uc3QgdXJsID0gbmV3IFVSTChyZXF1ZXN0LnVy"
    "bCk7CiAgICBjb25zdCBub3cgPSBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxMDAwKTsKCiAgICAvLyBIZWFsdGggYW5zd2VycyB0"
    "aGUgb25lIHF1ZXN0aW9uIHRoYXQgbWF0dGVyczogQ0FOIFRISVMgV09SS0VSIFNUT1JFIEEKICAgIC8vIERFQURMSU5FLCBBTkQg"
    "V0hJQ0ggV0FZPyBBIHdvcmtlciBkZXBsb3llZCB3aXRob3V0IGl0cyBzdG9yYWdlIHNlcnZlcwogICAgLy8gdHJhZmZpYyBoYXBw"
    "aWx5IHdoaWxlIGJlaW5nIHN0cnVjdHVyYWxseSB1bmFibGUgdG8gYXJtIGFueXRoaW5nIOKAlCB0aGUKICAgIC8vIHdvcnN0IGZh"
    "aWx1cmUsIGJlY2F1c2UgaXQgbG9va3MgZmluZS4gU28gd2UgcHJvYmUgdGhlIGJpbmRpbmdzIGFuZCByZXBvcnQKICAgIC8vIHBs"
    "YWlubHksIGluY2x1ZGluZyB3aGljaCBtb2RlIGlzIGxpdmU6IHRoZSBhbGFybSBwYXRoIGFuZCB0aGUgS1YgZmFsbGJhY2sKICAg"
    "IC8vIGhhdmUgbWF0ZXJpYWxseSBkaWZmZXJlbnQgZGV0ZWN0aW9uIHdpbmRvd3MsIGFuZCBxdWlldGx5IHJ1bm5pbmcgdGhlCiAg"
    "ICAvLyBzbG93ZXIgb25lIGlzIGV4YWN0bHkgdGhlIHNvcnQgb2YgdGhpbmcgeW91IHdhbnQgdG8gZmluZCBvdXQgYmVmb3JlIHlv"
    "dQogICAgLy8gbmVlZCBpdCByYXRoZXIgdGhhbiBhZnRlci4KICAgIGlmICh1cmwucGF0aG5hbWUgPT09ICcvaGVhbHRoJykgewog"
    "ICAgICBjb25zdCBhbGFybU1vZGUgPSAhIWVudi5TV0lUQ0g7CiAgICAgIGxldCBrdiA9IGZhbHNlLCBhcm1lZCA9IDAsIHdyaXRl"
    "c1RvZGF5ID0gMDsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBiZWF0cyA9IGF3YWl0IHJlYWRCZWF0cyhlbnYpOwogICAgICAg"
    "IGt2ID0gdHJ1ZTsKICAgICAgICBmb3IgKGNvbnN0IFssIHJdIG9mIHN3aXRjaGVzKGJlYXRzKSkgewogICAgICAgICAgaWYgKHIg"
    "JiYgci5kZWFkbGluZSAmJiAhci5maXJlZEF0ICYmIG5vdyA8IHIuZGVhZGxpbmUpIGFybWVkKys7CiAgICAgICAgfQogICAgICAg"
    "IHdyaXRlc1RvZGF5ID0gKGJlYXRzLl9fbWV0YSAmJiBiZWF0cy5fX21ldGEud3JpdGVzKSB8fCAwOwogICAgICB9IGNhdGNoIHsK"
    "ICAgICAgICBrdiA9IGZhbHNlOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBubyBiaW5kaW5nOiBjYW5ub3Qg"
    "c3RvcmUKICAgICAgfQogICAgICBjb25zdCBpZCA9IHVybC5zZWFyY2hQYXJhbXMuZ2V0KCdpZCcpOwogICAgICBsZXQgc3cgPSBu"
    "dWxsOwogICAgICBpZiAoYWxhcm1Nb2RlICYmIGlkKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IHN0dWIgPSBlbnYu"
    "U1dJVENILmdldChlbnYuU1dJVENILmlkRnJvbU5hbWUoaWQpKTsKICAgICAgICAgIHN3ID0gYXdhaXQgKGF3YWl0IHN0dWIuZmV0"
    "Y2goJ2h0dHBzOi8vc2VudGluZWwvc3RhdHVzJywgewogICAgICAgICAgICBtZXRob2Q6ICdQT1NUJywgYm9keTogSlNPTi5zdHJp"
    "bmdpZnkoeyBzdGF0dXM6IHRydWUgfSksCiAgICAgICAgICB9KSkuanNvbigpOwogICAgICAgICAgaWYgKHN3LmFybWVkKSBhcm1l"
    "ZCsrOwogICAgICAgIH0gY2F0Y2ggeyBzdyA9IG51bGw7IH0KICAgICAgfQogICAgICByZXR1cm4ganNvbih7CiAgICAgICAgb2s6"
    "IHRydWUsCiAgICAgICAgc2VydmljZTogJ3BpbGluay1zZW50aW5lbCcsCiAgICAgICAgdmVyc2lvbjogNCwKICAgICAgICBidWls"
    "ZDogQlVJTEQsCiAgICAgICAgbW9kZTogYWxhcm1Nb2RlID8gJ2FsYXJtJyA6ICdrdi1sZWFzZScsCiAgICAgICAga3YsCiAgICAg"
    "ICAgYXJtZWQsCiAgICAgICAgc3dpdGNoOiBzdywKICAgICAgICAvLyBXaGF0IHRoaXMgbW9kZSBjb3N0cyBwZXIgZGF5IGF0IGEg"
    "Mi1taW51dGUgYmVhdCwgYW5kIGhvdyBsYXRlIGFuCiAgICAgICAgLy8gYWxlcnQgY2FuIGJlLiBSZXBvcnRlZCByYXRoZXIgdGhh"
    "biBhc3N1bWVkLCBiZWNhdXNlIHRoZSBsYXN0IHZlcnNpb24KICAgICAgICAvLyB3YXMgd3JvbmcgYWJvdXQgZXhhY3RseSB0aGlz"
    "LgogICAgICAgIGJ1ZGdldDogYWxhcm1Nb2RlCiAgICAgICAgICA/IHsgc3RvcmU6ICdkdXJhYmxlLW9iamVjdCcsIHdyaXRlc1Bl"
    "ckRheTogNzIwLCBvZkxpbWl0OiAxMDAwMDAsCiAgICAgICAgICAgICAgZGV0ZWN0aW9uU2VjOiBbREVGQVVMVF9HUkFDRV9TRUMs"
    "IERFRkFVTFRfR1JBQ0VfU0VDXSB9CiAgICAgICAgICA6ICgoKSA9PiB7CiAgICAgICAgICAgICAgY29uc3QgdyA9IHdpbmRvdyhE"
    "RUZBVUxUX0dSQUNFX1NFQywgdHVuaW5nKGVudikpOwogICAgICAgICAgICAgIHJldHVybiB7IHN0b3JlOiAna3YnLAogICAgICAg"
    "ICAgICAgICAgICAgICAgIHdyaXRlc1BlckRheTogTWF0aC5yb3VuZCg4NjQwMCAvICh3LmhvbGQgLSB3LnJlbmV3QXQpKSwKICAg"
    "ICAgICAgICAgICAgICAgICAgICBvZkxpbWl0OiAxMDAwLCB3cml0ZXNUb2RheSwKICAgICAgICAgICAgICAgICAgICAgICBkZXRl"
    "Y3Rpb25TZWM6IFt3LnJlbmV3QXQsIHcuaG9sZF0gfTsKICAgICAgICAgICAgfSkoKSwKICAgICAgfSk7CiAgICB9CgogICAgaWYg"
    "KHVybC5wYXRobmFtZSAhPT0gJy9iZWF0JyB8fCByZXF1ZXN0Lm1ldGhvZCAhPT0gJ1BPU1QnKSB7CiAgICAgIHJldHVybiBuZXcg"
    "UmVzcG9uc2UoJ25vdCBmb3VuZCcsIHsgc3RhdHVzOiA0MDQgfSk7CiAgICB9CgogICAgY29uc3QgcmF3ID0gYXdhaXQgcmVxdWVz"
    "dC50ZXh0KCk7CiAgICBpZiAocmF3Lmxlbmd0aCA+IE1BWF9CT0RZKSByZXR1cm4gbmV3IFJlc3BvbnNlKCd0b28gbGFyZ2UnLCB7"
    "IHN0YXR1czogNDEzIH0pOwoKICAgIGxldCBib2R5OwogICAgdHJ5IHsgYm9keSA9IEpTT04ucGFyc2UocmF3KTsgfSBjYXRjaCB7"
    "IHJldHVybiBuZXcgUmVzcG9uc2UoJ2JhZCBqc29uJywgeyBzdGF0dXM6IDQwMCB9KTsgfQoKICAgIGlmICghKGF3YWl0IHZlcmlm"
    "eUhtYWMoZW52LlNFTlRJTkVMX1NFQ1JFVCwgcmF3LCByZXF1ZXN0LmhlYWRlcnMuZ2V0KCd4LXNlbnRpbmVsLWhtYWMnKSkpKSB7"
    "CiAgICAgIHJldHVybiBuZXcgUmVzcG9uc2UoJ2JhZCBzaWduYXR1cmUnLCB7IHN0YXR1czogNDAxIH0pOwogICAgfQoKICAgIC8v"
    "IFJlamVjdCBzdGFsZSByZXBsYXlzOiBhbiBvbGQgaGVhcnRiZWF0IGNhcHR1cmVkIG9mZiB0aGUgd2lyZSBtdXN0IG5vdCBiZQog"
    "ICAgLy8gcmVwbGF5YWJsZSBsYXRlciB0byBwdXNoIHRoZSBkZWFkbGluZSBmb3J3YXJkIHdoaWxlIHRoZSBQaSBpcyBhY3R1YWxs"
    "eSBkb3duLgogICAgaWYgKE1hdGguYWJzKChib2R5LnNlbnRBdCB8fCAwKSAtIG5vdykgPiBNQVhfU0tFV19TRUMpIHsKICAgICAg"
    "cmV0dXJuIG5ldyBSZXNwb25zZSgnc3RhbGUnLCB7IHN0YXR1czogNDAwIH0pOwogICAgfQogICAgaWYgKCFib2R5LmlkKSByZXR1"
    "cm4gbmV3IFJlc3BvbnNlKCdtaXNzaW5nIGlkJywgeyBzdGF0dXM6IDQwMCB9KTsKCiAgICBpZiAoZW52LlNXSVRDSCkgewogICAg"
    "ICBjb25zdCBzdHViID0gZW52LlNXSVRDSC5nZXQoZW52LlNXSVRDSC5pZEZyb21OYW1lKGJvZHkuaWQpKTsKICAgICAgcmV0dXJu"
    "IHN0dWIuZmV0Y2goJ2h0dHBzOi8vc2VudGluZWwvYmVhdCcsIHsKICAgICAgICBtZXRob2Q6ICdQT1NUJywgYm9keTogSlNPTi5z"
    "dHJpbmdpZnkoYm9keSksCiAgICAgIH0pOwogICAgfQogICAgcmV0dXJuIGt2QmVhdChlbnYsIGJvZHksIG5vdyk7CiAgfSwKCiAg"
    "LyoqCiAgICogQ3JvbiB0aWNrLCBvbmNlIGEgbWludXRlIOKAlCBLViBmYWxsYmFjayBvbmx5LgogICAqCiAgICogSW4gYWxhcm0g"
    "bW9kZSB0aGlzIHJldHVybnMgaW1tZWRpYXRlbHkgYW5kIHRoZSBzY2hlZHVsZSBjYW4gYmUgZGVsZXRlZDsgaXQKICAgKiBzdGF5"
    "cyByZWdpc3RlcmVkIHNvIHRoYXQgYSBXb3JrZXIgd2hpY2ggZmVsbCBiYWNrIHRvIEtWIHN0aWxsIGhhcyBhIHN3ZWVwZXIuCiAg"
    "ICogSXQgcmVhZHMgb25lIGtleSBhbmQgd3JpdGVzIG9ubHkgaWYgc29tZXRoaW5nIGFjdHVhbGx5IGZpcmVkLiBOb3RoaW5nIGhl"
    "cmUKICAgKiB3cml0ZXMgdG8gcHJvdmUgaXQgcmFuOiB0aGF0IHdhcyB2MydzIGxlYWsuCiAgICovCiAgYXN5bmMgc2NoZWR1bGVk"
    "KGV2ZW50LCBlbnYpIHsKICAgIGlmIChlbnYuU1dJVENIKSByZXR1cm47ICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBhbGFy"
    "bXMgaGFuZGxlIGV4cGlyeQoKICAgIGNvbnN0IG5vdyA9IE1hdGguZmxvb3IoRGF0ZS5ub3coKSAvIDEwMDApOwogICAgbGV0IGJl"
    "YXRzOwogICAgdHJ5IHsgYmVhdHMgPSBhd2FpdCByZWFkQmVhdHMoZW52KTsgfQogICAgY2F0Y2ggeyByZXR1cm47IH0gICAgICAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgIC8vIG5vIEtWIGJpbmRpbmcg4oCUIG5vdGhpbmcgd2UgY2FuIGRvCgogICAgbGV0IGNo"
    "YW5nZWQgPSBmYWxzZTsKICAgIGZvciAoY29uc3QgW2lkLCByZWNdIG9mIHN3aXRjaGVzKGJlYXRzKSkgewogICAgICBpZiAoIXJl"
    "YyB8fCAhcmVjLmRlYWRsaW5lKSBjb250aW51ZTsKICAgICAgaWYgKG5vdyA8IHJlYy5kZWFkbGluZSkgY29udGludWU7ICAgICAg"
    "ICAgICAgICAvLyBzdGlsbCB3aXRoaW4gaXRzIHdpbmRvdwogICAgICBpZiAocmVjLmZpcmVkQXQpIGNvbnRpbnVlOyAgICAgICAg"
    "ICAgICAgICAgICAgIC8vIGFscmVhZHkgYWxlcnRlZDsgZG9uJ3QgbmFnCgogICAgICBjb25zdCByZXN1bHRzID0gYXdhaXQgc2Vu"
    "ZFRvQXBucyhyZWMsIGFwbnNCYXNlcyhlbnYpKTsKICAgICAgY29uc29sZS5sb2coYFtzZW50aW5lbF0gJHtpZH0gbGFwc2VkICgk"
    "e3JlYy5sYWJlbCB8fCAndW5sYWJlbGxlZCd9KSAtPmAsCiAgICAgICAgICAgICAgICAgIEpTT04uc3RyaW5naWZ5KHJlc3VsdHMp"
    "KTsKCiAgICAgIGlmICghYW55RGVsaXZlcmVkKHJlc3VsdHMpICYmIChyZWMuYXR0ZW1wdHMgfHwgMCkgKyAxIDwgQVBOU19SRVRS"
    "SUVTKSB7CiAgICAgICAgcmVjLmF0dGVtcHRzID0gKHJlYy5hdHRlbXB0cyB8fCAwKSArIDE7CiAgICAgICAgcmVjLmRlYWRsaW5l"
    "ID0gbm93ICsgdHVuaW5nKGVudikucmV0cnlTZWM7ICAgLy8gdHJ5IGFnYWluIG9uIGEgbGF0ZXIgc3dlZXAKICAgICAgfSBlbHNl"
    "IHsKICAgICAgICByZWMuZmlyZWRBdCA9IG5vdzsKICAgICAgfQogICAgICBjaGFuZ2VkID0gdHJ1ZTsKICAgIH0KCiAgICAvLyBU"
    "aGUgT05MWSB3cml0ZSB0aGUgY3JvbiBldmVyIGRvZXMsIGFuZCBvbmx5IHdoZW4gYW4gYWxlcnQgYWN0dWFsbHkgZmlyZWQuCiAg"
    "ICBpZiAoY2hhbmdlZCkgewogICAgICBjb3VudFdyaXRlKGJlYXRzLCBub3cpOwogICAgICBhd2FpdCBlbnYuU0VOVElORUwucHV0"
    "KEJFQVRTX0tFWSwgSlNPTi5zdHJpbmdpZnkoYmVhdHMpKTsKICAgIH0KICB9LAp9Owo="
)


def _sentinel_worker_source():
    return base64.b64decode(SENTINEL_WORKER_B64).decode()


def _sentinel_build():
    """Fingerprint of the worker we would deploy, computed the same way
    tools/embed-sentinel.py computes the stamp inside it.

    Lets the deploy ask a live worker "were you built from this?" instead of
    assuming the upload it sent is the one running. That assumption is how a
    stale worker survived months of fixes: the version number read 3 in both
    builds and nothing ever compared them."""
    src = _sentinel_worker_source()
    neutral = re.sub(r"^const BUILD = '[^']*';$", "const BUILD = '';", src, flags=re.M)
    return hashlib.sha256(neutral.encode()).hexdigest()[:12]


def sentinel_preflight():
    """Everything that must already be true before a deploy is worth starting.

    Each blocker names the thing the user has to do, not the thing that is
    missing. Setup that fails at the last step with "could not arm" -- when the
    real answer was "this phone never registered for notifications" -- is the
    troubleshooting this whole flow exists to delete.
    """
    blockers = []
    try:
        import httpx                                    # noqa: F401
    except ImportError:
        blockers.append({
            'code': 'httpx',
            'title': 'A dependency is missing on your Pi',
            'detail': 'The heartbeat needs the httpx library.',
            'fix': 'pip3 install "httpx[http2]" --break-system-packages'})

    if not _apns_config():
        blockers.append({
            'code': 'apns_config',
            'title': 'Push notifications are not set up on this Pi',
            'detail': 'Offline alerts arrive as notifications, so this has to work first.',
            'fix': 'Set up push notifications for this Pi, then come back.'})
    elif not APNS_KEY_FILE.exists():
        blockers.append({
            'code': 'apns_key',
            'title': 'The push key is missing on your Pi',
            'detail': 'Your Pi has push settings but not the key file they refer to.',
            'fix': 'Copy your APNs key to ~/.pilink/apns_key.p8 on the Pi.'})

    if not load_push_tokens():
        blockers.append({
            'code': 'no_devices',
            'title': "No phone is registered with this Pi yet",
            'detail': "There is nowhere to send an alert, so setup would finish and "
                      "then never reach anyone.",
            'fix': "Open PiLink's main screen once so this phone registers, then come back."})

    return {'ok': not blockers, 'blockers': blockers}


# The two permissions the deploy actually needs, and how to prove we have each
# without changing anything. A token missing one of these fails much later with
# a Cloudflare error that names neither -- so we find out here and say which.
_CF_PERMISSION_PROBES = [
    ('Workers Scripts',     'Edit', '/workers/scripts?per_page=1'),
    ('Workers KV Storage',  'Edit', '/storage/kv/namespaces?per_page=1'),
]


def cf_token_report(token, account_id=None):
    """What this token is, and what it can't do -- before anything is created.

    Returns {'ok', 'error', 'accounts': [...], 'accountId', 'missing': [names]}.
    `missing` is the useful part: it names the exact permission rows the user
    has to add, in the words Cloudflare's own UI uses for them.
    """
    token = (token or '').strip()
    if not token:
        return {'ok': False, 'error': 'No token was provided.', 'accounts': []}
    if len(token) < 20:
        return {'ok': False, 'accounts': [],
                'error': 'That looks too short to be a Cloudflare token — paste the whole thing.'}

    ok, _, err = _cf_api('GET', '/user/tokens/verify', token)
    if not ok:
        low = err.lower()
        if 'expired' in low:
            msg = 'That token has expired. Create a new one in Cloudflare.'
        elif 'inactive' in low or 'disabled' in low:
            msg = 'That token has been disabled in Cloudflare.'
        else:
            msg = "Cloudflare didn't recognise that token. Check you copied all of it."
        return {'ok': False, 'error': msg, 'accounts': []}

    ok, accounts, err = _cf_api('GET', '/accounts', token)
    accounts = accounts or []
    if not ok or not accounts:
        return {'ok': False, 'accounts': [],
                'error': "That token works but can't see any Cloudflare account. When you "
                         'created it, both permissions need to be under Account, not Zone.'}

    picked = account_id or (accounts[0]['id'] if len(accounts) == 1 else None)
    if not picked:
        # More than one account and no choice made: this is a question for the
        # user, not a guess. Deploying into the wrong account is invisible until
        # they go looking for a worker that is somewhere else.
        return {'ok': False, 'error': '', 'accounts': accounts,
                'needAccount': True, 'missing': []}

    if not any(a['id'] == picked for a in accounts):
        return {'ok': False, 'accounts': accounts,
                'error': 'That account is not one this token can see.'}

    missing = []
    for label, level, probe in _CF_PERMISSION_PROBES:
        good, _, perr = _cf_api('GET', f'/accounts/{picked}{probe}', token)
        # authz failures are what we are testing for; anything else (a network
        # blip, a 5xx) must not be reported to the user as a missing permission.
        if not good and ('9109' in perr or '10000' in perr or 'authentication'
                         in perr.lower() or 'not authorized' in perr.lower()
                         or 'permission' in perr.lower()):
            missing.append(f'Account · {label} · {level}')

    return {'ok': not missing, 'accounts': accounts, 'accountId': picked,
            'missing': missing,
            'error': '' if not missing else
                     'That token is missing ' + (' and '.join(missing)) + '.'}


def _cf_api(method, path, token, body=None, multipart=None):
    """One Cloudflare API call -> (ok, result, error_str). Mirrors the standalone
    probe pi-server/pilink-sentinel-deploy.py, including the User-Agent that gets
    past Cloudflare's edge (default library UAs are 403'd with error 1010)."""
    base = 'https://api.cloudflare.com/client/v4'
    url = path if path.startswith('http') else base + path
    headers = {'authorization': f'Bearer {token}', 'user-agent': SENTINEL_UA}
    data = None
    if multipart is not None:
        boundary, data = multipart
        headers['content-type'] = f'multipart/form-data; boundary={boundary}'
    elif body is not None:
        data = json.dumps(body).encode()
        headers['content-type'] = 'application/json'
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            payload = json.loads(r.read().decode() or '{}')
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors='replace')
        try:
            payload = json.loads(raw)
        except Exception:
            return False, None, f'HTTP {e.code}: {raw[:200]}'
    except Exception as e:
        return False, None, f'{type(e).__name__}: {e}'
    if payload.get('success'):
        return True, payload.get('result'), ''
    errs = payload.get('errors') or [{'message': 'unknown error'}]
    return False, None, '; '.join(
        f"[{e.get('code', '?')}] {e.get('message', '')}" for e in errs)


def _cf_multipart(worker_src, metadata):
    """Cloudflare wants the script as multipart: a JSON metadata part naming the
    entrypoint and its bindings, plus the module source."""
    boundary = '----pilink' + secrets.token_hex(16)
    out = []

    def part(hdrs, payload):
        out.append(f'--{boundary}\r\n'.encode())
        out.append(hdrs.encode())
        out.append(b'\r\n')
        out.append(payload.encode() if isinstance(payload, str) else payload)
        out.append(b'\r\n')

    part('content-disposition: form-data; name="metadata"\r\n'
         'content-type: application/json\r\n', json.dumps(metadata))
    part('content-disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
         'content-type: application/javascript+module\r\n', worker_src)
    out.append(f'--{boundary}--\r\n'.encode())
    return boundary, b''.join(out)


def deploy_sentinel_worker(token, emit, name='pilink-sentinel', account_id=None):
    """Provision the user's OWN Cloudflare watcher from the Pi, reporting progress
    via emit(msg). Returns (ok, info). The token lives in memory only and is never
    written to disk -- the worker runs forever without it, so it can be revoked
    the moment this returns. This mirrors pilink-sentinel-deploy.py, the probe
    that proved the path live on 2026-07-22.
    """
    emit('Checking your Cloudflare account…')
    report = cf_token_report(token, account_id)
    if not report.get('ok'):
        # Hand the structured report back rather than a sentence. The screen can
        # then show "add this exact permission" or "pick which account", which
        # are recoverable in one tap, instead of a dead end.
        return False, {'error': report.get('error') or 'That token cannot be used.',
                       'accounts': report.get('accounts', []),
                       'needAccount': report.get('needAccount', False),
                       'missing': report.get('missing', [])}
    acct = f"/accounts/{report['accountId']}"

    emit('Setting up storage…')
    ok, res, _ = _cf_api('GET', f'{acct}/workers/subdomain', token)
    subdomain = (res or {}).get('subdomain') if ok else None
    if not subdomain:
        # A brand-new account has no workers.dev name until something claims one.
        # The old code tried a single random name and, if that collided, told the
        # user to go and do it in the dashboard themselves -- which is exactly the
        # kind of dead end this flow is supposed to not have. Names are global, so
        # collisions are normal; just try again.
        last = ''
        for _ in range(5):
            guess = f'pilink-{secrets.token_hex(4)}'
            ok, _, last = _cf_api('PUT', f'{acct}/workers/subdomain', token,
                                  body={'subdomain': guess})
            if ok:
                subdomain = guess
                break
        if not subdomain:
            return False, {'error': "Your account doesn't have a workers.dev address yet and "
                                    f"one couldn't be claimed automatically. {last}"}

    kv_id = None
    ok, res, _ = _cf_api('GET', f'{acct}/storage/kv/namespaces?per_page=100', token)
    for ns in (res or []) if ok else []:
        if ns.get('title') == name:
            kv_id = ns['id']
            break
    if not kv_id:
        ok, res, err = _cf_api('POST', f'{acct}/storage/kv/namespaces', token,
                               body={'title': name})
        if not ok:
            return False, {'error': f'Could not create storage. {err}'}
        kv_id = res['id']

    emit('Uploading your watcher…')
    secret = os.urandom(32).hex()          # generated here, on the machine that uses it
    src = _sentinel_worker_source()
    kv_binding = {'type': 'kv_namespace', 'name': 'SENTINEL', 'namespace_id': kv_id}
    base_meta = {
        'main_module': 'worker.js',
        'compatibility_date': '2025-10-08',
        'bindings': [kv_binding],
    }

    # Preferred shape: the deadline lives in a Durable Object alarm, which costs
    # one row write of a 100,000/day budget instead of one KV write of a 1,000/day
    # one. The free plan allows Durable Objects ONLY with the SQLite backend, so
    # the migration must say new_sqlite_classes -- new_classes is refused with
    # error 10097 and takes the whole deploy down with it.
    #
    # Migration tags are names, not versions: re-sending a tag that has already
    # been applied is a no-op, so a redeploy over a worker that already has the
    # class is fine. A redeploy over a KV-era worker applies it for the first time.
    do_meta = dict(base_meta)
    do_meta['bindings'] = [kv_binding,
                           {'type': 'durable_object_namespace',
                            'name': 'SWITCH', 'class_name': 'Switch'}]
    do_meta['migrations'] = {'new_tag': 'v1', 'new_sqlite_classes': ['Switch']}

    # If the account or the token can't do Durable Objects, we do NOT fail the
    # deploy: the same worker runs on KV with a lease instead, which is still
    # five times cheaper than what it replaces. A watcher running in the slower
    # mode is worth far more than no watcher, and /health reports which one is
    # live so nothing about the degradation is silent.
    mode = 'alarm'
    ok, _, err = _cf_api('PUT', f'{acct}/workers/scripts/{name}', token,
                         multipart=_cf_multipart(src, do_meta))
    if not ok:
        print(f'[sentinel] durable object deploy refused ({err}); falling back to KV')
        emit('Durable Objects unavailable — using the simpler storage…')
        mode = 'kv-lease'
        ok, _, err = _cf_api('PUT', f'{acct}/workers/scripts/{name}', token,
                             multipart=_cf_multipart(src, base_meta))
    if not ok:
        return False, {'error': f'Upload failed. {err}'}
    # Secret via the dedicated endpoint: the multipart binding is *inherited* from
    # the previous version on re-deploy, which silently keeps an old secret.
    ok, _, err = _cf_api('PUT', f'{acct}/workers/scripts/{name}/secrets', token,
                         body={'name': 'SENTINEL_SECRET', 'text': secret, 'type': 'secret_text'})
    if not ok:
        return False, {'error': f'Could not set the secret. {err}'}

    emit('Scheduling the checks…')
    ok, _, err = _cf_api('PUT', f'{acct}/workers/scripts/{name}/schedules', token,
                         body=[{'cron': '* * * * *'}])
    if not ok:
        return False, {'error': f'Could not schedule the checks. {err}'}
    ok, _, _ = _cf_api('POST', f'{acct}/workers/scripts/{name}/subdomain', token,
                       body={'enabled': True, 'previews_enabled': False})
    if not ok:
        _cf_api('POST', f'{acct}/workers/scripts/{name}/subdomain', token,
                body={'enabled': True})

    url = f'https://{name}.{subdomain}.workers.dev'

    emit('Making sure it answers…')
    healthy, health = False, {}
    for _ in range(12):        # up to ~60s; a fresh worker isn't instantly reachable
        try:
            hreq = urllib.request.Request(url + '/health', headers={'user-agent': SENTINEL_UA})
            with urllib.request.urlopen(hreq, timeout=10) as r:
                health = json.loads(r.read().decode())
            healthy = bool(health.get('kv'))
            break
        except Exception:
            time.sleep(5)
    if not healthy:
        return False, {'error': "The watcher deployed but isn't answering yet. Give it a "
                                'minute, then re-open this screen to finish.'}

    # Ask the worker what it actually is, rather than assuming the upload we sent
    # is the one that took. Two things get checked and neither is cosmetic:
    #
    #   mode  -- an accepted upload whose migration didn't apply looks identical
    #            to success while running the expensive path.
    #   build -- a fingerprint of the source it was compiled from. If something
    #            else deploys this worker (a Git integration on the dashboard, an
    #            older copy of this repo, the standalone script from a stale
    #            checkout) it wins silently and every later fix goes nowhere.
    #            That happened: a worker predating everything in the repo ran for
    #            months while the source read as correct.
    live_mode = health.get('mode', 'kv-lease')
    if live_mode != mode:
        print(f'[sentinel] uploaded {mode} but the worker reports {live_mode}')
        mode = live_mode

    want_build, live_build = _sentinel_build(), health.get('build', '')
    if live_build != want_build:
        return False, {
            'error': "The watcher deployed, but the one answering isn't the one we just "
                     "uploaded — something else is deploying to this worker. Check "
                     "Cloudflare → Workers → " + name + " → Settings for a connected Git "
                     "repository, disconnect it, and set this up again.",
            'liveBuild': live_build, 'wantBuild': want_build}

    emit('Sending a test check-in…')
    if not _sentinel_probe_beat(url, secret):
        return False, {'error': 'The watcher rejected the test check-in — the secret did '
                                'not take. Try again.'}

    # Only now, once it demonstrably works, write the config the loop will pick up.
    SENTINEL_CONFIG_FILE.write_text(json.dumps(
        {'url': url + '/beat', 'secret': secret, 'id': CONFIG['name'], 'mode': mode}, indent=2))
    SENTINEL_CONFIG_FILE.chmod(0o600)
    return True, {'url': url, 'mode': mode}


def _sentinel_probe_beat(url, secret):
    """Arm and immediately disarm a throwaway 'setup-probe' switch, to prove the
    HMAC/secret round-trips before we claim success. Uses its own id so it never
    touches this Pi's real record."""
    def signed(body):
        raw = json.dumps(body)
        sig = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
        return urllib.request.Request(
            url + '/beat', data=raw.encode(), method='POST',
            headers={'content-type': 'application/json', 'x-sentinel-hmac': sig,
                     'user-agent': SENTINEL_UA})
    try:
        with urllib.request.urlopen(signed(
                {'id': 'setup-probe', 'sentAt': int(time.time()),
                 'deadline': int(time.time()) + 3600, 'topic': 'setup',
                 'deviceTokens': [], 'payload': {'aps': {}}, 'label': 'setup'}), timeout=20) as r:
            if r.status != 200:
                return False
    except Exception:
        return False
    try:                        # best-effort cleanup so it can't linger
        urllib.request.urlopen(signed(
            {'id': 'setup-probe', 'sentAt': int(time.time()), 'disarm': True}), timeout=20)
    except Exception:
        pass
    return True


# ── Threshold monitoring ─────────────────────────────────────────────────────
#
# Thresholds are configured in the app but MUST be evaluated here: the whole
# point of a push is that it arrives when the app isn't running, so an app-side
# check would only ever fire when you were already looking.
THRESHOLDS_FILE = CONFIG_DIR / 'thresholds.json'
THRESHOLD_SUSTAIN_SEC = 120   # must stay breached this long before alerting


def load_thresholds() -> dict:
    if THRESHOLDS_FILE.exists():
        try:
            return json.loads(THRESHOLDS_FILE.read_text())
        except Exception:
            pass
    return {}


def save_thresholds(d: dict):
    THRESHOLDS_FILE.write_text(json.dumps(d, indent=2))


def _check_optional_deps():
    """Report missing optional dependencies at startup, with the fix.

    The server runs from a venv, so `pip3 install` in a shell lands somewhere the
    server cannot see. Printing the venv's own pip path removes the guesswork --
    this exact confusion cost a day of "push is configured but nothing arrives".
    """
    pip_hint = os.path.join(os.path.dirname(sys.executable), 'pip')
    missing = []
    for mod, why in (('httpx', 'push notifications'), ('h2', 'push notifications (HTTP/2)')):
        try:
            __import__(mod)
        except ImportError:
            missing.append((mod, why))
    if missing:
        print(f'[deps] running from {sys.executable}')
        for mod, why in missing:
            print(f'[deps] MISSING {mod} — {why} will not work')
        print(f'[deps] fix: {pip_hint} install "httpx[http2]"')
        print('[deps] then: sudo systemctl restart pilink-server')
    return [m for m, _ in missing]


def _announce_startup():
    """Tell the app the Pi is back. Delayed so networking and the token file are
    ready, and so a reboot loop doesn't machine-gun notifications."""
    time.sleep(20)
    try:
        up = time.time() - psutil.boot_time()
        # Distinguish a machine reboot from a service restart. Both land here,
        # but they mean very different things: one says your reboot schedule (or
        # power cut) happened, the other says a server update finished. Reporting
        # "uptime 1440 min" after an update was accurate and useless.
        if up < 180:
            title = f'{CONFIG["name"]} restarted'
            body  = "It finished starting up and is back online."
        else:
            title = f'{CONFIG["name"]} is back online'
            body  = "PiLink updated and is running again. Your Pi itself stayed on."
        push_notify('presence', title, body, key='startup')
    except Exception as e:
        print(f'[push] startup announce failed: {e}')


def threshold_monitor_loop():
    """Alert only on a SUSTAINED breach. CPU and RAM spike constantly during
    normal work; notifying on a single sample would train you to ignore them."""
    breached_since = {}
    while True:
        try:
            th = load_thresholds()
            if th and load_push_tokens():
                cpu  = psutil.cpu_percent(interval=1)
                ram  = psutil.virtual_memory().percent
                disk = psutil.disk_usage('/').percent
                temp = None
                try:
                    temp = int(Path('/sys/class/thermal/thermal_zone0/temp').read_text()) / 1000.0
                except Exception:
                    pass

                # Each entry carries the plain-English headline, because
                # "Temperature high" makes you work out the consequence while
                # "running hot" just tells you.
                checks = [
                    ('cpu',  cpu,  th.get('cpuWarnPct'),  'CPU',         '%',  'is working hard',
                     'CPU has been at {v}% for over {m} minutes (your limit is {l}%).'),
                    ('ram',  ram,  th.get('ramWarnPct'),  'Memory',      '%',  'is low on memory',
                     'Memory has been {v}% full for over {m} minutes (your limit is {l}%).'),
                    ('disk', disk, th.get('diskWarnPct'), 'Disk',        '%',  'is running out of space',
                     'The disk is {v}% full (your limit is {l}%).'),
                    ('temp', temp, th.get('tempWarnC'),   'Temperature', 'C',  'is running hot',
                     'It has been {v}\u00b0C for over {m} minutes (your limit is {l}\u00b0C).'),
                ]
                now = time.time()
                for name, value, limit, label, unit, headline, template in checks:
                    if value is None or not limit:
                        breached_since.pop(name, None)
                        continue
                    if value >= float(limit):
                        started = breached_since.setdefault(name, now)
                        if now - started >= THRESHOLD_SUSTAIN_SEC:
                            mins = int(THRESHOLD_SUSTAIN_SEC / 60)
                            push_notify(
                                'threshold',
                                f'{CONFIG["name"]} {headline}',
                                template.format(v=f'{value:.0f}', l=limit, m=mins),
                                key=name,
                                extra={'metric': name, 'value': value, 'limit': limit},
                            )
                    else:
                        breached_since.pop(name, None)
        except Exception as e:
            print(f'[threshold] {e}')
        time.sleep(30)


# Keys the app is allowed to set via set_agent_config
ALLOWED_AGENT_KEYS = frozenset({
    'autoRestartEnabled',
    'escalationThreshold',
    'escalationCooldownMinutes',
})

# Trust-on-first-use SSH host-key store (replaces paramiko.AutoAddPolicy)
KNOWN_SSH_HOSTS = CONFIG_DIR / 'known_ssh_hosts'

class _TOFUPolicy(paramiko.MissingHostKeyPolicy):
    """Accept the host key on first connect; reject mismatches on subsequent ones."""
    def missing_host_key(self, client, hostname, key):
        entry_id = f'{hostname} {key.get_name()}'
        stored: dict = {}
        if KNOWN_SSH_HOSTS.exists():
            for line in KNOWN_SSH_HOSTS.read_text().splitlines():
                parts = line.split()
                if len(parts) == 3:
                    stored[f'{parts[0]} {parts[1]}'] = parts[2]
        if entry_id not in stored:
            with open(KNOWN_SSH_HOSTS, 'a') as f:
                f.write(f'{entry_id} {key.get_base64()}\n')
            KNOWN_SSH_HOSTS.chmod(0o600)
        elif stored[entry_id] != key.get_base64():
            raise paramiko.SSHException(
                f'SSH host key mismatch for {hostname}. '
                f'If the Pi was reinstalled, delete {KNOWN_SSH_HOSTS} to reset.'
            )

def load_agent_config():
    if AGENT_CONFIG_FILE.exists():
        try:
            return {**DEFAULT_AGENT_CONFIG, **json.loads(AGENT_CONFIG_FILE.read_text())}
        except Exception:
            pass
    return dict(DEFAULT_AGENT_CONFIG)

def save_agent_config(cfg):
    AGENT_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    AGENT_CONFIG_FILE.chmod(0o600)

def load_agent_status():
    if AGENT_STATUS_FILE.exists():
        try:
            status = json.loads(AGENT_STATUS_FILE.read_text())
            fresh = (int(time.time() * 1000) - status.get('lastHeartbeat', 0)) < AGENT_STALE_MS
            return {**status, 'agentRunning': fresh}
        except Exception:
            pass
    return {'agentRunning': False, 'watchedServices': 0}

# Pre-launch — bumped by hand for now. Real version control comes later.
VERSION = '0.3.7'

def load_config():
    if CONFIG_FILE.exists():
        cfg = json.loads(CONFIG_FILE.read_text())
        # Keep the reported version in sync with the code actually running,
        # even though config.json (pi_id/pairing_key/name/model) persists
        # across deploys.
        if cfg.get('version') != VERSION:
            cfg['version'] = VERSION
            CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
            CONFIG_FILE.chmod(0o600)
        return cfg
    cfg = {
        'pi_id':       secrets.token_hex(8),
        'pairing_key': secrets.token_hex(16),
        'name':        subprocess.getoutput('hostname'),
        'model':       get_model(),
        'version':     VERSION,
    }
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    CONFIG_FILE.chmod(0o600)
    print(f"\n  Pi ID:       {cfg['pi_id']}")
    print(f"  Pairing Key: {cfg['pairing_key']}")
    print("\n  Enter these into the PiLink iOS app to pair.\n")
    return cfg

def get_model():
    try:
        return open('/proc/device-tree/model').read().strip('\x00')
    except Exception:
        return 'Raspberry Pi'

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

def get_tailscale_ip():
    """
    Returns this Pi's tailnet (100.x) IPv4 address if the `tailscale` CLI is
    installed and the node is logged in, else None. Lets the app auto-fill
    the "Tailscale address" field instead of requiring the user to open the
    Tailscale app and copy it manually.
    """
    try:
        result = subprocess.run(
            ['tailscale', 'ip', '-4'],
            capture_output=True, text=True, timeout=5,
        )
        ip = result.stdout.strip().splitlines()[0].strip() if result.stdout.strip() else ''
        return ip or None
    except Exception:
        return None

CONFIG = load_config()

# Registry of authenticated sessions so the event-pusher can broadcast to phones.
ACTIVE_SESSIONS = set()
SESSIONS_LOCK = threading.Lock()

def broadcast(msg):
    """Send a message to every currently authenticated client."""
    with SESSIONS_LOCK:
        sessions = list(ACTIVE_SESSIONS)
    for sess in sessions:
        sess.send(msg)


def get_boot_config_path():
    """Return the path to /boot/firmware/config.txt or /boot/config.txt, whichever exists."""
    for p in ['/boot/firmware/config.txt', '/boot/config.txt']:
        if os.path.exists(p):
            return p
    return None

def get_eth_led_config():
    """Read eth_led0 / eth_led1 dtparam values from boot config."""
    path = get_boot_config_path()
    if not path:
        return {'supported': False, 'path': None, 'led0': None, 'led1': None,
                'error': 'No boot config found'}
    try:
        led0 = led1 = None
        with open(path, 'r') as f:
            for line in f:
                s = line.strip()
                if s.startswith('dtparam=eth_led0='):
                    led0 = s.split('=', 2)[2]
                elif s.startswith('dtparam=eth_led1='):
                    led1 = s.split('=', 2)[2]
        return {'supported': True, 'path': path, 'led0': led0, 'led1': led1}
    except Exception as e:
        return {'supported': False, 'path': path, 'led0': None, 'led1': None, 'error': str(e)}

def set_eth_led_config(led0_val, led1_val):
    """Write eth_led0 / eth_led1 dtparam values into boot config.
    Pass None to remove the line (revert to hardware default).
    Requires sudo to write the root-owned boot partition."""
    path = get_boot_config_path()
    if not path:
        raise FileNotFoundError('No boot config found (/boot/firmware/config.txt or /boot/config.txt)')
    with open(path, 'r') as f:
        lines = f.readlines()
    new_lines = []
    found0 = found1 = False
    for line in lines:
        s = line.strip()
        if s.startswith('dtparam=eth_led0='):
            found0 = True
            if led0_val is not None:
                new_lines.append(f'dtparam=eth_led0={led0_val}\n')
            # else: omit line (remove setting)
        elif s.startswith('dtparam=eth_led1='):
            found1 = True
            if led1_val is not None:
                new_lines.append(f'dtparam=eth_led1={led1_val}\n')
        else:
            new_lines.append(line)
    if not found0 and led0_val is not None:
        new_lines.append(f'dtparam=eth_led0={led0_val}\n')
    if not found1 and led1_val is not None:
        new_lines.append(f'dtparam=eth_led1={led1_val}\n')
    content = ''.join(new_lines)
    # Write via sudo cp from a temp file (boot partition is root-owned)
    tmp = '/tmp/pilink_boot_cfg_tmp.txt'
    with open(tmp, 'w') as f:
        f.write(content)
    result = subprocess.run(['sudo', 'cp', tmp, path], capture_output=True, timeout=10)
    try:
        os.unlink(tmp)
    except Exception:
        pass
    if result.returncode != 0:
        raise PermissionError(
            f'Could not write {path}: {result.stderr.decode().strip()}'
        )

def get_leds():
    """Read all LEDs from /sys/class/leds and return their state."""
    import os
    leds = []
    base = '/sys/class/leds'
    if not os.path.isdir(base):
        return leds
    for name in sorted(os.listdir(base)):
        led_path = os.path.join(base, name)
        try:
            brightness = int(open(os.path.join(led_path, 'brightness')).read().strip())
            max_brightness = int(open(os.path.join(led_path, 'max_brightness')).read().strip())
            trigger_raw = open(os.path.join(led_path, 'trigger')).read().strip()
            available, current = [], 'none'
            for tok in trigger_raw.split():
                if tok.startswith('[') and tok.endswith(']'):
                    current = tok[1:-1]
                    available.append(current)
                else:
                    available.append(tok)
            leds.append({
                'name': name,
                'brightness': brightness,
                'max_brightness': max_brightness,
                'trigger': current,
                'available_triggers': available,
            })
        except Exception:
            pass
    return leds

LED_STATE_FILE = CONFIG_DIR / 'led_state.json'

def _write_led_attr(base, attr, value):
    """Write a sysfs LED attribute, falling back to passwordless `sudo tee` if the
    service user lacks direct write permission on the file."""
    path = os.path.join(base, attr)
    try:
        with open(path, 'w') as f:
            f.write(value)
        return
    except PermissionError:
        pass
    result = subprocess.run(['sudo', 'tee', path], input=f'{value}\n'.encode(),
                            capture_output=True, timeout=5)
    if result.returncode != 0:
        user = os.environ.get('USER', 'pi')
        raise PermissionError(f'Cannot write LED {attr} — run: sudo usermod -a -G led {user}')

def save_led_state(name, trigger):
    """Remember one LED's desired trigger so it can be restored after a reboot."""
    try:
        state = {}
        if LED_STATE_FILE.exists():
            state = json.loads(LED_STATE_FILE.read_text())
        state[name] = trigger
        LED_STATE_FILE.write_text(json.dumps(state))
        try:
            LED_STATE_FILE.chmod(0o600)
        except Exception:
            pass
    except Exception as e:
        print(f'[led] could not persist state: {e}')

def set_led(name, trigger, persist=True):
    """Set one LED's trigger. 'none' means OFF in the app, so we also force the
    brightness to 0 — otherwise the LED just freezes at whatever value it last had.
    The desired state is persisted and re-applied on boot by restore_leds(), because
    sysfs LED triggers reset to their kernel defaults on every reboot (which is why
    an LED the user turned off came back on after a restart)."""
    base = f'/sys/class/leds/{name}'
    if not os.path.isdir(base):
        raise FileNotFoundError(f'LED {name!r} not found')
    _write_led_attr(base, 'trigger', trigger)
    if trigger == 'none':
        try:
            _write_led_attr(base, 'brightness', '0')
        except Exception:
            pass
    if persist:
        save_led_state(name, trigger)

def restore_leds():
    """Re-apply saved LED triggers at startup so a light the user turned off stays
    off across reboots. Called once from serve()."""
    try:
        if not LED_STATE_FILE.exists():
            return
        state = json.loads(LED_STATE_FILE.read_text())
    except Exception:
        return
    for name, trigger in state.items():
        try:
            set_led(name, trigger, persist=False)
            print(f'[led] restored {name} -> {trigger}')
        except Exception as e:
            print(f'[led] restore {name} failed: {e}')

def get_stats():
    cpu  = psutil.cpu_percent(interval=0.2)
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    temp = 0.0
    try:
        temp = int(open('/sys/class/thermal/thermal_zone0/temp').read()) / 1000
    except Exception: pass
    # Report the active interface so the app can label the link wired vs wireless.
    # Prefer a wired link that's up (eth0, but also Pi 5's end0 and USB enx*),
    # then a wireless one (wlan0/wl*). Only matching on "eth" missed those names
    # and made an Ethernet Pi report as Wi-Fi.
    iface = 'wlan0'
    _stats = psutil.net_if_stats()
    for name, st in _stats.items():
        if st.isup and (name.startswith('eth') or name.startswith('en')):
            iface = name
            break
    else:
        for name, st in _stats.items():
            if st.isup and (name.startswith('wlan') or name.startswith('wl')):
                iface = name
                break
    net = psutil.net_io_counters()
    return {
        'cpuPercent':    round(cpu, 1),
        'ramPercent':    round(mem.percent, 1),
        'ramUsedGb':     round(mem.used / 1e9, 2),
        'ramTotalGb':    round(mem.total / 1e9, 2),
        'tempCelsius':   round(temp, 1),
        'diskPercent':   round(disk.percent, 1),
        'diskUsedGb':    round(disk.used / 1e9, 1),
        'diskTotalGb':   round(disk.total / 1e9, 1),
        'uptimeSeconds': int(time.time() - psutil.boot_time()),
        'networkInterface': iface,
        'networkRxMbs':  round(net.bytes_recv / 1e6, 2),
        'networkTxMbs':  round(net.bytes_sent / 1e6, 2),
        'online': True,
        'lastSeen': int(time.time() * 1000),
    }

def list_files(path):
    try:
        p = safe_path(path)
        entries = []
        for e in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            try:
                st_ = e.stat()
                entry = {
                    'name': e.name, 'path': str(e),
                    'isDir': e.is_dir(), 'size': st_.st_size,
                    'modified': int(st_.st_mtime * 1000),
                    'permissions': stat.filemode(st_.st_mode),
                }
                if e.is_dir():
                    try:
                        entry['itemCount'] = sum(1 for _ in e.iterdir())
                    except (PermissionError, OSError):
                        pass
                entries.append(entry)
            except PermissionError: pass
        return entries
    except Exception: return []

def delete_path(path):
    p = safe_path(path)
    if p.is_dir():
        shutil.rmtree(p)
    else:
        p.unlink()

def rename_path(path, new_name):
    p = safe_path(path)
    new_name = Path(new_name).name  # strip any directory components from the new name
    new_path = p.parent / new_name
    p.rename(new_path)
    return str(new_path)

def move_path(path, dest_dir):
    p = safe_path(path)
    d = safe_path(dest_dir)
    new_path = d / p.name
    shutil.move(str(p), str(new_path))
    return str(new_path)

# Text-only read/write for the in-app Edit feature. Restricted client-side to
# doc/code-kind files, so plain UTF-8 (not base64) keeps this simple — JSON
# already escapes embedded newlines/quotes correctly.
MAX_EDIT_SIZE = 2 * 1024 * 1024  # 2MB

def read_file_text(path):
    p = safe_path(path)
    size = p.stat().st_size
    if size > MAX_EDIT_SIZE:
        raise ValueError(f'File too large to edit in-app ({size} bytes)')
    return p.read_text(encoding='utf-8', errors='replace')

def write_file_text(path, content):
    p = safe_path(path)
    p.write_text(content, encoding='utf-8')

# Base64 read for Download — unlike Edit this has to handle arbitrary binary
# files (images, archives, etc.), so it can't assume valid UTF-8 text.
MAX_DOWNLOAD_SIZE = 25 * 1024 * 1024  # 25MB — keep the single-message JSON payload sane

def read_file_base64(path):
    import base64
    p = safe_path(path)
    size = p.stat().st_size
    if size > MAX_DOWNLOAD_SIZE:
        raise ValueError(f'File too large to download in-app ({size} bytes)')
    return base64.b64encode(p.read_bytes()).decode('ascii'), p.name

# -- Package update helpers (apt + pip) ----------------------------------------
_PIP_BIN = os.path.expanduser('~/.pilink/venv/bin/pip')

def _parse_apt_upgradable(text):
    """Parse `apt list --upgradable` output into [{name, old, new}]."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if '/' not in line or 'upgradable from:' not in line:
            continue
        try:
            name = line.split('/', 1)[0]
            new_ver = line.split()[1]
            old_ver = line.split('upgradable from:')[1].strip().rstrip(']').strip()
            out.append({'name': name, 'old': old_ver, 'new': new_ver})
        except Exception:
            continue
    return out

def _pip_outdated():
    """Outdated pip packages in the PiLink venv as [{name, old, new}]."""
    pip = _PIP_BIN if os.path.exists(_PIP_BIN) else 'pip3'
    r = subprocess.run([pip, 'list', '--outdated', '--format=json'],
                       capture_output=True, text=True, timeout=60)
    data = json.loads(r.stdout or '[]')
    return [{'name': d.get('name', ''), 'old': d.get('version', ''),
             'new': d.get('latest_version', '')} for d in data]

def _pkg_display(items):
    return [f"{i['name']}  {i['old']} \u2192 {i['new']}" if i.get('old') and i.get('new')
            else i['name'] for i in items]

# -- GitHub self-update source (Pi pulls its own code; app only triggers) -------
GITHUB_REPO       = 'spencermoya-byte/PiLink'
GITHUB_BRANCH     = 'main'
GITHUB_TOKEN_FILE = CONFIG_DIR / 'github_token'   # optional; required for a PRIVATE repo

def _github_token():
    """Read the optional read-only GitHub token used for private-repo pulls."""
    try:
        t = GITHUB_TOKEN_FILE.read_text().strip()
        return t or None
    except Exception:
        return None

def _http_get(url, timeout=25, accept='application/vnd.github+json'):
    headers = {'User-Agent': 'PiLink-Server', 'Accept': accept}
    tok = _github_token()
    if tok:
        headers['Authorization'] = f'Bearer {tok}'
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def _latest_release():
    """(tag, notes, date) of the newest published GitHub release (including
    pre-releases / alpha), or (None, '', '') if none exist or GitHub is
    unreachable. `date` is the ISO published_at, surfaced so the update sheet can
    show a real release date instead of a placeholder. Uses the list endpoint
    because /releases/latest hides pre-releases."""
    try:
        data = json.loads(_http_get(
            f'https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=10').decode('utf-8', 'replace'))
        if isinstance(data, list):
            for rel in data:            # newest first
                if rel.get('draft'):
                    continue
                tag = rel.get('tag_name')
                if tag:
                    return tag, (rel.get('body') or ''), (rel.get('published_at') or '')
        return None, '', ''
    except Exception:
        return None, '', ''

def _fetch_requirements(ref):
    """Pull requirements.txt for the same ref so the self-update can install
    anything new.

    Uses the authenticated Contents API when a token is present -- the repo is
    private, and raw.githubusercontent 404s anonymously for private content, so
    the naive raw URL would silently return nothing and skip the install.

    Returns bytes, or None if unavailable (older tags may predate the file, and
    that must never break an update)."""
    try:
        tok = _github_token()
        if tok:
            return _http_get(
                f'https://api.github.com/repos/{GITHUB_REPO}/contents/pi-server/requirements.txt?ref={ref}',
                accept='application/vnd.github.raw')
        return _http_get(
            f'https://raw.githubusercontent.com/{GITHUB_REPO}/{ref}/pi-server/requirements.txt',
            accept='text/plain')
    except Exception:
        return None


def _fetch_server_source(ref):
    """Download pilink-server.py (+agent) from the repo at `ref`. With a token
    present, uses the authenticated Contents API (works for a PRIVATE repo);
    otherwise the public raw host. Returns (server_bytes, agent_bytes_or_None)."""
    tok = _github_token()
    def get(path):
        if tok:
            return _http_get(f'https://api.github.com/repos/{GITHUB_REPO}/contents/{path}?ref={ref}',
                             accept='application/vnd.github.raw')
        return _http_get(f'https://raw.githubusercontent.com/{GITHUB_REPO}/{ref}/{path}',
                         accept='text/plain')
    server = get('pi-server/pilink-server.py')
    try:
        agent = get('pi-server/pilink-agent.py')
        if len(agent) < 128:
            agent = None
    except Exception:
        agent = None
    return server, agent

def _atomic_write_bytes(path, data):
    tmp = str(path) + '.new'
    with open(tmp, 'wb') as fh:
        fh.write(data)
    os.replace(tmp, str(path))

# -- Git helpers ---------------------------------------------------------------
def _git(path, args, timeout=15):
    return subprocess.run(['git', '-C', str(path)] + args,
                          capture_output=True, text=True, timeout=timeout)

def _is_git_repo(path):
    try:
        r = _git(path, ['rev-parse', '--is-inside-work-tree'], timeout=6)
        return r.returncode == 0 and r.stdout.strip() == 'true'
    except Exception:
        return False

# -- Per-repo service kill switch ----------------------------------------------
REPO_SWITCH_FILE = CONFIG_DIR / 'repo_switch.json'
_SYSTEMD_DIRS = ['/etc/systemd/system', '/lib/systemd/system',
                 '/run/systemd/system', '/usr/lib/systemd/system']

def load_repo_switch() -> dict:
    if REPO_SWITCH_FILE.exists():
        try:
            return json.loads(REPO_SWITCH_FILE.read_text())
        except Exception:
            return {}
    return {}

def save_repo_switch(d: dict):
    REPO_SWITCH_FILE.write_text(json.dumps(d, indent=2))
    REPO_SWITCH_FILE.chmod(0o600)

def _repo_referenced(blob: str, repo: str) -> bool:
    """True if `repo` appears as a real path (the dir itself or a parent) in blob,
    not merely a string prefix (so /x/stream does NOT match /x/streaming)."""
    return any((repo + sfx) in blob for sfx in ('/', '\n', ' ', '"', "'"))

def _units_for_repo(repo: str) -> list:
    """systemd .service units whose ExecStart/WorkingDirectory live under `repo`."""
    try:
        repo = str(Path(repo).resolve())
    except Exception:
        return []
    dirs = [d for d in _SYSTEMD_DIRS if os.path.isdir(d)]
    if not dirs:
        return []
    try:
        r = subprocess.run(['grep', '-rlF', repo] + dirs,
                           capture_output=True, text=True, timeout=15)
    except Exception:
        return []
    cand = sorted({os.path.basename(x.strip()) for x in r.stdout.splitlines()
                   if x.strip().endswith('.service')})
    confirmed = []
    for unit in cand:
        try:
            sh = subprocess.run(['systemctl', 'show', unit, '--no-pager',
                                 '-p', 'WorkingDirectory,ExecStart,FragmentPath'],
                                capture_output=True, text=True, timeout=6)
            if _repo_referenced(sh.stdout, repo):
                confirmed.append(unit)
        except Exception:
            continue
    return confirmed

def load_schedules():
    return json.loads(SCHED_FILE.read_text()) if SCHED_FILE.exists() else []

def save_schedules(s):
    SCHED_FILE.write_text(json.dumps(s, indent=2))

def _schedule_failed(s, detail):
    """A schedule that silently fails to do anything is worse than one that errors
    loudly -- you keep believing it works. Log, audit, and tell the app."""
    print(f'[scheduler] FAILED {s.get("id")} ({s.get("type")}): {detail}')
    audit('schedule_failed', {'id': s.get('id'), 'type': s.get('type'), 'error': detail})
    broadcast({'type': 'schedule_error', 'scheduleId': s.get('id'), 'error': detail})
    label = s.get('label') or s.get('type') or 'A scheduled task'
    reason = _plain_reason(detail)
    push_notify('schedule',
                f'{CONFIG["name"]}: "{label}" didn\'t run',
                (reason + ' Open PiLink for details.') if reason
                else 'The scheduled task failed. Open PiLink to see why.',
                key=str(s.get('id')))

def run_schedule(s):
    """Execute a schedule and REPORT THE OUTCOME.

    `sudo -n` is deliberate: without it sudo blocks on a password prompt that no
    one can answer from a systemd service, the command dies, and the scheduler
    happily records a successful run. That is precisely how a nightly reboot can
    look scheduled for months and never once fire. With -n, a missing sudoers
    rule fails immediately and visibly ('a password is required').
    """
    t     = s.get('type', 'custom')
    label = s.get('label') or t
    cmd   = s.get('command') or s.get('scriptPath') or ''   # app stores the command as scriptPath

    # Re-arm the Sentinel BEFORE going down, so the message matches the cause.
    #
    # Crucially this is not a pre-fired notification: it only ever sends if we
    # FAIL to come back. A healthy reboot reconnects, the heartbeat resumes, and
    # nothing is delivered. A shutdown disarms entirely, because staying off is
    # the whole point and alerting on it would be noise.
    if t == 'reboot':
        sentinel_send(SENTINEL_REBOOT_GRACE, kind='scheduled-reboot', label=label)
    elif t == 'shutdown':
        sentinel_send(0, disarm=True)

    if   t == 'reboot':   argv, shell = ['sudo', '-n', 'reboot'], False
    elif t == 'shutdown': argv, shell = ['sudo', '-n', 'shutdown', '-h', 'now'], False
    elif t == 'update':   argv, shell = ['sudo', '-n', 'apt-get', 'update', '-y'], False
    elif t in ('custom', 'script') and cmd:
        argv, shell = cmd, True
    else:
        _schedule_failed(s, f'nothing to run (type={t!r}, no command)')
        return

    try:
        r = subprocess.run(argv, shell=shell, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        _schedule_failed(s, 'timed out after 1h')
        return
    except Exception as e:
        _schedule_failed(s, f'{type(e).__name__}: {e}')
        return

    if r.returncode != 0:
        # Surface the most useful line rather than a bare exit code.
        lines = ((r.stderr or '') + (r.stdout or '')).strip().splitlines()
        _schedule_failed(s, lines[-1].strip() if lines else f'exit {r.returncode}')
    else:
        print(f'[scheduler] {s.get("id")} ({t}) ok')

def _cron_field(field, value, lo, hi):
    """Match one cron field. Supports *, a, a-b, a,b, */n, a-b/n."""
    for part in field.strip().split(','):
        part = part.strip()
        step = 1
        if '/' in part:
            rng, step_s = part.split('/', 1)
            try: step = int(step_s)
            except ValueError: continue
            if step <= 0: continue
        else:
            rng = part
        if rng == '*':
            start, end = lo, hi
        elif '-' in rng:
            a, b = rng.split('-', 1)
            try: start, end = int(a), int(b)
            except ValueError: continue
        else:
            try: start = end = int(rng)
            except ValueError: continue
        if start > end: continue
        if start <= value <= end and (value - start) % step == 0:
            return True
    return False

def _cron_matches(expr, when):
    """Standard 5-field cron: minute hour day-of-month month day-of-week."""
    parts = expr.split()
    if len(parts) != 5: return False
    mn, hr, dom, mon, dow = parts
    tm = time.localtime(when)
    cron_dow = (tm.tm_wday + 1) % 7   # py Mon=0..Sun=6 -> cron Sun=0..Sat=6
    dow_ok = _cron_field(dow, cron_dow, 0, 7) or (cron_dow == 0 and _cron_field(dow, 7, 0, 7))
    dom_ok = _cron_field(dom, tm.tm_mday, 1, 31)
    if dom.strip() != '*' and dow.strip() != '*':
        day_ok = dom_ok or dow_ok          # cron quirk: both restricted => OR
    else:
        day_ok = dom_ok and dow_ok
    return (_cron_field(mn, tm.tm_min, 0, 59) and
            _cron_field(hr, tm.tm_hour, 0, 23) and
            _cron_field(mon, tm.tm_mon, 1, 12) and day_ok)

def _cron_valid(expr):
    """Structural check on a 5-field cron expression.

    Without this, _cron_next discovers a malformed expression the expensive way:
    532,800 iterations (370 days x 1440 minutes) of _cron_matches, each building
    a localtime struct, before finally returning 0. That cost was paid on every
    scheduler tick for a broken schedule -- and the caller then treated the 0 as
    "no next run" and invented a 24-hour cadence.
    """
    parts = (expr or '').split()
    if len(parts) != 5:
        return False
    bounds = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
    for part, (lo, hi) in zip(parts, bounds):
        for chunk in part.split(','):
            chunk = chunk.strip()
            if not chunk:
                return False
            if '/' in chunk:
                rng, step = chunk.split('/', 1)
                if not step.isdigit() or int(step) <= 0:
                    return False
            else:
                rng = chunk
            if rng == '*':
                continue
            if '-' in rng:
                a, b = rng.split('-', 1)
                if not (a.isdigit() and b.isdigit()):
                    return False
                if not (lo <= int(a) <= hi and lo <= int(b) <= hi and int(a) <= int(b)):
                    return False
            elif not rng.isdigit() or not (lo <= int(rng) <= hi):
                return False
    return True

def _cron_next(expr, after):
    """First matching UNIX time (minute resolution) strictly after `after` seconds,
    within ~370 days. Returns 0 if never / invalid."""
    if not _cron_valid(expr): return 0
    t = (int(after) // 60 + 1) * 60
    for _ in range(370 * 24 * 60):
        if _cron_matches(expr, t): return t
        t += 60
    return 0

def scheduler_loop():
    announced = False
    last_heartbeat = 0
    while True:
        try:
            schedules = load_schedules()
            now_ms = int(time.time() * 1000)
            changed = False

            # State the plan once at startup, and re-state it hourly. Without
            # this the loop is completely silent unless something fires, so a
            # schedule that never runs leaves no evidence of WHY -- was it
            # disabled, was nextRun wrong, was the server even up? Now the
            # journal answers that on its own.
            if not announced or now_ms - last_heartbeat > 3600000:
                announced = True
                last_heartbeat = now_ms
                if not schedules:
                    print('[scheduler] no schedules stored')
                for s in schedules:
                    when = s.get('nextRun', 0)
                    when_s = (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(when / 1000))
                              if when else 'never')
                    state = 'enabled' if s.get('enabled') else 'DISABLED (will not run)'
                    print(f'[scheduler] {s.get("label") or s.get("id")}: {state}, '
                          f'cron={s.get("cronExpression")!r}, next={when_s}')
            for s in schedules:
                if not s.get('enabled'): continue
                nxt = s.get('nextRun', 0)
                if nxt and now_ms >= nxt:
                    threading.Thread(target=run_schedule, args=(s,), daemon=True).start()
                    s['lastRun'] = now_ms
                    nxt_s = _cron_next(s.get('cronExpression', ''), now_ms // 1000)
                    # Record history HERE, not in the app. The app only ever
                    # appended runs it happened to be connected for, so a 3am
                    # reboot left no trace and "did it run?" was unanswerable.
                    s['execHistory'] = ([now_ms] + list(s.get('execHistory') or []))[:25]
                    if nxt_s:
                        s['nextRun'] = nxt_s * 1000
                    else:
                        # DO NOT invent a cadence here. The old code fell back to
                        # now + 24h, which silently turned a schedule with a bad
                        # cron expression into a timer anchored to whenever it
                        # happened to fire -- so "every day at midnight" quietly
                        # became "every 24h from 1:21pm", drifting, with nothing
                        # anywhere reporting a problem. Stop it and say so.
                        s['nextRun'] = 0
                        _schedule_failed(s, f'invalid cron expression {s.get("cronExpression")!r} — schedule stopped')
                    changed = True
                    broadcast({
                        'type':       'schedule_fired',
                        'scheduleId': s.get('id'),
                        'lastRun':    now_ms,
                        'nextRun':    s['nextRun'],
                    })
                    print(f'[scheduler] fired {s.get("id")} ({s.get("type")})')
            if changed: save_schedules(schedules)
        except Exception as e:
            print(f'[scheduler] {e}')
        time.sleep(30)

def icloud_register_loop():
    while True:
        try:
            ADDR_FILE.write_text(json.dumps({
                'ip': get_local_ip(), 'port': PORT,
                'piId': CONFIG['pi_id'], 'ts': int(time.time() * 1000),
            }))
        except Exception as e:
            print(f'[icloud] {e}')
        time.sleep(60)

# -- Dispatch table: message type -> (handler method, run in a thread?, pass msg?).
#    ClientSession.handle() looks every message type up here; each maps to an
#    on_* handler method, so handle() itself is just auth + this dispatch.
_ROUTES = {
    'get_processes': ('on_processes', False, False),
    'get_services': ('on_get_services', True, False),
    'get_storage': ('on_get_storage', True, False),
    'get_git_repos': ('on_get_git_repos', True, False),
    'git_status': ('on_git_status', True, True),
    'git_pull': ('on_git_pull', True, True),
    'git_clone': ('on_git_clone', True, True),
    'get_deploy_key': ('on_get_deploy_key', True, False),
    'git_remove': ('on_git_remove', True, True),
    'set_hostname': ('on_set_hostname', True, True),
    'set_repo_switch': ('on_set_repo_switch', True, True),
    'set_managed_service': ('on_set_managed_service', True, True),
    'control_service': ('on_control_service', True, True),
    'check_updates': ('on_check_updates', True, False),
    'run_update': ('on_run_update', True, True),
    'delete_file': ('on_delete_file', False, True),
    'rename_file': ('on_rename_file', False, True),
    'move_file': ('on_move_file', False, True),
    'read_file': ('on_read_file', False, True),
    'write_file': ('on_write_file', False, True),
    'download_file': ('on_download_file', True, True),
    'upload_file': ('on_upload_file', True, True),
    'terminal_input': ('on_term_input', True, True),
    'tail_log': ('on_tail_log', True, True),
    'stop_log': ('on_stop_log', False, False),
    'ssh_connect': ('on_ssh_connect', True, True),
    'ssh_input': ('on_ssh_input', False, True),
    'ssh_resize': ('on_ssh_resize', False, True),
    'ssh_disconnect': ('on_ssh_disconnect', False, False),
    'command': ('on_command', False, True),
    'run_schedule': ('on_run_schedule', False, True),
    'get_cron': ('on_get_cron', True, False),
    'get_tls_cert': ('on_get_tls_cert', True, False),
    'write_b64_file': ('on_write_b64_file', True, True),
    'restart_server': ('on_restart_server', True, False),
    'check_server_update': ('on_check_server_update', True, False),
    'pull_update': ('on_pull_update', True, True),
    'rotate_key': ('on_rotate_key', True, False),
    'set_ip_lock': ('on_set_ip_lock', False, True),
    # handlers with real logic, extracted from handle() into methods:
    'get_stats': ('on_get_stats', False, True),
    'list_files': ('on_list_files', False, True),
    'kill_process': ('on_kill_process', False, True),
    'get_schedules': ('on_get_schedules', False, True),
    'set_schedule': ('on_set_schedule', False, True),
    'delete_schedule': ('on_delete_schedule', False, True),
    'register_push': ('on_register_push', False, True),
    'unregister_push': ('on_unregister_push', False, True),
    'set_thresholds': ('on_set_thresholds', False, True),
    'get_thresholds': ('on_get_thresholds', False, True),
    'get_alerts': ('on_get_alerts', False, True),
    'clear_alerts': ('on_clear_alerts', False, True),
    'set_sentinel': ('on_set_sentinel', False, True),
    'deploy_sentinel': ('on_deploy_sentinel', False, True),
    'get_sentinel_status': ('on_get_sentinel_status', False, True),
    'test_sentinel': ('on_test_sentinel', False, True),
    'sentinel_preflight': ('on_sentinel_preflight', False, True),
    'check_sentinel_token': ('on_check_sentinel_token', False, True),
    'sentinel_test_ack': ('on_sentinel_test_ack', False, True),
    'verify_sentinel': ('on_verify_sentinel', False, True),
    'test_push': ('on_test_push', False, True),
    'get_agent_config': ('on_get_agent_config', False, True),
    'set_agent_config': ('on_set_agent_config', False, True),
    'get_agent_status': ('on_get_agent_status', False, True),
    'get_leds': ('on_get_leds', False, True),
    'set_led': ('on_set_led', False, True),
    'get_eth_leds': ('on_get_eth_leds', False, True),
    'set_eth_leds': ('on_set_eth_leds', False, True),
    'get_ip_lock': ('on_get_ip_lock', False, True),
    'get_tailscale_ip': ('on_get_tailscale_ip', False, True),
    # Thermostat (Phase 2 M3): read the shared store; setpoint/mode writes are
    # picked up by the thermostat.service control loop.
    'get_thermostat': ('on_get_thermostat', True, True),
    'get_thermostat_history': ('on_get_thermostat_history', True, True),
    'set_setpoint': ('on_set_setpoint', False, True),
    'set_mode': ('on_set_mode', False, True),
    'set_optimized_charging': ('on_set_optimized_charging', False, True),
}


THERMOSTAT_DB = os.path.expanduser('~/.pilink/thermostat.db')
_THERMOSTAT = {'store': None}


def _thermostat():
    """Lazily import the thermostat package and open the shared SQLite store
    (written by thermostat.service). Kept lazy so the server still boots if the
    thermostat package/db aren't deployed yet — the handlers surface the failure
    to the app instead of crashing the whole server at import time."""
    if _THERMOSTAT['store'] is None:
        from thermostat.store import Store
        _THERMOSTAT['store'] = Store(THERMOSTAT_DB)
    from thermostat import api
    return api, _THERMOSTAT['store']


class ClientSession:
    def __init__(self, conn, addr):
        self.conn    = conn
        self.addr    = addr
        self.authed  = False
        self.buf     = ''
        self.term_pid = self.term_fd = None
        self.ssh_client = self.ssh_channel = None
        self.log_proc = None
        self.last_active = time.time()
        # Handlers run in their own threads and all call send(). Concurrent
        # sendall() can interleave newline-framed JSON, and on a TLS socket it
        # corrupts the record stream outright — so writes are serialised.
        self._send_lock = threading.Lock()

    def send(self, msg):
        try:
            data = (json.dumps(msg) + '\n').encode()
            with self._send_lock:
                self.conn.sendall(data)
        except Exception: pass

    def run(self):
        try:
            while True:
                chunk = self.conn.recv(4096)
                if not chunk: break
                self.buf += chunk.decode('utf-8', errors='replace')
                if len(self.buf) > MAX_BUF_SIZE:
                    self.send({'type': 'error', 'message': 'Message too large — connection closed'})
                    break
                while '\n' in self.buf:
                    line, self.buf = self.buf.split('\n', 1)
                    line = line.strip()
                    if not line: continue
                    try:
                        self.handle(json.loads(line))
                    except json.JSONDecodeError:
                        pass
                    except Exception as e:
                        # A handler blew up — report it instead of letting the
                        # exception kill this session thread silently.
                        error('handle', e, {'ip': self.addr[0], 'sample': line[:200]})
        except (ConnectionResetError, OSError):
            pass
        finally:
            self.cleanup()
            print(f'[pilink] {self.addr} disconnected')

    def on_check_updates(self):
        """Report available apt + pip upgrades, streamed per-system so the app can
        render each card the moment its result lands. Order matters: the cached apt
        list is instant, so it paints first; pip's PyPI query is slow but independent,
        so it goes next; the apt cache refresh (sudo apt-get update) is the slowest
        step, so it runs last and re-sends apt only if the authoritative list differs.
        Each message carries a single system; the app merges them. (The old behaviour
        sent one combined message only after all of this finished — up to ~3 minutes of
        blank spinner.)"""
        # 1) apt from the current cache — instant, so the first card paints now.
        try:
            r = subprocess.run(['apt', 'list', '--upgradable'],
                               capture_output=True, text=True, timeout=30)
            apt_items = _parse_apt_upgradable(r.stdout)
            self.send({'type': 'check_updates_result',
                       'systems': {'apt': {'count': len(apt_items), 'packages': _pkg_display(apt_items), 'items': apt_items}}})
        except Exception as e:
            apt_items = None
            self.send({'type': 'check_updates_result',
                       'systems': {'apt': {'count': 0, 'packages': [], 'error': str(e)}}})
        # 2) pip — slow (queries PyPI per package); send when ready.
        try:
            items = _pip_outdated()
            self.send({'type': 'check_updates_result',
                       'systems': {'pip': {'count': len(items), 'packages': _pkg_display(items), 'items': items}}})
        except Exception as e:
            self.send({'type': 'check_updates_result',
                       'systems': {'pip': {'count': 0, 'packages': [], 'error': str(e)}}})
        # 3) refresh the apt cache (slowest, needs passwordless sudo); re-send apt
        #    only if the authoritative list differs from the cached one above.
        try:
            subprocess.run(['sudo', '-n', 'apt-get', 'update', '-qq'], capture_output=True, timeout=90)
            r = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True, timeout=30)
            refreshed = _parse_apt_upgradable(r.stdout)
            if apt_items is None or _pkg_display(refreshed) != _pkg_display(apt_items):
                self.send({'type': 'check_updates_result',
                           'systems': {'apt': {'count': len(refreshed), 'packages': _pkg_display(refreshed), 'items': refreshed}}})
        except Exception:
            pass

    def on_run_update(self, msg):
        """Apply upgrades, streaming output; report the exact packages changed."""
        system = msg.get('system', '')
        if system == 'apt-upgrade':
            before = _parse_apt_upgradable(subprocess.run(
                ['apt', 'list', '--upgradable'], capture_output=True, text=True, timeout=30).stdout)
            cmd = ['sudo', '-n', 'apt-get', 'upgrade', '-y']
        elif system == 'pip':
            before = _pip_outdated()
            pip = _PIP_BIN if os.path.exists(_PIP_BIN) else 'pip3'
            names = [i['name'] for i in before]
            cmd = ([pip, 'install', '-U'] + names) if names else None
        else:
            self.send({'type': 'update_done', 'system': system, 'ok': False, 'error': 'unknown system'})
            return
        if not cmd:
            self.send({'type': 'update_done', 'system': system, 'ok': True, 'changed': []})
            return
        ok = True
        # Stream output in BATCHES, not one message per line. pip/apt emit output
        # faster than the app can parse+dispatch each as its own TCP message, and
        # the flood piled up on the JS thread and froze the app until the stream
        # ended. Coalesce up to ~40 lines (or every 0.4s) into one message carrying
        # `lines` (the batch) plus `line` (the latest, for older app builds).
        buf: list = []
        last_flush = time.time()
        def flush():
            if not buf:
                return
            self.send({'type': 'update_output', 'system': system,
                       'line': buf[-1], 'lines': list(buf)})
            buf.clear()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            for line in proc.stdout:
                buf.append(line.rstrip())
                if len(buf) >= 40 or (time.time() - last_flush) >= 0.4:
                    flush()
                    last_flush = time.time()
            flush()
            proc.wait(timeout=1800)
            ok = (proc.returncode == 0)
        except Exception as e:
            ok = False
            flush()
            self.send({'type': 'update_output', 'system': system,
                       'line': f'error: {e}', 'lines': [f'error: {e}']})
        audit('run_update', {'system': system, 'ok': ok, 'count': len(before), 'ip': self.addr[0]})
        self.send({'type': 'update_done', 'system': system, 'ok': ok, 'changed': before})

    def on_check_server_update(self):
        """Report the running version vs the latest GitHub release (or main)."""
        tag, notes, date = _latest_release()
        if tag:
            latest = tag.lstrip('v')
            self.send({'type': 'server_update_info', 'source': 'release',
                       'current': VERSION, 'latest': latest, 'tag': tag,
                       'notes': notes, 'date': date, 'hasUpdate': latest != VERSION})
        else:
            self.send({'type': 'server_update_info', 'source': 'main',
                       'current': VERSION, 'tag': GITHUB_BRANCH, 'notes': '',
                       'hasUpdate': True})

    def on_pull_update(self, msg):
        """Fetch server code from GitHub (latest release, else main), verify, install, restart."""
        try:
            self.send({'type': 'server_update_progress', 'message': 'Finding latest release...'})
            tag, _, _ = _latest_release()
            ref = tag or GITHUB_BRANCH
            self.send({'type': 'server_update_progress', 'message': f'Downloading {ref} from GitHub...'})
            server_src, agent_src = _fetch_server_source(ref)
            if not server_src or len(server_src) < 512:
                self.send({'type': 'server_update_error', 'message': 'Downloaded server file looks too small; aborted.'})
                return
            try:
                compile(server_src, 'pilink-server.py', 'exec')  # never install code that will not run
            except SyntaxError as e:
                self.send({'type': 'server_update_error', 'message': f'Downloaded server has a syntax error; aborted ({e}).'})
                return
            # Install dependencies BEFORE the new code takes over. The in-app
            # update path used to replace only the .py, so a release that needed
            # a new package installed cleanly and then failed at runtime with the
            # feature silently doing nothing -- which is exactly how push
            # notifications appeared to work for a full day while the server
            # couldn't import httpx. deploy-pi.ps1 always did this; the button
            # did not.
            self.send({'type': 'server_update_progress', 'message': 'Checking dependencies...'})
            try:
                reqs = _fetch_requirements(ref)
                if reqs:
                    req_path = CONFIG_DIR / 'requirements.txt'
                    _atomic_write_bytes(req_path, reqs)
                    r = subprocess.run([_PIP_BIN, 'install', '-r', str(req_path), '--quiet'],
                                       capture_output=True, text=True, timeout=300)
                    if r.returncode == 0:
                        print('[update] dependencies up to date')
                    else:
                        # Do NOT abort: the new code may well run fine without it,
                        # and bricking an update over a package is worse. Say so
                        # loudly instead of failing silently.
                        detail = (r.stderr or r.stdout or '').strip().splitlines()
                        msg = detail[-1] if detail else f'pip exit {r.returncode}'
                        print(f'[update] WARNING dependency install failed: {msg}')
                        self.send({'type': 'server_update_progress',
                                   'message': f'Warning: dependency install failed ({msg}). Continuing.'})
            except Exception as e:
                print(f'[update] WARNING could not install dependencies: {e}')

            self.send({'type': 'server_update_progress', 'message': 'Installing...'})
            _atomic_write_bytes(CONFIG_DIR / 'pilink-server.py', server_src)
            if agent_src:
                _atomic_write_bytes(CONFIG_DIR / 'pilink-agent.py', agent_src)
            audit('pull_update', {'ref': ref, 'ip': self.addr[0]})
            self.send({'type': 'server_update_done', 'ref': ref})
            def restart():
                time.sleep(1.5)   # let server_update_done flush
                os._exit(0)       # systemd (Restart=always) relaunches with the new code
            threading.Thread(target=restart, daemon=True).start()
        except Exception as e:
            self.send({'type': 'server_update_error', 'message': str(e)})

    def on_run_schedule(self, msg):
        """Run a schedule immediately (the app's 'Run Now' button)."""
        sid = msg.get('scheduleId')
        scheds = load_schedules()
        s = next((x for x in scheds if x.get('id') == sid), None)
        if not s:
            # Previously a bare `return`. If the app asked to run a schedule this
            # Pi doesn't have, absolutely nothing happened and nothing was said --
            # no run, no error, no "last run" update. The app looked like it had
            # done something. Say so instead.
            known = [x.get('id') for x in scheds]
            print(f'[scheduler] run_schedule for unknown id {sid!r}; this Pi has {known}')
            self.send({'type': 'schedule_error', 'scheduleId': sid,
                       'error': "This Pi doesn't have that scheduled task. "
                                "Open the Scheduler screen to sync it, then try again."})
            return
        audit('run_schedule', {'id': sid, 'type': s.get('type'), 'ip': self.addr[0]})
        print(f'[scheduler] run now: {s.get("label") or sid} (type={s.get("type")})')
        threading.Thread(target=run_schedule, args=(s,), daemon=True).start()
        now_ms = int(time.time() * 1000)
        s['lastRun'] = now_ms
        s['execHistory'] = ([now_ms] + list(s.get('execHistory') or []))[:25]
        save_schedules(scheds)
        broadcast({'type': 'schedule_fired', 'scheduleId': sid,
                   'lastRun': now_ms, 'nextRun': s.get('nextRun', 0)})

    def on_get_tls_cert(self):
        """Hand the app our TLS certificate so it can pin it.

        The certificate is public by definition — it's presented in the clear
        during every TLS handshake. Only the private key is secret, and that
        never leaves the Pi. This runs on the authenticated channel, so a caller
        already proved it knows the pairing key.

        The app stores this PEM and uses it as the SOLE trusted CA for later
        connections, which is what turns "encrypted to somebody" into
        "encrypted to *this* Pi"."""
        try:
            pem = TLS_CERT.read_text()
            fingerprint = cert_fingerprint()
        except Exception as e:
            self.send({'type': 'tls_cert', 'error': f'certificate unavailable: {e}'})
            return
        self.send({'type': 'tls_cert', 'pem': pem, 'fingerprint': fingerprint})

    def on_get_cron(self):
        """Read the user + root crontabs so the app can SHOW existing system cron
        jobs (e.g. a root '0 0 * * * /sbin/reboot'). Root needs passwordless sudo
        for `crontab -l`; if absent, root jobs are simply omitted."""
        jobs = []
        for src, cmd in (('user', ['crontab', '-l']),
                         ('root', ['sudo', '-n', 'crontab', '-l'])):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            except Exception:
                continue
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                toks = line.split()
                if '=' in toks[0]:            # env assignment (SHELL=..., PATH=...)
                    continue
                if line.startswith('@'):      # @reboot / @daily / ...
                    parts = line.split(None, 1)
                    jobs.append({'expr': parts[0], 'command': parts[1] if len(parts) > 1 else '',
                                 'source': src, 'raw': line})
                elif len(toks) >= 6:
                    jobs.append({'expr': ' '.join(toks[:5]), 'command': ' '.join(toks[5:]),
                                 'source': src, 'raw': line})
        self.send({'type': 'cron_jobs', 'data': jobs})

    def on_get_storage(self):
        """Filesystems (df) + block devices (lsblk) + best-effort SMART health."""
        data = {'filesystems': [], 'disks': []}
        try:
            r = subprocess.run(['df', '-B1', '-T'], capture_output=True, text=True, timeout=8)
            for ln in r.stdout.splitlines()[1:]:
                p = ln.split()
                if len(p) < 7 or not p[0].startswith('/dev/'):
                    continue
                try:
                    data['filesystems'].append({'source': p[0], 'fstype': p[1],
                        'sizeBytes': int(p[2]), 'usedBytes': int(p[3]), 'availBytes': int(p[4]),
                        'pct': p[5], 'mount': ' '.join(p[6:])})
                except ValueError:
                    continue
        except Exception as e:
            data['fsError'] = str(e)
        try:
            r = subprocess.run(['lsblk', '-b', '-J', '-o', 'NAME,SIZE,TYPE,MODEL,TRAN,ROTA'],
                               capture_output=True, text=True, timeout=8)
            tree = json.loads(r.stdout or '{}')
            smart = shutil.which('smartctl')
            for n in tree.get('blockdevices', []):
                if n.get('type') != 'disk':
                    continue
                name = n.get('name', '')
                tran = n.get('tran')
                disk = {'name': name, 'sizeBytes': int(n.get('size') or 0),
                        'model': (n.get('model') or '').strip(), 'tran': tran,
                        'rota': bool(n.get('rota')),
                        'isSD': name.startswith('mmcblk') or tran == 'mmc'}
                if smart and tran != 'mmc':
                    try:
                        sr = subprocess.run(['sudo', '-n', 'smartctl', '-H', '-j', f'/dev/{name}'],
                                            capture_output=True, text=True, timeout=8)
                        j = json.loads(sr.stdout or '{}')
                        passed = j.get('smart_status', {}).get('passed')
                        if passed is not None:
                            disk['smartHealthy'] = passed
                    except Exception:
                        pass
                data['disks'].append(disk)
        except Exception as e:
            data['diskError'] = str(e)
        self.send({'type': 'storage', 'data': data})

    def on_get_git_repos(self):
        """Discover git repos under the home directory (bounded depth)."""
        try:
            home = str(Path.home())
            r = subprocess.run(['find', home, '-maxdepth', '5', '-type', 'd', '-name', '.git'],
                               capture_output=True, text=True, timeout=20)
            repos, seen = [], set()
            for gitdir in r.stdout.splitlines():
                gitdir = gitdir.strip()
                if not gitdir.endswith('/.git'):
                    continue
                repo = gitdir[:-5]
                if repo and repo not in seen:
                    seen.add(repo)
                    repos.append({'path': repo, 'name': os.path.basename(repo) or repo})
            state = load_repo_switch()
            for rp in repos:
                units = _units_for_repo(rp['path'])
                rp['services'] = len(units)
                rp['off'] = bool(state.get(rp['path'], {}).get('off'))
            repos.sort(key=lambda x: x['name'].lower())
            self.send({'type': 'git_repos', 'data': repos})
        except Exception as e:
            self.send({'type': 'git_repos', 'data': [], 'error': str(e)})

    def on_git_status(self, msg):
        raw = msg.get('path', '')
        try:
            path = safe_path(raw)
        except Exception as e:
            self.send({'type': 'git_status', 'path': raw, 'error': str(e)})
            return
        if not _is_git_repo(path):
            self.send({'type': 'git_status', 'path': raw, 'error': 'not a git repository'})
            return
        info = {'type': 'git_status', 'path': raw}
        try:
            info['branch'] = _git(path, ['rev-parse', '--abbrev-ref', 'HEAD']).stdout.strip()
            info['dirty'] = len([l for l in _git(path, ['status', '--porcelain']).stdout.splitlines() if l.strip()])
            info['remote'] = _git(path, ['remote', 'get-url', 'origin']).stdout.strip()
            ab = _git(path, ['rev-list', '--left-right', '--count', 'HEAD...@{u}'])
            if ab.returncode == 0 and ab.stdout.strip():
                nums = ab.stdout.split()
                if len(nums) >= 2:
                    info['ahead'], info['behind'] = int(nums[0]), int(nums[1])
            commits = []
            for line in _git(path, ['log', '-n', '20', '--pretty=format:%h%x1f%s%x1f%an%x1f%cr']).stdout.splitlines():
                p = line.split('\x1f')
                if len(p) == 4:
                    commits.append({'hash': p[0], 'subject': p[1], 'author': p[2], 'when': p[3]})
            info['commits'] = commits
        except Exception as e:
            info['error'] = str(e)
        self.send(info)

    def on_git_pull(self, msg):
        raw = msg.get('path', '')
        try:
            path = safe_path(raw)
        except Exception as e:
            self.send({'type': 'git_pull_result', 'path': raw, 'ok': False, 'output': str(e)})
            return
        if not _is_git_repo(path):
            self.send({'type': 'git_pull_result', 'path': raw, 'ok': False, 'output': 'not a git repository'})
            return
        audit('git_pull', {'path': str(path), 'ip': self.addr[0]})
        try:
            r = _git(path, ['pull', '--ff-only'], timeout=120)
            ok = r.returncode == 0
            out = (r.stdout + r.stderr).strip()
        except Exception as e:
            ok, out = False, str(e)
        self.send({'type': 'git_pull_result', 'path': raw, 'ok': ok, 'output': out[:4000]})

    def on_git_clone(self, msg):
        """Clone a repo by URL into an allowed folder (default: home). Public repos
        clone anonymously; private ones authenticate with whatever the Pi already
        has — an SSH deploy key, or a configured credential helper — because PiLink
        deliberately stores no git credentials of its own. Streams progress. A
        missing credential FAILS FAST rather than hanging on a hidden prompt:
        GIT_TERMINAL_PROMPT=0 kills the HTTPS username prompt and ssh BatchMode
        kills the SSH password / unknown-host-key prompt."""
        url = (msg.get('url') or '').strip()
        # URL guard: reject option-injection and anything that isn't a real git
        # transport. `--` is also passed to git below as a second line of defence.
        if not url or url.startswith('-'):
            self.send({'type': 'git_clone_result', 'ok': False, 'output': 'Enter a valid repository URL.'}); return
        low = url.lower()
        scp_like = bool(re.match(r'^[A-Za-z0-9._-]+@[A-Za-z0-9._.-]+:', url))   # git@host:path
        if not (low.startswith('https://') or low.startswith('ssh://') or scp_like):
            self.send({'type': 'git_clone_result', 'ok': False,
                       'output': 'Only https:// or ssh (git@host:path) URLs are allowed.'}); return
        # Destination must resolve inside an allowed prefix; default to home.
        try:
            base = safe_path(os.path.expanduser(msg.get('destDir') or '~'))
        except Exception as e:
            self.send({'type': 'git_clone_result', 'ok': False, 'output': f'Destination not allowed: {e}'}); return
        if not base.is_dir():
            self.send({'type': 'git_clone_result', 'ok': False, 'output': 'Destination folder does not exist.'}); return
        # Folder name from the URL (or an explicit override), stripped of any path.
        name = Path((msg.get('name') or url).rstrip('/').split('/')[-1]).name
        if name.endswith('.git'):
            name = name[:-4]
        if not name or name.startswith('.') or '/' in name:
            self.send({'type': 'git_clone_result', 'ok': False, 'output': 'Could not derive a folder name from that URL.'}); return
        target = base / name
        if target.exists():
            self.send({'type': 'git_clone_result', 'ok': False, 'output': f'"{name}" already exists in that folder.'}); return
        audit('git_clone', {'url': url, 'dest': str(target), 'ip': self.addr[0]})
        env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0',
               'GIT_SSH_COMMAND': 'ssh -o BatchMode=yes', 'GCM_INTERACTIVE': 'never'}
        tail, ok = [], False
        try:
            proc = subprocess.Popen(['git', 'clone', '--progress', '--', url, str(target)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1, env=env)
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    tail.append(line); tail[:] = tail[-40:]
                    self.send({'type': 'git_clone_progress', 'line': line})
            proc.wait(timeout=600)
            ok = (proc.returncode == 0)
        except Exception as e:
            tail.append(str(e))
        self.send({'type': 'git_clone_result', 'ok': ok,
                   'output': '\n'.join(tail)[-2000:], 'path': str(target) if ok else None})

    def on_get_deploy_key(self):
        """Return the Pi's SSH *public* key, for the user to add as a repo deploy
        key (read-only) or an account SSH key. Reuses an existing default key if
        the Pi has one; only generates a key (ed25519, no passphrase, at the
        default path so ssh uses it automatically) when none exists. The private
        key never leaves the Pi and is never sent."""
        ssh_dir = Path.home() / '.ssh'
        pub_path = None
        for cand in ('id_ed25519.pub', 'id_ecdsa.pub', 'id_rsa.pub'):
            p = ssh_dir / cand
            if p.exists():
                pub_path = p
                break
        generated = False
        if not pub_path:
            try:
                ssh_dir.mkdir(mode=0o700, exist_ok=True)
                key = ssh_dir / 'id_ed25519'
                subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-q',
                                '-f', str(key), '-C', f'pilink@{os.uname().nodename}'],
                               check=True, capture_output=True, timeout=30)
                pub_path = ssh_dir / 'id_ed25519.pub'
                generated = True
            except Exception as e:
                self.send({'type': 'deploy_key', 'ok': False, 'error': f'Could not create a key: {e}'}); return
        try:
            pub = pub_path.read_text().strip()
        except Exception as e:
            self.send({'type': 'deploy_key', 'ok': False, 'error': str(e)}); return
        audit('get_deploy_key', {'generated': generated, 'file': pub_path.name, 'ip': self.addr[0]})
        self.send({'type': 'deploy_key', 'ok': True, 'publicKey': pub, 'generated': generated})

    def on_git_remove(self, msg):
        """Delete a cloned repo directory. Guarded three ways: the path must resolve
        inside an allowed prefix (safe_path), must actually be a git repo (a stray or
        stale path can't be used to wipe an arbitrary folder), and can never be the
        home directory or ~/.pilink itself."""
        raw = msg.get('path', '')
        try:
            path = safe_path(raw)
        except Exception as e:
            self.send({'type': 'git_remove_result', 'path': raw, 'ok': False, 'error': str(e)}); return
        rp = path.resolve()
        if rp in (Path.home().resolve(), CONFIG_DIR.resolve()) or rp == Path('/'):
            self.send({'type': 'git_remove_result', 'path': raw, 'ok': False, 'error': 'Refusing to delete this directory.'}); return
        if not _is_git_repo(path):
            self.send({'type': 'git_remove_result', 'path': raw, 'ok': False, 'error': 'Not a git repository — nothing removed.'}); return
        try:
            shutil.rmtree(path)
            audit('git_remove', {'path': str(path), 'ip': self.addr[0]})
            self.send({'type': 'git_remove_result', 'path': raw, 'ok': True})
        except Exception as e:
            self.send({'type': 'git_remove_result', 'path': raw, 'ok': False, 'error': str(e)})

    def on_set_hostname(self, msg):
        """Change the Pi's real system hostname (not just the app's display label).
        Validates RFC 1123, sets it via hostnamectl, best-effort updates the
        127.0.1.1 line in /etc/hosts (so `sudo` doesn't warn about the old name),
        and restarts avahi so mDNS re-advertises <new>.local. The live TCP session
        is unaffected — only discovery/SSH-by-name follow the new name.
        Sudoers: NOPASSWD /usr/bin/hostnamectl (systemctl is already permitted)."""
        new = (msg.get('hostname') or '').strip()
        if not re.match(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$', new):
            self.send({'type': 'set_hostname_result', 'ok': False,
                       'error': 'Invalid hostname — letters, digits and hyphens only (max 63, no leading/trailing hyphen).'}); return
        try:
            old = subprocess.run(['hostname'], capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:
            old = ''
        r = subprocess.run(['sudo', '-n', 'hostnamectl', 'set-hostname', new],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            self.send({'type': 'set_hostname_result', 'ok': False,
                       'error': (r.stderr or 'hostnamectl failed — add a NOPASSWD sudoers rule for /usr/bin/hostnamectl.').strip()[:300]}); return
        # /etc/hosts 127.0.1.1 line — best effort; non-fatal if sudo lacks the rule.
        hosts_ok = False
        try:
            hr = subprocess.run(['sudo', '-n', 'sed', '-i',
                                 rf's/^\(127\.0\.1\.1[[:space:]]\+\).*/\1{new}/', '/etc/hosts'],
                                capture_output=True, text=True, timeout=10)
            hosts_ok = (hr.returncode == 0)
        except Exception:
            hosts_ok = False
        try:
            subprocess.run(['sudo', '-n', 'systemctl', 'restart', 'avahi-daemon'],
                           capture_output=True, timeout=15)
        except Exception:
            pass
        # hostnamectl already set the static hostname (and NetworkManager reads it),
        # so the router will show the new name after the Pi's next DHCP lease renewal
        # or a reboot. To make it immediate, best-effort re-request the lease on the
        # default interface. Non-disruptive (rebind, not a link down/up). Needs
        # NOPASSWD for nmcli (Bookworm+) or dhcpcd; otherwise it's a harmless no-op
        # and the name still propagates on the next renewal/reboot.
        renew_ok = False
        try:
            iface = subprocess.run(
                ['sh', '-c', "ip route show default 2>/dev/null | awk '{print $5; exit}'"],
                capture_output=True, text=True, timeout=5).stdout.strip()
            if iface:
                rr = subprocess.run(['sudo', '-n', 'nmcli', 'device', 'reapply', iface],
                                    capture_output=True, timeout=20)
                renew_ok = (rr.returncode == 0)
                if not renew_ok:
                    rr2 = subprocess.run(['sudo', '-n', 'dhcpcd', '-n', iface],
                                         capture_output=True, timeout=20)
                    renew_ok = (rr2.returncode == 0)
        except Exception:
            renew_ok = False
        audit('set_hostname', {'old': old, 'new': new, 'hosts_updated': hosts_ok,
                               'dhcp_renewed': renew_ok, 'ip': self.addr[0]})
        self.send({'type': 'set_hostname_result', 'ok': True, 'hostname': new,
                   'hostsUpdated': hosts_ok, 'dhcpRenewed': renew_ok, 'old': old})

    def on_set_repo_switch(self, msg):
        """Turn every service under a repo dir off (disable --now) or on (enable --now).
        Refuses self-critical units; persists state so 'off' survives reboots."""
        raw = msg.get('path', '')
        on = bool(msg.get('on'))
        try:
            repo = str(safe_path(raw))
        except Exception as e:
            self.send({'type': 'repo_switch_result', 'path': raw, 'ok': False, 'error': str(e)})
            return
        state = load_repo_switch()
        if on:
            units = state.get(repo, {}).get('units') or _units_for_repo(repo)
        else:
            units = _units_for_repo(repo)
        action = 'on' if on else 'off'
        affected, errors = [], []
        for unit in units:
            if unit in _SELF_CRITICAL:
                continue
            ok, err = _systemctl(action, unit)
            audit('repo_switch', {'repo': repo, 'unit': unit, 'action': action, 'ip': self.addr[0]})
            if ok:
                affected.append(unit)
            else:
                errors.append({'unit': unit, 'error': err})
        if on:
            state.pop(repo, None)
        elif affected:            # only record 'off' if at least one unit actually stopped
            state[repo] = {'off': True, 'units': affected}
        save_repo_switch(state)
        self.send({'type': 'repo_switch_result', 'path': raw, 'ok': not errors,
                   'on': on, 'affected': affected, 'errors': errors})

    def handle(self, msg):
        self.last_active = time.time()
        t = msg.get('type', '')
        if not self.authed:
            if t == 'auth':
                ip  = self.addr[0]
                now = time.time()
                # IP allowlist — checked before rate-limit and key to avoid leaking info
                ip_lock = load_ip_lock()
                if ip_lock.get('enabled') and ip not in ip_lock.get('allowed', []):
                    audit('ip_blocked', {'ip': ip})
                    self.send({'type': 'auth_fail'})
                    self.conn.close()
                    return
                with _AUTH_LOCK:
                    history = [ts for ts in _AUTH_FAILS.get(ip, []) if now - ts < AUTH_WINDOW_SEC]
                    if len(history) >= AUTH_MAX_ATTEMPTS:
                        self.send({'type': 'auth_fail', 'error': 'Too many attempts'})
                        self.conn.close()
                        return
                supplied = msg.get('pairingKey')
                try:
                    key_ok = isinstance(supplied, str) and hmac.compare_digest(
                        supplied.encode('utf-8'), CONFIG['pairing_key'].encode('utf-8'))
                except Exception:
                    key_ok = False
                if key_ok:
                    with _AUTH_LOCK:
                        _AUTH_FAILS.pop(ip, None)
                        _save_auth_fails(_AUTH_FAILS)
                    self.authed = True
                    audit('auth_ok', {'ip': ip})
                    self.send({'type': 'auth_ok', 'piId': CONFIG['pi_id'],
                               'version': CONFIG['version'], 'name': CONFIG['name'],
                               'tailscaleIp': get_tailscale_ip()})
                    threading.Thread(target=self.stats_loop, daemon=True).start()
                    threading.Thread(target=self._idle_watchdog, daemon=True).start()
                    with SESSIONS_LOCK:
                        ACTIVE_SESSIONS.add(self)
                    _cl   = msg.get('client') or 'pre-tls-build'
                    _want = msg.get('clientTls')
                    _over = isinstance(self.conn, ssl.SSLSocket)
                    print(f'[pilink] {self.addr} authenticated '
                          f'(client={_cl} wantsTls={_want} overTLS={_over})')
                else:
                    with _AUTH_LOCK:
                        history.append(now)
                        _AUTH_FAILS[ip] = history
                        _save_auth_fails(_AUTH_FAILS)
                    audit('auth_fail', {'ip': ip, 'count': len(history)})
                    print(f'[pilink] {ip} auth_fail ({len(history)}/{AUTH_MAX_ATTEMPTS})')
                    self.send({'type': 'auth_fail'})
                    self.conn.close()
            else:
                self.send({'type': 'auth_fail'})
                self.conn.close()
            return

        # Declarative dispatch: every message type maps to a handler method (see _ROUTES).
        route = _ROUTES.get(t)
        if route is not None:
            name, threaded, wants_msg = route
            fn = getattr(self, name)
            args = (msg,) if wants_msg else ()
            if threaded:
                threading.Thread(target=fn, args=args, daemon=True).start()
            else:
                fn(*args)
            return


    def on_get_stats(self, msg):
        self.send({'type': 'stats', 'data': get_stats()})

    def on_list_files(self, msg):
        self.send({'type': 'file_list', 'path': msg.get('path'), 'files': list_files(msg.get('path', '~'))})

    def on_kill_process(self, msg):
        pid = int(msg.get('pid') or 0)
        sig = msg.get('signal', 'KILL')
        if sig not in ('TERM', 'KILL'):  # only graceful or force; nothing exotic
            sig = 'KILL'
        if pid > 1:  # guard: 0 kills process group, 1 kills init/systemd
            try:
                proc = psutil.Process(pid)
                service_user = os.environ.get('USER') or os.environ.get('LOGNAME', '')
                proc_user = proc.username()
                if service_user and proc_user != service_user:
                    self.send({'type': 'error', 'message': f'Cannot kill PID {pid}: owned by {proc_user}'})
                else:
                    audit('kill_process', {'pid': pid, 'name': proc.name(), 'signal': sig, 'ip': self.addr[0]})
                    subprocess.run(['kill', '-' + sig, str(pid)])
            except psutil.NoSuchProcess:
                pass

    def on_get_schedules(self, msg):
        self.send({'type': 'schedules', 'data': load_schedules()})

    def on_set_schedule(self, msg):
        scheds = load_schedules()
        s = msg.get('schedule', {})
        # Server is authoritative on timing. Reject a bad expression at the
        # door rather than storing it and discovering the problem days later.
        expr = s.get('cronExpression')
        if expr and _cron_valid(expr):
            nxt = _cron_next(expr, time.time())
            if nxt: s['nextRun'] = nxt * 1000
        else:
            s['nextRun'] = 0
            detail = f'invalid cron expression {expr!r}' if expr else 'no cron expression'
            print(f'[scheduler] rejected timing for {s.get("id")}: {detail}')
            self.send({'type': 'schedule_error', 'scheduleId': s.get('id'),
                       'error': f'{detail} — this schedule will not run'})
        idx = next((i for i, x in enumerate(scheds) if x.get('id') == s.get('id')), None)
        if idx is not None:
            # The app owns intent (label/cron/enabled); the Pi owns history.
            # Without this, every push wiped the run history we just started
            # keeping, because the app's copy is missing anything it didn't
            # personally witness.
            prev = scheds[idx].get('execHistory') or []
            if prev and not s.get('execHistory'):
                s['execHistory'] = prev
            scheds[idx] = s
        else: scheds.append(s)
        save_schedules(scheds)

    def on_delete_schedule(self, msg):
        save_schedules([s for s in load_schedules() if s.get('id') != msg.get('id')])

    def on_register_push(self, msg):
        tok = (msg.get('token') or '').strip()
        if tok:
            toks = load_push_tokens()
            entry = toks.get(tok, {})
            entry['categories'] = [c for c in (msg.get('categories') or list(PUSH_CATEGORIES)) if c in PUSH_CATEGORIES]
            entry['updated'] = int(time.time())
            toks[tok] = entry
            save_push_tokens(toks)
            self.send({'type': 'push_registered', 'categories': entry['categories']})

    def on_unregister_push(self, msg):
        tok = (msg.get('token') or '').strip()
        toks = load_push_tokens()
        if toks.pop(tok, None) is not None:
            save_push_tokens(toks)

    def on_set_thresholds(self, msg):
        th = {k: msg.get(k) for k in ('cpuWarnPct', 'ramWarnPct', 'tempWarnC', 'diskWarnPct') if msg.get(k)}
        save_thresholds(th)
        self.send({'type': 'thresholds', 'data': th})

    def on_get_thresholds(self, msg):
        self.send({'type': 'thresholds', 'data': load_thresholds()})

    def on_get_alerts(self, msg):
        self.send({'type': 'alerts_list', 'data': _load_alerts()})

    def on_clear_alerts(self, msg):
        _save_alerts([]); audit('clear_alerts', {'ip': self.addr[0]}); self.send({'type': 'alerts_list', 'data': []})

    def on_set_sentinel(self, msg):
        # Configured from the app over the authenticated (and TLS-pinned)
        # channel, so the user never opens a terminal or edits a file.
        url    = (msg.get('url') or '').strip()
        secret = (msg.get('secret') or '').strip()
        if not url:
            SENTINEL_CONFIG_FILE.unlink(missing_ok=True)
            self.send({'type': 'sentinel_status', 'data': sentinel_status()})
        elif not url.startswith('https://'):
            self.send({'type': 'sentinel_status',
                       'data': {**sentinel_status(),
                                'error': 'That address must start with https://'}})
        else:
            SENTINEL_CONFIG_FILE.write_text(json.dumps({
                'url': url, 'secret': secret, 'id': CONFIG['name'],
            }, indent=2))
            SENTINEL_CONFIG_FILE.chmod(0o600)
            # Prove it works NOW rather than letting the user discover in a
            # week that they pasted the wrong address.
            ok = sentinel_send(SENTINEL_GRACE_SEC)
            self.send({'type': 'sentinel_status', 'data': sentinel_status(verified=ok)})

    def on_sentinel_preflight(self, msg):
        """Everything that would make a deploy pointless, checked before the user
        goes anywhere near Cloudflare. Nothing is worse than sending someone off
        to make a token and failing afterwards for a reason we already knew."""
        self.send({'type': 'sentinel_preflight', 'data': sentinel_preflight()})

    def on_check_sentinel_token(self, msg):
        """Validate a token WITHOUT creating anything, and say precisely what is
        wrong with it if something is. Reads only."""
        def _run():
            try:
                rep = cf_token_report(msg.get('token'), msg.get('accountId'))
            except Exception as e:
                rep = {'ok': False, 'accounts': [], 'error': f'Unexpected error: {e}'}
            self.send({'type': 'sentinel_token_report', 'data': rep})
        threading.Thread(target=_run, daemon=True).start()

    def on_deploy_sentinel(self, msg):
        # The Pi provisions the user's OWN Cloudflare watcher from a token
        # they paste in. The token is used in memory only and is never
        # written to disk; the worker runs without it afterward.
        tok = msg.get('token') or ''
        acct = msg.get('accountId') or None
        verify = msg.get('verify', True)

        def _run_deploy(tok=tok):
            def progress(m):
                self.send({'type': 'sentinel_deploy_progress', 'message': m})

            pre = sentinel_preflight()
            if not pre['ok']:
                self.send({'type': 'sentinel_deploy_error',
                           'message': pre['blockers'][0]['title'],
                           'blockers': pre['blockers'], 'data': sentinel_status()})
                return
            try:
                ok, info = deploy_sentinel_worker(tok, progress, account_id=acct)
            except Exception as e:
                ok, info = False, {'error': f'Unexpected error: {e}'}
            if not ok:
                self.send({'type': 'sentinel_deploy_error',
                           'message': info.get('error', 'Setup failed.'),
                           'accounts': info.get('accounts', []),
                           'needAccount': info.get('needAccount', False),
                           'missing': info.get('missing', []),
                           'data': sentinel_status()})
                return

            armed = sentinel_send(SENTINEL_GRACE_SEC)   # arm now, don't wait for the loop
            global _SENTINEL_LAST_OK, _SENTINEL_LAST_AT
            _SENTINEL_LAST_OK, _SENTINEL_LAST_AT = armed, int(time.time() * 1000)
            self.send({'type': 'sentinel_deploy_done', 'url': info.get('url', ''),
                       'mode': info.get('mode', ''), 'verifying': bool(verify),
                       'data': sentinel_status()})

            # Deployed is not the same as working. Prove it before saying so.
            if verify:
                progress('Proving it works — this takes about a minute…')
                sentinel_run_verification(
                    progress,
                    lambda good, detail: self.send(
                        {'type': 'sentinel_verified', 'ok': good, **detail,
                         'data': sentinel_status()}))
        threading.Thread(target=_run_deploy, daemon=True).start()

    def on_sentinel_test_ack(self, msg):
        """The phone telling us the test alert actually landed. This is the only
        signal that the whole chain works; nothing on the Pi can observe it."""
        _SENTINEL_VERIFY['confirmed'] = True
        self.send({'type': 'sentinel_status', 'data': sentinel_status()})

    def on_verify_sentinel(self, msg):
        """Re-run the end-to-end proof on demand."""
        def _run():
            sentinel_run_verification(
                lambda m: self.send({'type': 'sentinel_deploy_progress', 'message': m}),
                lambda good, detail: self.send(
                    {'type': 'sentinel_verified', 'ok': good, **detail,
                     'data': sentinel_status()}))
        threading.Thread(target=_run, daemon=True).start()

    def on_get_sentinel_status(self, msg):
        self.send({'type': 'sentinel_status', 'data': sentinel_status()})

    def on_test_sentinel(self, msg):
        # Arm a 60-second deadline and stop beating: the alert should arrive
        # about a minute later WITHOUT anyone unplugging anything.
        ok = sentinel_send(60, kind='test')
        global _SENTINEL_TEST_UNTIL
        _SENTINEL_TEST_UNTIL = time.time() + 90 if ok else 0
        self.send({'type': 'sentinel_test_result', 'ok': ok,
                   'error': '' if ok else 'Could not reach your Sentinel. Check the address.'})

    def on_test_push(self, msg):
        toks = load_push_tokens()
        if not toks:
            self.send({'type': 'push_test_result', 'ok': False,
                       'error': 'No device registered with this Pi. If the app was built without the aps-environment entitlement, iOS never issued a token.'})
        elif not _apns_config() or not APNS_KEY_FILE.exists():
            self.send({'type': 'push_test_result', 'ok': False,
                       'error': 'APNs credentials missing on the Pi (~/.pilink/apns_key.p8 and apns.json). See deploy-pi.ps1 step 7.'})
        else:
            # Wait for the real APNs outcome before answering. Reporting
            # success the instant a thread started meant every delivery
            # failure was invisible -- the dialog said "sent" for a push
            # that Apple had rejected.
            def _run_test():
                res = push_notify('presence', CONFIG['name'],
                                  "Test notification \u2014 everything's working.",
                                  key='test', extra={'test': True},
                                  bypass_cooldown=True)
                if res.get('skipped'):
                    self.send({'type': 'push_test_result', 'ok': False,
                               'error': f'Not sent: {res["skipped"]}'})
                elif res.get('sent'):
                    self.send({'type': 'push_test_result', 'ok': True,
                               'error': f'Apple accepted it for {res["sent"]} device(s). '
                                        f'If nothing appears, check Focus/notification settings on the phone.'})
                else:
                    errs = '; '.join(res.get('errors') or ['unknown error'])
                    self.send({'type': 'push_test_result', 'ok': False,
                               'error': f'Apple rejected it: {errs}'})
            threading.Thread(target=_run_test, daemon=True).start()

    def on_get_agent_config(self, msg):
        self.send({'type': 'agent_config', 'data': load_agent_config()})

    def on_set_agent_config(self, msg):
        cfg = load_agent_config()
        incoming = {k: v for k, v in msg.get('config', {}).items() if k in ALLOWED_AGENT_KEYS}
        cfg.update(incoming)
        save_agent_config(cfg)
        self.send({'type': 'agent_config', 'data': cfg})

    def on_get_agent_status(self, msg):
        self.send({'type': 'agent_status', 'data': load_agent_status()})

    def on_get_leds(self, msg):
        self.send({'type': 'leds', 'data': get_leds()})

    def on_set_led(self, msg):
        led_name = msg.get('name', '')
        try:
            set_led(led_name, msg.get('trigger', 'none'))
            self.send({'type': 'leds', 'data': get_leds()})
        except Exception as e:
            self.send({'type': 'led_error', 'name': led_name, 'message': str(e)})
            self.send({'type': 'leds', 'data': get_leds()})

    def on_get_eth_leds(self, msg):
        self.send({'type': 'eth_leds', 'data': get_eth_led_config()})

    def on_set_eth_leds(self, msg):
        try:
            set_eth_led_config(msg.get('led0'), msg.get('led1'))
            cfg = get_eth_led_config()
            cfg['pending_reboot'] = True
            self.send({'type': 'eth_leds', 'data': cfg})
        except Exception as e:
            self.send({'type': 'eth_led_error', 'message': str(e)})

    def on_get_ip_lock(self, msg):
        self.send({'type': 'ip_lock', 'data': load_ip_lock()})

    def on_get_tailscale_ip(self, msg):
        self.send({'type': 'tailscale_ip', 'data': get_tailscale_ip()})

    # ── Thermostat (Phase 2 M3) — thin wrappers over thermostat.api ─────────────
    def on_get_thermostat(self, msg):
        try:
            api, store = _thermostat()
        except Exception as e:
            self.send({'type': 'thermostat', 'error': f'thermostat unavailable: {e}'})
            return
        did = msg.get('device_id') or 'thermostat-01'
        self.send({'type': 'thermostat', 'data': api.build_status(store, did)})

    def on_get_thermostat_history(self, msg):
        try:
            api, store = _thermostat()
        except Exception as e:
            self.send({'type': 'thermostat_history', 'error': f'thermostat unavailable: {e}'})
            return
        did = msg.get('device_id') or 'thermostat-01'
        self.send({'type': 'thermostat_history', 'device_id': did,
                   'data': api.build_history(store, did,
                                             since=msg.get('since'), limit=msg.get('limit'))})

    def on_set_setpoint(self, msg):
        try:
            api, store = _thermostat()
        except Exception as e:
            self.send({'type': 'thermostat', 'error': f'thermostat unavailable: {e}'})
            return
        try:
            result = api.set_setpoint(store, msg.get('setpoint'))
        except ValueError as e:
            self.send({'type': 'thermostat', 'error': str(e)})
            return
        audit('set_setpoint', {'ip': self.addr[0], 'setpoint': result['setpoint']})
        self.send({'type': 'thermostat',
                   'data': api.build_status(store, msg.get('device_id') or 'thermostat-01')})

    def on_set_mode(self, msg):
        try:
            api, store = _thermostat()
        except Exception as e:
            self.send({'type': 'thermostat', 'error': f'thermostat unavailable: {e}'})
            return
        try:
            result = api.set_mode(store, msg.get('mode'))
        except ValueError as e:
            self.send({'type': 'thermostat', 'error': str(e)})
            return
        audit('set_mode', {'ip': self.addr[0], 'mode': result['mode']})
        self.send({'type': 'thermostat',
                   'data': api.build_status(store, msg.get('device_id') or 'thermostat-01')})

    def on_set_optimized_charging(self, msg):
        """Battery-health charging preference. Accepted even when the node has no
        charge-control wire — it persists and takes effect if the wire is added
        later, rather than being silently refused."""
        try:
            api, store = _thermostat()
        except Exception as e:
            self.send({'type': 'thermostat', 'error': f'thermostat unavailable: {e}'})
            return
        try:
            result = api.set_optimized_charging(store, msg.get('enabled'))
        except ValueError as e:
            self.send({'type': 'thermostat', 'error': str(e)})
            return
        audit('set_optimized_charging', {'ip': self.addr[0],
                                         'enabled': result['optimized_charging']})
        self.send({'type': 'thermostat',
                   'data': api.build_status(store, msg.get('device_id') or 'thermostat-01')})


    def stats_loop(self):
        while self.authed:
            self.send({'type': 'stats', 'data': get_stats()})
            time.sleep(1)

    def on_delete_file(self, msg):
        path = msg.get('path', '')
        try:
            delete_path(path)
            audit('delete_file', {'path': path, 'ip': self.addr[0]})
            self.send({'type': 'delete_result', 'path': path, 'success': True})
        except Exception as e:
            self.send({'type': 'delete_result', 'path': path, 'success': False, 'error': str(e)})

    def on_rename_file(self, msg):
        path = msg.get('path', '')
        new_name = msg.get('newName', '')
        try:
            new_path = rename_path(path, new_name)
            self.send({'type': 'rename_result', 'path': path, 'newPath': new_path, 'success': True})
        except Exception as e:
            self.send({'type': 'rename_result', 'path': path, 'success': False, 'error': str(e)})

    def on_move_file(self, msg):
        path = msg.get('path', '')
        dest = msg.get('destDir', '')
        try:
            new_path = move_path(path, dest)
            self.send({'type': 'move_result', 'path': path, 'newPath': new_path, 'success': True})
        except Exception as e:
            self.send({'type': 'move_result', 'path': path, 'success': False, 'error': str(e)})

    def on_read_file(self, msg):
        path = msg.get('path', '')
        try:
            content = read_file_text(path)
            self.send({'type': 'read_result', 'path': path, 'success': True, 'content': content})
        except Exception as e:
            self.send({'type': 'read_result', 'path': path, 'success': False, 'error': str(e)})

    def on_write_file(self, msg):
        path = msg.get('path', '')
        content = msg.get('content', '')
        try:
            write_file_text(path, content)
            self.send({'type': 'write_result', 'path': path, 'success': True})
        except Exception as e:
            self.send({'type': 'write_result', 'path': path, 'success': False, 'error': str(e)})

    def on_download_file(self, msg):
        path = msg.get('path', '')
        try:
            content, name = read_file_base64(path)
            self.send({'type': 'download_result', 'path': path, 'success': True, 'content': content, 'name': name})
        except Exception as e:
            self.send({'type': 'download_result', 'path': path, 'success': False, 'error': str(e)})

    def on_upload_file(self, msg):
        import base64 as _b64
        dest_dir = msg.get('destDir', '~')
        name     = Path(msg.get('name', 'upload')).name  # strip any directory components
        content  = msg.get('content', '')
        try:
            # Reject oversized uploads before decoding (base64 is ~4/3 raw size)
            if len(content) > MAX_UPLOAD_SIZE * 4 // 3:
                raise ValueError(f'Upload too large (limit {MAX_UPLOAD_SIZE // (1024 * 1024)} MB)')
            data = _b64.b64decode(content)
            if len(data) > MAX_UPLOAD_SIZE:
                raise ValueError(f'Upload too large ({len(data)} bytes)')
            dest = safe_path(dest_dir) / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            audit('upload_file', {'path': str(dest), 'size': len(data), 'ip': self.addr[0]})
            self.send({'type': 'upload_result', 'path': str(dest), 'success': True})
        except Exception as e:
            self.send({'type': 'upload_result', 'path': name, 'success': False, 'error': str(e)})

    def on_processes(self):
        procs = []
        for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent','status']):
            try:
                procs.append({'pid': p.info['pid'], 'name': p.info['name'],
                              'cpuPercent': round(p.info['cpu_percent'] or 0, 1),
                              'memPercent': round(p.info['memory_percent'] or 0, 1),
                              'status': p.info['status']})
            except Exception: pass
        self.send({'type': 'processes', 'data': sorted(procs, key=lambda x: x['cpuPercent'], reverse=True)[:50]})

    def on_get_services(self):
        self.send({'type': 'services', 'data': build_services()})

    def on_set_managed_service(self, msg):
        unit = msg.get('unit', '')
        managed = bool(msg.get('managed', False))
        if not _valid_unit(unit):
            self.send({'type': 'error', 'message': f'Invalid service unit: {unit}'})
            return
        units = set(load_managed_units())
        if managed:
            units.add(unit)
        else:
            units.discard(unit)
        save_managed_units(list(units))
        audit('set_managed_service', {'unit': unit, 'managed': managed, 'ip': self.addr[0]})
        self.send({'type': 'services', 'data': build_services()})

    def on_control_service(self, msg):
        unit   = msg.get('unit', '')
        action = msg.get('action', '')
        if action not in _SYSCTL_ARGS:
            self.send({'type': 'service_result', 'unit': unit, 'action': action,
                       'success': False, 'error': 'Unknown action'})
            return
        if not _valid_unit(unit):
            self.send({'type': 'service_result', 'unit': unit, 'action': action,
                       'success': False, 'error': 'Invalid unit name'})
            return
        # Any valid unit can be controlled (every action is audited below), but
        # refuse to turn OFF the units that keep this Pi reachable.
        if unit in _SELF_CRITICAL and action in ('stop', 'off', 'disable'):
            self.send({'type': 'service_result', 'unit': unit, 'action': action, 'success': False,
                       'error': 'Refusing - ' + unit[:-8] + ' keeps PiLink connected to this Pi. Use the terminal if you really mean to.'})
            return
        audit('control_service', {'unit': unit, 'action': action, 'ip': self.addr[0]})
        ok, err = _systemctl(action, unit)
        self.send({'type': 'service_result', 'unit': unit, 'action': action,
                   'success': ok, 'error': None if ok else err})
        self.send({'type': 'services', 'data': build_services()})

    def on_term_input(self, msg):
        if self.term_fd is None:
            self.term_pid, self.term_fd = pty.fork()
            if self.term_pid == 0:
                # Without this, bash inherits whatever cwd the pilink systemd
                # service happens to be running from (its own ~/.pilink config
                # folder) instead of starting somewhere sensible like a normal
                # login shell would.
                try:
                    os.chdir(os.path.expanduser('~'))
                except OSError:
                    pass
                os.execvpe('/bin/bash', ['/bin/bash', '-i'],
                           {**os.environ, 'TERM': 'xterm-256color'})
            else:
                # The terminal is the highest-privilege surface in the product
                # and was the only one leaving no audit record. Logged once per
                # PTY, not per keystroke.
                audit('terminal_open', {'ip': self.addr[0], 'pid': self.term_pid})
                threading.Thread(target=self._term_read, daemon=True).start()
        try:
            os.write(self.term_fd, msg['data'].encode())
        except OSError: pass

    def _term_read(self):
        # Coalesce PTY output: a command that dumps a lot (cat, a build) otherwise
        # floods the app with tiny messages and freezes its JS thread. Same bytes,
        # far fewer messages; the idle-flush keeps interactive output instant.
        co = StreamCoalescer(lambda s: self.send({'type': 'terminal_output', 'data': s}))
        while True:
            try:
                r, _, _ = select.select([self.term_fd], [], [], 0.05)
                if r:
                    data = os.read(self.term_fd, 4096)
                    if not data: break
                    co.add(_sanitise_pty(data).decode('utf-8', errors='replace'))
                else:
                    co.flush()
            except OSError: break
        co.flush()

    def on_tail_log(self, msg):
        self.on_stop_log()
        path = msg.get('path', 'journalctl')
        # 'journalctl' is a virtual path — use journalctl -f instead of tail.
        # This avoids permission issues with /var/log/* on systemd-based distros.
        if path == 'journalctl':
            cmd = ['journalctl', '-f', '-n', '100', '--no-pager', '-o', 'short-iso']
        elif path == 'journalctl-auth':
            cmd = ['journalctl', '-f', '-n', '100', '--no-pager', '-o', 'short-iso', '-u', 'ssh', '-u', 'sudo']
        elif path == 'journalctl-pilink':
            cmd = ['journalctl', '-f', '-n', '100', '--no-pager', '-o', 'short-iso', '-u', 'pilink-server', '-u', 'pilink-agent']
        else:
            validated = safe_path(path)  # raises PermissionError if outside allowed dirs
            cmd = ['tail', '-f', '-n', '100', str(validated)]
        self.log_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in self.log_proc.stdout:
            self.send({'type': 'log_line', 'data': line.rstrip()})

    def on_stop_log(self):
        if self.log_proc:
            try: self.log_proc.terminate()
            except Exception: pass
            self.log_proc = None

    def on_ssh_connect(self, msg):
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(_TOFUPolicy())
        try:
            self.send({'type': 'ssh_status', 'status': 'authenticating'})
            kw = {'hostname': '127.0.0.1', 'port': int(msg.get('port', 22)),
                  'username': msg.get('username', 'pi'), 'timeout': 10,
                  'allow_agent': False, 'look_for_keys': False}
            if msg.get('password'):
                kw['password'] = msg['password']
            else:
                for cls in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]:
                    try:
                        kw['pkey'] = cls.from_private_key_file(os.path.expanduser('~/.ssh/id_rsa'))
                        break
                    except Exception: pass
            c.connect(**kw)
            ch = c.invoke_shell(term='xterm-256color', width=220, height=50)
            ch.setblocking(False)
            self.ssh_client, self.ssh_channel = c, ch
            self.send({'type': 'ssh_status', 'status': 'connected'})
            co = StreamCoalescer(lambda s: self.send({'type': 'ssh_output', 'data': s}))
            while True:
                r, _, _ = select.select([ch], [], [], 0.05)
                if r:
                    d = ch.recv(8192)
                    if not d: break
                    co.add(_sanitise_pty(d).decode('utf-8', errors='replace'))
                else:
                    co.flush()
                if ch.closed: break
            co.flush()
        except paramiko.AuthenticationException:
            self.send({'type': 'ssh_status', 'status': 'error', 'detail': 'Wrong username or password'})
        except Exception as e:
            self.send({'type': 'ssh_status', 'status': 'error', 'detail': str(e)})
        finally:
            try: c.close()
            except Exception: pass
            self.ssh_client = self.ssh_channel = None
            self.send({'type': 'ssh_status', 'status': 'disconnected'})

    def on_ssh_input(self, msg):
        if self.ssh_channel:
            try: self.ssh_channel.send(msg.get('data', '').encode())
            except Exception: pass

    def on_ssh_resize(self, msg):
        if self.ssh_channel:
            try: self.ssh_channel.resize_pty(width=int(msg.get('cols', 80)), height=int(msg.get('rows', 24)))
            except Exception: pass

    def on_ssh_disconnect(self):
        if self.ssh_channel:
            try: self.ssh_channel.send(b'exit\n')
            except Exception: pass
        if self.ssh_client:
            try: self.ssh_client.close()
            except Exception: pass
        self.ssh_client = self.ssh_channel = None
        self.send({'type': 'ssh_status', 'status': 'disconnected'})

    def on_command(self, msg):
        cmd = msg.get('command')
        if cmd in ('reboot', 'shutdown'):
            # Same -n reasoning as run_schedule: never block on a hidden prompt.
            argv = ['sudo', '-n', 'reboot'] if cmd == 'reboot' else ['sudo', '-n', 'shutdown', '-h', 'now']
            # Same reasoning as run_schedule: widen the window for a reboot we
            # asked for, stand the switch down entirely for a shutdown.
            if cmd == 'reboot':
                sentinel_send(SENTINEL_REBOOT_GRACE, kind='scheduled-reboot', label='Reboot from PiLink')
            else:
                sentinel_send(0, disarm=True)
            audit(cmd, {'ip': self.addr[0]})
            self.send({'type': 'ok'})
            time.sleep(0.5)
            try:
                r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
                # Reaching here with a non-zero code means it did NOT happen --
                # a successful reboot never returns.
                if r.returncode != 0:
                    lines = ((r.stderr or '') + (r.stdout or '')).strip().splitlines()
                    detail = lines[-1].strip() if lines else f'exit {r.returncode}'
                    print(f'[command] {cmd} FAILED: {detail}')
                    audit(f'{cmd}_failed', {'error': detail, 'ip': self.addr[0]})
                    self.send({'type': 'error', 'message': f'{cmd.capitalize()} failed: {detail}'})
            except subprocess.TimeoutExpired:
                pass   # the machine is going down; no answer is the expected answer
        elif cmd == 'kill_all':
            self.cleanup()
            self.conn.close()

    def on_write_b64_file(self, msg):
        """Receive a base64-encoded file from the app and write it to disk.
        Restricted to ~/.pilink/ to prevent overwriting home-dir files like .bashrc or .ssh/."""
        import base64 as _b64
        path = msg.get('path', '')
        content_b64 = msg.get('content', '')
        expected_sha256 = msg.get('sha256', '')
        try:
            resolved = safe_path(path)
            # Extra restriction: only allow writes inside ~/.pilink/
            if not (resolved == CONFIG_DIR or resolved.is_relative_to(CONFIG_DIR)):
                raise PermissionError(f'write_b64_file is restricted to {CONFIG_DIR}')
            resolved.parent.mkdir(parents=True, exist_ok=True)
            data = _b64.b64decode(content_b64)
            if len(data) < 512:
                raise ValueError(f'Received file is suspiciously small ({len(data)} bytes) — rejected')
            # Optional SHA-256 content integrity check (app includes hash in message)
            if expected_sha256:
                actual_sha256 = hashlib.sha256(data).hexdigest()
                if actual_sha256 != expected_sha256:
                    raise ValueError('SHA-256 mismatch — content may have been tampered with')
            # Write atomically via temp file
            tmp = resolved.with_suffix(resolved.suffix + '.new')
            tmp.write_bytes(data)
            os.replace(str(tmp), str(resolved))
            audit('write_b64_file', {'path': str(resolved), 'size': len(data), 'ip': self.addr[0]})
            self.send({'type': 'write_b64_result', 'path': path, 'success': True})
        except Exception as e:
            self.send({'type': 'write_b64_result', 'path': path, 'success': False, 'error': str(e)})

    def on_restart_server(self):
        """Apply a pushed update by exiting cleanly so systemd (Restart=always,
        RestartSec=5) relaunches us with the freshly-written code. We deliberately
        do NOT `sudo systemctl restart` here: from this non-interactive daemon that
        needs passwordless sudo the user may not have set up -- which is exactly why
        the in-app 'Update Server' appeared to do nothing. Exiting needs no privileges."""
        audit('restart_server', {'ip': self.addr[0]})
        self.send({'type': 'update_done'})
        def restart():
            time.sleep(1.5)   # let the write_b64_file threads finish + update_done flush
            os._exit(0)       # a daemon thread cannot sys.exit the process; _exit kills it -> systemd relaunches
        threading.Thread(target=restart, daemon=True).start()

    def on_rotate_key(self):
        """Generate a new pairing key, persist it, broadcast key_rotated, then close all sessions."""
        new_key = secrets.token_hex(16)
        CONFIG['pairing_key'] = new_key
        CONFIG_FILE.write_text(json.dumps(CONFIG, indent=2))
        CONFIG_FILE.chmod(0o600)
        audit('rotate_key', {'ip': self.addr[0]})
        # Tell all connected apps the new key before closing so they can update SecureStore
        broadcast({'type': 'key_rotated', 'newKey': new_key})
        time.sleep(0.5)
        with SESSIONS_LOCK:
            sessions = list(ACTIVE_SESSIONS)
        for sess in sessions:
            try: sess.conn.close()
            except Exception: pass

    def on_set_ip_lock(self, msg):
        """Enable/disable the IP allowlist. When enabling, auto-adds the current client IP."""
        enabled = bool(msg.get('enabled', False))
        cfg = load_ip_lock()
        cfg['enabled'] = enabled
        if enabled:
            ip = self.addr[0]
            if ip not in cfg.get('allowed', []):
                cfg.setdefault('allowed', []).append(ip)
        save_ip_lock(cfg)
        audit('set_ip_lock', {'ip': self.addr[0], 'enabled': enabled})
        self.send({'type': 'ip_lock', 'data': cfg})

    def _idle_watchdog(self):
        """Disconnect authenticated sessions silent for longer than IDLE_TIMEOUT_SEC."""
        while self.authed:
            time.sleep(60)
            if self.authed and time.time() - self.last_active > IDLE_TIMEOUT_SEC:
                print(f'[pilink] {self.addr} idle timeout — disconnecting')
                audit('idle_timeout', {'ip': self.addr[0]})
                try: self.conn.close()
                except Exception: pass
                break

    def cleanup(self):
        self.authed = False
        with SESSIONS_LOCK:
            ACTIVE_SESSIONS.discard(self)
        if self.term_pid:
            try: os.kill(self.term_pid, 9)
            except Exception: pass
        if self.term_fd:
            try: os.close(self.term_fd)
            except Exception: pass
        if self.ssh_client:
            try: self.ssh_client.close()
            except Exception: pass
        if self.log_proc:
            try: self.log_proc.terminate()
            except Exception: pass


# ── Agent event pusher ────────────────────────────────────────────────────────
def event_pusher_loop():
    last_line = 0
    if EVENTS_LOG.exists():
        with open(EVENTS_LOG) as f:
            last_line = sum(1 for _ in f)
    while True:
        try:
            if EVENTS_LOG.exists():
                with open(EVENTS_LOG) as f:
                    lines = f.readlines()
                if len(lines) > last_line:
                    for line in lines[last_line:]:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except Exception:
                            continue
                        broadcast({'type': 'agent_event', 'event': event})
                        # Only the ones that mean something is wrong. The agent
                        # logs plenty of routine chatter and pushing all of it
                        # would make the channel worthless.
                        # Kind names verified against what pilink-agent.py
                        # actually emits: service_state_change, service_restart,
                        # escalation, file_change. Guessing here would produce a
                        # notification category that silently never fires.
                        kind = event.get('kind') or ''
                        svc  = event.get('service') or 'A service'
                        name = _friendly_unit(svc)
                        if kind == 'service_restart':
                            ok = event.get('success')
                            if ok:
                                push_notify('service',
                                            f'{CONFIG["name"]}: {name} restarted',
                                            'It stopped unexpectedly and PiLink started it again. '
                                            'Nothing needed from you.',
                                            key=f'restart:{svc}')
                            else:
                                push_notify('service',
                                            f'{CONFIG["name"]}: {name} is down',
                                            "It stopped unexpectedly and PiLink couldn't start it again.",
                                            key=f'restart:{svc}')
                        elif kind == 'escalation':
                            times = event.get('failureCount', 'several')
                            push_notify('service',
                                        f'{CONFIG["name"]}: {name} keeps stopping',
                                        f'It has failed {times} times in a row, so PiLink has stopped '
                                        'trying to restart it.',
                                        key=f'escalation:{svc}')
                        elif kind == 'service_state_change' and event.get('to') == 'failed':
                            # Only a genuine failure, and only when the agent didn't
                            # already auto-restart it (that path sends its own, single
                            # notification). A clean 'inactive' is never notified --
                            # that was the "no longer running" spam from oneshot units
                            # like NetworkManager-dispatcher that stop by design.
                            push_notify('service',
                                        f'{CONFIG["name"]}: {name} stopped working',
                                        "It failed and wasn't restarted automatically. "
                                        "Open PiLink to look into it.",
                                        key=f'failed:{svc}')
                    last_line = len(lines)
        except Exception as e:
            print(f'[event_pusher] {e}')
        time.sleep(2)


def mdns_register_loop():
    """Advertise this Pi as _pilink._tcp.local. so the iOS app can discover it via mDNS."""
    if Zeroconf is None:
        print('[mdns] zeroconf package not installed - skipping mDNS advertisement (pip3 install zeroconf --break-system-packages)')
        return
    zc = None
    while True:
        try:
            ip = get_local_ip()
            zc = Zeroconf()
            info = ServiceInfo(
                '_pilink._tcp.local.',
                f'{CONFIG["name"]}._pilink._tcp.local.',
                addresses=[socket.inet_aton(ip)],
                port=PORT,
                properties={
                    'model': CONFIG['model'],
                    'pairingKey': CONFIG['pairing_key'],
                    'piId': CONFIG['pi_id'],
                    'version': CONFIG['version'],
                    # Certificate identity, advertised out of band. The app
                    # verifies the cert it is offered against this before
                    # pinning, so first contact is authenticated rather than
                    # trust-on-first-use. Empty if cert generation failed.
                    'certFp': cert_fingerprint(),
                },
            )
            zc.register_service(info)
            print(f'[mdns] Advertising _pilink._tcp.local. as "{CONFIG["name"]}" on {ip}:{PORT}')

            last_ip = ip
            while True:
                time.sleep(30)
                if get_local_ip() != last_ip:
                    print('[mdns] IP changed, re-registering service')
                    break
        except Exception as e:
            print(f'[mdns] error: {e}')
            time.sleep(10)
        finally:
            try:
                if zc:
                    zc.close()
            except Exception:
                pass


_TLS_CTX = None

def _tls_context():
    """Server SSL context built once from the self-signed cert."""
    global _TLS_CTX
    if _TLS_CTX is None:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(TLS_CERT), keyfile=str(TLS_KEY))
            _TLS_CTX = ctx
        except Exception as e:
            print(f'[tls] context unavailable ({e}) - TLS clients will be refused')
            _TLS_CTX = False
    return _TLS_CTX or None

def _accept_session(conn, addr):
    """Opportunistic TLS. Peek at the first byte: 0x16 is a TLS ClientHello, so
    wrap the socket; anything else is served as plaintext. Handling both on one
    port means upgrading the app can never lock you out of the Pi - an older
    plaintext client keeps working while a TLS-capable one gets encryption."""
    try:
        conn.settimeout(5)
        first = conn.recv(1, socket.MSG_PEEK)
        if not first:
            conn.close()
            return
        if first[0] == 0x16:
            ctx = _tls_context()
            if ctx is None:
                conn.close()
                return
            conn = ctx.wrap_socket(conn, server_side=True)
            print(f'[tls] {addr} connected over TLS')
        conn.settimeout(None)
    except socket.timeout:
        # reachability probes connect without sending anything - close quietly
        try: conn.close()
        except Exception: pass
        return
    except Exception as e:
        print(f'[tls] setup failed for {addr}: {e}')
        try: conn.close()
        except Exception: pass
        return
    ClientSession(conn, addr).run()

def serve():
    # Opportunistic TLS: this listener serves BOTH plaintext and TLS on the same
    # port (see _accept_session), so the app can be upgraded without any risk of
    # locking you out. The self-signed cert is generated on first run and the app
    # pins its fingerprint TOFU-style. Auth is still enforced at the application
    # layer via the pairingKey on every connection.
    ensure_tls_cert()

    # Surface uncaught exceptions from handler threads (see _thread_excepthook).
    threading.excepthook = _thread_excepthook

    # Re-apply any LED state the user set — sysfs triggers reset to kernel defaults
    # on every reboot, so without this an LED turned off in the app comes back on.
    try:
        restore_leds()
    except Exception as e:
        print(f'[led] restore_leds failed: {e}')

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', PORT))
    srv.listen(10)
    ip = get_local_ip()
    print(f'[pilink] Listening on 0.0.0.0:{PORT}  (IP: {ip})')

    while True:
        conn, addr = srv.accept()
        print(f'[pilink] {addr} connected')
        threading.Thread(target=_accept_session, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    print(f'\n  PiLink Server v{CONFIG["version"]}')
    print(f'  Device: {CONFIG["name"]}')
    # The Pi announces its own return. It cannot announce its departure -- if
    # it's down it can't send anything -- so "went offline" is detected app-side.
    _check_optional_deps()
    threading.Thread(target=sentinel_loop,       daemon=True).start()
    threading.Thread(target=_announce_startup,   daemon=True).start()
    threading.Thread(target=threshold_monitor_loop, daemon=True).start()
    threading.Thread(target=scheduler_loop,       daemon=True).start()
    threading.Thread(target=icloud_register_loop, daemon=True).start()
    threading.Thread(target=mdns_register_loop,   daemon=True).start()
    threading.Thread(target=event_pusher_loop,     daemon=True).start()
    serve()
