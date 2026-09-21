#!/usr/bin/env python3
"""
PiLink Agent — Sensor + Recovery Layer

Runs separately from pilink-server.py. Its job:
  1. Auto-discover boot-enabled services and watch their state
  2. Watch a list of files/folders for changes
  3. Print a structured event whenever something happens
  4. If enabled (Settings → Self-healing agent → Auto-restart failed
     services), try to restart anything that crashes, and escalate
     (emit a louder event) after N consecutive failed restarts

Config lives in ~/.pilink/agent_config.json — pilink-server.py reads/writes
the same file so the phone app's Settings screen can control this agent
without it needing its own TCP listener.

Run:  python3 pilink-agent.py
Then: in another terminal, stop a service (sudo systemctl stop <name>)
      or edit a watched file, and watch this print the event.

Install deps:  pip3 install watchdog --break-system-packages
Requires passwordless sudo for `systemctl restart <service>` to actually
restart anything — see install-agent.sh.
"""

import json
import time
import subprocess
import threading
from pathlib import Path
from datetime import datetime

# Files inside AGENT_DIR that the watcher must never react to.
# These are written by the agent itself — reacting to them causes an
# infinite feedback loop (the bug that grew events.jsonl to 93 GB).
AGENT_INTERNAL_FILES = {
    'events.jsonl',
    'events.jsonl.1',
    'events.jsonl.2',
    'agent_status.json',
}

# Log rotation: cap events.jsonl at 5 MB, keep 2 backups.
MAX_EVENTS_BYTES  = 5 * 1024 * 1024   # 5 MB
MAX_EVENTS_BACKUPS = 2

# watchdog is the standard, efficient file-watching library.
# Falls back to polling if it's not installed.
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAVE_WATCHDOG = True
except ImportError:
    HAVE_WATCHDOG = False

# ──────────────────────────────────────────────────────────────────────────────
# Config — what to watch
# ──────────────────────────────────────────────────────────────────────────────

AGENT_DIR     = Path.home() / '.pilink'
WATCHLIST_FILE = AGENT_DIR / 'watchlist.json'
AGENT_CONFIG_FILE = AGENT_DIR / 'agent_config.json'
AGENT_STATUS_FILE = AGENT_DIR / 'agent_status.json'
AGENT_DIR.mkdir(parents=True, exist_ok=True)

# Default folders to watch for file changes.
# Phase 5 (app control) will let you edit this list from your phone.
DEFAULT_WATCHLIST = {
    'files': [
        '/etc/nginx',
        '/etc/systemd/system',
        str(Path.home() / '.pilink'),
    ],
    # Services list is auto-discovered; this is just for any extras you want pinned.
    'extra_services': [],
}

def load_watchlist():
    if WATCHLIST_FILE.exists():
        try:
            return json.loads(WATCHLIST_FILE.read_text())
        except Exception:
            pass
    WATCHLIST_FILE.write_text(json.dumps(DEFAULT_WATCHLIST, indent=2))
    return dict(DEFAULT_WATCHLIST)

# ──────────────────────────────────────────────────────────────────────────────
# Recovery config — read fresh every poll cycle so pilink-server.py (running
# as a separate process) can change it live from the phone app's Settings
# screen without restarting the agent. pilink-server.py reads/writes this
# same file via get_agent_config / set_agent_config.
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_AGENT_CONFIG = {
    'autoRestartEnabled': True,
    'escalationThreshold': 3,       # consecutive failed restarts before escalating
    'escalationCooldownMinutes': 15,  # don't re-escalate the same service more often than this
}

def load_agent_config():
    if AGENT_CONFIG_FILE.exists():
        try:
            return {**DEFAULT_AGENT_CONFIG, **json.loads(AGENT_CONFIG_FILE.read_text())}
        except Exception:
            pass
    AGENT_CONFIG_FILE.write_text(json.dumps(DEFAULT_AGENT_CONFIG, indent=2))
    return dict(DEFAULT_AGENT_CONFIG)

def write_status(watched_services: int, auto_restart_enabled: bool):
    try:
        AGENT_STATUS_FILE.write_text(json.dumps({
            'watchedServices': watched_services,
            'autoRestartEnabled': auto_restart_enabled,
            'lastHeartbeat': int(time.time() * 1000),
        }))
    except Exception as e:
        print(f"[agent] could not write status file: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# Event emission — for now, just print. Later this goes to the notification pipe.
# ──────────────────────────────────────────────────────────────────────────────

EVENTS_LOG = AGENT_DIR / 'events.jsonl'

_emit_lock = threading.Lock()

def _rotate_events_log():
    """Rotate events.jsonl when it exceeds MAX_EVENTS_BYTES.
    Keeps MAX_EVENTS_BACKUPS compressed copies (.1, .2 …) then drops the oldest."""
    try:
        if not EVENTS_LOG.exists() or EVENTS_LOG.stat().st_size < MAX_EVENTS_BYTES:
            return
        # Shift existing backups down: .2 → deleted, .1 → .2, live → .1
        for i in range(MAX_EVENTS_BACKUPS, 0, -1):
            src = AGENT_DIR / f'events.jsonl.{i}'
            dst = AGENT_DIR / f'events.jsonl.{i + 1}'
            if src.exists():
                if i == MAX_EVENTS_BACKUPS:
                    src.unlink()   # drop the oldest
                else:
                    src.rename(dst)
        EVENTS_LOG.rename(AGENT_DIR / 'events.jsonl.1')
        EVENTS_LOG.touch()
        print(f"[agent] events.jsonl rotated (exceeded {MAX_EVENTS_BYTES // 1024 // 1024} MB)")
    except Exception as e:
        print(f"[agent] log rotation failed: {e}")

def emit_event(event: dict):
    event['ts'] = int(time.time() * 1000)
    event['time_readable'] = datetime.now().strftime('%H:%M:%S')
    line = json.dumps(event)
    print(f"[EVENT] {line}")
    with _emit_lock:
        try:
            _rotate_events_log()
            with open(EVENTS_LOG, 'a') as f:
                f.write(line + '\n')
        except Exception as e:
            print(f"[agent] could not write event log: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# Service monitoring
# ──────────────────────────────────────────────────────────────────────────────

def discover_boot_services():
    """Find every service set to start on boot — these are the ones that MATTER."""
    try:
        out = subprocess.run(
            ['systemctl', 'list-unit-files', '--type=service', '--state=enabled', '--no-legend', '--no-pager'],
            capture_output=True, text=True, timeout=10
        ).stdout
        services = []
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0].endswith('.service'):
                svc = parts[0]
                if _service_is_oneshot(svc):
                    continue        # designed to go inactive; not a crash candidate
                services.append(svc)
        return services
    except Exception as e:
        print(f"[agent] Could not discover services: {e}")
        return []

def service_is_active(service: str) -> bool:
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == 'active'
    except Exception:
        return False

def service_state(service: str) -> str:
    """Raw systemctl state: 'active', 'inactive', 'failed', 'activating', ...

    The distinction that matters: only 'failed' means the unit crashed and systemd
    is not recovering it. Plain 'inactive' is a CLEAN stop -- a oneshot finishing
    its job, or a deliberate stop -- and must never be mistaken for a crash. Reading
    'inactive' as a crash is what made NetworkManager-dispatcher (which goes inactive
    on every network event, by design) spam restart notifications endlessly.
    """
    try:
        r = subprocess.run(['systemctl', 'is-active', service],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or 'unknown'
    except Exception:
        return 'unknown'

def _service_is_oneshot(service: str) -> bool:
    """Oneshot units are designed to run and then go inactive (dispatchers,
    one-time setup jobs). There is nothing to 'keep alive' and restarting one just
    re-runs a finished task, so we don't watch them at all."""
    try:
        r = subprocess.run(['systemctl', 'show', service, '--property=Type', '--value'],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == 'oneshot'
    except Exception:
        return False

def service_is_enabled(service: str) -> bool:
    """False only if the unit is explicitly disabled/masked — i.e. someone turned
    it off on purpose. The self-healing agent uses this so it never resurrects a
    service that was deliberately disabled (e.g. by the Git-screen repo kill switch
    or a manual `systemctl disable`)."""
    try:
        r = subprocess.run(['systemctl', 'is-enabled', service],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() not in ('disabled', 'masked')
    except Exception:
        return True

def restart_service(service: str) -> bool:
    """Try to bring a crashed service back up. Requires passwordless sudo for
    `systemctl restart` on this user — see install-agent.sh."""
    try:
        subprocess.run(['sudo', 'systemctl', 'restart', service], capture_output=True, text=True, timeout=15)
    except Exception as e:
        print(f"[agent] could not invoke restart for {service}: {e}")
        return False
    time.sleep(2)  # give it a moment to come up before checking
    return service_is_active(service)

def monitor_services(extra_services):
    """Poll service states; emit an event when one changes, and — if enabled
    in agent_config.json — try to restart anything that crashed. Phase 1 only
    watched and reported; this is Phase 2: real recovery + escalation."""
    services = discover_boot_services()
    for s in extra_services:
        if s not in services:
            services.append(s)

    print(f"[agent] Watching {len(services)} services")
    for s in services:
        print(f"          - {s}")

    # Establish initial state (raw systemctl state, so we can tell a crash from a
    # clean stop rather than collapsing everything to active/inactive).
    state = {s: service_state(s) for s in services}
    failure_counts: dict = {}
    last_escalation: dict = {}

    while True:
        time.sleep(3)
        cfg = load_agent_config()
        write_status(len(services), cfg['autoRestartEnabled'])

        for s in services:
            now = service_state(s)
            was = state.get(s, now)
            if now == was:
                continue

            # A crash is systemd's OWN verdict: the unit is 'failed'. A transition
            # to plain 'inactive' is a clean stop and must NOT trigger recovery or
            # a notification -- that false equivalence was the dispatcher-spam bug.
            crashed = now == 'failed' and was != 'failed'

            if crashed and cfg['autoRestartEnabled'] and service_is_enabled(s):
                # Handle it as a restart; emit ONLY the restart event, never also a
                # state_change for the same crash (that produced two notifications).
                success = restart_service(s)
                emit_event({'kind': 'service_restart', 'service': s, 'success': success})
                if success:
                    failure_counts[s] = 0
                    now = 'active'                      # reflect post-restart reality
                else:
                    failure_counts[s] = failure_counts.get(s, 0) + 1
                    threshold = cfg['escalationThreshold']
                    cooldown_s = cfg['escalationCooldownMinutes'] * 60
                    last = last_escalation.get(s, 0)
                    if failure_counts[s] >= threshold and (time.time() - last) >= cooldown_s:
                        emit_event({
                            'kind': 'escalation', 'service': s,
                            'failureCount': failure_counts[s], 'thresholdReached': True,
                        })
                        last_escalation[s] = time.time()
                        failure_counts[s] = 0
            else:
                # Informational only: a clean stop, a recovery, or a failure we're
                # not auto-restarting. One event, so the app's live view stays
                # honest without the notification channel crying wolf.
                emit_event({'kind': 'service_state_change', 'service': s,
                            'from': was, 'to': now})

            state[s] = now

# ──────────────────────────────────────────────────────────────────────────────
# File monitoring
# ──────────────────────────────────────────────────────────────────────────────

def _is_agent_internal(path: str) -> bool:
    """Return True for files the agent writes itself — never emit events for these."""
    return Path(path).name in AGENT_INTERNAL_FILES and Path(path).parent.resolve() == AGENT_DIR.resolve()

if HAVE_WATCHDOG:
    class WatchHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if not event.is_directory and not _is_agent_internal(event.src_path):
                emit_event({'kind': 'file_change', 'change': 'modified', 'path': event.src_path})
        def on_created(self, event):
            if not event.is_directory and not _is_agent_internal(event.src_path):
                emit_event({'kind': 'file_change', 'change': 'created', 'path': event.src_path})
        def on_deleted(self, event):
            if not event.is_directory and not _is_agent_internal(event.src_path):
                emit_event({'kind': 'file_change', 'change': 'deleted', 'path': event.src_path})
        def on_moved(self, event):
            if not event.is_directory and not _is_agent_internal(event.src_path):
                emit_event({'kind': 'file_change', 'change': 'moved',
                            'path': event.src_path, 'to': event.dest_path})

    def monitor_files(paths):
        observer = Observer()
        handler = WatchHandler()
        watched = 0
        for p in paths:
            path = Path(p)
            if path.exists():
                observer.schedule(handler, str(path), recursive=True)
                watched += 1
                print(f"[agent] Watching files: {p}")
            else:
                print(f"[agent] Skipping (not found): {p}")
        observer.start()
        print(f"[agent] File watcher active on {watched} location(s)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

else:
    def monitor_files(paths):
        """Fallback: poll file modification times if watchdog isn't installed."""
        print("[agent] watchdog not installed — using slower polling fallback")
        print("[agent] install with: pip3 install watchdog --break-system-packages")
        seen = {}
        valid = [p for p in paths if Path(p).exists()]
        for p in valid:
            print(f"[agent] Watching files (poll): {p}")
        while True:
            for base in valid:
                for f in Path(base).rglob('*'):
                    if f.is_file() and not _is_agent_internal(str(f)):
                        try:
                            mtime = f.stat().st_mtime
                            key = str(f)
                            if key in seen and seen[key] != mtime:
                                emit_event({'kind': 'file_change', 'change': 'modified', 'path': key})
                            seen[key] = mtime
                        except Exception:
                            pass
            time.sleep(2)

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("\n  PiLink Agent — Sensor + Recovery Layer")
    print("  Watching for service and file changes. Press Ctrl+C to stop.\n")

    watchlist = load_watchlist()

    # Services in a background thread
    t = threading.Thread(
        target=monitor_services,
        args=(watchlist.get('extra_services', []),),
        daemon=True
    )
    t.start()

    # Files in the main thread (blocks)
    monitor_files(watchlist.get('files', []))

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[agent] Stopped.")
