#!/usr/bin/env python3
"""
pilink-push-test.py — diagnose the push notification chain, one link at a time.

Run on the Pi:      python3 pilink-push-test.py
Send a real push:   python3 pilink-push-test.py --send

The point of this script is that "no notification arrived" has about eight
possible causes and they need completely different fixes. Each check below
prints PASS/FAIL for exactly one link, so you find out which one.

USEFUL BEFORE THE REBUILD: with no registered devices you can still prove your
APNs credentials are correct, by sending to a deliberately bogus device token.
Apple's response tells you which half is wrong:

    BadDeviceToken       -> your key/team/topic are RIGHT, the token is fake (expected here)
    InvalidProviderToken -> your .p8, Key ID, or Team ID is wrong
    TopicDisallowed      -> bundleId in apns.json doesn't match the key's app

That distinction is the whole reason to test before burning a Codemagic build.
"""

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

CONFIG_DIR       = Path.home() / '.pilink'
APNS_KEY_FILE    = CONFIG_DIR / 'apns_key.p8'
APNS_CONFIG_FILE = CONFIG_DIR / 'apns.json'
PUSH_TOKENS_FILE = CONFIG_DIR / 'push_tokens.json'

FAKE_TOKEN = 'a' * 64   # well-formed but not a real device

ok_count = 0
fail_count = 0


def check(label, passed, detail=''):
    global ok_count, fail_count
    if passed:
        ok_count += 1
        print(f'  PASS  {label}')
    else:
        fail_count += 1
        print(f'  FAIL  {label}')
    if detail:
        for line in str(detail).splitlines():
            print(f'        {line}')
    return passed


print('\n=== 1. Credentials on disk ===')
have_key = check('apns_key.p8 exists', APNS_KEY_FILE.exists(),
                 '' if APNS_KEY_FILE.exists() else
                 'Copy it from the Apple Developer portal:\n'
                 '  scp AuthKey_XXXXXXXXXX.p8 <pi>:~/.pilink/apns_key.p8')
if have_key:
    mode = oct(APNS_KEY_FILE.stat().st_mode)[-3:]
    check(f'apns_key.p8 permissions are 600 (found {mode})', mode == '600',
          '' if mode == '600' else 'Fix with: chmod 600 ~/.pilink/apns_key.p8')

cfg = None
if check('apns.json exists', APNS_CONFIG_FILE.exists(),
         '' if APNS_CONFIG_FILE.exists() else
         'Create it with your Key ID, Team ID and bundle ID.'):
    try:
        cfg = json.loads(APNS_CONFIG_FILE.read_text())
        missing = [k for k in ('keyId', 'teamId', 'bundleId') if not cfg.get(k)]
        check('apns.json has keyId, teamId, bundleId', not missing,
              f'Missing: {", ".join(missing)}' if missing else
              f'keyId={cfg["keyId"]}  teamId={cfg["teamId"]}  bundleId={cfg["bundleId"]}')
    except Exception as e:
        check('apns.json is valid JSON', False, e)


def server_python():
    """Which interpreter does the systemd service actually run?

    This matters more than it sounds. `pip3 install` as your user lands in
    ~/.local/lib/..., but if the service runs from a venv it cannot see that at
    all — so the dependency looks installed from the shell and is missing from
    the server's point of view. Checking only this script's own environment is
    how you get a green diagnostic and a server that still can't send.
    """
    try:
        out = subprocess.run(['systemctl', 'cat', 'pilink-server'],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            if line.strip().startswith('ExecStart='):
                cmd = line.split('=', 1)[1].strip()
                first = cmd.split()[0]
                if 'python' in first:
                    return first
                # e.g. ExecStart=/usr/bin/env python3 /path/server.py
                for part in cmd.split():
                    if 'python' in part:
                        return part
    except Exception:
        pass
    return None


print('\n=== 2. Python dependencies ===')
srv_py = server_python()
if srv_py and os.path.realpath(srv_py) != os.path.realpath(sys.executable):
    print(f'  NOTE  this script runs {sys.executable}')
    print(f'        the SERVER runs {srv_py}')
    print('        checking BOTH — a package installed for one may be invisible to the other')

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    check('cryptography (JWT signing)', True)
    have_crypto = True
except ImportError as e:
    check('cryptography (JWT signing)', False, f'{e}\nInstall: pip3 install cryptography --break-system-packages')
    have_crypto = False

if srv_py:
    for mod in ('httpx', 'h2', 'cryptography'):
        r = subprocess.run([srv_py, '-c', f'import {mod}'], capture_output=True, text=True)
        check(f'{mod} importable BY THE SERVER ({os.path.basename(os.path.dirname(os.path.dirname(srv_py)))})',
              r.returncode == 0,
              '' if r.returncode == 0 else
              f'The server cannot import {mod}. Install it into ITS environment:\n'
              f'  {os.path.join(os.path.dirname(srv_py), "pip")} install "httpx[http2]"\n'
              f'then: sudo systemctl restart pilink-server')

try:
    import httpx
    check('httpx installed', True)
    try:
        import h2  # noqa: F401
        check('h2 (HTTP/2 support — Apple requires it)', True)
        have_http = True
    except ImportError:
        check('h2 (HTTP/2 support — Apple requires it)', False,
              'Install: pip3 install "httpx[http2]" --break-system-packages')
        have_http = False
except ImportError:
    check('httpx installed', False, 'Install: pip3 install "httpx[http2]" --break-system-packages')
    have_http = False


print('\n=== 3. JWT signing ===')
jwt = None
if have_crypto and have_key and cfg:
    try:
        def b64(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b'=')

        key = serialization.load_pem_private_key(APNS_KEY_FILE.read_bytes(), password=None)
        check('.p8 parses as a private key', True, f'type={type(key).__name__}')
        is_ec = isinstance(key, ec.EllipticCurvePrivateKey)
        check('key is an EC key (APNs keys are P-256)', is_ec,
              '' if is_ec else 'This does not look like an APNs auth key.')

        header  = b64(json.dumps({'alg': 'ES256', 'kid': cfg['keyId']}, separators=(',', ':')).encode())
        payload = b64(json.dumps({'iss': cfg['teamId'], 'iat': int(time.time())}, separators=(',', ':')).encode())
        signing_input = header + b'.' + payload
        der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, sv = asym_utils.decode_dss_signature(der)
        raw_sig = r.to_bytes(32, 'big') + sv.to_bytes(32, 'big')
        jwt = (signing_input + b'.' + b64(raw_sig)).decode()

        # The classic failure: sending DER instead of raw r||s. Apple rejects it
        # with a 403 that says nothing useful about why.
        check('signature is raw r||s, 64 bytes (not DER)', len(raw_sig) == 64,
              f'got {len(raw_sig)} bytes; DER would be ~{len(der)}')
        check('JWT has three parts', jwt.count('.') == 2)
    except Exception as e:
        check('JWT built', False, e)
else:
    print('  SKIP  (needs the credentials and cryptography above)')


print('\n=== 4. Registered devices ===')
tokens = {}
if PUSH_TOKENS_FILE.exists():
    try:
        tokens = json.loads(PUSH_TOKENS_FILE.read_text())
    except Exception as e:
        check('push_tokens.json is valid JSON', False, e)
if tokens:
    check(f'{len(tokens)} device(s) registered', True)
    for t, meta in tokens.items():
        print(f'        {t[:16]}…  categories={meta.get("categories")}  host={meta.get("host", "unknown")}')
else:
    print('  INFO  no devices registered yet')
    print('        Expected until the app is rebuilt WITH the aps-environment')
    print('        entitlement — iOS refuses to issue a token without it, so')
    print('        registration is a silent no-op by design.')
    print('        Credentials can still be verified below.')


print('\n=== 5. Talking to Apple ===')
if not (jwt and have_http and cfg):
    print('  SKIP  (needs everything above to pass)')
else:
    send_real = '--send' in sys.argv
    targets = list(tokens.keys()) if (send_real and tokens) else [FAKE_TOKEN]
    if targets == [FAKE_TOKEN]:
        print('  Using a deliberately fake device token.')
        print('  "BadDeviceToken" here is the GOOD result — it proves Apple accepted')
        print('  your key, team and topic, and only rejected the made-up token.\n')
    else:
        print(f'  Sending a real test notification to {len(targets)} device(s).\n')

    payload = {
        'aps': {'alert': {'title': 'PiLink test', 'body': 'Push notifications are working.'},
                'sound': 'default'},
        'pilink': {'category': 'presence', 'test': True},
    }
    try:
        with httpx.Client(http2=True) as client:
            for token in targets:
                for host in ('api.push.apple.com', 'api.sandbox.push.apple.com'):
                    try:
                        r = client.post(
                            f'https://{host}/3/device/{token}',
                            headers={'authorization': f'bearer {jwt}',
                                     'apns-topic': cfg['bundleId'],
                                     'apns-push-type': 'alert',
                                     'apns-priority': '10'},
                            json=payload, timeout=10)
                    except Exception as e:
                        check(f'{host} reachable', False, e)
                        continue

                    reason = ''
                    try:
                        reason = r.json().get('reason', '')
                    except Exception:
                        pass
                    env = 'production' if 'sandbox' not in host else 'sandbox'

                    if r.status_code == 200:
                        check(f'delivered to APNs ({env})', True,
                              'Check your phone.' if token != FAKE_TOKEN else '')
                        break
                    if reason == 'BadDeviceToken':
                        if token == FAKE_TOKEN:
                            check(f'credentials accepted by APNs ({env})', True,
                                  'BadDeviceToken as expected — key, team and topic are correct.')
                        else:
                            check(f'device token valid ({env})', False,
                                  'Token rejected. It may be stale — reopen the app to re-register.')
                        continue
                    if reason == 'InvalidProviderToken':
                        check('provider token accepted', False,
                              'Your .p8, Key ID or Team ID is wrong, or the key lacks APNs.\n'
                              'Check keyId matches the AuthKey_<KEYID>.p8 filename.')
                        break
                    if reason == 'TopicDisallowed':
                        check('bundle ID matches the key', False,
                              f'bundleId "{cfg["bundleId"]}" is not permitted by this key.')
                        break
                    if reason == 'ExpiredProviderToken':
                        check('provider token fresh', False, 'Clock skew? Check `timedatectl` on the Pi.')
                        break
                    check(f'{host} accepted the request', False, f'HTTP {r.status_code} {reason}')
                    break
    except Exception as e:
        check('APNs request', False, e)


print(f'\n=== {ok_count} passed, {fail_count} failed ===')
if fail_count == 0 and not tokens:
    print('Credentials are good. Rebuild the app with the aps-environment')
    print('entitlement, open it once, then re-run with --send.')
elif fail_count == 0:
    print('Whole chain is healthy. Run with --send to push to your phone.')
sys.exit(1 if fail_count else 0)
