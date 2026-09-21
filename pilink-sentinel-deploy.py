#!/usr/bin/env python3
"""
pilink-sentinel-deploy.py — deploy the Sentinel watcher from the Pi itself.

WHY THIS EXISTS

The "Deploy to Cloudflare" button clones into your GitHub account, and GitHub's
2FA cannot be completed on a phone: you leave Safari for the GitHub app to read
the code, and by the time you come back the page has reset. That makes the
button permanently unusable from the device PiLink actually runs on.

The Pi, however, is a Linux machine with internet access. It can do everything
the button does by calling Cloudflare's API directly — no GitHub, no repository,
no code pasting, and no URL to copy back, because the Pi ends up knowing the
address it just created.

    python3 pilink-sentinel-deploy.py --token <CLOUDFLARE_API_TOKEN>

Create the token at: https://dash.cloudflare.com/profile/api-tokens
  -> Create Token -> Create Custom Token, with exactly two permissions:
       Account | Workers Scripts     | Edit
       Account | Workers KV Storage  | Edit

THIS IS A PROBE, NOT THE FINAL FLOW. It prints PASS/FAIL for every individual
API call so that when something disagrees with expectations we learn WHICH call
and WHAT Cloudflare actually said, rather than "setup failed". Two things in
particular are unverified and this script exists to settle them:

  1. how a brand-new account gets its workers.dev subdomain, and
  2. whether a token limited to the two permissions above is allowed to enable
     the per-script subdomain.

Nothing here is written to disk unless you pass --write. Add --cleanup to delete
the worker and KV namespace again, so a failed run leaves nothing behind to
collide with on the retry — the trap that "a repository with that name already
exists" sets with the button flow.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API = 'https://api.cloudflare.com/client/v4'
CONFIG_DIR = Path.home() / '.pilink'
SENTINEL_CONFIG = CONFIG_DIR / 'sentinel.json'
COMPAT_DATE = '2025-10-08'

# Cloudflare's edge 403s (error 1010) requests from known automation libraries
# BEFORE they reach the Worker. The default `Python-urllib/3.x` UA is on that
# denylist, so /health and /beat probes fail with a 403 that looks like the
# worker is broken when it is fine. Any named UA passes (verified on the Pi:
# curl -> 200, urllib default -> 403, urllib + this -> 200). The api.cloudflare
# .com control plane does NOT do this, but sending the header everywhere is
# harmless and keeps one code path.
UA = 'PiLink-Sentinel/1.0 (+https://github.com/spencermoya-byte/PiLink)'

ok_count = 0
fail_count = 0
facts = {}


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


def die(msg):
    print(f'\n  STOP  {msg}')
    print(f'\n{ok_count} passed, {fail_count} failed\n')
    sys.exit(1)


def api(method, path, token, body=None, multipart=None):
    """One Cloudflare API call. Returns (ok, result, error_string).

    Cloudflare answers with {"success": bool, "errors": [{code, message}], ...}
    on both 2xx and 4xx, so the error path has to read the body either way —
    the HTTP status alone never says which permission you forgot.
    """
    url = path if path.startswith('http') else API + path
    headers = {'authorization': f'Bearer {token}', 'user-agent': UA}
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
            return False, None, f'HTTP {e.code}: {raw[:300]}'
    except Exception as e:
        return False, None, f'{type(e).__name__}: {e}'

    if payload.get('success'):
        return True, payload.get('result'), ''

    errs = payload.get('errors') or [{'message': 'unknown error'}]
    return False, None, '; '.join(
        f"[{e.get('code', '?')}] {e.get('message', '')}" for e in errs)


def build_multipart(worker_src, metadata):
    """Cloudflare wants the script as multipart: a JSON `metadata` part naming
    the entrypoint and declaring bindings, plus the module source itself."""
    boundary = '----pilink' + secrets.token_hex(16)
    out = []

    def part(headers, payload):
        out.append(f'--{boundary}\r\n'.encode())
        out.append(headers.encode())
        out.append(b'\r\n')
        out.append(payload if isinstance(payload, bytes) else payload.encode())
        out.append(b'\r\n')

    part('content-disposition: form-data; name="metadata"\r\n'
         'content-type: application/json\r\n',
         json.dumps(metadata))
    part('content-disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
         'content-type: application/javascript+module\r\n',
         worker_src)
    out.append(f'--{boundary}--\r\n'.encode())
    return boundary, b''.join(out)


def find_worker_source(explicit):
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.exists() else None
    here = Path(__file__).resolve().parent
    for candidate in (here / 'worker.js',
                      here / 'sentinel_worker.js',
                      here.parent / 'sentinel' / 'worker.js',
                      CONFIG_DIR / 'sentinel_worker.js'):
        if candidate.exists():
            return candidate
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--token', help='Cloudflare API token (or set CF_API_TOKEN)')
    ap.add_argument('--worker', help='path to worker.js')
    ap.add_argument('--name', default='pilink-sentinel', help='worker name')
    ap.add_argument('--write', action='store_true',
                    help='write ~/.pilink/sentinel.json on success')
    ap.add_argument('--cleanup', action='store_true',
                    help='delete the worker and KV namespace, then exit')
    args = ap.parse_args()

    token = args.token or os.environ.get('CF_API_TOKEN')
    if not token:
        try:
            token = input('Cloudflare API token: ').strip()
        except (EOFError, KeyboardInterrupt):
            token = ''
    if not token:
        die('No token given. Create one at '
            'https://dash.cloudflare.com/profile/api-tokens')

    # ---------------------------------------------------------------- 1
    print('\n=== 1. Token ===')
    good, result, err = api('GET', '/user/tokens/verify', token)
    if not check('token is valid', good, err):
        die('Cloudflare rejected the token itself, so nothing below can work.')
    facts['token_status'] = (result or {}).get('status')
    check(f"token status is active (got {facts['token_status']})",
          facts['token_status'] == 'active')

    # ---------------------------------------------------------------- 2
    print('\n=== 2. Account ===')
    good, result, err = api('GET', '/accounts', token)
    if not check('can list accounts', good, err):
        die('Without an account id no other call can be addressed.\n'
            'If this failed on permissions, the token needs ACCOUNT-scoped\n'
            '(not zone-scoped) Workers permissions.')
    if not result:
        die('Token is valid but sees no accounts.')
    account = result[0]
    facts['account_id'] = account['id']
    facts['account_name'] = account.get('name', '?')
    check(f"found account: {facts['account_name']}", True, f"id={facts['account_id']}")
    if len(result) > 1:
        print(f'  NOTE  {len(result)} accounts visible; using the first.')
        for a in result:
            print(f"        {a['id']}  {a.get('name')}")

    acct = f"/accounts/{facts['account_id']}"

    # ---------------------------------------------------------------- cleanup
    if args.cleanup:
        print('\n=== Cleanup ===')
        good, _, err = api('DELETE', f'{acct}/workers/scripts/{args.name}', token)
        check(f'deleted worker {args.name}', good, err)
        good, result, err = api('GET', f'{acct}/storage/kv/namespaces?per_page=100', token)
        if good:
            for ns in result or []:
                if ns.get('title') in (args.name, f'{args.name}-SENTINEL'):
                    g2, _, e2 = api('DELETE',
                                    f"{acct}/storage/kv/namespaces/{ns['id']}", token)
                    check(f"deleted KV namespace {ns['title']}", g2, e2)
        print(f'\n{ok_count} passed, {fail_count} failed\n')
        return

    # ---------------------------------------------------------------- 3
    # THE FIRST UNVERIFIED THING. A fresh account may have no workers.dev
    # subdomain at all, in which case one has to be claimed before any worker
    # can have a public address.
    print('\n=== 3. workers.dev subdomain ===')
    good, result, err = api('GET', f'{acct}/workers/subdomain', token)
    subdomain = (result or {}).get('subdomain') if good else None
    if good and subdomain:
        facts['subdomain'] = subdomain
        check(f'account already has a subdomain: {subdomain}.workers.dev', True)
    else:
        check('account has an existing workers.dev subdomain', False,
              err or 'none set')
        guess = f'pilink-{secrets.token_hex(3)}'
        print(f'  TRY   claiming "{guess}.workers.dev"')
        good, result, err = api('PUT', f'{acct}/workers/subdomain', token,
                                body={'subdomain': guess})
        if check(f'claimed subdomain {guess}', good, err):
            facts['subdomain'] = guess
        else:
            die('No workers.dev subdomain, and claiming one failed.\n'
                'Claim one by hand at dash.cloudflare.com -> Workers & Pages\n'
                '(it asks on first visit), then re-run this script.')

    # ---------------------------------------------------------------- 4
    print('\n=== 4. KV namespace ===')
    good, result, err = api('GET', f'{acct}/storage/kv/namespaces?per_page=100', token)
    existing = None
    if good:
        for ns in result or []:
            if ns.get('title') == args.name:
                existing = ns
                break
    if existing:
        facts['kv_id'] = existing['id']
        check(f'reusing existing namespace "{args.name}"', True,
              f"id={facts['kv_id']}")
    else:
        good, result, err = api('POST', f'{acct}/storage/kv/namespaces', token,
                                body={'title': args.name})
        if not check(f'created namespace "{args.name}"', good, err):
            die('Without KV the watcher has nowhere to hold your deadline.\n'
                'Check the token has: Account | Workers KV Storage | Edit')
        facts['kv_id'] = result['id']
        print(f"        id={facts['kv_id']}")

    # ---------------------------------------------------------------- 5
    print('\n=== 5. Worker script ===')
    src_path = find_worker_source(args.worker)
    if not check('found worker.js', src_path is not None,
                 '' if src_path else
                 'Put worker.js next to this script, or pass --worker <path>'):
        die('Nothing to deploy.')
    worker_src = src_path.read_text(encoding='utf-8')
    print(f'        {src_path}  ({len(worker_src)} bytes)')

    # Generated here, on the machine that will use it. It cannot be mistyped,
    # cannot lose its quotes in a heredoc, and never travels anywhere except
    # into the binding below.
    sentinel_secret = secrets.token_hex(32)

    # KV binding goes in the script upload. The SECRET does NOT: on a re-upload
    # Cloudflare preserves the previous version's secret and ignores a new
    # secret_text here, so the worker would keep an OLD secret while the Pi signs
    # with the new one -> every heartbeat 401s. We set the secret authoritatively
    # via the dedicated endpoint below instead, which overwrites unconditionally.
    kv_binding = {'type': 'kv_namespace', 'name': 'SENTINEL',
                  'namespace_id': facts['kv_id']}
    metadata = {
        'main_module': 'worker.js',
        'compatibility_date': COMPAT_DATE,
        'bindings': [kv_binding],
    }

    # The deadline lives in a Durable Object alarm, not a KV write per beat.
    # Free-plan Durable Objects are SQLite-backed ONLY, so the migration must say
    # new_sqlite_classes -- new_classes is refused with error 10097 and takes the
    # whole upload down with it. Migration tags are names, not versions:
    # re-sending an applied tag is a no-op, so redeploying over a worker that
    # already has the class is fine, and redeploying over a KV-era one applies it
    # for the first time.
    #
    # This must match deploy_sentinel_worker() in pilink-server.py exactly. Two
    # deploy paths that produce DIFFERENT workers is the failure this whole
    # rewrite came out of: the running worker had drifted from the source, and
    # nothing noticed for months.
    do_metadata = dict(metadata)
    do_metadata['bindings'] = [kv_binding,
                               {'type': 'durable_object_namespace',
                                'name': 'SWITCH', 'class_name': 'Switch'}]
    do_metadata['migrations'] = {'new_tag': 'v1', 'new_sqlite_classes': ['Switch']}

    good, result, err = api('PUT', f'{acct}/workers/scripts/{args.name}', token,
                            multipart=build_multipart(worker_src, do_metadata))
    if good:
        check('uploaded worker with Durable Object alarm + KV binding', True, '')
    else:
        # Not fatal. The same worker runs on KV with a lease instead, which is
        # still far cheaper than a write per beat. A watcher in the slower mode
        # beats no watcher, and /health reports which one is actually live.
        print(f'        durable objects unavailable ({err}) — falling back to KV')
        good, result, err = api('PUT', f'{acct}/workers/scripts/{args.name}', token,
                                multipart=build_multipart(worker_src, metadata))
        if not check('uploaded worker with KV binding', good, err):
            die('The upload itself failed — see the error above.')

    # Set the shared secret explicitly. This is the fix for the 401 the multipart
    # secret_text produced on re-deploys: this endpoint overwrites every time, so
    # the worker's SENTINEL_SECRET always equals the value the Pi signs with.
    good, result, err = api('PUT', f'{acct}/workers/scripts/{args.name}/secrets',
                            token, body={'name': 'SENTINEL_SECRET',
                                         'text': sentinel_secret,
                                         'type': 'secret_text'})
    if not check('set SENTINEL_SECRET on the worker', good, err):
        die('Could not set the shared secret — heartbeats would 401.\n'
            'Check the token has: Account | Workers Scripts | Edit')

    # ---------------------------------------------------------------- 6
    print('\n=== 6. Cron trigger ===')
    good, result, err = api('PUT', f'{acct}/workers/scripts/{args.name}/schedules',
                            token, body=[{'cron': '* * * * *'}])
    check('set cron to every minute', good, err)
    if not good:
        print('        WITHOUT THIS NOTHING EVER FIRES. The worker will accept')
        print('        heartbeats and store them and never look at them again.')

    # ---------------------------------------------------------------- 7
    # THE SECOND UNVERIFIED THING: can a token holding only the two Workers
    # permissions switch on the public address?
    print('\n=== 7. Public address ===')
    good, result, err = api('POST', f'{acct}/workers/scripts/{args.name}/subdomain',
                            token, body={'enabled': True, 'previews_enabled': False})
    if not check('enabled workers.dev route for this worker', good, err):
        print('        Retrying without previews_enabled...')
        good, result, err = api('POST',
                                f'{acct}/workers/scripts/{args.name}/subdomain',
                                token, body={'enabled': True})
        check('enabled workers.dev route (fallback form)', good, err)

    facts['url'] = f"https://{args.name}.{facts['subdomain']}.workers.dev"
    print(f"        {facts['url']}")

    # ---------------------------------------------------------------- 8
    print('\n=== 8. Does it actually answer? ===')
    health = None
    for attempt in range(1, 13):          # up to ~60s; propagation is not instant
        try:
            hreq = urllib.request.Request(facts['url'] + '/health',
                                          headers={'user-agent': UA})
            with urllib.request.urlopen(hreq, timeout=10) as r:
                health = json.loads(r.read().decode())
            break
        except Exception as e:
            if attempt == 12:
                check('worker responds on /health', False, f'{type(e).__name__}: {e}')
            else:
                time.sleep(5)
    if health:
        check('worker responds on /health', True, json.dumps(health))
        check('KV binding resolves inside the worker', health.get('kv') is True,
              '' if health.get('kv') else
              'The worker is live but has no storage — it cannot hold a deadline.')

        # Ask the worker what it actually is, rather than trusting the upload we
        # sent. This is the check that would have caught the drift: the deployed
        # worker reported a build nobody in the repo had, and no step compared.
        import hashlib
        import re as _re
        src_txt = worker_src
        neutral = _re.sub(r"^const BUILD = '[^']*';$", "const BUILD = '';",
                          src_txt, flags=_re.M)
        want_build = hashlib.sha256(neutral.encode()).hexdigest()[:12]
        got_build = health.get('build', '')
        check('the live worker was built from this worker.js',
              got_build == want_build,
              f'live build {got_build or "(none reported)"}, this source is {want_build}'
              ' — something else is deploying this worker')
        check('the deadline is held by a Durable Object alarm, not a KV write per beat',
              health.get('mode') == 'alarm',
              f'running in {health.get("mode") or "an unknown"} mode: alerts still '
              'work but can be up to 20 minutes late, and cost ~144 KV writes/day')

    # ---------------------------------------------------------------- 9
    print('\n=== 9. A real heartbeat ===')
    body = {
        'id': 'probe',
        'sentAt': int(time.time()),
        'deadline': int(time.time()) + 3600,
        'topic': 'com.spencer.pilink',
        'deviceTokens': [],
        'payload': {'aps': {'alert': {'title': 'probe', 'body': 'probe'}}},
        'label': 'deploy-probe',
    }
    raw = json.dumps(body)
    sig = hmac.new(sentinel_secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        facts['url'] + '/beat', data=raw.encode(), method='POST',
        headers={'content-type': 'application/json', 'x-sentinel-hmac': sig,
                 'user-agent': UA})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            check(f'heartbeat accepted (HTTP {r.status})', r.status == 200,
                  r.read().decode()[:200])
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors='replace')[:200]
        check('heartbeat accepted', False, f'HTTP {e.code}: {detail}')
        if e.code == 401:
            print('        The secret binding did not take effect.')
        elif e.code >= 500:
            print('        Almost certainly the missing KV binding.')
    except Exception as e:
        check('heartbeat accepted', False, f'{type(e).__name__}: {e}')

    # Clean up the probe key so it cannot linger and fire at a stranger.
    body = {'id': 'probe', 'sentAt': int(time.time()), 'disarm': True}
    raw = json.dumps(body)
    sig = hmac.new(sentinel_secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
    try:
        urllib.request.urlopen(urllib.request.Request(
            facts['url'] + '/beat', data=raw.encode(), method='POST',
            headers={'content-type': 'application/json',
                     'x-sentinel-hmac': sig, 'user-agent': UA}), timeout=20)
        print('  PASS  probe heartbeat disarmed')
    except Exception as e:
        print(f'  NOTE  could not disarm probe key: {e}')

    # ---------------------------------------------------------------- 10
    print('\n=== 10. Pi configuration ===')
    if args.write and fail_count == 0:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SENTINEL_CONFIG.write_text(json.dumps({
            'url': facts['url'] + '/beat',
            'secret': sentinel_secret,
            'id': os.uname().nodename,
        }, indent=2) + '\n', encoding='utf-8')
        SENTINEL_CONFIG.chmod(0o600)
        check(f'wrote {SENTINEL_CONFIG}', True)
        print('        Restart the server to pick it up:')
        print('          sudo systemctl restart pilink-server')
    elif args.write:
        # Refuse to write a config that points the Pi at a worker it just
        # failed to reach -- that would arm a switch guaranteed to fire.
        print(f'  SKIP  {fail_count} check(s) failed above — NOT writing '
              f'{SENTINEL_CONFIG.name}.')
        print('        Fix the failure and re-run; nothing was changed on the Pi.')
    else:
        print('  SKIP  not written (re-run with --write once the above is clean)')

    # ---------------------------------------------------------------- summary
    print('\n' + '=' * 62)
    print(f'{ok_count} passed, {fail_count} failed')
    print('=' * 62)
    print('\nWhat the app will need to reproduce this:')
    for k in ('account_id', 'subdomain', 'kv_id', 'url'):
        if k in facts:
            print(f'  {k:12} {facts[k]}')
    if not args.write:
        print(f'\n  secret       {sentinel_secret}')
        print('  (regenerated on every run; --write stores it for you instead)')
    print('\nThe cron trigger can take up to 15 minutes to start firing on a')
    print('brand-new worker (Cloudflare propagation). The heartbeat above proves')
    print('the worker STORES correctly; the real proof it FIRES is the 60-second')
    print('armed test from the app once the v0.3.4 server is on the Pi.\n')


if __name__ == '__main__':
    main()
