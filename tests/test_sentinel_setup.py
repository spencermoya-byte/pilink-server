"""Tests for one-tap Sentinel setup: preflight, token diagnosis, deploy, proof.

Same technique as test_server_logic.py — the functions are lifted out of the REAL
server source with `ast` and exec'd in a seeded namespace, so these test the
shipping code rather than a re-implementation, with no Pi and no Cloudflare.

WHAT THESE ARE ACTUALLY FOR

Setup is a chain of about ten steps against someone else's API, and every failure
mode is invisible from the outside: a token that verifies but can't write KV, an
account picked by index when there were two, a subdomain name that collided, an
upload that succeeded while its migration didn't, a worker that answers perfectly
and is not the one we uploaded. Each of those used to surface as one generic
sentence, or as nothing at all.

So these tests assert on WHAT THE USER IS TOLD, not just on return codes. A
deploy that fails is fine; a deploy that fails without naming the fix is the bug.
"""
import ast
import json
import time
import types
from pathlib import Path

import pytest

SERVER = Path(__file__).resolve().parent.parent / "pilink-server.py"
_TREE = ast.parse(SERVER.read_text())


def load(names, **globals_):
    """Extract named top-level functions/assignments and exec them together."""
    wanted = [n for n in _TREE.body
              if (isinstance(n, ast.FunctionDef) and n.name in names)
              or (isinstance(n, ast.Assign)
                  and any(getattr(t, "id", None) in names for t in n.targets))]
    found = {n.name for n in wanted if isinstance(n, ast.FunctionDef)}
    found |= {t.id for n in wanted if isinstance(n, ast.Assign)
              for t in n.targets if hasattr(t, "id")}
    missing = names - found
    assert not missing, f"not found in server source: {missing}"
    ns = dict(globals_)
    exec(compile(ast.Module(body=wanted, type_ignores=[]), str(SERVER), "exec"), ns)
    return ns


# ── preflight ────────────────────────────────────────────────────────────────

def _preflight(apns=True, key=True, tokens=True):
    ns = load(
        {"sentinel_preflight"},
        _apns_config=lambda: {"bundleId": "com.spencer.pilink"} if apns else None,
        APNS_KEY_FILE=types.SimpleNamespace(exists=lambda: key),
        load_push_tokens=lambda: {"tok": 1} if tokens else {},
    )
    return ns["sentinel_preflight"]()


def test_preflight_clean_when_everything_is_ready():
    assert _preflight()["ok"] is True


@pytest.mark.parametrize("kwargs,code", [
    ({"apns": False}, "apns_config"),
    ({"key": False}, "apns_key"),
    ({"tokens": False}, "no_devices"),
])
def test_preflight_names_each_blocker(kwargs, code):
    r = _preflight(**kwargs)
    assert r["ok"] is False
    assert code in [b["code"] for b in r["blockers"]]


def test_every_blocker_tells_the_user_what_to_do():
    """A blocker without a fix is just a complaint. The whole point of preflight
    is that the user finds out BEFORE going to Cloudflare, and knows the action."""
    for kwargs in ({"apns": False}, {"key": False}, {"tokens": False}):
        for b in _preflight(**kwargs)["blockers"]:
            assert b["title"] and b["detail"] and b["fix"]
            assert len(b["fix"]) > 10


# ── token diagnosis ──────────────────────────────────────────────────────────

def _report(responses, token="t" * 40, account_id=None):
    """responses: {path_fragment: (ok, result, err)}; first matching fragment wins."""
    calls = []

    def fake_api(method, path, tok, body=None, multipart=None):
        calls.append((method, path))
        # Exact match first: the permission probes live UNDER /accounts/<id>/...,
        # so plain substring matching would have "/accounts" swallow them and the
        # probes would silently never run — a test that passes by not testing.
        if path in responses:
            return responses[path]
        for frag, resp in responses.items():
            if frag != "/accounts" and frag in path:
                return resp
        return True, [], ""

    ns = load({"cf_token_report", "_CF_PERMISSION_PROBES"}, _cf_api=fake_api)
    return ns["cf_token_report"](token, account_id), calls


ONE_ACCOUNT = {"/accounts": (True, [{"id": "acc1", "name": "Spencer's Account"}], "")}
DENIED = (False, None, "[9109] Unauthorized to access requested resource")


def test_a_working_token_reports_ok():
    rep, _ = _report({**ONE_ACCOUNT, "verify": (True, {}, "")})
    assert rep["ok"] is True and rep["accountId"] == "acc1"


def test_a_short_token_is_rejected_without_calling_cloudflare():
    rep, calls = _report({}, token="abc")
    assert rep["ok"] is False and calls == []
    assert "whole thing" in rep["error"]


def test_an_unrecognised_token_says_so_plainly():
    rep, _ = _report({"verify": (False, None, "[1000] Invalid API Token")})
    assert rep["ok"] is False
    assert "didn't recognise" in rep["error"] and "copied all of it" in rep["error"]


def test_an_expired_token_is_distinguished_from_a_wrong_one():
    rep, _ = _report({"verify": (False, None, "[1000] This API Token has expired")})
    assert "expired" in rep["error"].lower()


def test_zone_scoped_token_is_told_it_needed_account_scope():
    """The commonest mistake: the token exists and verifies, but every permission
    was added under Zone, so it can see no account at all."""
    rep, _ = _report({"verify": (True, {}, ""), "/accounts": (True, [], "")})
    assert rep["ok"] is False
    assert "Account, not Zone" in rep["error"]


def test_missing_kv_permission_is_named_exactly():
    rep, _ = _report({**ONE_ACCOUNT, "verify": (True, {}, ""),
                      "/storage/kv/namespaces": DENIED})
    assert rep["ok"] is False
    assert rep["missing"] == ["Account · Workers KV Storage · Edit"]
    assert "Workers KV Storage" in rep["error"]


def test_missing_scripts_permission_is_named_exactly():
    rep, _ = _report({**ONE_ACCOUNT, "verify": (True, {}, ""),
                      "/workers/scripts": DENIED})
    assert rep["missing"] == ["Account · Workers Scripts · Edit"]


def test_both_missing_permissions_are_listed_together():
    rep, _ = _report({**ONE_ACCOUNT, "verify": (True, {}, ""),
                      "/workers/scripts": DENIED, "/storage/kv/namespaces": DENIED})
    assert len(rep["missing"]) == 2
    assert " and " in rep["error"]


def test_a_transient_error_is_not_reported_as_a_missing_permission():
    """A 500 or a dropped connection must never tell the user to go and add a
    permission they already have — they would add it, fail again, and be stuck."""
    rep, _ = _report({**ONE_ACCOUNT, "verify": (True, {}, ""),
                      "/storage/kv/namespaces": (False, None, "HTTP 502: bad gateway")})
    assert rep["missing"] == []


def test_two_accounts_asks_instead_of_guessing():
    """Deploying into the wrong account is invisible: everything succeeds and the
    watcher is simply somewhere the user never looks."""
    rep, _ = _report({"verify": (True, {}, ""),
                      "/accounts": (True, [{"id": "a", "name": "Personal"},
                                           {"id": "b", "name": "Work"}], "")})
    assert rep["ok"] is False and rep["needAccount"] is True
    assert len(rep["accounts"]) == 2
    assert rep["error"] == ""          # a question, not a failure


def test_a_chosen_account_is_honoured():
    rep, _ = _report({"verify": (True, {}, ""),
                      "/accounts": (True, [{"id": "a"}, {"id": "b"}], "")},
                     account_id="b")
    assert rep["ok"] is True and rep["accountId"] == "b"


def test_an_account_the_token_cannot_see_is_refused():
    rep, _ = _report({"verify": (True, {}, ""), "/accounts": (True, [{"id": "a"}], "")},
                     account_id="zzz")
    assert rep["ok"] is False and "not one this token can see" in rep["error"]


# ── deploy ───────────────────────────────────────────────────────────────────

class FakeCloudflare:
    """Enough of the Workers API to exercise the deploy end to end."""

    def __init__(self, subdomain="spencer", subdomain_collisions=0,
                 durable_objects=True, live_build=None, mode=None):
        self.subdomain = subdomain
        self.collisions = subdomain_collisions
        self.durable_objects = durable_objects
        self.live_build = live_build
        self.forced_mode = mode
        self.uploads = []          # every upload ATTEMPTED, in order
        self.applied = None        # the one that actually took
        self.schedules = []
        self.secrets = []

    def api(self, method, path, token, body=None, multipart=None):
        if "/user/tokens/verify" in path:
            return True, {}, ""
        if path == "/accounts":
            return True, [{"id": "acc1", "name": "Spencer"}], ""
        if "/workers/subdomain" in path:
            if method == "GET":
                return (True, {"subdomain": self.subdomain}, "") if self.subdomain \
                    else (True, {}, "")
            if self.collisions > 0:
                self.collisions -= 1
                return False, None, "[10035] subdomain is already taken"
            self.subdomain = body["subdomain"]
            return True, {}, ""
        if "/storage/kv/namespaces" in path:
            if method == "GET":
                return True, [], ""
            return True, {"id": "kv123"}, ""
        if "/workers/scripts/" in path and path.endswith("/secrets"):
            self.secrets.append(body["name"])
            return True, {}, ""
        if "/workers/scripts/" in path and path.endswith("/schedules"):
            self.schedules.append(body)
            return True, {}, ""
        if "/workers/scripts/" in path and path.endswith("/subdomain"):
            return True, {}, ""
        if "/workers/scripts/" in path and method == "PUT":
            meta = json.loads(multipart[0])
            self.uploads.append(meta)
            if meta.get("migrations") and not self.durable_objects:
                return False, None, ("[10097] In order to use Durable Objects with a free "
                                     "plan, you must create a namespace using a "
                                     "`new_sqlite_classes` migration.")
            self.applied = meta
            return True, {}, ""
        return True, {}, ""

    def health(self):
        # The mode a real worker reports comes from the bindings it actually has,
        # which is the upload that SUCCEEDED — not the one that was tried first.
        has_do = bool((self.applied or {}).get("migrations"))
        return {"ok": True, "kv": True, "build": self.live_build or "BUILD",
                "mode": self.forced_mode or ("alarm" if has_do else "kv-lease")}


def _deploy(cf, tmp_path, probe_ok=True):
    """Run the real deploy_sentinel_worker against a fake Cloudflare."""
    cfg_file = tmp_path / "sentinel.json"
    emitted = []

    class Resp:
        def __init__(self, payload):
            self.payload = payload
            self.status = 200

        def read(self):
            return json.dumps(self.payload).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(req, timeout=None):
        return Resp(cf.health())

    # multipart -> (metadata_json, body); the fake reads element 0.
    def multipart(src, metadata):
        return (json.dumps(metadata), b"")

    ns = load(
        {"deploy_sentinel_worker"},
        _cf_api=cf.api,
        _cf_multipart=multipart,
        _sentinel_worker_source=lambda: "// worker",
        _sentinel_build=lambda: "BUILD",
        cf_token_report=load({"cf_token_report", "_CF_PERMISSION_PROBES"},
                             _cf_api=cf.api)["cf_token_report"],
        _sentinel_probe_beat=lambda url, secret: probe_ok,
        SENTINEL_CONFIG_FILE=cfg_file,
        SENTINEL_UA="test",
        CONFIG={"name": "streaming-pi"},
        os=__import__("os"), json=json, time=time, secrets=__import__("secrets"),
        urllib=types.SimpleNamespace(
            request=types.SimpleNamespace(Request=lambda *a, **k: None,
                                          urlopen=urlopen)),
        print=lambda *a, **k: None,
    )
    ok, info = ns["deploy_sentinel_worker"]("t" * 40, emitted.append)
    return ok, info, emitted, cfg_file


def test_deploy_prefers_the_durable_object_alarm(tmp_path):
    cf = FakeCloudflare()
    ok, info, _, cfg_file = _deploy(cf, tmp_path)
    assert ok, info
    assert info["mode"] == "alarm"
    first = cf.uploads[0]
    assert first["migrations"] == {"new_tag": "v1", "new_sqlite_classes": ["Switch"]}
    assert any(b["type"] == "durable_object_namespace" for b in first["bindings"])
    assert any(b["type"] == "kv_namespace" for b in first["bindings"])
    assert json.loads(cfg_file.read_text())["mode"] == "alarm"


def test_deploy_falls_back_to_kv_rather_than_failing(tmp_path):
    """An account that can't do Durable Objects still gets a working watcher.
    A slower watcher is worth vastly more than a failed setup."""
    cf = FakeCloudflare(durable_objects=False)
    ok, info, _, cfg_file = _deploy(cf, tmp_path)
    assert ok, info
    assert info["mode"] == "kv-lease"
    assert len(cf.uploads) == 2                       # tried DO, then KV
    assert "migrations" not in cf.uploads[1]
    assert json.loads(cfg_file.read_text())["mode"] == "kv-lease"


def test_a_brand_new_account_gets_a_workers_subdomain_claimed_for_it(tmp_path):
    cf = FakeCloudflare(subdomain=None)
    ok, info, _, _ = _deploy(cf, tmp_path)
    assert ok, info
    assert cf.subdomain and cf.subdomain.startswith("pilink-")


def test_a_colliding_subdomain_name_is_retried_not_surrendered(tmp_path):
    """Names are global, so collisions are ordinary. The old code tried once and
    told the user to go and do it themselves in the dashboard."""
    cf = FakeCloudflare(subdomain=None, subdomain_collisions=3)
    ok, info, _, _ = _deploy(cf, tmp_path)
    assert ok, info


def test_a_subdomain_that_can_never_be_claimed_reports_it(tmp_path):
    cf = FakeCloudflare(subdomain=None, subdomain_collisions=99)
    ok, info, _, cfg_file = _deploy(cf, tmp_path)
    assert not ok
    assert "workers.dev" in info["error"]
    assert not cfg_file.exists()        # nothing recorded from a failed setup


def test_a_worker_someone_else_deployed_is_caught(tmp_path):
    """The failure that hid for months: the running worker was not the uploaded
    one. Setup must refuse to call that success, and must name the likely cause."""
    cf = FakeCloudflare(live_build="deadbeef0000")
    ok, info, _, cfg_file = _deploy(cf, tmp_path)
    assert not ok
    assert "isn't the one we just uploaded" in info["error"]
    assert "Git repository" in info["error"]
    assert info["liveBuild"] == "deadbeef0000" and info["wantBuild"] == "BUILD"
    assert not cfg_file.exists()


def test_an_upload_whose_migration_silently_did_not_apply_is_recorded_honestly(tmp_path):
    """Cloudflare accepted the DO upload but the worker came up on KV. Setup
    succeeds — it works — but must not claim the mode it asked for."""
    cf = FakeCloudflare(mode="kv-lease")
    ok, info, _, cfg_file = _deploy(cf, tmp_path)
    assert ok, info
    assert info["mode"] == "kv-lease"
    assert json.loads(cfg_file.read_text())["mode"] == "kv-lease"


def test_a_rejected_test_checkin_does_not_leave_a_half_written_config(tmp_path):
    cf = FakeCloudflare()
    ok, info, _, cfg_file = _deploy(cf, tmp_path, probe_ok=False)
    assert not ok and not cfg_file.exists()


def test_the_cron_and_secret_are_always_set(tmp_path):
    cf = FakeCloudflare()
    ok, _, _, _ = _deploy(cf, tmp_path)
    assert ok
    assert cf.secrets == ["SENTINEL_SECRET"]
    assert cf.schedules == [[{"cron": "* * * * *"}]]


def test_progress_is_reported_in_words_a_person_understands(tmp_path):
    """The user is watching this. "Uploading your watcher" is fine; "PUT
    /accounts/.../workers/scripts" is not."""
    cf = FakeCloudflare()
    _deploy(cf, tmp_path)
    _, _, emitted, _ = _deploy(cf, tmp_path)
    assert emitted
    for m in emitted:
        assert "/" not in m and "workers" not in m.lower()


# ── the end-to-end proof ─────────────────────────────────────────────────────

def _verify(sent_ok=True, ack_after=None, health=None, tmp_path=None):
    """Run the real verification with a stubbed watcher and a scripted ack."""
    cfg = {"url": "https://w.workers.dev/beat", "secret": "s", "id": "streaming-pi"}
    cfg_file = (tmp_path / "sentinel.json") if tmp_path else Path("/dev/null")
    if tmp_path:
        cfg_file.write_text(json.dumps(cfg))
    state = {"active": False, "startedAt": 0, "confirmed": False}
    sends, emitted, finished = [], [], []

    started = time.time()

    class Clock:
        """Compress the wait so the test doesn't take three minutes."""
        def time(self):
            return started + (time.time() - started) * 400

        def sleep(self, s):
            time.sleep(min(s, 0.01))

    def send(grace, kind="unexpected", label="", disarm=False):
        sends.append((grace, kind))
        if kind == "test" and ack_after is not None:
            state["confirmed"] = True
        return sent_ok

    ns = load(
        {"sentinel_run_verification"},
        load_sentinel_config=lambda: cfg,
        CONFIG={"name": "streaming-pi"},
        _SENTINEL_VERIFY=state,
        SENTINEL_VERIFY_GRACE=45, SENTINEL_VERIFY_WAIT=165, SENTINEL_GRACE_SEC=360,
        sentinel_send=send,
        _sentinel_health=lambda c, d=None: health,
        SENTINEL_CONFIG_FILE=cfg_file,
        json=json, time=Clock(),
        _SENTINEL_TEST_UNTIL=0,
    )
    ns["sentinel_run_verification"](emitted.append,
                                    lambda ok, d: finished.append((ok, d)))
    return finished[0], sends, ns


def test_verification_succeeds_when_the_phone_confirms(tmp_path):
    (ok, detail), sends, _ = _verify(ack_after=0, tmp_path=tmp_path)
    assert ok is True
    assert (45, "test") in sends
    assert json.loads((tmp_path / "sentinel.json").read_text())["verifiedAt"] > 0


def test_verification_re_arms_normally_afterwards(tmp_path):
    """Whatever happened, the Pi must not be left with the test's short deadline
    or with the heartbeat still paused."""
    _, sends, ns = _verify(ack_after=0, tmp_path=tmp_path)
    assert sends[-1] == (360, "unexpected")
    assert ns["_SENTINEL_TEST_UNTIL"] == 0


def test_a_watcher_that_fired_but_was_not_received_blames_notifications():
    (ok, detail), _, _ = _verify(health={"switch": {"firedAt": 123, "armed": False}})
    assert ok is False and detail["stage"] == "delivery" and detail["fired"] is True
    assert "notification problem" in detail["message"]


def test_a_watcher_that_never_fired_is_not_blamed_on_the_phone():
    (ok, detail), _, _ = _verify(health={"switch": {"firedAt": 0, "armed": True}})
    assert ok is False and detail["stage"] == "fire" and detail["fired"] is False
    assert "never raised" in detail["message"]


def test_an_unreachable_watcher_is_reported_as_such():
    (ok, detail), _, _ = _verify(health=None)
    assert ok is False and detail["stage"] == "unreachable"


def test_a_failure_to_arm_stops_immediately_instead_of_waiting():
    (ok, detail), sends, ns = _verify(sent_ok=False)
    assert ok is False and detail["stage"] == "arm"
    assert len(sends) == 1              # did not sit out the whole window first
    assert ns["_SENTINEL_TEST_UNTIL"] == 0


def test_every_failure_explains_itself():
    for health in ({"switch": {"firedAt": 5}}, {"switch": {"firedAt": 0}}, None):
        (ok, detail), _, _ = _verify(health=health)
        assert not ok
        assert len(detail["message"]) > 40 and detail["stage"]
