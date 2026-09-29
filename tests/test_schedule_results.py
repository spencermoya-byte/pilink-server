"""A failed schedule must leave something the app can show.

The push used to say "Open PiLink for details" while the reason lived only in
the journal, so the app had nothing to open to. These lift the real functions
out of the server (same ast approach as test_server_logic) and check that an
outcome is persisted on the schedule, carries a fix, survives the app pushing
its own copy back, and routes the notification to that schedule.
"""
import ast
import json
import os
import threading
import time
import urllib.error
from pathlib import Path

SERVER = Path(__file__).resolve().parent.parent / "pilink-server.py"


def load(names, **globals_):
    tree = ast.parse(SERVER.read_text())
    wanted = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    missing = names - {n.name for n in wanted}
    assert not missing, f"functions not found in server source: {missing}"
    ns = dict(globals_)
    exec(compile(ast.Module(body=wanted, type_ignores=[]), str(SERVER), "exec"), ns)  # noqa: S102
    return ns


def make_env(tmp_path):
    sent, pushes = [], []
    ns = load(
        {"_plain_reason", "_plain_fix", "load_schedules", "save_schedules",
         "_record_schedule_result", "_schedule_failed"},
        json=json, os=os, time=time,
        SCHED_FILE=tmp_path / "schedules.json",
        _sched_lock=threading.RLock(),
        CONFIG={"name": "dev-pi"},
        broadcast=sent.append,
        audit=lambda *a, **k: None,
        push_notify=lambda *a, **k: pushes.append((a, k)),
    )
    return ns, sent, pushes


def test_failure_is_persisted_with_reason_and_fix(tmp_path):
    ns, sent, pushes = make_env(tmp_path)
    s = {"id": "s1", "type": "reboot", "label": "Nightly reboot"}
    ns["save_schedules"]([s])

    ns["_schedule_failed"](s, "sudo: a password is required", run_at=1000)

    stored = ns["load_schedules"]()[0]
    last = stored["lastResult"]
    assert last["ok"] is False and last["at"] == 1000
    assert last["error"] == "sudo: a password is required"
    assert "permission" in last["reason"]
    assert "fix-permissions.sh" in last["fix"]
    assert stored["runLog"][0] == last

    # The app is told live, with the same reason and fix.
    err = next(m for m in sent if m["type"] == "schedule_error")
    assert err["scheduleId"] == "s1" and err["fix"] == last["fix"]


def test_notification_routes_to_the_schedule(tmp_path):
    ns, _, pushes = make_env(tmp_path)
    s = {"id": "s1", "type": "custom", "label": "Backup"}
    ns["save_schedules"]([s])
    ns["_schedule_failed"](s, "bash: backup.sh: command not found")

    (args, kwargs), = pushes
    assert kwargs["extra"] == {"kind": "schedule_failed", "scheduleId": "s1"}
    assert "Open PiLink" not in args[2]           # no promise the app can't keep
    assert "couldn't be found" in kwargs["alert_message"]


def test_success_clears_to_ok_and_keeps_history(tmp_path):
    ns, _, _ = make_env(tmp_path)
    s = {"id": "s1", "type": "custom"}
    ns["save_schedules"]([s])
    ns["_schedule_failed"](s, "exit 1", run_at=1000)
    ns["_record_schedule_result"](s, True, run_at=2000)

    stored = ns["load_schedules"]()[0]
    assert stored["lastResult"] == {"at": 2000, "ok": True}
    assert [e["at"] for e in stored["runLog"]] == [2000, 1000]


def test_every_failure_gets_a_fix(tmp_path):
    ns, _, _ = make_env(tmp_path)
    for detail in ["", "exit 2", "timed out after 1h", "Permission denied",
                   "invalid cron expression 'x' — schedule stopped",
                   "nothing to run (type='custom', no command)"]:
        assert ns["_plain_fix"](detail, {"type": "custom"})


def test_custom_sudo_failure_is_not_told_to_run_fix_permissions(tmp_path):
    ns, _, _ = make_env(tmp_path)
    fix = ns["_plain_fix"]("sudo: a password is required", {"type": "custom"})
    assert "fix-permissions" not in fix and "password" in fix


def test_run_log_is_capped(tmp_path):
    ns, _, _ = make_env(tmp_path)
    s = {"id": "s1", "type": "custom"}
    ns["save_schedules"]([s])
    for i in range(40):
        ns["_record_schedule_result"](s, True, run_at=i + 1)
    assert len(ns["load_schedules"]()[0]["runLog"]) == 25


def test_set_schedule_keeps_the_pis_outcomes():
    """The app pushes its whole copy on every Scheduler open; that copy must not
    wipe (or forge) the outcome the Pi recorded."""
    src = SERVER.read_text()
    body = src[src.index("    def on_set_schedule"):src.index("    def on_delete_schedule")]
    assert "for k in ('runLog', 'lastResult')" in body


def test_github_errors_say_what_to_do():
    ns = load({"_github_error"}, urllib=urllib, UPDATE_REPO="spencermoya-byte/pilink-server")
    err = lambda code: urllib.error.HTTPError("u", code, "x", {}, None)  # noqa: E731
    assert "no repo at spencermoya-byte/pilink-server" in ns["_github_error"](err(404))
    assert "rate-limiting" in ns["_github_error"](err(403))
    assert "HTTP 500" in ns["_github_error"](err(500))
    assert "couldn't reach GitHub" in ns["_github_error"](urllib.error.URLError("Name or service not known"))


def test_updates_come_from_the_public_mirror_without_a_token():
    """Update Server must work on a Pi with no GitHub token (dev-pi)."""
    src = SERVER.read_text()
    assert "UPDATE_REPO       = 'spencermoya-byte/pilink-server'" in src
    for fn in ("def _latest_release", "def _fetch_requirements", "def _fetch_server_source"):
        body = src[src.index(fn):src.index("\ndef ", src.index(fn) + 5)]
        assert "UPDATE_REPO" in body and "auth=False" in body, fn
        assert "{GITHUB_REPO}" not in body, fn
    # No release published is not "an update is waiting".
    check = src[src.index("    def on_check_server_update"):src.index("    def on_pull_update")]
    assert "'hasUpdate': True" not in check
