"""Unit tests for the server's pure, security-relevant logic.

Importing pilink-server.py pulls heavy runtime deps (psutil, paramiko) and runs
module-level side effects, so we lift just the self-contained functions out of the
REAL source with `ast` and exec them in an isolated namespace. This tests the
actual server code (not a re-implementation) with no Pi dependencies, and without
changing the server or how it's deployed.
"""
import ast
import tempfile
import time
from pathlib import Path

import pytest

SERVER = Path(__file__).resolve().parent.parent / "pilink-server.py"


def load(names, **globals_):
    """Extract the named top-level functions from the server and exec them in a
    fresh namespace seeded with `globals_` (their only external references)."""
    tree = ast.parse(SERVER.read_text())
    wanted = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    missing = names - {n.name for n in wanted}
    assert not missing, f"functions not found in server source: {missing}"
    module = ast.Module(body=wanted, type_ignores=[])
    ns = dict(globals_)
    exec(compile(module, str(SERVER), "exec"), ns)  # noqa: S102 - trusted local source
    return ns


# ── Cron logic (scheduler correctness + malformed-input rejection) ──────────────

_cron = load({"_cron_field", "_cron_matches", "_cron_valid", "_cron_next"}, time=time)
cron_valid = _cron["_cron_valid"]
cron_matches = _cron["_cron_matches"]
cron_next = _cron["_cron_next"]


@pytest.mark.parametrize(
    "expr",
    [
        "30 2 * * *",      # daily
        "0 3 * * 0",       # weekly (Sun)
        "15 4 * * 1,3,5",  # weekly multi-day
        "0 2 1,15 * *",    # monthly multi-day
        "*/15 * * * *",    # step
        "0 0 * * 1-5",     # weekday range
        "0 */2 * * *",     # every 2 hours
    ],
)
def test_cron_valid_accepts_well_formed(expr):
    assert cron_valid(expr) is True


@pytest.mark.parametrize(
    "expr",
    [
        "",                # empty
        "30 2 * *",        # only 4 fields
        "30 2 * * * *",    # 6 fields
        "60 2 * * *",      # minute out of range
        "30 24 * * *",     # hour out of range
        "30 2 32 * *",     # day-of-month out of range
        "30 2 * 13 *",     # month out of range
        "30 2 * * 8",      # day-of-week out of range
        "a b c d e",       # non-numeric
        "30 2 * * */0",    # zero step
        "30 2 5-2 * *",    # inverted range
    ],
)
def test_cron_valid_rejects_malformed(expr):
    # The docstring on _cron_valid explains why this matters: a malformed expr
    # otherwise costs 532,800 _cron_matches iterations per scheduler tick.
    assert cron_valid(expr) is False


def test_cron_matches_daily_and_weekday():
    when = time.mktime((2024, 1, 3, 2, 30, 0, 0, 0, -1))  # Wed 2024-01-03 02:30 local
    assert cron_matches("30 2 * * *", when) is True
    assert cron_matches("30 2 * * 3", when) is True   # cron Wed == 3
    assert cron_matches("31 2 * * *", when) is False  # wrong minute
    assert cron_matches("30 2 * * 4", when) is False  # wrong weekday


def test_cron_next_finds_following_minute_and_rejects_bad():
    when = time.mktime((2024, 1, 3, 2, 30, 0, 0, 0, -1))
    assert cron_next("35 2 * * *", when) == int(time.mktime((2024, 1, 3, 2, 35, 0, 0, 0, -1)))
    assert cron_next("bad expr", when) == 0
    assert cron_next("60 2 * * *", when) == 0  # invalid -> 0, never iterates


# ── safe_path (path-traversal guard — the core filesystem security boundary) ────

def _safe_path_in(root):
    ns = load({"safe_path"}, Path=Path, ALLOWED_PATH_PREFIXES=[root])
    return ns["safe_path"]


def test_safe_path_allows_inside_root():
    root = Path(tempfile.mkdtemp()).resolve()
    safe_path = _safe_path_in(root)
    assert safe_path(str(root / "notes.txt")) == root / "notes.txt"
    assert safe_path(str(root / "sub" / "deep.log")) == root / "sub" / "deep.log"


def test_safe_path_blocks_traversal_and_absolute_escape():
    root = Path(tempfile.mkdtemp()).resolve()
    safe_path = _safe_path_in(root)
    with pytest.raises(PermissionError):
        safe_path(str(root / ".." / ".." / "etc" / "passwd"))
    with pytest.raises(PermissionError):
        safe_path("/etc/passwd")
    with pytest.raises(PermissionError):
        safe_path(str(root) + "/../" + root.name + "_evil")  # sibling prefix trick
