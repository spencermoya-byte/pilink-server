"""Dispatch-integrity test for the server's ClientSession.handle() router.

Parses the REAL server source with `ast` (importing pilink-server.py pulls heavy
Pi-only deps) and enforces three things about the post-auth message router:

  1. every message type routes to a handler method that actually exists,
  2. no message type is handled by more than one branch,
  3. the full {type -> handler} routing table matches a committed golden file.

(3) is the safety net for the planned `if/elif` -> handler-registry refactor: the
golden table is invariant, so the refactor must reproduce it exactly. Runs in CI,
needs no Raspberry Pi, and executes none of the (often destructive) handler code.
"""
import ast
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE.parent / "pilink-server.py"
GOLDEN = HERE / "dispatch_routes.json"


def _extract():
    """Return (routes {type: handler}, class method names, duplicate types)."""
    tree = ast.parse(SERVER.read_text())
    cls = next(n for n in ast.walk(tree)
               if isinstance(n, ast.ClassDef) and n.name == "ClientSession")
    methods = {n.name for n in cls.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    handle = next(n for n in cls.body
                  if isinstance(n, ast.FunctionDef) and n.name == "handle")

    def handler_of(body):
        # Inspect ONLY this branch's own statements (not the nested elif orelse).
        for stmt in body:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    f = sub.func
                    if (isinstance(f.value, ast.Name) and f.value.id == "self"
                            and f.attr.startswith("on_")):
                        return f.attr
                    if f.attr == "Thread":  # threading.Thread(target=self.on_x, ...)
                        for kw in sub.keywords:
                            if (kw.arg == "target" and isinstance(kw.value, ast.Attribute)
                                    and isinstance(kw.value.value, ast.Name)
                                    and kw.value.value.id == "self"):
                                return kw.value.attr
        return "inline"

    def types_of(test):
        if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
                and test.left.id == "t"):
            c = test.comparators[0]
            if isinstance(c, ast.Constant):
                return [c.value]
            if isinstance(c, (ast.Tuple, ast.List)):
                return [e.value for e in c.elts if isinstance(e, ast.Constant)]
        return []

    routes, duplicates = {}, []

    # Declarative table (post-refactor): _ROUTES = {type: (method, threaded, wants_msg)}.
    table = next((n for n in tree.body if isinstance(n, ast.Assign)
                  and any(getattr(t, "id", None) == "_ROUTES" for t in n.targets)), None)
    if table is not None:
        for key, val in zip(table.value.keys, table.value.values):
            if key.value in routes:
                duplicates.append(key.value)
            routes[key.value] = val.elts[0].value  # first tuple element = method name

    def walk(stmt):
        for typ in types_of(stmt.test):
            if typ in routes:
                duplicates.append(typ)
            routes[typ] = handler_of(stmt.body)
        for sub in stmt.orelse:
            if isinstance(sub, ast.If):
                walk(sub)

    for stmt in handle.body:
        if isinstance(stmt, ast.If):
            walk(stmt)
    return routes, methods, duplicates


ROUTES, METHODS, DUPLICATES = _extract()


def test_every_routed_handler_method_exists():
    missing = sorted(h for h in ROUTES.values() if h != "inline" and h not in METHODS)
    assert not missing, f"dispatch routes to non-existent methods: {missing}"


def test_no_duplicate_message_type_branches():
    dupes = sorted(set(DUPLICATES))
    assert not dupes, f"message types handled by more than one branch: {dupes}"


def test_routing_table_matches_golden_snapshot():
    golden = json.loads(GOLDEN.read_text())
    derived = dict(sorted(ROUTES.items()))
    added = {k: derived[k] for k in derived.keys() - golden.keys()}
    removed = {k: golden[k] for k in golden.keys() - derived.keys()}
    changed = {k: {"was": golden[k], "now": derived[k]}
               for k in golden.keys() & derived.keys() if golden[k] != derived[k]}
    assert not (added or removed or changed), (
        "dispatch routing changed vs the golden snapshot:\n"
        f"  added   = {added}\n  removed = {removed}\n  changed = {changed}\n"
        "If this change is intentional, regenerate pi-server/tests/dispatch_routes.json."
    )


def test_extractor_found_the_router():
    # Defends against the parser silently matching nothing (e.g. a future refactor
    # the extractor no longer understands) and the suite going quietly green.
    assert len(ROUTES) >= 50, f"only {len(ROUTES)} routes parsed - extractor is stale"
