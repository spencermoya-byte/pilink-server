"""The listener refuses plaintext, the advert carries no key, and the one
pre-auth request is the certificate.

_accept_session is lifted from the real source (ast, like the other tests)
and driven over a real socketpair, so the first-byte sniff is exercised for
real rather than asserted about.
"""
import ast
import json
import socket
import ssl
import threading
from pathlib import Path

SERVER = Path(__file__).resolve().parent.parent / "pilink-server.py"
SRC = SERVER.read_text()


def load(names, **globals_):
    tree = ast.parse(SRC)
    wanted = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert {n.name for n in wanted} == names
    ns = dict(globals_)
    exec(compile(ast.Module(body=wanted, type_ignores=[]), str(SERVER), "exec"), ns)  # noqa: S102
    return ns


def run_accept(first_bytes, config):
    sessions, audits = [], []
    ns = load({"_accept_session"},
              socket=socket, ssl=ssl, CONFIG=config,
              audit=lambda *a, **k: audits.append(a),
              _tls_context=lambda: None,
              ClientSession=lambda conn, addr: type("S", (), {"run": lambda self: sessions.append(conn)})())
    srv, cli = socket.socketpair()
    cli.sendall(first_bytes)
    t = threading.Thread(target=ns["_accept_session"], args=(srv, ("10.0.0.9", 5555)))
    t.start(); t.join(5)
    cli.settimeout(1)
    try:
        reply = cli.recv(4096)
    except (socket.timeout, OSError):
        reply = b""
    cli.close()
    return sessions, audits, reply


def test_plaintext_is_refused_by_default():
    sessions, audits, reply = run_accept(b'{"type": "auth", "pairingKey": "x"}\n', {})
    assert sessions == []                                  # never reaches auth
    assert audits and audits[0][0] == "plaintext_refused"
    msg = json.loads(reply.decode().strip())
    assert msg["type"] == "auth_fail" and "encrypted" in msg["error"]


def test_plaintext_allowed_only_when_owner_opts_in():
    sessions, _, _ = run_accept(b'{"type": "auth"}\n', {"allow_plaintext": True})
    assert len(sessions) == 1


def test_tls_clienthello_is_not_treated_as_plaintext():
    # 0x16 routes to the TLS branch; with no context available it closes rather
    # than falling through to a plaintext session.
    sessions, audits, _ = run_accept(b"\x16\x03\x01\x00\x05hello", {})
    assert sessions == [] and audits == []


def test_mdns_advert_does_not_carry_the_pairing_key():
    body = SRC[SRC.index("def mdns_register_loop"):SRC.index("def _tls_context")]
    props = body[body.index("properties={"):body.index("},", body.index("properties={"))]
    assert "pairing_key" not in props and "'pairingKey'" not in props
    assert "'certFp'" in props                             # identity is still published


def test_only_the_certificate_is_served_before_auth():
    body = SRC[SRC.index("        if not self.authed:"):SRC.index("            if t == 'auth':")]
    assert "t == 'get_tls_cert'" in body and "self.on_get_tls_cert()" in body
    # and nothing else is dispatched pre-auth
    assert body.count("self.on_") == 1
