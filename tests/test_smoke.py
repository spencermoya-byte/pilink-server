"""Smoke test — proves the pytest pipeline runs in CI.

Deliberately self-contained: importing pilink-server.py pulls heavy runtime deps
(psutil, paramiko) and runs module-level side effects, so real server-handler
tests wait for the Phase 2 modularization. For now this mirrors the server's
RFC-1123 hostname validation so the test is at least meaningful.
"""
import re

HOSTNAME_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


def test_accepts_valid_hostnames():
    assert HOSTNAME_RE.match('PiLink')
    assert HOSTNAME_RE.match('pi-4b')
    assert HOSTNAME_RE.match('a')


def test_rejects_invalid_hostnames():
    assert not HOSTNAME_RE.match('-leading-hyphen')
    assert not HOSTNAME_RE.match('trailing-hyphen-')
    assert not HOSTNAME_RE.match('has space')
    assert not HOSTNAME_RE.match('under_score')
    assert not HOSTNAME_RE.match('')
