"""Unit tests for the SQLite store (in-memory, no Pi)."""
import pytest

from thermostat.ingest import Telemetry
from thermostat.store import Store


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def _tele(device_id="thermostat-01", temp_f=77.4, **kw):
    return Telemetry(device_id=device_id, temp_f=temp_f, **kw)


def test_insert_and_latest_round_trip(store):
    store.insert_telemetry(_tele(temp_f=75.0, batt_v=3.9, batt_ma=120.0), ts=100.0)
    store.insert_telemetry(_tele(temp_f=76.0, batt_v=3.8, batt_ma=-90.0), ts=200.0)
    latest = store.latest_telemetry("thermostat-01")
    assert latest.temp_f == pytest.approx(76.0)      # newest wins
    assert latest.batt_ma == pytest.approx(-90.0)
    assert latest.solar_v is None                    # absent field stays None


def test_latest_none_when_empty(store):
    assert store.latest_telemetry("nope") is None


def test_history_order_and_filters(store):
    for i, ts in enumerate([100.0, 200.0, 300.0, 400.0]):
        store.insert_telemetry(_tele(temp_f=70.0 + i), ts=ts)
    rows = store.telemetry_history("thermostat-01")
    assert [r["ts"] for r in rows] == [100.0, 200.0, 300.0, 400.0]  # ascending
    windowed = store.telemetry_history("thermostat-01", since=150.0, until=350.0)
    assert [r["ts"] for r in windowed] == [200.0, 300.0]
    assert len(store.telemetry_history("thermostat-01", limit=2)) == 2


def test_prune_removes_old_rows(store):
    for ts in (100.0, 200.0, 300.0):
        store.insert_telemetry(_tele(), ts=ts)
    removed = store.prune_telemetry(before_ts=250.0)
    assert removed == 2
    remaining = store.telemetry_history("thermostat-01")
    assert [r["ts"] for r in remaining] == [300.0]


def test_events_record_and_query(store):
    store.record_event("thermostat-01", "status", "online", ts=1.0)
    store.record_event("thermostat-01", "bad_telemetry", "boom", ts=2.0)
    store.record_event("other", "status", "offline", ts=3.0)
    all_dev = store.events(device_id="thermostat-01")
    assert [e["kind"] for e in all_dev] == ["bad_telemetry", "status"]  # newest first
    only_bad = store.events(kind="bad_telemetry")
    assert len(only_bad) == 1 and only_bad[0]["detail"] == "boom"


def test_node_status_upsert(store):
    store.set_node_status("thermostat-01", True, ts=10.0)
    assert store.get_node_status("thermostat-01") == {"online": True, "ts": 10.0}
    store.set_node_status("thermostat-01", False, ts=20.0)
    assert store.get_node_status("thermostat-01") == {"online": False, "ts": 20.0}
    assert store.get_node_status("unknown") is None


def test_state_kv_json_round_trip(store):
    store.set_state("coulomb", {"soc_ah": 3.21, "cap": 5.0})
    assert store.get_state("coulomb") == {"soc_ah": 3.21, "cap": 5.0}
    store.set_state("coulomb", {"soc_ah": 4.0})   # upsert
    assert store.get_state("coulomb") == {"soc_ah": 4.0}
    assert store.get_state("missing", default=42) == 42
