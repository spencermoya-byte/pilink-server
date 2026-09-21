"""Unit tests for MQTT message routing + service config (no broker, no paho)."""
import json

import pytest

from thermostat import service, simdata
from thermostat.mqtt_ingest import handle_message
from thermostat.store import Store

TELE_TOPIC = "pilink/thermostat-01/telemetry"
STATUS_TOPIC = "pilink/thermostat-01/status"


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def test_good_telemetry_is_stored_and_callback_fires(store):
    seen = []
    frame = simdata.NodeSim().frame(temp_f=76.5, batt_ma=150.0)
    result = handle_message(store, TELE_TOPIC, json.dumps(frame), now=1000.0,
                            on_telemetry=lambda t, ts: seen.append((t, ts)))
    assert result is not None
    assert store.latest_telemetry("thermostat-01").temp_f == pytest.approx(76.5)
    assert seen and seen[0][1] == 1000.0


def test_bad_telemetry_is_dropped_and_logged(store):
    result = handle_message(store, TELE_TOPIC, "{not json", now=5.0)
    assert result is None
    assert store.latest_telemetry("thermostat-01") is None
    bad = store.events(kind="bad_telemetry")
    assert len(bad) == 1 and bad[0]["device_id"] == "thermostat-01"


def test_out_of_range_telemetry_dropped(store):
    frame = simdata.NodeSim().frame(temp_f=76.0)
    frame["batt_v"] = 99.0  # not a 1S LiPo -> rejected by the validator
    assert handle_message(store, TELE_TOPIC, json.dumps(frame)) is None
    assert store.events(kind="bad_telemetry")


@pytest.mark.parametrize("payload,online", [("online", True), ("offline", False)])
def test_status_updates_node_state(store, payload, online):
    handle_message(store, STATUS_TOPIC, payload, now=42.0)
    assert store.get_node_status("thermostat-01") == {"online": online, "ts": 42.0}
    assert store.events(kind="status")[0]["detail"] == payload


def test_bad_status_logged(store):
    assert handle_message(store, STATUS_TOPIC, "weird") is None
    assert store.events(kind="bad_status")


def test_unknown_topic_is_ignored(store):
    assert handle_message(store, "pilink/thermostat-01/config", "{}") is None
    assert store.latest_telemetry("thermostat-01") is None


def test_simdata_stream_flows_through(store):
    sim = simdata.NodeSim()
    frames = simdata.ramp(sim, 74.0, 82.0, steps=10, solar_ma=300.0, batt_ma=100.0)
    for i, f in enumerate(frames):
        handle_message(store, TELE_TOPIC, json.dumps(f), now=float(i))
    assert len(store.telemetry_history("thermostat-01")) == 10
    assert store.latest_telemetry("thermostat-01").temp_f == pytest.approx(82.0)


def test_build_ingestor_reads_env(monkeypatch, store):
    monkeypatch.setenv("PILINK_MQTT_HOST", "10.0.0.5")
    monkeypatch.setenv("PILINK_MQTT_PORT", "8883")
    monkeypatch.setenv("PILINK_MQTT_USER", "pilink-pi")
    monkeypatch.setenv("PILINK_MQTT_PASS", "secret")
    ing = service.build_ingestor(store)
    assert ing.host == "10.0.0.5"
    assert ing.port == 8883
    assert ing.username == "pilink-pi"
