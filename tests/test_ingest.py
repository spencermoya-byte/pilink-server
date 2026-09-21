"""Unit tests for untrusted-telemetry parsing/validation + a sim round-trip."""
import json

import pytest

from thermostat import simdata
from thermostat.ingest import (
    Telemetry,
    TelemetryError,
    device_id_from_topic,
    parse_status,
    parse_telemetry,
)

# The exact contract example from the firmware handoff.
GOOD = {
    "id": "thermostat-01", "fw": "0.1.0", "uptime_s": 1234, "rssi": -55,
    "temp_f": 77.4, "humidity": 48.2,
    "solar_v": 6.02, "solar_ma": 410.5, "solar_mw": 2471.0,
    "batt_v": 3.92, "batt_ma": 180.3, "batt_mw": 707.0,
}


def test_parse_full_contract_frame():
    t = parse_telemetry(json.dumps(GOOD))
    assert isinstance(t, Telemetry)
    assert t.device_id == "thermostat-01"
    assert t.temp_f == pytest.approx(77.4)
    assert t.batt_ma == pytest.approx(180.3)  # signed: + = charging


def test_accepts_bytes_payload():
    t = parse_telemetry(json.dumps(GOOD).encode("utf-8"))
    assert t.device_id == "thermostat-01"


def test_missing_sensor_fields_are_none():
    # Contract: missing-sensor fields are omitted, not zeroed.
    t = parse_telemetry(json.dumps({"id": "x", "temp_f": 75.0}))
    assert t.temp_f == pytest.approx(75.0)
    assert t.solar_v is None and t.batt_v is None and t.humidity is None


def test_device_id_falls_back_to_topic():
    t = parse_telemetry(json.dumps({"temp_f": 70.0}),
                        topic="pilink/thermostat-07/telemetry")
    assert t.device_id == "thermostat-07"


def test_device_id_from_topic_helper():
    assert device_id_from_topic("pilink/abc/telemetry") == "abc"
    assert device_id_from_topic("pilink/abc/status") == "abc"
    assert device_id_from_topic("nope") is None
    assert device_id_from_topic(None) is None


@pytest.mark.parametrize("payload", [
    "{not json",
    "",
    "3.14",           # bare number, not an object
    "[1, 2, 3]",      # array, not an object
    '"a string"',
])
def test_malformed_or_non_object_rejected(payload):
    with pytest.raises(TelemetryError):
        parse_telemetry(payload)


def test_missing_id_and_no_topic_rejected():
    with pytest.raises(TelemetryError):
        parse_telemetry(json.dumps({"temp_f": 70.0}))


@pytest.mark.parametrize("field,value", [
    ("temp_f", 999.0),     # way out of hardware range
    ("temp_f", -100.0),
    ("humidity", 150.0),
    ("batt_v", 12.0),      # not a 1S LiPo
    ("solar_v", -1.0),
    ("rssi", 20.0),        # positive rssi is impossible
])
def test_out_of_range_field_rejected(field, value):
    bad = dict(GOOD)
    bad[field] = value
    with pytest.raises(TelemetryError):
        parse_telemetry(json.dumps(bad))


@pytest.mark.parametrize("value", [True, False, "hot"])
def test_non_numeric_field_rejected(value):
    # bool is an int subclass, so it must be explicitly rejected as a reading.
    bad = dict(GOOD)
    bad["temp_f"] = value
    with pytest.raises(TelemetryError):
        parse_telemetry(json.dumps(bad))


def test_fuel_gauge_fields_parsed():
    frame = dict(GOOD)
    frame.update({"batt_pct": 76.5, "batt_rate": -4.2, "charge_control": True,
                  "charging": False})
    t = parse_telemetry(json.dumps(frame))
    assert t.batt_pct == pytest.approx(76.5)
    assert t.batt_rate == pytest.approx(-4.2)   # signed: negative = discharging
    assert t.charge_control is True
    assert t.charging is False


def test_charge_control_defaults_false_when_absent():
    # A node without the EN wire simply omits the flag; we must not assume it can
    # control charging.
    t = parse_telemetry(json.dumps(GOOD))
    assert t.charge_control is False
    assert t.charging is None


@pytest.mark.parametrize("field,value", [
    ("batt_pct", 150.0),     # not a percentage
    ("batt_pct", -5.0),
    ("batt_rate", 5000.0),   # implausible %/hr
])
def test_fuel_gauge_out_of_range_rejected(field, value):
    bad = dict(GOOD)
    bad[field] = value
    with pytest.raises(TelemetryError):
        parse_telemetry(json.dumps(bad))


def test_charge_control_must_be_boolean():
    bad = dict(GOOD)
    bad["charge_control"] = "yes"
    with pytest.raises(TelemetryError):
        parse_telemetry(json.dumps(bad))


def test_null_field_treated_as_missing():
    # An explicit JSON null is "sensor absent", not an error.
    t = parse_telemetry(json.dumps({"id": "x", "temp_f": None}))
    assert t.temp_f is None


def test_nan_and_inf_rejected():
    # json.dumps emits NaN/Infinity tokens that Python's json will read back.
    for token in ("NaN", "Infinity", "-Infinity"):
        payload = '{"id": "x", "temp_f": %s}' % token
        with pytest.raises(TelemetryError):
            parse_telemetry(payload)


@pytest.mark.parametrize("raw,expected", [
    ("online", True),
    ("offline", False),
    ('"online"', True),
    ("OFFLINE", False),
    (b"online", True),
])
def test_parse_status(raw, expected):
    assert parse_status(raw) is expected


def test_parse_status_rejects_garbage():
    with pytest.raises(TelemetryError):
        parse_status("maybe")


# ── round-trip: the sim generator must always produce contract-valid frames ─────

def test_simdata_frames_round_trip_through_ingest():
    sim = simdata.NodeSim()
    frames = simdata.ramp(sim, 74.0, 82.0, steps=20, solar_ma=350.0, batt_ma=120.0)
    for f in frames:
        t = parse_telemetry(json.dumps(f))
        assert t.device_id == "thermostat-01"
        assert 74.0 <= t.temp_f <= 82.0
        assert t.solar_ma == pytest.approx(350.0)
