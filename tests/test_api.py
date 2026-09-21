"""Unit tests for the app-facing thermostat API helpers (in-memory store)."""
import pytest

from thermostat import api
from thermostat.ingest import Telemetry
from thermostat.store import Store


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


@pytest.mark.parametrize("value,expected", [
    (75, 75.0),
    (68, 68.0),
    (85, 85.0),
    (60, 68.0),     # clamp low
    (99, 85.0),     # clamp high
    ("72", 72.0),   # numeric string ok
])
def test_clamp_setpoint(value, expected):
    assert api.clamp_setpoint(value) == pytest.approx(expected)


@pytest.mark.parametrize("bad", ["hot", None, float("nan")])
def test_clamp_setpoint_rejects_bad(bad):
    with pytest.raises(ValueError):
        api.clamp_setpoint(bad)


def test_validate_mode():
    assert api.validate_mode("auto") == "auto"
    assert api.validate_mode("off") == "off"
    with pytest.raises(ValueError):
        api.validate_mode("cool")


def test_set_setpoint_and_mode_persist(store):
    assert api.set_setpoint(store, 130)["setpoint"] == 85.0   # clamped
    assert store.get_state("setpoint") == 85.0
    assert api.set_mode(store, "off")["mode"] == "off"
    assert store.get_state("mode") == "off"


def test_build_status_shape(store):
    store.insert_telemetry(
        Telemetry(device_id="thermostat-01", temp_f=76.0, humidity=48.0,
                  solar_v=6.0, solar_ma=300.0, solar_mw=1800.0,
                  batt_v=3.9, batt_ma=-100.0, batt_mw=-390.0),
        ts=1000.0)
    store.set_node_status("thermostat-01", True, ts=1000.0)
    store.set_state("setpoint", 78.0)
    store.set_state("control", {"state": "cooling", "power": True})
    status = api.build_status(store, "thermostat-01", now=1030.0)
    assert status["online"] is True
    assert status["configured"] is True
    assert status["reading_age_s"] == pytest.approx(30.0)   # 30 s old -> stale in the app
    assert status["setpoint_f"] == 78.0
    assert status["mode"] == "auto"                     # default when unset
    assert status["room"]["temp_f"] == pytest.approx(76.0)
    assert status["room"]["solar_mw"] == pytest.approx(1800.0)
    assert status["room"]["solar_v"] == pytest.approx(6.0)
    assert status["room"]["batt_ma"] == pytest.approx(-100.0)
    assert status["control"]["state"] == "cooling"


def test_build_status_empty_store(store):
    status = api.build_status(store, "nobody")
    assert status["online"] is False
    assert status["configured"] is False    # a plain Pi is not a thermostat
    assert status["reading_age_s"] is None  # nothing has EVER been received
    assert status["room"] is None
    assert status["setpoint_f"] is None


def test_reading_age_tracks_the_newest_reading(store):
    store.insert_telemetry(Telemetry(device_id="thermostat-01", temp_f=70.0), ts=100.0)
    store.insert_telemetry(Telemetry(device_id="thermostat-01", temp_f=71.0), ts=160.0)
    status = api.build_status(store, "thermostat-01", now=175.0)
    assert status["reading_age_s"] == pytest.approx(15.0)


def test_build_status_exposes_health_and_charge_capability(store):
    store.set_state("battery_health", {"estimated_health_pct": 97.2, "cycles": 43})
    store.set_state("charge_control", True)
    store.set_state("optimized_charging", True)
    status = api.build_status(store, "thermostat-01")
    assert status["battery_health"]["estimated_health_pct"] == pytest.approx(97.2)
    assert status["charge_control"] is True
    assert status["optimized_charging"] is True


def test_charge_control_defaults_false_so_ui_disables_the_toggle(store):
    status = api.build_status(store, "thermostat-01")
    assert status["charge_control"] is False
    assert status["optimized_charging"] is False
    assert status["battery_health"] is None


def test_set_optimized_charging_persists(store):
    assert api.set_optimized_charging(store, True) == {"optimized_charging": True}
    assert store.get_state("optimized_charging") is True
    api.set_optimized_charging(store, False)
    assert store.get_state("optimized_charging") is False


@pytest.mark.parametrize("bad", ["yes", 1, None])
def test_set_optimized_charging_rejects_non_boolean(store, bad):
    with pytest.raises(ValueError):
        api.set_optimized_charging(store, bad)


def test_build_history(store):
    for i, ts in enumerate([1.0, 2.0, 3.0]):
        store.insert_telemetry(
            Telemetry(device_id="thermostat-01", temp_f=70.0 + i, batt_v=3.9), ts=ts)
    hist = api.build_history(store, "thermostat-01", limit=2)
    assert len(hist) == 2
    assert set(hist[0]) == {"ts", "temp_f", "batt_v", "solar_mw"}
