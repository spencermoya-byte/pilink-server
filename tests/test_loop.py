"""Unit tests for the control-loop runner (in-memory store + FakeAC, no Duo)."""
import pytest

from thermostat.ac import FakeAC
from thermostat.analytics import BatteryEstimator
from thermostat.battery import HealthTracker
from thermostat.control import ControlState, Thermostat, ThermostatConfig
from thermostat.ingest import Telemetry
from thermostat.loop import ControlLoop
from thermostat.store import Store


def _cfg(**kw):
    # Zero the timers so state transitions are driven purely by temperature here;
    # the timer behaviour itself is covered by test_control.py.
    base = dict(min_on_s=0.0, min_off_s=0.0, resume_debounce_s=0.0, stale_timeout_s=15.0)
    base.update(kw)
    return ThermostatConfig(**base)


def _tele(temp_f=85.0, **kw):
    return Telemetry(device_id="thermostat-01", temp_f=temp_f, **kw)


def test_active_loop_applies_cooling_when_hot():
    loop = ControlLoop(Thermostat(_cfg(), initial_state=ControlState.IDLE),
                       FakeAC(), observe_only=False)
    loop.on_telemetry(_tele(85.0), ts=100.0)
    res = loop.tick(now=100.0)
    assert res.state is ControlState.COOLING
    assert loop.adapter.commands[-1].power is True


def test_observe_only_never_touches_adapter():
    store = Store(":memory:")
    ac = FakeAC()
    loop = ControlLoop(Thermostat(_cfg(), initial_state=ControlState.IDLE),
                       ac, store=store, observe_only=True)
    loop.on_telemetry(_tele(85.0), ts=100.0)
    loop.tick(now=100.0)
    assert ac.commands == []
    assert store.events(kind="control_observe")
    store.close()


def test_command_applied_once_until_it_changes():
    ac = FakeAC()
    loop = ControlLoop(Thermostat(_cfg(), initial_state=ControlState.IDLE),
                       ac, observe_only=False)
    loop.on_telemetry(_tele(85.0), ts=100.0)
    loop.tick(100.0)
    loop.tick(101.0)                       # still hot, still COOLING -> no new command
    assert len(ac.commands) == 1
    loop.on_telemetry(_tele(70.0), ts=102.0)   # cool -> IDLE -> a new (power-off) command
    loop.tick(102.0)
    assert len(ac.commands) == 2
    assert ac.commands[-1].power is False


def test_no_telemetry_powers_the_ac_off():
    ac = FakeAC()
    loop = ControlLoop(Thermostat(_cfg()), ac, observe_only=False)  # starts FAILSAFE
    res = loop.tick(now=100.0)
    assert res.state is ControlState.FAILSAFE
    # Powered OFF, never handed back to the Duo's own thermostat.
    assert ac.commands[-1].power is False


def test_battery_estimator_snapshots_into_store():
    store = Store(":memory:")
    loop = ControlLoop(Thermostat(_cfg(), initial_state=ControlState.IDLE), FakeAC(),
                       store=store,
                       battery=BatteryEstimator(capacity_ah=5.0, soc_ah=5.0))
    loop.on_telemetry(_tele(78.0, batt_v=3.9, batt_ma=-250.0, solar_mw=0.0), ts=0.0)
    loop.on_telemetry(_tele(78.0, batt_v=3.9, batt_ma=-250.0, solar_mw=0.0), ts=3600.0)
    snap = store.get_state("battery")
    assert snap is not None
    assert snap["soc_ah"] == pytest.approx(4.75, abs=1e-6)   # -0.25 Ah over 1 h
    store.close()


def test_fuel_gauge_takes_priority_over_coulomb_counting():
    store = Store(":memory:")
    est = BatteryEstimator(capacity_ah=5.0, soc_ah=5.0)
    loop = ControlLoop(Thermostat(_cfg()), FakeAC(), store=store, battery=est)
    # Gauge reports 42%; a stale coulomb estimate says full. The gauge wins.
    loop.on_telemetry(_tele(78.0, batt_v=3.8, batt_pct=42.0, batt_rate=-3.0), ts=0.0)
    loop.on_telemetry(_tele(78.0, batt_v=3.8, batt_pct=42.0, batt_rate=-3.0), ts=60.0)
    batt = store.get_state("battery")
    assert batt["source"] == "fuel_gauge"
    assert batt["soc_percent"] == pytest.approx(42.0)
    assert batt["time_to_empty_s"] == pytest.approx(42.0 / 3.0 * 3600.0)
    store.close()


def test_health_tracked_without_any_charge_control_wire():
    store = Store(":memory:")
    loop = ControlLoop(Thermostat(_cfg()), FakeAC(), store=store,
                       health=HealthTracker())
    # charge_control defaults False — health must still accumulate.
    loop.on_telemetry(_tele(104.0, batt_v=4.15, batt_pct=95.0), ts=0.0)
    loop.on_telemetry(_tele(104.0, batt_v=4.15, batt_pct=95.0), ts=3600.0)
    health = store.get_state("battery_health")
    assert health is not None
    assert health["high_soc_hours"] == pytest.approx(1.0)
    assert health["estimated_health_pct"] < 100.0
    assert store.get_state("charge_control") is False
    store.close()


def test_health_state_persists_and_resumes():
    store = Store(":memory:")
    loop = ControlLoop(Thermostat(_cfg()), FakeAC(), store=store,
                       health=HealthTracker())
    loop.on_telemetry(_tele(78.0, batt_v=4.0, batt_pct=90.0), ts=0.0)
    loop.on_telemetry(_tele(78.0, batt_v=4.0, batt_pct=50.0), ts=3600.0)
    saved = store.get_state("battery_health_state")
    resumed = HealthTracker.from_dict(saved)
    assert resumed.cycles == pytest.approx(0.2)   # 40 points / 200
    store.close()


def test_charge_control_capability_recorded_when_present():
    store = Store(":memory:")
    loop = ControlLoop(Thermostat(_cfg()), FakeAC(), store=store)
    loop.on_telemetry(_tele(78.0, batt_v=4.0, batt_pct=80.0, charge_control=True), ts=0.0)
    assert store.get_state("charge_control") is True
    store.close()


def test_setpoint_synced_from_store():
    store = Store(":memory:")
    store.set_state("setpoint", 72.0)   # app changed the setpoint via the server
    loop = ControlLoop(Thermostat(_cfg()), FakeAC(), store=store, observe_only=True)
    loop.on_telemetry(_tele(74.0), ts=0.0)
    loop.tick(now=100.0)
    assert loop.thermostat.cfg.setpoint_f == 72.0
    store.close()


def test_mode_off_forces_ac_off_regardless_of_temp():
    store = Store(":memory:")
    store.set_state("mode", "off")
    ac = FakeAC()
    loop = ControlLoop(Thermostat(_cfg(), initial_state=ControlState.IDLE),
                       ac, store=store, observe_only=False)
    loop.on_telemetry(_tele(90.0), ts=0.0)   # hot, but the loop is switched off
    res = loop.tick(now=100.0)
    assert res is None                        # off short-circuits the thermostat
    assert ac.commands[-1].power is False
    assert store.get_state("control")["state"] == "off"
    store.close()
