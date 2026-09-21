"""Unit tests for the pure thermostat control logic (deadband, min on/off,
fail-safe, no short-cycling). No Pi, no AC, injected clock."""
import math

import pytest

from thermostat.control import (
    ACMode,
    ControlState,
    Thermostat,
    ThermostatConfig,
    command_for,
    decide,
)

ON = 79.0
OFF = 77.0


def _decide(state, temp, elapsed, *, healthy=True, resume_ok=True,
            min_on=240.0, min_off=180.0):
    return decide(state, temp_f=temp, on_temp_f=ON, off_temp_f=OFF,
                  elapsed_s=elapsed, min_on_s=min_on, min_off_s=min_off,
                  healthy=healthy, resume_ok=resume_ok)


# ── decide(): IDLE hysteresis + min-off ─────────────────────────────────────────

def test_idle_stays_below_on_temp():
    assert _decide(ControlState.IDLE, 78.5, 9999) is ControlState.IDLE


def test_idle_to_cooling_needs_on_temp_and_min_off():
    # Hot enough but min-off not yet satisfied -> stay IDLE.
    assert _decide(ControlState.IDLE, 80.0, 100.0) is ControlState.IDLE
    # Hot enough and min-off elapsed -> cool.
    assert _decide(ControlState.IDLE, 80.0, 200.0) is ControlState.COOLING


# ── decide(): COOLING hysteresis + min-on ───────────────────────────────────────

def test_cooling_stays_above_off_temp():
    assert _decide(ControlState.COOLING, 78.0, 9999) is ControlState.COOLING


def test_cooling_to_idle_needs_off_temp_and_min_on():
    # Cool enough but min-on not satisfied -> keep cooling (protect compressor).
    assert _decide(ControlState.COOLING, 76.0, 100.0) is ControlState.COOLING
    # Cool enough and min-on elapsed -> idle.
    assert _decide(ControlState.COOLING, 76.0, 300.0) is ControlState.IDLE


# ── decide(): fail-safe ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("state", list(ControlState))
def test_unhealthy_always_failsafe(state):
    assert _decide(state, math.nan, 9999, healthy=False) is ControlState.FAILSAFE


def test_failsafe_holds_until_resume_ok():
    assert _decide(ControlState.FAILSAFE, 85.0, 9999, resume_ok=False) is ControlState.FAILSAFE


def test_failsafe_resume_picks_cooling_if_hot_else_idle():
    assert _decide(ControlState.FAILSAFE, 85.0, 9999, resume_ok=True) is ControlState.COOLING
    assert _decide(ControlState.FAILSAFE, 70.0, 9999, resume_ok=True) is ControlState.IDLE


# ── command mapping ─────────────────────────────────────────────────────────────

def test_command_for_states():
    cfg = ThermostatConfig()
    idle = command_for(ControlState.IDLE, cfg)
    assert idle.power is False and idle.mode is ACMode.OFF and idle.target_f is None

    cool = command_for(ControlState.COOLING, cfg)
    assert cool.power is True and cool.mode is ACMode.COOL
    assert cool.target_f == pytest.approx(cfg.cool_pin_f)

    # FAILSAFE powers OFF. It must NEVER hand cooling back to the Duo's own
    # thermostat: that sensor reads wrong, which is why this project exists.
    fs = command_for(ControlState.FAILSAFE, cfg)
    assert fs.power is False and fs.mode is ACMode.OFF and fs.target_f is None


# ── Thermostat driver integration ───────────────────────────────────────────────

def test_full_cycle_with_timers():
    cfg = ThermostatConfig()  # setpoint 78 -> on 79 / off 77, min_off 180, min_on 240
    t = Thermostat(cfg)

    # Starts FAILSAFE; healthy telemetry must debounce (30 s) before resuming.
    assert t.tick(0.0, 80.0, last_sample_ts=0.0).state is ControlState.FAILSAFE
    # 30 s later, still hot -> resume straight into COOLING.
    assert t.tick(30.0, 80.0, last_sample_ts=30.0).state is ControlState.COOLING

    # Cools below off-temp but before min-on -> keep cooling.
    assert t.tick(60.0, 76.0, last_sample_ts=60.0).state is ControlState.COOLING
    # After min-on (entered COOLING at t=30, need +240) -> idle.
    assert t.tick(300.0, 76.0, last_sample_ts=300.0).state is ControlState.IDLE

    # Warms past on-temp but before min-off -> stay idle.
    assert t.tick(360.0, 80.0, last_sample_ts=360.0).state is ControlState.IDLE
    # After min-off (entered IDLE at t=300, need +180) -> cool again.
    r = t.tick(485.0, 80.0, last_sample_ts=485.0)
    assert r.state is ControlState.COOLING and r.command.power is True


def test_stale_telemetry_trips_failsafe():
    t = Thermostat(ThermostatConfig(), initial_state=ControlState.IDLE)
    # Fresh sample keeps us in control.
    assert t.tick(0.0, 78.0, last_sample_ts=0.0).state is ControlState.IDLE
    # Sample is now 20 s old (> 15 s stale timeout) -> fail-safe.
    r = t.tick(1000.0, 78.0, last_sample_ts=980.0)
    assert r.state is ControlState.FAILSAFE and r.healthy is False
    # Powered OFF, never handed back to the Duo's own thermostat (#38).
    assert r.command.power is False


def test_implausible_temp_trips_failsafe():
    t = Thermostat(ThermostatConfig(), initial_state=ControlState.IDLE)
    r = t.tick(0.0, 240.0, last_sample_ts=0.0)  # 240 °F is not a real room
    assert r.state is ControlState.FAILSAFE


def test_no_short_cycle_under_noisy_temperature():
    """Over a long noisy run the compressor must never on/off faster than the
    min on/off times — the core anti-short-cycle guarantee."""
    cfg = ThermostatConfig()
    t = Thermostat(cfg)
    # Prime out of FAILSAFE.
    t.tick(0.0, 78.0, last_sample_ts=0.0)
    t.tick(30.0, 78.0, last_sample_ts=30.0)

    changes: list[tuple[float, ControlState]] = []
    prev = t.state
    now = 30.0
    # ~2 h at 5 s cadence, temperature dithering right across the deadband.
    for i in range(1440):
        now += 5.0
        temp = 78.0 + 3.0 * math.sin(i / 2.0)  # swings ~75..81, crossing on/off
        r = t.tick(now, temp, last_sample_ts=now)
        if r.state is not prev:
            changes.append((now, r.state))
            prev = r.state

    # Measure dwell time of each completed COOLING/IDLE interval.
    for (t0, s0), (t1, _s1) in zip(changes, changes[1:]):
        dwell = t1 - t0
        if s0 is ControlState.COOLING:
            assert dwell >= cfg.min_on_s - 1e-9, f"short cool cycle: {dwell}s"
        elif s0 is ControlState.IDLE:
            assert dwell >= cfg.min_off_s - 1e-9, f"short off cycle: {dwell}s"
    # And it should actually have cycled at least once (sanity on the test itself).
    assert any(s is ControlState.COOLING for _, s in changes)
