"""Unit tests for battery health tracking + charge policy (pure, no hardware)."""
import pytest

from thermostat.battery import (
    CHARGE_TEMP_MAX_C,
    HEALTH_FLOOR_PCT,
    HealthTracker,
    decide_charge,
    estimate_health_pct,
)

HOUR = 3600.0


# ── health model ─────────────────────────────────────────────────────────────

def test_new_battery_is_100_percent():
    assert estimate_health_pct(0, 0, 0, 0) == pytest.approx(100.0)


def test_cycles_degrade_health():
    # 500 full cycles ≈ 20% loss, the headline number the model is tuned to.
    assert estimate_health_pct(500, 0, 0, 0) == pytest.approx(80.0)


def test_high_soc_hours_degrade_health():
    # A year parked above 90% ≈ 7% loss.
    assert estimate_health_pct(0, 8760, 0, 0) == pytest.approx(93.0, abs=0.1)


def test_deep_discharges_degrade_health():
    assert estimate_health_pct(0, 0, 0, 10) == pytest.approx(99.5)


def test_health_never_exceeds_100_or_falls_below_floor():
    assert estimate_health_pct(0, 0, 0, 0) <= 100.0
    assert estimate_health_pct(10_000, 100_000, 100_000, 1000) == HEALTH_FLOOR_PCT


# ── cycle counting ───────────────────────────────────────────────────────────

def test_full_discharge_and_recharge_is_one_cycle():
    t = HealthTracker()
    t.step(100.0, 25.0, 4.1, 0)      # seed
    t.step(0.0, 25.0, 3.6, HOUR)     # 100 points down
    t.step(100.0, 25.0, 4.1, HOUR)   # 100 points up  => 200 total => 1 cycle
    assert t.cycles == pytest.approx(1.0)


def test_partial_charges_accrue_proportionally():
    t = HealthTracker()
    t.step(80.0, 25.0, 4.0, 0)
    t.step(60.0, 25.0, 3.8, HOUR)    # 20 points => 0.1 cycle
    assert t.cycles == pytest.approx(0.1)


def test_no_cycle_counted_on_first_sample():
    t = HealthTracker()
    t.step(50.0, 25.0, 3.8, HOUR)
    assert t.cycles == 0.0


# ── stressor accumulation ────────────────────────────────────────────────────

def test_hours_above_90_percent_accumulate():
    t = HealthTracker()
    t.step(95.0, 25.0, 4.15, HOUR)
    t.step(95.0, 25.0, 4.15, HOUR)
    assert t.high_soc_hours == pytest.approx(2.0)


def test_time_below_threshold_is_not_counted():
    t = HealthTracker()
    t.step(70.0, 25.0, 3.9, HOUR * 5)
    assert t.high_soc_hours == 0.0


def test_hot_hours_and_temperature_extremes():
    t = HealthTracker()
    t.step(50.0, 40.0, 3.8, HOUR)    # hot
    t.step(50.0, 10.0, 3.8, HOUR)    # cool
    assert t.hot_hours == pytest.approx(1.0)
    assert t.peak_temp_c == pytest.approx(40.0)
    assert t.min_temp_c == pytest.approx(10.0)


def test_deep_discharge_is_edge_triggered():
    t = HealthTracker()
    for _ in range(5):               # five samples in one excursion
        t.step(2.0, 25.0, 3.2, HOUR)
    assert t.deep_discharges == 1    # one event, not five
    t.step(50.0, 25.0, 3.9, HOUR)    # recover
    t.step(2.0, 25.0, 3.2, HOUR)     # second excursion
    assert t.deep_discharges == 2


# ── persistence ──────────────────────────────────────────────────────────────

def test_tracker_round_trips_through_dict():
    t = HealthTracker()
    t.step(95.0, 40.0, 4.15, HOUR)
    t.step(50.0, 40.0, 3.8, HOUR)
    restored = HealthTracker.from_dict(t.to_dict())
    assert restored.cycles == pytest.approx(t.cycles)
    assert restored.high_soc_hours == pytest.approx(t.high_soc_hours)
    assert restored.hot_hours == pytest.approx(t.hot_hours)
    # Continuing from a restored tracker must not double-count a phantom cycle.
    restored.step(50.0, 25.0, 3.8, HOUR)
    assert restored.cycles == pytest.approx(t.cycles)


def test_from_dict_handles_missing_state():
    assert HealthTracker.from_dict(None).cycles == 0.0
    assert HealthTracker.from_dict({}).deep_discharges == 0


# ── charge policy ────────────────────────────────────────────────────────────

def test_temperature_limits_apply_even_when_optimization_is_off():
    # Chemistry, not preference: these must hold regardless of the toggle.
    assert decide_charge(50.0, -5.0, optimized=False, local_hour=12).allow is False
    assert decide_charge(50.0, -5.0, optimized=False, local_hour=12).reason == "too_cold"
    assert decide_charge(50.0, 50.0, optimized=False, local_hour=12).allow is False
    assert decide_charge(50.0, 50.0, optimized=False, local_hour=12).reason == "too_hot"


def test_normal_mode_charges_to_full():
    d = decide_charge(99.0, 25.0, optimized=False, local_hour=12)
    assert d.allow is True and d.reason == "normal"


def test_optimized_holds_at_80_during_the_day():
    d = decide_charge(85.0, 25.0, optimized=True, local_hour=11)
    assert d.allow is False and d.reason == "optimized_hold"


def test_optimized_resumes_below_the_hysteresis_floor():
    d = decide_charge(70.0, 25.0, optimized=True, local_hour=11)
    assert d.allow is True and d.reason == "below_resume"


def test_hysteresis_band_holds_previous_state():
    # Between resume (75) and hold (80): don't chatter.
    assert decide_charge(78.0, 25.0, optimized=True, local_hour=11,
                         currently_charging=True).allow is True
    assert decide_charge(78.0, 25.0, optimized=True, local_hour=11,
                         currently_charging=False).allow is False


def test_evening_topup_allows_full_charge():
    d = decide_charge(85.0, 25.0, optimized=True, local_hour=17)
    assert d.allow is True and d.reason == "evening_topup"


def test_unknown_clock_fails_open():
    # A node that has never reached NTP must not refuse to charge.
    d = decide_charge(85.0, 25.0, optimized=True, local_hour=None)
    assert d.allow is True and d.reason == "clock_unknown"


def test_unknown_soc_fails_open():
    d = decide_charge(None, 25.0, optimized=True, local_hour=11)
    assert d.allow is True and d.reason == "soc_unknown"


def test_missing_temperature_does_not_block_charging():
    d = decide_charge(50.0, None, optimized=False, local_hour=12)
    assert d.allow is True


def test_hot_limit_boundary_is_inclusive_of_safe_values():
    # Exactly at the limit is still allowed; above it is not.
    assert decide_charge(50.0, CHARGE_TEMP_MAX_C, optimized=False, local_hour=12).allow is True
    assert decide_charge(50.0, CHARGE_TEMP_MAX_C + 0.1, optimized=False,
                         local_hour=12).allow is False
