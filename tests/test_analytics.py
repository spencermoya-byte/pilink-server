"""Unit tests for the pure battery + solar analytics (no Pi, no clock)."""
import math

import pytest

from thermostat import analytics as a


# ── coulomb integration ─────────────────────────────────────────────────────────

def test_coulomb_step_charges_and_discharges():
    # +1000 mA (1 A) for 3600 s adds exactly 1 Ah.
    assert a.coulomb_step(2.0, 1000.0, 3600.0) == pytest.approx(3.0)
    # -500 mA for 1800 s removes 0.25 Ah.
    assert a.coulomb_step(2.0, -500.0, 1800.0) == pytest.approx(1.75)


def test_coulomb_step_zero_dt_is_noop():
    assert a.coulomb_step(1.234, 999.0, 0.0) == pytest.approx(1.234)


# ── soc_percent ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("soc,cap,pct", [
    (5.0, 5.0, 100.0),
    (2.5, 5.0, 50.0),
    (0.0, 5.0, 0.0),
    (6.0, 5.0, 100.0),   # clamps high
    (-1.0, 5.0, 0.0),    # clamps low
])
def test_soc_percent(soc, cap, pct):
    assert a.soc_percent(soc, cap) == pytest.approx(pct)


def test_soc_percent_zero_capacity_is_safe():
    assert a.soc_percent(1.0, 0.0) == 0.0


# ── full detection ──────────────────────────────────────────────────────────────

def test_is_full_at_cv_taper():
    # 5 Ah cell -> C/20 = 250 mA taper threshold.
    assert a.is_full(4.20, 200.0, 5.0) is True
    assert a.is_full(4.21, 250.0, 5.0) is True


@pytest.mark.parametrize("v,ma", [
    (4.10, 200.0),   # not at full voltage yet
    (4.20, 400.0),   # still bulk-charging above the taper
    (4.20, 0.0),     # resting, not charging -> not a full anchor
    (4.20, -300.0),  # discharging
])
def test_is_full_negatives(v, ma):
    assert a.is_full(v, ma, 5.0) is False


# ── time to empty / full ────────────────────────────────────────────────────────

def test_time_to_empty_discharging():
    # 2 Ah left, discharging at 1 A -> 2 h = 7200 s.
    assert a.time_to_empty_s(2.0, -1000.0) == pytest.approx(7200.0)


def test_time_to_empty_none_when_not_discharging():
    assert a.time_to_empty_s(2.0, 0.0) is None
    assert a.time_to_empty_s(2.0, 500.0) is None


def test_time_to_full_charging():
    # 4 Ah into a 5 Ah cell, 1 Ah to go at 0.5 A -> 2 h.
    assert a.time_to_full_s(4.0, 5.0, 500.0) == pytest.approx(7200.0)


def test_time_to_full_none_or_zero():
    assert a.time_to_full_s(4.0, 5.0, -100.0) is None
    assert a.time_to_full_s(5.0, 5.0, 100.0) == 0.0


# ── solar energy ────────────────────────────────────────────────────────────────

def test_energy_step_wh():
    # 3600 mW (3.6 W) for 3600 s -> 3.6 Wh.
    assert a.energy_step_wh(0.0, 3600.0, 3600.0) == pytest.approx(3.6)


# ── OCV helpers ─────────────────────────────────────────────────────────────────

def test_ir_compensation_direction():
    # Charging reads high -> OCV lower; discharging reads low -> OCV higher.
    assert a.ir_compensated_ocv(4.00, 1000.0, 0.15) == pytest.approx(3.85)
    assert a.ir_compensated_ocv(3.70, -1000.0, 0.15) == pytest.approx(3.85)


def test_ocv_to_soc_monotonic_and_clamped():
    assert a.ocv_to_soc_percent(3.0) == 0.0
    assert a.ocv_to_soc_percent(4.3) == 100.0
    mid = a.ocv_to_soc_percent(3.80)
    assert 40.0 < mid < 70.0
    # monotonic non-decreasing across the table
    xs = [3.3, 3.5, 3.7, 3.8, 3.9, 4.0, 4.1, 4.2]
    ys = [a.ocv_to_soc_percent(x) for x in xs]
    assert ys == sorted(ys)


# ── BatteryEstimator flows ──────────────────────────────────────────────────────

def test_estimator_full_anchor_resets_to_100():
    est = a.BatteryEstimator(capacity_ah=5.0, soc_ah=3.0)
    # A tapered charge sample at 4.2 V should re-anchor to full.
    est.step(4.20, 200.0, solar_mw=1200.0, dt_s=5.0)
    snap = est.snapshot(4.20, 200.0)
    assert snap.soc_percent == pytest.approx(100.0)
    assert snap.soc_ah == pytest.approx(5.0)


def test_estimator_overnight_discharge_tracks_down():
    est = a.BatteryEstimator(capacity_ah=5.0, soc_ah=5.0)
    # 8 h at -250 mA with no sun = -2.0 Ah -> 60%.
    for _ in range(8):
        est.step(3.85, -250.0, solar_mw=0.0, dt_s=3600.0)
    snap = est.snapshot(3.85, -250.0)
    assert snap.soc_ah == pytest.approx(3.0, abs=1e-6)
    assert snap.soc_percent == pytest.approx(60.0)
    assert snap.time_to_empty_s == pytest.approx(3.0 / 0.25 * 3600.0)


def test_estimator_seeds_from_voltage_when_uninitialised():
    est = a.BatteryEstimator(capacity_ah=5.0)  # soc_ah unknown
    est.step(3.90, 0.0, dt_s=0.0)
    assert est.soc_ah is not None
    assert 0.0 < est.soc_ah <= 5.0


def test_estimator_solar_accumulates_and_resets():
    est = a.BatteryEstimator(capacity_ah=5.0, soc_ah=4.0)
    est.step(3.9, 100.0, solar_mw=3600.0, dt_s=3600.0)
    assert est.solar_wh_today == pytest.approx(3.6)
    est.reset_daily()
    assert est.solar_wh_today == 0.0


def test_estimator_drift_alarm_when_coulomb_and_voltage_disagree():
    # Coulomb says ~full but the resting voltage says nearly empty -> drift flag.
    est = a.BatteryEstimator(capacity_ah=5.0, soc_ah=5.0)
    snap = est.snapshot(3.50, 0.0)
    assert snap.drift_alarm is True


def test_snapshot_fields_are_finite():
    est = a.BatteryEstimator(capacity_ah=5.0, soc_ah=2.5)
    snap = est.snapshot(3.8, -200.0)
    assert math.isfinite(snap.soc_percent)
    assert math.isfinite(snap.ocv_v)
