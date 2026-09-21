"""Battery + solar analytics for the thermostat sensor node — pure functions.

Everything here is deterministic and I/O-free: it takes numbers (plus a caller-
supplied dt) and returns numbers, so it unit-tests without a Pi, a broker, or a
wall clock. The battery INA219 reports *net* battery current (``batt_ma``, with
``+`` = charging), so state-of-charge is a coulomb integral of that one signal,
periodically re-anchored to 100% at detected full charge and sanity-checked
against an IR-compensated open-circuit-voltage estimate.

Capacity learning (deriving true usable Ah from the charge counted between an
empty anchor and a full anchor) is intentionally left for a later milestone; for
now ``usable_capacity_ah`` defaults to the nameplate capacity.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise

DEFAULT_FULL_V = 4.20
DEFAULT_EMPTY_V = 3.50
DEFAULT_TAPER_FRACTION = 0.05  # charge current below C/20 (while at full_v) => full
DEFAULT_R_INTERNAL_OHM = 0.15  # cell + wiring; rough, used only for the OCV sanity check
DEFAULT_DRIFT_ALARM_PCT = 15.0

# Approximate resting OCV -> SoC for a single-cell LiPo. Deliberately coarse: it
# is a sanity anchor against the (more accurate) coulomb integral, never primary.
_OCV_SOC_TABLE = [
    (3.30, 0.0), (3.50, 5.0), (3.60, 10.0), (3.70, 25.0), (3.75, 40.0),
    (3.80, 55.0), (3.85, 68.0), (3.90, 78.0), (3.95, 87.0), (4.00, 92.0),
    (4.10, 97.0), (4.20, 100.0),
]


def clamp(x: float, lo: float, hi: float) -> float:
    """Clamp ``x`` into the inclusive range [``lo``, ``hi``]."""
    return max(lo, min(x, hi))


def coulomb_step(soc_ah: float, batt_ma: float, dt_s: float) -> float:
    """Integrate net battery current over ``dt_s`` seconds into charge (Ah)."""
    return soc_ah + (batt_ma / 1000.0) * (dt_s / 3600.0)


def soc_percent(soc_ah: float, usable_capacity_ah: float) -> float:
    """State of charge as a 0-100% of usable capacity."""
    if usable_capacity_ah <= 0:
        return 0.0
    return clamp(soc_ah / usable_capacity_ah * 100.0, 0.0, 100.0)


def is_full(batt_v: float, batt_ma: float, capacity_ah: float,
            full_v: float = DEFAULT_FULL_V,
            taper_fraction: float = DEFAULT_TAPER_FRACTION) -> bool:
    """True at the CV-phase full-charge knee: at ``full_v`` and still taking only a
    trickle (0 < charge current <= C * ``taper_fraction``)."""
    taper_ma = capacity_ah * 1000.0 * taper_fraction
    return batt_v >= full_v and 0.0 < batt_ma <= taper_ma


def time_to_empty_s(soc_ah: float, batt_ma: float) -> float | None:
    """Seconds until empty at the current net current, or ``None`` if not
    discharging (``batt_ma`` >= 0)."""
    if batt_ma >= 0:
        return None
    amps = abs(batt_ma) / 1000.0
    if amps == 0:
        return None
    return soc_ah / amps * 3600.0


def time_to_full_s(soc_ah: float, usable_capacity_ah: float,
                   batt_ma: float) -> float | None:
    """Seconds until full at the current net charge current, or ``None`` if not
    charging (``batt_ma`` <= 0)."""
    if batt_ma <= 0:
        return None
    remaining = usable_capacity_ah - soc_ah
    if remaining <= 0:
        return 0.0
    return remaining / (batt_ma / 1000.0) * 3600.0


def energy_step_wh(accum_wh: float, power_mw: float, dt_s: float) -> float:
    """Accumulate milliwatt power over ``dt_s`` seconds into watt-hours."""
    return accum_wh + power_mw * dt_s / 3.6e6


def ir_compensated_ocv(batt_v: float, batt_ma: float,
                       r_internal_ohm: float = DEFAULT_R_INTERNAL_OHM) -> float:
    """Estimate open-circuit voltage from a loaded/charging terminal reading.

    ``batt_ma`` is signed (+ charging), so ``V - I*R`` corrects in both
    directions: charging reads high (subtract), discharging reads low (add).
    """
    return batt_v - (batt_ma / 1000.0) * r_internal_ohm


def ocv_to_soc_percent(v_oc: float) -> float:
    """Interpolate the coarse LiPo OCV->SoC table (clamped at the ends)."""
    tbl = _OCV_SOC_TABLE
    if v_oc <= tbl[0][0]:
        return tbl[0][1]
    if v_oc >= tbl[-1][0]:
        return tbl[-1][1]
    for (v0, s0), (v1, s1) in pairwise(tbl):
        if v0 <= v_oc <= v1:
            frac = (v_oc - v0) / (v1 - v0)
            return s0 + frac * (s1 - s0)
    return tbl[-1][1]  # unreachable given the guards above


@dataclass(frozen=True)
class BatterySnapshot:
    soc_ah: float
    soc_percent: float
    time_to_empty_s: float | None
    time_to_full_s: float | None
    ocv_v: float
    ocv_soc_percent: float
    drift_alarm: bool
    solar_wh_today: float


@dataclass
class BatteryEstimator:
    """Coulomb-counting SoC tracker with voltage re-anchoring at full charge.

    Stateful but deterministic: feed it ``(batt_v, batt_ma, solar_mw, dt_s)``
    samples via :meth:`step` and read a :class:`BatterySnapshot` from
    :meth:`snapshot`. No clock or I/O — ``dt_s`` is supplied by the caller.
    """

    capacity_ah: float = 5.0
    usable_capacity_ah: float | None = None
    soc_ah: float | None = None
    full_v: float = DEFAULT_FULL_V
    taper_fraction: float = DEFAULT_TAPER_FRACTION
    r_internal_ohm: float = DEFAULT_R_INTERNAL_OHM
    drift_alarm_pct: float = DEFAULT_DRIFT_ALARM_PCT
    solar_wh_today: float = 0.0

    def __post_init__(self) -> None:
        if self.usable_capacity_ah is None:
            self.usable_capacity_ah = self.capacity_ah

    def seed_from_voltage(self, batt_v: float, batt_ma: float = 0.0) -> None:
        """Initialise SoC from an IR-compensated voltage estimate (used when no
        coulomb history exists yet, e.g. first boot before a full anchor)."""
        ocv = ir_compensated_ocv(batt_v, batt_ma, self.r_internal_ohm)
        self.soc_ah = ocv_to_soc_percent(ocv) / 100.0 * self.usable_capacity_ah

    def step(self, batt_v: float, batt_ma: float,
             solar_mw: float = 0.0, dt_s: float = 0.0) -> None:
        if self.soc_ah is None:
            self.seed_from_voltage(batt_v, batt_ma)
        self.soc_ah = coulomb_step(self.soc_ah, batt_ma, dt_s)
        if is_full(batt_v, batt_ma, self.capacity_ah, self.full_v, self.taper_fraction):
            self.soc_ah = self.usable_capacity_ah
        self.soc_ah = clamp(self.soc_ah, 0.0, self.usable_capacity_ah)
        self.solar_wh_today = energy_step_wh(self.solar_wh_today, solar_mw, dt_s)

    def snapshot(self, batt_v: float, batt_ma: float) -> BatterySnapshot:
        soc = self.soc_ah if self.soc_ah is not None else 0.0
        pct = soc_percent(soc, self.usable_capacity_ah)
        ocv = ir_compensated_ocv(batt_v, batt_ma, self.r_internal_ohm)
        ocv_pct = ocv_to_soc_percent(ocv)
        return BatterySnapshot(
            soc_ah=soc,
            soc_percent=pct,
            time_to_empty_s=time_to_empty_s(soc, batt_ma),
            time_to_full_s=time_to_full_s(soc, self.usable_capacity_ah, batt_ma),
            ocv_v=ocv,
            ocv_soc_percent=ocv_pct,
            drift_alarm=abs(pct - ocv_pct) >= self.drift_alarm_pct,
            solar_wh_today=self.solar_wh_today,
        )

    def reset_daily(self) -> None:
        """Zero the per-day solar energy accumulator (call at local midnight)."""
        self.solar_wh_today = 0.0
