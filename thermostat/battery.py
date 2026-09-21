"""Battery health tracking and charge management — pure logic.

Two related jobs, both I/O-free so they unit-test without hardware:

* :class:`HealthTracker` accumulates the *stressors* that age a lithium cell —
  charge cycles, hours spent at high state-of-charge, hours spent hot, and
  deep-discharge events — and derives an **estimated** health percentage.
* :func:`decide_charge` says whether charging should be allowed right now,
  implementing the Apple-style "hold at 80%, top up before you need it" policy
  plus temperature safety limits.

**On the honesty of "health %":** a real capacity measurement requires counting
charge in and out across a full cycle, which needs current sensing. The MAX17048
is a voltage-model gauge and cannot do that, so the number here is *modelled*
from stressors rather than measured. The coefficients below are literature-typical
for consumer LiPo, documented and tunable — but this is an estimate and the UI
labels it as one.

**Charge control is optional.** Pausing charging requires a GPIO wired to the
bq24074's EN pad. When that wire is absent the node reports
``charge_control=False``: health tracking still works, :func:`decide_charge` is
simply never acted on, and the app disables the toggle rather than lying about it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── Health model coefficients ────────────────────────────────────────────────
# Rough but defensible for consumer LiPo. Sources vary; these are chosen so the
# model produces sane totals: ~500 full cycles -> ~20% loss, and a year parked
# at high charge -> ~7% loss, which is the right order of magnitude.
LOSS_PER_CYCLE_PCT = 0.040        # 500 cycles ≈ 20%
LOSS_PER_HIGH_SOC_HOUR_PCT = 0.0008   # 8760 h at >90% ≈ 7%/yr
LOSS_PER_HOT_HOUR_PCT = 0.0015    # heat compounds calendar aging
LOSS_PER_DEEP_DISCHARGE_PCT = 0.05    # each deep discharge is notably damaging
HEALTH_FLOOR_PCT = 50.0           # don't report nonsense at extreme age

HIGH_SOC_THRESHOLD_PCT = 90.0     # "parked full" — the dominant calendar stressor
HOT_THRESHOLD_C = 35.0            # above this, aging accelerates markedly
DEEP_DISCHARGE_V = 3.30           # below this the cell is being abused

# ── Charge policy defaults (Apple-style) ─────────────────────────────────────
HOLD_PCT = 80.0                   # daytime ceiling when optimized charging is on
RESUME_PCT = 75.0                 # hysteresis floor — resume charging below this
TOPUP_HOUR = 16                   # local hour to allow a full charge before night
CHARGE_TEMP_MIN_C = 0.0           # charging below freezing causes lithium plating
CHARGE_TEMP_MAX_C = 45.0          # charging hot degrades the cell fast


def estimate_health_pct(cycles: float, high_soc_hours: float,
                        hot_hours: float, deep_discharges: int) -> float:
    """Model remaining capacity as a percentage of original. See module docstring
    for why this is an estimate rather than a measurement."""
    loss = (cycles * LOSS_PER_CYCLE_PCT
            + high_soc_hours * LOSS_PER_HIGH_SOC_HOUR_PCT
            + hot_hours * LOSS_PER_HOT_HOUR_PCT
            + deep_discharges * LOSS_PER_DEEP_DISCHARGE_PCT)
    return max(HEALTH_FLOOR_PCT, min(100.0, 100.0 - loss))


@dataclass(frozen=True)
class HealthSnapshot:
    estimated_health_pct: float
    cycles: float
    high_soc_hours: float
    hot_hours: float
    deep_discharges: int
    peak_temp_c: float | None
    min_temp_c: float | None


@dataclass
class HealthTracker:
    """Accumulates ageing stressors from telemetry samples.

    Deterministic and clock-free: the caller supplies ``dt_s``. Persist
    :meth:`to_dict` between restarts so history isn't lost.
    """

    cycles: float = 0.0
    high_soc_hours: float = 0.0
    hot_hours: float = 0.0
    deep_discharges: int = 0
    peak_temp_c: float | None = None
    min_temp_c: float | None = None
    _last_soc: float | None = field(default=None, repr=False)
    _in_deep_discharge: bool = field(default=False, repr=False)

    def step(self, soc_pct: float | None, temp_c: float | None,
             batt_v: float | None, dt_s: float) -> None:
        hours = max(0.0, dt_s) / 3600.0

        if soc_pct is not None:
            # One "equivalent full cycle" = 200 percentage points of movement
            # (100 down + 100 up), so partial charges accrue proportionally.
            if self._last_soc is not None:
                self.cycles += abs(soc_pct - self._last_soc) / 200.0
            self._last_soc = soc_pct
            if soc_pct >= HIGH_SOC_THRESHOLD_PCT:
                self.high_soc_hours += hours

        if temp_c is not None:
            if temp_c >= HOT_THRESHOLD_C:
                self.hot_hours += hours
            self.peak_temp_c = temp_c if self.peak_temp_c is None else max(self.peak_temp_c, temp_c)
            self.min_temp_c = temp_c if self.min_temp_c is None else min(self.min_temp_c, temp_c)

        if batt_v is not None:
            # Edge-triggered: one event per excursion, not one per sample.
            if batt_v <= DEEP_DISCHARGE_V and not self._in_deep_discharge:
                self.deep_discharges += 1
                self._in_deep_discharge = True
            elif batt_v > DEEP_DISCHARGE_V + 0.1:
                self._in_deep_discharge = False

    def snapshot(self) -> HealthSnapshot:
        return HealthSnapshot(
            estimated_health_pct=estimate_health_pct(
                self.cycles, self.high_soc_hours, self.hot_hours, self.deep_discharges),
            cycles=self.cycles,
            high_soc_hours=self.high_soc_hours,
            hot_hours=self.hot_hours,
            deep_discharges=self.deep_discharges,
            peak_temp_c=self.peak_temp_c,
            min_temp_c=self.min_temp_c,
        )

    def to_dict(self) -> dict:
        return {"cycles": self.cycles, "high_soc_hours": self.high_soc_hours,
                "hot_hours": self.hot_hours, "deep_discharges": self.deep_discharges,
                "peak_temp_c": self.peak_temp_c, "min_temp_c": self.min_temp_c,
                "last_soc": self._last_soc}

    @classmethod
    def from_dict(cls, d: dict | None) -> HealthTracker:
        if not d:
            return cls()
        t = cls(
            cycles=float(d.get("cycles", 0.0)),
            high_soc_hours=float(d.get("high_soc_hours", 0.0)),
            hot_hours=float(d.get("hot_hours", 0.0)),
            deep_discharges=int(d.get("deep_discharges", 0)),
            peak_temp_c=d.get("peak_temp_c"),
            min_temp_c=d.get("min_temp_c"),
        )
        t._last_soc = d.get("last_soc")
        return t


def time_to_empty_s(soc_pct: float | None, rate_pct_per_hr: float | None) -> float | None:
    """Seconds until empty from the fuel gauge's %/hour rate, or None if not
    discharging. (MAX17048 reports a signed rate; negative = discharging.)"""
    if soc_pct is None or rate_pct_per_hr is None or rate_pct_per_hr >= 0:
        return None
    return soc_pct / abs(rate_pct_per_hr) * 3600.0


def time_to_full_s(soc_pct: float | None, rate_pct_per_hr: float | None) -> float | None:
    """Seconds until full, or None if not charging."""
    if soc_pct is None or rate_pct_per_hr is None or rate_pct_per_hr <= 0:
        return None
    remaining = max(0.0, 100.0 - soc_pct)
    return remaining / rate_pct_per_hr * 3600.0


def gauge_snapshot(batt_pct: float | None, batt_rate: float | None,
                   batt_v: float | None) -> dict:
    """Battery card payload built straight from the fuel gauge — no coulomb
    counting, no drift correction, because the chip already did that work."""
    return {
        "soc_percent": batt_pct,
        "rate_pct_per_hr": batt_rate,
        "batt_v": batt_v,
        "time_to_empty_s": time_to_empty_s(batt_pct, batt_rate),
        "time_to_full_s": time_to_full_s(batt_pct, batt_rate),
        "source": "fuel_gauge",
    }


@dataclass(frozen=True)
class ChargeDecision:
    """Whether charging should be permitted, and why (the reason is shown in the
    app so the behaviour is never mysterious)."""

    allow: bool
    reason: str


def decide_charge(soc_pct: float | None, temp_c: float | None, *,
                  optimized: bool, local_hour: int | None,
                  currently_charging: bool = True,
                  hold_pct: float = HOLD_PCT, resume_pct: float = RESUME_PCT,
                  topup_hour: int = TOPUP_HOUR,
                  temp_min_c: float = CHARGE_TEMP_MIN_C,
                  temp_max_c: float = CHARGE_TEMP_MAX_C) -> ChargeDecision:
    """Pure charge-gating decision.

    Temperature limits apply **regardless** of the optimized-charging toggle —
    they are a safety property of lithium chemistry, not a user preference.
    Charging below freezing plates lithium onto the anode (permanent damage and a
    genuine safety issue); charging hot ages the cell rapidly.
    """
    if temp_c is not None:
        if temp_c < temp_min_c:
            return ChargeDecision(False, "too_cold")
        if temp_c > temp_max_c:
            return ChargeDecision(False, "too_hot")

    if not optimized:
        return ChargeDecision(True, "normal")

    # Evening top-up: enter the night full, the way a phone finishes charging
    # before your alarm. Unknown clock -> fail open (charge normally).
    if local_hour is None:
        return ChargeDecision(True, "clock_unknown")
    if local_hour >= topup_hour:
        return ChargeDecision(True, "evening_topup")

    if soc_pct is None:
        return ChargeDecision(True, "soc_unknown")
    if soc_pct >= hold_pct:
        return ChargeDecision(False, "optimized_hold")
    if soc_pct <= resume_pct:
        return ChargeDecision(True, "below_resume")
    # Inside the hysteresis band: keep doing whatever we were doing, so the
    # charger doesn't chatter on/off around the threshold.
    return ChargeDecision(currently_charging, "hysteresis")
