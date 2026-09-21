"""Thermostat control state machine — pure decision logic.

Actuation is normal power on/off, like a household thermostat:

  * ``IDLE``     -> the Duo is powered fully off (quiet, no fan).
  * ``COOLING``  -> powered on in Cool mode with its own target pinned low, so its
                    biased intake sensor can't satisfy and pre-empt us.
  * ``FAILSAFE`` -> the Duo is powered fully off whenever our room telemetry is
                    stale or implausible. It is NEVER handed back to its own
                    built-in thermostat: that sensor is inaccurate, which is the
                    reason this exists at all.

The transition function :func:`decide` is pure. :class:`Thermostat` layers the
timers and freshness bookkeeping on top but takes ``now`` as an argument, so both
unit-test without a Pi or an AC. Compressor protection (a minimum on-time and a
minimum off-time) plus the deadband bound the cycle rate so power-cycling the
unit can't short-cycle the compressor.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum


class ControlState(str, Enum):
    IDLE = "idle"
    COOLING = "cooling"
    FAILSAFE = "failsafe"


class ACMode(str, Enum):
    COOL = "cool"
    FAN = "fan"
    OFF = "off"


@dataclass(frozen=True)
class ACCommand:
    """Desired AC state the adapter should enforce (converted to msmart-ng / °C
    at the boundary). ``target_f`` is ``None`` only when powered off."""

    power: bool
    mode: ACMode
    target_f: float | None


@dataclass(frozen=True)
class ThermostatConfig:
    setpoint_f: float = 78.0
    band_high_f: float = 1.0   # turn ON at setpoint + band_high  (78 -> 79)
    band_low_f: float = 1.0    # turn OFF at setpoint - band_low   (78 -> 77)
    min_on_s: float = 240.0    # minimum cooling run (4 min)
    min_off_s: float = 180.0   # minimum compressor-off (3 min, anti short-cycle)
    cool_pin_f: float = 61.0   # ~16 °C: pin the AC's own target low while we drive it
    stale_timeout_s: float = 15.0    # 3x the default 5 s telemetry cadence
    resume_debounce_s: float = 30.0  # telemetry must be healthy this long to exit FAILSAFE
    room_min_f: float = 40.0   # plausibility band for the room sensor
    room_max_f: float = 120.0

    @property
    def on_temp_f(self) -> float:
        return self.setpoint_f + self.band_high_f

    @property
    def off_temp_f(self) -> float:
        return self.setpoint_f - self.band_low_f


def decide(current: ControlState, *, temp_f: float, on_temp_f: float,
           off_temp_f: float, elapsed_s: float, min_on_s: float, min_off_s: float,
           healthy: bool, resume_ok: bool) -> ControlState:
    """Pure next-state transition.

    ``healthy`` = telemetry fresh AND room temp plausible. ``resume_ok`` = it has
    been healthy long enough to leave FAILSAFE (debounced upstream). ``elapsed_s``
    is time spent in ``current``. When unhealthy, ``temp_f`` is ignored, so a NaN
    placeholder is safe.
    """
    if not healthy:
        return ControlState.FAILSAFE
    if current is ControlState.FAILSAFE:
        if not resume_ok:
            return ControlState.FAILSAFE
        # Resume by continuing to cool if hot (the compressor was likely running
        # under the Duo's own control, so this isn't a cold restart), else idle.
        return ControlState.COOLING if temp_f >= on_temp_f else ControlState.IDLE
    if current is ControlState.COOLING:
        if temp_f <= off_temp_f and elapsed_s >= min_on_s:
            return ControlState.IDLE
        return ControlState.COOLING
    # IDLE
    if temp_f >= on_temp_f and elapsed_s >= min_off_s:
        return ControlState.COOLING
    return ControlState.IDLE


def command_for(state: ControlState, cfg: ThermostatConfig) -> ACCommand:
    """Map a control state to the AC command that realises it.

    FAILSAFE powers the unit OFF. It used to hand cooling back to the Duo's own
    thermostat, which is exactly the thing that must never happen: the Duo's
    intake sensor reads wrong, which is the entire reason this project exists.
    Losing our own sensor is not a reason to trust the one we already know is
    bad. A warm room is recoverable; a unit quietly cooling to its own wrong
    idea of the temperature is not.

    The firmware's thermoCommandFor() matches this, and
    tools/verify-control-parity.py asserts the two agree.
    """
    if state is ControlState.COOLING:
        return ACCommand(power=True, mode=ACMode.COOL, target_f=cfg.cool_pin_f)
    return ACCommand(power=False, mode=ACMode.OFF, target_f=None)


@dataclass(frozen=True)
class TickResult:
    state: ControlState
    command: ACCommand
    changed: bool
    healthy: bool


class Thermostat:
    """Stateful driver: tracks state-entry time and telemetry freshness, and calls
    :func:`decide` each tick. Deterministic — the caller supplies ``now``."""

    def __init__(self, config: ThermostatConfig | None = None, *,
                 initial_state: ControlState = ControlState.FAILSAFE) -> None:
        self.cfg = config or ThermostatConfig()
        self.state = initial_state
        self._entered_at: float | None = None
        self._healthy_since: float | None = None

    def tick(self, now: float, temp_f: float | None,
             last_sample_ts: float | None) -> TickResult:
        cfg = self.cfg
        fresh = last_sample_ts is not None and (now - last_sample_ts) <= cfg.stale_timeout_s
        plausible = temp_f is not None and cfg.room_min_f <= temp_f <= cfg.room_max_f
        healthy = fresh and plausible

        if healthy:
            if self._healthy_since is None:
                self._healthy_since = now
        else:
            self._healthy_since = None
        resume_ok = (self._healthy_since is not None
                     and (now - self._healthy_since) >= cfg.resume_debounce_s)

        if self._entered_at is None:
            self._entered_at = now
        elapsed = now - self._entered_at

        new_state = decide(
            self.state,
            temp_f=temp_f if temp_f is not None else math.nan,
            on_temp_f=cfg.on_temp_f,
            off_temp_f=cfg.off_temp_f,
            elapsed_s=elapsed,
            min_on_s=cfg.min_on_s,
            min_off_s=cfg.min_off_s,
            healthy=healthy,
            resume_ok=resume_ok,
        )
        changed = new_state is not self.state
        if changed:
            self.state = new_state
            self._entered_at = now
        return TickResult(state=new_state, command=command_for(new_state, cfg),
                          changed=changed, healthy=healthy)
