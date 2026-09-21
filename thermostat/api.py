"""App-facing thermostat API helpers — pure builders + input validation.

The pilink-server handlers are thin wrappers over these: they read the shared
SQLite store (written by ``thermostat.service``) to build the status/history the
app shows, and validate the setpoint/mode writes that the control loop then picks
up. Keeping the shaping + validation here (rather than inlined in the 178 KB
server) means it unit-tests against an in-memory :class:`~thermostat.store.Store`.
"""
from __future__ import annotations

import math
import time

SETPOINT_MIN_F = 68.0
SETPOINT_MAX_F = 85.0
MODES = ("auto", "off")


def clamp_setpoint(value) -> float:
    """Coerce + clamp an app-supplied setpoint into the safe range."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"setpoint must be a number, got {value!r}") from None
    if math.isnan(f):
        raise ValueError("setpoint must be a finite number")
    return max(SETPOINT_MIN_F, min(f, SETPOINT_MAX_F))


def validate_mode(value) -> str:
    if value not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {value!r}")
    return value


def set_setpoint(store, value) -> dict:
    f = clamp_setpoint(value)
    store.set_state("setpoint", f)
    return {"setpoint": f}


def set_mode(store, value) -> dict:
    m = validate_mode(value)
    store.set_state("mode", m)
    return {"mode": m}


def set_optimized_charging(store, value) -> dict:
    """Enable/disable Apple-style optimized charging. Accepted even when no
    charge-control wire is present — the setting persists and takes effect if the
    wire is added later, rather than being silently refused."""
    if not isinstance(value, bool):
        raise ValueError(f"optimized_charging must be true or false, got {value!r}")
    store.set_state("optimized_charging", value)
    return {"optimized_charging": value}


def _room(t) -> dict | None:
    if t is None:
        return None
    return {"temp_f": t.temp_f, "humidity": t.humidity,
            "solar_v": t.solar_v, "solar_ma": t.solar_ma, "solar_mw": t.solar_mw,
            "batt_v": t.batt_v, "batt_ma": t.batt_ma, "batt_mw": t.batt_mw}


def build_status(store, device_id: str = "thermostat-01", *,
                 now: float | None = None) -> dict:
    """Assemble the full thermostat snapshot the app shows.

    ``reading_age_s`` is computed HERE, on the Pi, rather than sending a raw
    timestamp for the phone to subtract: the age is then immune to clock skew
    between the Pi and the device, so the app can trust it to decide whether the
    readings it is showing are actually live.
    """
    now = time.time() if now is None else now
    latest = store.latest_telemetry(device_id)
    latest_ts = store.latest_telemetry_ts(device_id)
    node = store.get_node_status(device_id)
    control = store.get_state("control")
    setpoint = store.get_state("setpoint")
    # "configured" = this Pi is actually running a thermostat: any telemetry seen,
    # a node status, or control/setpoint state written. Lets the app auto-detect
    # thermostat Pis and keep the feature hidden on plain ones (an empty DB the
    # server just created on first query stays configured=False).
    configured = (latest is not None or node is not None
                  or control is not None or setpoint is not None)
    return {
        "device_id": device_id,
        "configured": configured,
        "online": node["online"] if node else False,
        "last_seen": node["ts"] if node else None,
        # Seconds since the newest reading, or None if no reading has EVER
        # arrived. The app uses this to label readings live vs stale.
        "reading_age_s": (now - latest_ts) if latest_ts is not None else None,
        "setpoint_f": setpoint,
        "mode": store.get_state("mode", "auto"),
        "room": _room(latest),
        "control": control,
        "battery": store.get_state("battery"),
        "battery_health": store.get_state("battery_health"),
        # False when the node has no wire to the charger's EN pad: health is
        # still tracked, but the app disables the optimized-charging toggle
        # instead of offering a control that would do nothing.
        "charge_control": bool(store.get_state("charge_control", False)),
        "optimized_charging": bool(store.get_state("optimized_charging", False)),
    }


def _coerce_int(value, *, default: int, lo: int, hi: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(n, hi))


def _coerce_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def build_history(store, device_id: str = "thermostat-01", *,
                  since=None, limit=None) -> list[dict]:
    lim = _coerce_int(limit, default=500, lo=1, hi=5000)
    rows = store.telemetry_history(device_id, since=_coerce_float(since), limit=lim)
    return [{"ts": r["ts"], "temp_f": r["temp_f"], "batt_v": r["batt_v"],
             "solar_mw": r["solar_mw"]} for r in rows]
