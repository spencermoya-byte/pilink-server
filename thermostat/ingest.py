"""Parse + validate untrusted MQTT telemetry from the sensor node — pure.

The ESP32 is treated as an untrusted source on the LAN: every telemetry frame is
JSON-decoded, checked against the Phase 1 contract, and range-checked against the
sensor hardware limits. Anything malformed or out of range raises
:class:`TelemetryError` so the ingest layer drops it (and the control loop,
seeing no fresh sample, fails safe). Missing-sensor fields are allowed per the
contract (omitted -> ``None``).
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass

# Per-field hardware-plausible bounds; a *present* value outside its range is
# treated as a corrupt frame and rejected (the whole telemetry message is dropped).
_BOUNDS: dict[str, tuple[float, float]] = {
    "temp_f": (-40.0, 185.0),
    "humidity": (0.0, 100.0),
    "solar_v": (0.0, 30.0),
    "solar_ma": (-100.0, 3000.0),
    "solar_mw": (-1000.0, 20000.0),
    "batt_v": (0.0, 6.0),
    "batt_ma": (-5000.0, 5000.0),
    "batt_mw": (-25000.0, 25000.0),
    # MAX17048 fuel gauge: state of charge, and its signed rate of change in
    # %/hour (+ = charging). These replace coulomb-counting from batt_ma.
    "batt_pct": (0.0, 100.0),
    "batt_rate": (-200.0, 200.0),
    "rssi": (-120.0, 0.0),
    "uptime_s": (0.0, 4.0e9),
}


class TelemetryError(ValueError):
    """Raised when a telemetry/status frame is malformed or out of range."""


@dataclass(frozen=True)
class Telemetry:
    device_id: str
    fw: str | None = None
    uptime_s: float | None = None
    rssi: float | None = None
    temp_f: float | None = None
    humidity: float | None = None
    solar_v: float | None = None
    solar_ma: float | None = None
    solar_mw: float | None = None
    batt_v: float | None = None
    batt_ma: float | None = None
    batt_mw: float | None = None
    batt_pct: float | None = None
    batt_rate: float | None = None
    # True when the node has a GPIO wired to the charger's EN pad and can
    # therefore pause charging. False (the default) means health is tracked but
    # not actively managed — the app disables the toggle rather than pretending.
    charge_control: bool = False
    charging: bool | None = None


def device_id_from_topic(topic: str | None) -> str | None:
    """Extract ``<id>`` from ``pilink/<id>/telemetry`` (or ``.../status``)."""
    parts = topic.split("/") if topic else []
    if len(parts) >= 3 and parts[0] == "pilink":
        return parts[1]
    return None


def _decode(payload: str | bytes | bytearray, what: str) -> str:
    if isinstance(payload, (bytes, bytearray)):
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as e:
            raise TelemetryError(f"{what} not valid UTF-8: {e}") from e
    return payload


def _num(obj: dict, key: str) -> float | None:
    if key not in obj or obj[key] is None:
        return None
    val = obj[key]
    # bool is an int subclass; reject it so True/False can't masquerade as a reading.
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise TelemetryError(f"field {key!r} is not numeric: {val!r}")
    val = float(val)
    if math.isnan(val) or math.isinf(val):
        raise TelemetryError(f"field {key!r} is not finite")
    lo, hi = _BOUNDS[key]
    if not lo <= val <= hi:
        raise TelemetryError(f"field {key!r}={val} out of range [{lo}, {hi}]")
    return val


def parse_telemetry(payload: str | bytes | bytearray, *,
                    topic: str | None = None) -> Telemetry:
    """Parse and validate a telemetry payload. Raises :class:`TelemetryError`."""
    text = _decode(payload, "payload")
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError) as e:
        raise TelemetryError(f"payload not valid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise TelemetryError(f"telemetry must be a JSON object, got {type(obj).__name__}")

    device_id = obj.get("id") or device_id_from_topic(topic)
    if not isinstance(device_id, str) or not device_id.strip():
        raise TelemetryError("missing device id ('id' field or pilink/<id>/... topic)")

    fw = obj.get("fw")
    if fw is not None and not isinstance(fw, str):
        raise TelemetryError("field 'fw' must be a string")

    def _flag(key: str, default=None):
        val = obj.get(key, default)
        if val is not None and not isinstance(val, bool):
            raise TelemetryError(f"field {key!r} must be a boolean")
        return val

    return Telemetry(
        device_id=device_id.strip(),
        fw=fw,
        uptime_s=_num(obj, "uptime_s"),
        rssi=_num(obj, "rssi"),
        temp_f=_num(obj, "temp_f"),
        humidity=_num(obj, "humidity"),
        solar_v=_num(obj, "solar_v"),
        solar_ma=_num(obj, "solar_ma"),
        solar_mw=_num(obj, "solar_mw"),
        batt_v=_num(obj, "batt_v"),
        batt_ma=_num(obj, "batt_ma"),
        batt_mw=_num(obj, "batt_mw"),
        batt_pct=_num(obj, "batt_pct"),
        batt_rate=_num(obj, "batt_rate"),
        charge_control=bool(_flag("charge_control", False)),
        charging=_flag("charging"),
    )


_STATUS_VALUES = {"online": True, "offline": False}


def parse_status(payload: str | bytes | bytearray) -> bool:
    """Parse a retained LWT status payload into ``online`` (True) / ``offline``."""
    text = _decode(payload, "status").strip().strip('"').lower()
    if text not in _STATUS_VALUES:
        raise TelemetryError(f"status must be 'online' or 'offline', got {payload!r}")
    return _STATUS_VALUES[text]
