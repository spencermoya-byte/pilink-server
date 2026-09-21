"""Synthetic telemetry generation for local end-to-end testing — pure.

Produces contract-shaped telemetry dicts for a few scenarios (steady state, a
temperature ramp, battery discharge/charge) with no I/O, so tests can round-trip
them through :func:`thermostat.ingest.parse_telemetry` and
``tools/sim_publisher.py`` can publish them to a real broker with no hardware
attached.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class NodeSim:
    """A tiny model of the sensor node that emits contract-shaped frames."""

    device_id: str = "thermostat-01"
    fw: str = "0.1.0"
    temp_f: float = 78.0
    humidity: float = 48.0
    batt_v: float = 3.90
    solar_v: float = 6.0
    uptime_s: int = 0

    def frame(self, *, temp_f: float | None = None, solar_ma: float = 0.0,
              batt_ma: float = 0.0, dt_s: float = 5.0,
              batt_pct: float | None = None, batt_rate: float | None = None,
              charge_control: bool | None = None) -> dict:
        """Build one contract-shaped telemetry frame.

        Passing ``batt_pct``/``batt_rate`` emits the MAX17048 fuel-gauge shape
        (what the real node sends); leaving them out emits the older INA219
        current-sensor shape. Both are valid telemetry, so this doubles as a
        regression check that the Pi still accepts either.
        """
        if temp_f is not None:
            self.temp_f = temp_f
        self.uptime_s += int(dt_s)
        solar_mw = solar_ma * self.solar_v
        batt_mw = batt_ma * self.batt_v
        frame = {
            "id": self.device_id,
            "fw": self.fw,
            "uptime_s": self.uptime_s,
            "rssi": -55,
            "temp_f": round(self.temp_f, 2),
            "humidity": round(self.humidity, 2),
            "solar_v": round(self.solar_v, 2),
            "solar_ma": round(solar_ma, 1),
            "solar_mw": round(solar_mw, 1),
            "batt_v": round(self.batt_v, 3),
        }
        if batt_pct is None:
            frame["batt_ma"] = round(batt_ma, 1)
            frame["batt_mw"] = round(batt_mw, 1)
        else:
            frame["batt_pct"] = round(batt_pct, 1)
            if batt_rate is not None:
                frame["batt_rate"] = round(batt_rate, 2)
        if charge_control is not None:
            frame["charge_control"] = charge_control
        return frame


def ramp(sim: NodeSim, start_f: float, end_f: float, steps: int,
         *, solar_ma: float = 0.0, batt_ma: float = 0.0,
         dt_s: float = 5.0) -> list[dict]:
    """A list of frames whose temperature ramps linearly from start to end."""
    frames = []
    span = max(steps - 1, 1)
    for i in range(steps):
        temp = start_f + (end_f - start_f) * (i / span)
        frames.append(sim.frame(temp_f=temp, solar_ma=solar_ma,
                                 batt_ma=batt_ma, dt_s=dt_s))
    return frames
