"""Air-conditioner adapter — turn control-loop :class:`ACCommand`s into actions.

The control loop depends only on the tiny sync interface (``apply`` / ``refresh``
/ ``close``), so it unit-tests against :class:`FakeAC`. :class:`MsmartAC` is the
real implementation over msmart-ng: it runs the library's async calls on a
private event-loop thread and translates our Fahrenheit power/mode/target command
into the Celsius msmart properties. The pure translation (:func:`command_to_settings`,
:func:`f_to_c_half`) is what gets tested; the on-the-wire path is validated on the
real Duo (M2 observe-only, then active).
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading

from thermostat.control import ACCommand

log = logging.getLogger("pilink.ac")

# Midea portable ACs accept ~16-30 C targets in 0.5 C steps.
DEFAULT_C_MIN = 16.0
DEFAULT_C_MAX = 30.0


def f_to_c_half(temp_f: float, c_min: float = DEFAULT_C_MIN,
                c_max: float = DEFAULT_C_MAX) -> float:
    """Fahrenheit -> Celsius rounded to the nearest 0.5 C and clamped to range."""
    c = (temp_f - 32.0) * 5.0 / 9.0
    c = round(c * 2.0) / 2.0
    return max(c_min, min(c, c_max))


def command_to_settings(command: ACCommand, *, fan: str = "auto",
                        c_min: float = DEFAULT_C_MIN,
                        c_max: float = DEFAULT_C_MAX) -> dict:
    """Pure mapping of an :class:`ACCommand` to intended msmart settings.

    Powered off -> just ``power_state=False``. Powered on -> Cool mode at the
    (converted, clamped) target with the configured fan speed.
    """
    if not command.power:
        return {"power_state": False, "fan": fan}
    return {
        "power_state": True,
        "mode": "cool",
        "target_temperature": f_to_c_half(command.target_f, c_min, c_max),
        "fan": fan,
    }


class FakeAC:
    """Records applied commands; for tests and dry runs."""

    def __init__(self) -> None:
        self.commands: list[ACCommand] = []
        self.status_value: dict | None = None

    def apply(self, command: ACCommand) -> None:
        self.commands.append(command)

    def refresh(self) -> dict | None:
        return self.status_value

    def close(self) -> None:
        pass


class NullAC:
    """Logs what it *would* do but never touches hardware — for observe-only."""

    def apply(self, command: ACCommand) -> None:
        log.info("observe-only: would apply %s", command)

    def refresh(self) -> dict | None:
        return None

    def close(self) -> None:
        pass


class _AsyncRunner:
    """Runs coroutines to completion on a private event loop in a daemon thread,
    so the sync control loop can drive msmart-ng's async API."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def run(self, coro, timeout: float = 15.0):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    def close(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=2.0)
        self._loop.close()


class MsmartAC:
    """Local control of a Midea Duo over msmart-ng (LAN, port 6444)."""

    def __init__(self, ip: str, device_id: int, *, port: int = 6444,
                 token: str | None = None, key: str | None = None,
                 fan: str = "auto", c_min: float = DEFAULT_C_MIN,
                 c_max: float = DEFAULT_C_MAX, display_fahrenheit: bool = True,
                 timeout: float = 15.0) -> None:
        from msmart.device import AirConditioner  # local import: only needed for real control
        self._ac_cls = AirConditioner
        self._dev = AirConditioner(ip, int(device_id), int(port))
        self._token = token
        self._key = key
        self._authed = False
        self._runner = _AsyncRunner()
        self.fan = fan
        self.c_min = c_min
        self.c_max = c_max
        self.display_fahrenheit = display_fahrenheit
        self.timeout = timeout

    def _ensure_auth(self) -> None:
        if not self._authed and self._token and self._key:
            self._runner.run(self._dev.authenticate(self._token, self._key), self.timeout)
            self._authed = True

    def _fan_enum(self, name: str):
        return getattr(self._ac_cls.FanSpeed, name.upper(), self._ac_cls.FanSpeed.AUTO)

    def apply(self, command: ACCommand) -> None:
        self._ensure_auth()
        settings = command_to_settings(command, fan=self.fan,
                                       c_min=self.c_min, c_max=self.c_max)
        dev = self._dev
        dev.power_state = settings["power_state"]
        if settings["power_state"]:
            dev.operational_mode = self._ac_cls.OperationalMode.COOL
            dev.target_temperature = settings["target_temperature"]
            dev.fan_speed = self._fan_enum(settings["fan"])
            if self.display_fahrenheit:
                dev.fahrenheit = True
        self._runner.run(dev.apply(), self.timeout)

    def refresh(self) -> dict | None:
        self._ensure_auth()
        self._runner.run(self._dev.refresh(), self.timeout)
        dev = self._dev
        mode = getattr(dev.operational_mode, "name", None)
        return {
            "power_state": dev.power_state,
            "operational_mode": mode,
            "target_temperature_c": dev.target_temperature,
            "indoor_temperature_c": dev.indoor_temperature,
            "online": dev.online,
        }

    def close(self) -> None:
        self._runner.close()


def build_ac_from_env() -> MsmartAC:
    """Construct an :class:`MsmartAC` from PILINK_AC_* environment variables."""
    ip = os.environ.get("PILINK_AC_IP")
    device_id = os.environ.get("PILINK_AC_ID")
    if not ip or not device_id:
        raise RuntimeError("active control needs PILINK_AC_IP and PILINK_AC_ID")
    return MsmartAC(
        ip, int(device_id),
        port=int(os.environ.get("PILINK_AC_PORT", "6444")),
        token=os.environ.get("PILINK_AC_TOKEN"),
        key=os.environ.get("PILINK_AC_KEY"),
        fan=os.environ.get("PILINK_AC_FAN", "auto"),
    )
