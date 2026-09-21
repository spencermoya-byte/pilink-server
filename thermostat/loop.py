"""Control-loop runner: telemetry -> decision -> AC command.

Ties the pieces together: telemetry arrives via the MQTT ingest callback
(:meth:`on_telemetry`), the M0 :class:`~thermostat.control.Thermostat` decides the
next state on each :meth:`tick`, and the resulting command is sent to an AC
adapter — unless ``observe_only`` is set, in which case the intended command is
only logged as an event (the M2 "watch it first" mode). The live setpoint and
on/off mode are read from the store each tick (the app writes them via the
server), and the current control state is written back for the app to display.
Battery analytics update from each telemetry frame.

:meth:`tick` and :meth:`on_telemetry` take their time/inputs as arguments and
hold no wall-clock of their own, so the whole thing unit-tests with an in-memory
store and a :class:`~thermostat.ac.FakeAC`.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, replace

from thermostat.battery import gauge_snapshot
from thermostat.control import ACCommand, ACMode, Thermostat, TickResult

log = logging.getLogger("pilink.thermostat.loop")

_OFF_COMMAND = ACCommand(power=False, mode=ACMode.OFF, target_f=None)


class ControlLoop:
    def __init__(self, thermostat: Thermostat, adapter, *, store=None,
                 device_id: str = "thermostat-01", battery=None,
                 health=None, observe_only: bool = True) -> None:
        self.thermostat = thermostat
        self.adapter = adapter
        self.store = store
        self.device_id = device_id
        self.battery = battery
        self.health = health
        self.observe_only = observe_only
        self._last_charge_control: bool | None = None
        self.mode = "auto"
        self._last_temp_f: float | None = None
        self._last_sample_ts: float | None = None
        self._prev_batt_ts: float | None = None
        self._last_command = None
        self._stop: threading.Event | None = None
        self._thread: threading.Thread | None = None

    # Wire this as the MQTT ingest on_telemetry callback.
    def on_telemetry(self, t, ts: float) -> None:
        self._last_temp_f = t.temp_f
        self._last_sample_ts = ts
        dt = None if self._prev_batt_ts is None else ts - self._prev_batt_ts

        # Fuel gauge (MAX17048) is authoritative when present — it already does
        # the modelling that coulomb counting approximates.
        if t.batt_pct is not None:
            if self.store is not None:
                self.store.set_state("battery",
                                     gauge_snapshot(t.batt_pct, t.batt_rate, t.batt_v))
        # Fall back to coulomb counting only when there's no gauge (INA219 build).
        elif (self.battery is not None and dt is not None
                and t.batt_v is not None and t.batt_ma is not None):
            self.battery.step(t.batt_v, t.batt_ma, t.solar_mw or 0.0, dt)
            if self.store is not None:
                snap = self.battery.snapshot(t.batt_v, t.batt_ma)
                self.store.set_state("battery", asdict(snap))

        # Health tracking works from either source, and needs no charge-control
        # wire — it only observes. The first sample is fed with dt=0 so it SEEDS
        # the tracker (recording the starting charge level and temperature)
        # without accruing time; skipping it would silently lose the first
        # reading and under-count the first cycle.
        if self.health is not None:
            temp_c = None if t.temp_f is None else (t.temp_f - 32.0) * 5.0 / 9.0
            self.health.step(t.batt_pct, temp_c, t.batt_v, dt if dt is not None else 0.0)
            if self.store is not None:
                self.store.set_state("battery_health", asdict(self.health.snapshot()))
                self.store.set_state("battery_health_state", self.health.to_dict())

        if self.store is not None and t.charge_control != self._last_charge_control:
            self._last_charge_control = t.charge_control
            self.store.set_state("charge_control", t.charge_control)

        if t.batt_v is not None or t.batt_pct is not None:
            self._prev_batt_ts = ts

    def _sync_from_store(self) -> None:
        if self.store is None:
            return
        setpoint = self.store.get_state("setpoint")
        if setpoint is not None and setpoint != self.thermostat.cfg.setpoint_f:
            self.thermostat.cfg = replace(self.thermostat.cfg, setpoint_f=float(setpoint))
        self.mode = self.store.get_state("mode", "auto")

    def tick(self, now: float) -> TickResult | None:
        self._sync_from_store()
        if self.mode == "off":
            state_label, command, healthy, res = "off", _OFF_COMMAND, True, None
        else:
            res = self.thermostat.tick(now, self._last_temp_f, self._last_sample_ts)
            state_label, command, healthy = res.state.value, res.command, res.healthy
        if command != self._last_command:
            self._drive(state_label, command)
            self._last_command = command
        self._persist_control(state_label, command, healthy, now)
        return res

    def _drive(self, state_label: str, command: ACCommand) -> None:
        verb = "observe" if self.observe_only else "apply"
        power = "on" if command.power else "off"
        target = "" if command.target_f is None else f" @ {command.target_f:.0f}F"
        log.info("control %s: %s -> AC %s%s", verb, state_label, power, target)
        if self.observe_only:
            if self.store is not None:
                self.store.record_event(self.device_id, "control_observe",
                                        f"{state_label} {command}")
            return
        self.adapter.apply(command)
        if self.store is not None:
            self.store.record_event(self.device_id, "control_apply",
                                    f"{state_label} {command}")

    def _persist_control(self, state_label: str, command: ACCommand,
                         healthy: bool, now: float) -> None:
        if self.store is None:
            return
        self.store.set_state("control", {
            "state": state_label, "power": command.power,
            "target_f": command.target_f, "healthy": healthy, "ts": now,
        })

    def start(self, interval_s: float = 10.0) -> None:
        stop = threading.Event()

        def run() -> None:
            while not stop.is_set():
                self.tick(time.time())
                stop.wait(interval_s)

        thread = threading.Thread(target=run, daemon=True)
        self._stop = stop
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        if self._stop is not None:
            self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
