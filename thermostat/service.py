"""Runnable entrypoint: MQTT ingest -> store, with an optional control loop.

Config comes from the environment so no secrets live in the repo:

    PILINK_MQTT_HOST (127.0.0.1)   PILINK_MQTT_PORT (1883)
    PILINK_MQTT_USER  PILINK_MQTT_PASS    PILINK_DB (~/.pilink/thermostat.db)
    PILINK_DEVICE_ID (thermostat-01)
    PILINK_CONTROL    off | observe | active | relay | relay-observe  (default off)
    PILINK_TICK_S     control-loop cadence, seconds (default 10)

    # anything that drives the Duo (active, relay) also needs:
    PILINK_AC_IP  PILINK_AC_ID  PILINK_AC_TOKEN  PILINK_AC_KEY  [PILINK_AC_PORT  PILINK_AC_FAN]

M1 ran ingest only; M2 added the Pi-side control loop. ``observe`` logs the
decision it *would* make without touching the AC; ``active`` drives the Duo via
msmart-ng.

``relay`` is Stage 2 of moving the thermostat onto the node: the ESP32 owns the
setpoint, the weekly schedule and the control loop, and publishes the state it
wants; this process only executes it. **The Pi's own control loop is structurally
OFF in relay mode** — that is the point, not an oversight. Two loops deciding for
one compressor would fight, and the node's is the one that keeps working when
this machine is down. ``relay-observe`` logs what it would do without touching
the AC, for a dry run.

The ingest + store path is unchanged in every mode.
"""
from __future__ import annotations

import logging
import os
import signal
import time

from thermostat.mqtt_ingest import MqttIngestor
from thermostat.store import Store

log = logging.getLogger("pilink.thermostat")


def default_db_path() -> str:
    return os.path.expanduser(os.environ.get("PILINK_DB", "~/.pilink/thermostat.db"))


def _log_telemetry(t, ts) -> None:
    temp = "n/a" if t.temp_f is None else f"{t.temp_f:.1f}F"
    batt = "n/a" if t.batt_v is None else f"{t.batt_v:.2f}V"
    solar = "n/a" if t.solar_mw is None else f"{t.solar_mw:.0f}mW"
    log.info("telemetry %s temp=%s batt=%s solar=%s", t.device_id, temp, batt, solar)


def build_ingestor(store, on_telemetry=_log_telemetry) -> MqttIngestor:
    return MqttIngestor(
        store,
        host=os.environ.get("PILINK_MQTT_HOST", "127.0.0.1"),
        port=int(os.environ.get("PILINK_MQTT_PORT", "1883")),
        username=os.environ.get("PILINK_MQTT_USER") or None,
        password=os.environ.get("PILINK_MQTT_PASS") or None,
        on_telemetry=on_telemetry,
    )


def build_executor():
    """Build a CommandExecutor for relay mode, or ``None`` in every other mode.

    Relay means the node decides and this process carries it out, so no local
    control loop is built — see the module docstring.
    """
    mode = os.environ.get("PILINK_CONTROL", "off").lower()
    if mode not in ("relay", "relay-observe"):
        return None
    from thermostat.ac import NullAC, build_ac_from_env
    from thermostat.executor import CommandExecutor

    observe = mode == "relay-observe"
    adapter = NullAC() if observe else build_ac_from_env()
    return CommandExecutor(adapter, observe_only=observe)


def build_control_loop(store):
    """Build a ControlLoop per PILINK_CONTROL, or ``None`` when control is off.

    Returns None in relay mode too: the node is the brain there, and a second
    loop on this machine would fight it for the compressor.
    """
    mode = os.environ.get("PILINK_CONTROL", "off").lower()
    if mode not in ("observe", "active"):
        return None
    from thermostat.ac import NullAC, build_ac_from_env
    from thermostat.analytics import BatteryEstimator
    from thermostat.control import Thermostat, ThermostatConfig
    from thermostat.loop import ControlLoop

    adapter = build_ac_from_env() if mode == "active" else NullAC()
    return ControlLoop(
        Thermostat(ThermostatConfig()), adapter, store=store,
        device_id=os.environ.get("PILINK_DEVICE_ID", "thermostat-01"),
        battery=BatteryEstimator(), observe_only=(mode != "active"),
    )


class _Stopper:
    def __init__(self) -> None:
        self.stopped = False

    def __call__(self, *_args) -> None:
        self.stopped = True


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    db = default_db_path()
    os.makedirs(os.path.dirname(db), exist_ok=True)
    store = Store(db)
    loop = build_control_loop(store)
    executor = build_executor()

    def on_telemetry(t, ts) -> None:
        _log_telemetry(t, ts)
        if loop is not None:
            loop.on_telemetry(t, ts)

    on_command = (lambda payload, ts: executor.handle(payload)) if executor else None

    ingestor = build_ingestor(store, on_telemetry)
    ingestor.on_command = on_command
    log.info("starting thermostat ingest -> %s (control=%s%s)", db,
             os.environ.get("PILINK_CONTROL", "off"),
             ", executing node commands" if executor else "")
    ingestor.start()
    if loop is not None:
        loop.start(interval_s=float(os.environ.get("PILINK_TICK_S", "10")))

    stop = _Stopper()
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    while not stop.stopped:
        time.sleep(1.0)

    if loop is not None:
        loop.stop()
    ingestor.stop()
    store.close()
    log.info("stopped")


if __name__ == "__main__":
    main()
