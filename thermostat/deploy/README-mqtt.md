# Phase 2 · M1 — Mosquitto + ingest (Pi side)

This is the deploy step for M1. The code (SQLite store + MQTT ingest) is built and
unit-tested in `pi-server/thermostat/`; this doc gets the broker + ingest service
running on the Pi.

## 1. Install + configure the broker

```
cd pi-server/thermostat/deploy
sudo PILINK_PI_PASS='choose-a-strong-one' \
     PILINK_ESP32_PASS='must-match-secrets.h' \
     ./setup-mosquitto.sh
```

Creates two least-privilege accounts:

| Account | Who | May do |
|---------|-----|--------|
| `pilink-pi` | the Pi control server | read `pilink/#`, publish `pilink/+/config` |
| `pilink-esp32` | the ESP32 node | publish only `pilink/thermostat-01/{telemetry,status}`, read its own `config` |

A leaked node credential therefore can't spoof other topics or read the bus.

**Credential mapping — get this right:**

- `pilink-esp32` username/password **must equal** `MQTT_USER` / `MQTT_PASS` in the
  firmware's `include/secrets.h`.
- The Pi service reads its own account from `PILINK_MQTT_USER` / `PILINK_MQTT_PASS`
  (set these to `pilink-pi` + its password).

## 2. Run the ingest service

```
PILINK_MQTT_USER=pilink-pi PILINK_MQTT_PASS='...' \
  python3 -m thermostat.service
```

It subscribes to `pilink/+/telemetry` and `pilink/+/status`, validates every
frame, and writes to `~/.pilink/thermostat.db` (override with `PILINK_DB`), logging
one line per frame. A systemd unit like the existing `pilink-server.service` can
wrap this later; M1 just needs it running. (Run it from `pi-server/` so
`thermostat` is importable, or install the package.)

## 3. Smoke-test without the ESP32

From any machine on the LAN (needs `pip install paho-mqtt`):

```
python tools/sim_publisher.py --host <pi-ip> --username pilink-esp32 \
    --password '...' --scenario ramp
```

Watch the service log for the frames, then confirm they landed:

```
sqlite3 ~/.pilink/thermostat.db \
  'SELECT ts, temp_f, batt_v FROM telemetry ORDER BY ts DESC LIMIT 5;'
```

Also try `--scenario discharge`, `--gap 20` (silence — the M2 control loop will
fail-safe on staleness), and `--offline` (retained LWT).

## 4. Harden

- A router firewall rule blocking the Duo (and ideally the broker port) from the
  internet — the broker is LAN-only by design.
- Broker TLS is the planned fast-follow; reuse the app↔Pi pinned-cert pattern.
