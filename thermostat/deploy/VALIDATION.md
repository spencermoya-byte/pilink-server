# Phase 2 — hardware validation runbook

End-to-end bring-up of the thermostat on the real Pi + Duo, in the safe order:
prove the data path first, watch the control decisions without touching the
compressor, then hand it the AC. Everything up to step 5 is harmless; the AC is
only driven in step 6.

Conventions: the Pi runs everything from `~/.pilink/` in the venv at
`~/.pilink/venv/`. `<pi-ip>` is your Pi (`192.168.4.88` per the handoff).

---

## 0. Deploy the code

From the repo on Windows:

```
.\deploy-pi.ps1 -PiHost <pi-ip>
```

This now also syncs `pi-server/thermostat/` → `~/.pilink/thermostat/` and installs
`paho-mqtt` + `msmart-ng` into the venv (they're in `requirements.txt`), then
restarts `pilink-server` with the new thermostat handlers.

**Sanity check** the server picked up the package:

```
ssh spencermoya@<pi-ip> "ls ~/.pilink/thermostat && ~/.pilink/venv/bin/python -c 'import thermostat, paho.mqtt.client; print(\"imports ok\")'"
```

---

## 1. Broker — Mosquitto + ACLs

```
ssh spencermoya@<pi-ip>
sudo PILINK_PI_PASS='pick-a-strong-one' \
     PILINK_ESP32_PASS='must-match-firmware-secrets.h' \
     ~/.pilink/thermostat/deploy/setup-mosquitto.sh
```

Confirm it's up and the ACLs bit:

```
systemctl is-active mosquitto
# should print: active
mosquitto_sub -h localhost -u pilink-pi -P '***' -t 'pilink/#' -v   # leave running in one shell
```

The `pilink-esp32` password **must** equal `MQTT_PASS` in the firmware's
`include/secrets.h` (and the username `MQTT_USER`).

---

## 2. Run ingest, observe-only control

In a second SSH shell — note `cd ~/.pilink` so `thermostat` is importable:

```
cd ~/.pilink
PILINK_MQTT_USER=pilink-pi PILINK_MQTT_PASS='***' \
PILINK_CONTROL=observe \
~/.pilink/venv/bin/python -m thermostat.service
```

`observe` logs the Cool/off decision it *would* make on each tick but never
touches an AC. You'll see `starting thermostat ingest ... (control=observe)`.

---

## 3. Smoke-test the pipeline (no ESP32, no AC)

From your laptop (repo dir; `pip install paho-mqtt` once):

```
python tools/sim_publisher.py --host <pi-ip> --username pilink-esp32 \
    --password '***' --scenario ramp
```

Expected in the **service** log: one `telemetry ...` line per frame, and a
`control_observe` event flipping to **cooling** as the ramp crosses ~79 °F and
back to **idle** below ~77 °F. Then confirm it persisted:

```
sqlite3 ~/.pilink/thermostat.db \
  "SELECT ts, temp_f, batt_v FROM telemetry ORDER BY ts DESC LIMIT 5;"
sqlite3 ~/.pilink/thermostat.db \
  "SELECT ts, kind, detail FROM events ORDER BY ts DESC LIMIT 10;"
```

Also exercise the failure paths:

```
python tools/sim_publisher.py --host <pi-ip> --username pilink-esp32 --password '***' \
    --scenario ramp --gap 20 --offline
```

`--gap 20` (20 s of silence) should trip a **failsafe** decision on staleness;
`--offline` writes the retained LWT and you'll see the node marked offline.

---

## 4. (Optional) real ESP32 telemetry

If the firmware's flashed, point it at the broker with the `pilink-esp32` creds
and confirm real frames arrive (`temp_f`, `humidity`, `solar_*`, `batt_*`) and
`status` = online. The decisions in the log should now track your actual room.

---

## 5. Fetch the Midea token (one-time cloud login)

Needed only for active control; fully local afterwards.

```
~/.pilink/venv/bin/msmart-ng discover --account <midea-email> --password '<pw>'
```

Note the Duo's `ip`, `id`, `token`, and `key` from the output. (If discover finds
nothing, confirm the Duo is on the same LAN and reachable.)

---

## 6. Go active — drive the Duo

Restart the service with control active and the AC env set:

```
cd ~/.pilink
PILINK_MQTT_USER=pilink-pi PILINK_MQTT_PASS='***' \
PILINK_CONTROL=active \
PILINK_AC_IP=<duo-ip> PILINK_AC_ID=<duo-id> \
PILINK_AC_TOKEN=<token> PILINK_AC_KEY=<key> \
~/.pilink/venv/bin/python -m thermostat.service
```

Drive it with the sim (or the real sensor) and verify on the actual unit:

- it powers **on to Cool** above the on-point and **fully off** below the off-point;
- no rapid cycling — a fresh Cool never starts within ~3 min of the last stop
  (min-off) and never stops within ~4 min of starting (min-on);
- cut telemetry (`--gap`) and confirm it **fails safe**: hands cooling back to the
  Duo's own thermostat rather than leaving the compressor stranded.

Then **firewall the Duo off the internet** at the router — control is fully LAN-local.

---

## 7. Setpoint / mode from the app

`set_setpoint` and `set_mode` write to the shared DB; the loop picks them up on
its next tick. Until the Phase 3 UI exists you can confirm the plumbing directly:

```
# set the app-facing setpoint by hand, then watch the loop adopt it:
sqlite3 ~/.pilink/thermostat.db "INSERT INTO state (key,value) VALUES ('setpoint','72.0') \
  ON CONFLICT(key) DO UPDATE SET value=excluded.value;"
# 'off' should power the Duo down regardless of temperature:
sqlite3 ~/.pilink/thermostat.db "INSERT INTO state (key,value) VALUES ('mode','\"off\"') \
  ON CONFLICT(key) DO UPDATE SET value=excluded.value;"
```

(The server's `set_setpoint`/`set_mode` handlers do exactly these writes, with
range-clamping and enum validation — this is just how to test without the UI.)

---

## Rollback / stop

Stop the service (Ctrl-C, or kill it). With nothing commanding it, the Duo's own
thermostat resumes — that's the designed fail-safe, so stopping is always safe.
For a permanent service, wrap the step-6 command in a systemd unit modeled on
`pilink-server.service` (ask and I'll write it).
