#!/usr/bin/env bash
# Set up Mosquitto for the PiLink thermostat: LAN-only, auth required, per-user
# ACLs (least privilege). Run on the Raspberry Pi with sudo. Re-running updates
# the config and (re)sets the two account passwords.
#
#   sudo PILINK_PI_PASS='...' PILINK_ESP32_PASS='...' ./setup-mosquitto.sh
#
# The esp32 account's username/password MUST match MQTT_USER / MQTT_PASS in the
# firmware's include/secrets.h. The Pi service reads its own account from
# PILINK_MQTT_USER / PILINK_MQTT_PASS (see thermostat/service.py).
set -euo pipefail

PI_USER="${PILINK_PI_USER:-pilink-pi}"
ESP32_USER="${PILINK_ESP32_USER:-pilink-esp32}"
DEVICE_ID="${PILINK_DEVICE_ID:-thermostat-01}"
CONF=/etc/mosquitto/conf.d/pilink.conf
ACL=/etc/mosquitto/pilink.acl
PWFILE=/etc/mosquitto/pilink.passwd

if [[ $EUID -ne 0 ]]; then
  echo "Please run with sudo (this writes under /etc/mosquitto/)." >&2
  exit 1
fi
: "${PILINK_PI_PASS:?set PILINK_PI_PASS to the Pi account password}"
: "${PILINK_ESP32_PASS:?set PILINK_ESP32_PASS (must match firmware secrets.h)}"

echo "==> installing mosquitto"
apt-get update -qq
apt-get install -y mosquitto mosquitto-clients

echo "==> writing $CONF"
cat > "$CONF" <<EOF
# PiLink thermostat broker — managed by setup-mosquitto.sh
listener 1883
# Binds all interfaces on :1883; keep it off the WAN with a router firewall rule
# (see README-mqtt.md). To bind a single NIC instead: listener 1883 <pi-lan-ip>
allow_anonymous false
password_file $PWFILE
acl_file $ACL
# NOTE: persistence is intentionally NOT set here — the stock
# /etc/mosquitto/mosquitto.conf already declares it, and Mosquitto 2.0 treats a
# duplicate persistence_location as a fatal config error.
EOF

echo "==> writing $ACL (least privilege)"
cat > "$ACL" <<EOF
# The Pi control server: read the whole namespace, publish node config only.
user $PI_USER
topic read pilink/#
topic write pilink/+/config

# The ESP32 sensor node: publish only its own telemetry + status, read only its
# own config. Add a block per extra node, or switch to a %u/%c pattern.
user $ESP32_USER
topic write pilink/$DEVICE_ID/telemetry
topic write pilink/$DEVICE_ID/status
topic read pilink/$DEVICE_ID/config
EOF

echo "==> setting account passwords"
# -c creates/overwrites the file with the first user; then append the second.
mosquitto_passwd -b -c "$PWFILE" "$PI_USER" "$PILINK_PI_PASS"
mosquitto_passwd -b "$PWFILE" "$ESP32_USER" "$PILINK_ESP32_PASS"
# Ownership: mosquitto 2.x prints "owner is not root ... future versions will
# refuse to load this file" for these. DO NOT "fix" that with `chown root:root`
# on Debian/Raspberry Pi OS — the packaged unit runs the broker as
# `User=mosquitto` and never as root, so a root-owned 0600 file is unreadable
# and mosquitto fails to start outright (verified the hard way).
# That warning targets deployments where mosquitto starts as root and drops
# privileges itself; there, root can read the file before the drop. Here the
# only way to satisfy it would be making the credential file world-readable,
# which is strictly worse than the warning. mosquitto:mosquitto + 0600 is the
# tightest setting that works: only the broker's own user can read it.
chown mosquitto:mosquitto "$PWFILE" "$ACL"
chmod 600 "$PWFILE"
chmod 644 "$ACL"

echo "==> restarting mosquitto"
systemctl enable mosquitto
systemctl restart mosquitto
sleep 1
systemctl is-active mosquitto

echo "==> done. quick self-test (fill in the passwords):"
echo "    mosquitto_sub -h localhost -u $PI_USER -P '***' -t 'pilink/#' -v &"
echo "    mosquitto_pub -h localhost -u $ESP32_USER -P '***' -t pilink/$DEVICE_ID/status -m online"
