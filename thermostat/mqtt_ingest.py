"""Wire the MQTT broker onto the M0 ingest validators and the SQLite store.

:func:`handle_message` is the pure routing core — given a topic and raw payload
it validates via :mod:`thermostat.ingest` and writes to the :class:`~thermostat.
store.Store`, recording an event for anything it rejects — so it unit-tests with
no broker. :class:`MqttIngestor` is the thin paho layer that subscribes to
``pilink/+/telemetry`` and ``.../status`` and feeds each message through
:func:`handle_message`. :func:`make_client` papers over the paho 1.x/2.x
constructor change.
"""
from __future__ import annotations

import time

from thermostat.ingest import (
    TelemetryError,
    device_id_from_topic,
    parse_status,
    parse_telemetry,
)


def handle_message(store, topic, payload, *, now=None, on_telemetry=None,
                   on_command=None):
    """Route one MQTT message to the store. Returns the parsed value, or ``None``
    if the payload was rejected or the topic was not recognised."""
    now = time.time() if now is None else now
    kind = topic.rsplit("/", 1)[-1] if topic else ""

    if kind == "telemetry":
        try:
            t = parse_telemetry(payload, topic=topic)
        except TelemetryError as e:
            store.record_event(device_id_from_topic(topic) or "?",
                               "bad_telemetry", str(e), ts=now)
            return None
        store.insert_telemetry(t, ts=now)
        if on_telemetry is not None:
            on_telemetry(t, now)
        return t

    if kind == "status":
        did = device_id_from_topic(topic) or "?"
        try:
            online = parse_status(payload)
        except TelemetryError as e:
            store.record_event(did, "bad_status", str(e), ts=now)
            return None
        store.set_node_status(did, online, now)
        store.record_event(did, "status", "online" if online else "offline", ts=now)
        return online

    if kind == "command":
        # The node decided; the Pi only carries it out. Nothing is written to
        # the store — the resulting AC state comes back via normal telemetry.
        if on_command is None:
            return None
        return on_command(payload, now)

    return None


def make_client(username=None, password=None, client_id=None):
    """Construct a paho client that works on both paho-mqtt 1.x and 2.x.

    Requesting callback API v1 on paho 2.x keeps the classic on_connect/on_message
    signatures this module uses; on paho 1.x that enum doesn't exist, so we fall
    back to the bare constructor.
    """
    import paho.mqtt.client as mqtt
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        client = mqtt.Client(client_id=client_id)  # paho-mqtt 1.x
    if username:
        client.username_pw_set(username, password)
    return client


class MqttIngestor:
    """Subscribe to the node topics and persist every validated frame."""

    def __init__(self, store, *, host="127.0.0.1", port=1883, username=None,
                 password=None, topic_prefix="pilink", on_telemetry=None,
                 on_command=None, client_id="pilink-ingest"):
        self.store = store
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.prefix = topic_prefix
        self.on_telemetry = on_telemetry
        self.on_command = on_command
        self.client_id = client_id
        self._client = None

    def _on_connect(self, client, userdata, flags, rc):
        client.subscribe(f"{self.prefix}/+/telemetry")
        client.subscribe(f"{self.prefix}/+/status")
        # Only subscribed when something is actually executing, so an
        # ingest-only Pi never sees commands. The node publishes this retained,
        # so subscribing also recovers the current desired state after a Pi
        # restart instead of waiting for the next change.
        if self.on_command is not None:
            client.subscribe(f"{self.prefix}/+/command")

    def _on_message(self, client, userdata, msg):
        handle_message(self.store, msg.topic, msg.payload,
                       on_telemetry=self.on_telemetry,
                       on_command=self.on_command)

    def start(self):
        self._client = make_client(self.username, self.password, self.client_id)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.connect(self.host, self.port, keepalive=60)
        self._client.loop_start()

    def stop(self):
        if self._client is not None:
            self._client.loop_stop()
            self._client.disconnect()
            self._client = None
