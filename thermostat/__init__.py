"""PiLink thermostat — Pi-side analytics, control, and ingest (Phase 2, M0).

Pure, dependency-light modules so the safety-critical logic unit-tests in CI with
no Raspberry Pi, MQTT broker, or air conditioner attached. The I/O layers (MQTT
ingest wiring, the msmart-ng adapter, the SQLite store, and the server route
handlers) land in later milestones on top of these building blocks.
"""

__version__ = "0.1.0"
