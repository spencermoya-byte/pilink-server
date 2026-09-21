"""Execute AC commands decided by the ESP32.

Stage 2 of moving the thermostat onto the node: the ESP32 owns the setpoint, the
weekly schedule and the control loop, and publishes the state it wants as a
retained message on ``pilink/<device>/command``. This module is the Pi's half —
it turns that message into a call on the msmart-ng adapter.

The Pi is an ACTUATOR ARM here, not the brain. It deliberately holds no policy:
no hysteresis, no timers, no schedule. Every one of those decisions was already
made on the node, and duplicating any of them here would let the two disagree.

:func:`parse_command` is pure and validated, in the same shape as
:mod:`thermostat.ingest`, so it unit-tests with no broker and no AC.

Once Stage 4 lands and the node drives the Duo directly, this becomes the
fallback path rather than the primary one.
"""
from __future__ import annotations

import json
import logging

from thermostat.control import ACCommand, ACMode

log = logging.getLogger("pilink.thermostat.exec")

# Same plausibility band the node's own config uses. A command outside it means
# a corrupt payload, not a real intent.
TARGET_MIN_F = 50.0
TARGET_MAX_F = 90.0


class CommandError(ValueError):
    """Raised for a malformed or implausible command payload."""


def parse_command(payload) -> ACCommand:
    """Validate one command payload into an :class:`ACCommand`.

    ``{"power": true, "target_f": 61.0}`` or ``{"power": false}``.
    """
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CommandError(f"payload is not utf-8: {e}") from e
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as e:
            raise CommandError(f"payload is not JSON: {e}") from e
    if not isinstance(payload, dict):
        raise CommandError("payload is not an object")

    power = payload.get("power")
    if not isinstance(power, bool):
        raise CommandError("power must be a boolean")

    if not power:
        return ACCommand(power=False, mode=ACMode.OFF, target_f=None)

    target = payload.get("target_f")
    if isinstance(target, bool) or not isinstance(target, (int, float)):
        raise CommandError("target_f must be a number when power is true")
    target = float(target)
    if not TARGET_MIN_F <= target <= TARGET_MAX_F:
        raise CommandError(
            f"target_f {target} outside {TARGET_MIN_F}-{TARGET_MAX_F}F")
    return ACCommand(power=True, mode=ACMode.COOL, target_f=target)


class CommandExecutor:
    """Apply node-decided commands to the AC, skipping no-op repeats.

    The node republishes periodically so a dropped message self-heals, which
    means most arrivals restate the current state. Applying every one would put
    needless traffic on the AC, so identical commands are skipped — but any
    FAILURE clears that memory, so the next restatement retries rather than
    being suppressed as a duplicate.
    """

    def __init__(self, adapter, *, observe_only: bool = False) -> None:
        self.adapter = adapter
        self.observe_only = observe_only
        self.last: ACCommand | None = None
        self.applied = 0
        self.failures = 0

    def handle(self, payload) -> ACCommand | None:
        """Returns the command applied, or ``None`` if rejected or a repeat."""
        try:
            cmd = parse_command(payload)
        except CommandError as e:
            log.warning("rejected command: %s", e)
            self.failures += 1
            return None

        if cmd == self.last:
            return None
        if self.observe_only:
            log.info("observe: would set power=%s target=%s", cmd.power, cmd.target_f)
            self.last = cmd
            return cmd

        try:
            self.adapter.apply(cmd)
        except Exception as e:                     # noqa: BLE001 - adapter is 3rd party
            # Do NOT record it as applied: the node restates within a minute and
            # that restatement must be allowed through to retry.
            log.error("failed to apply command: %s", e)
            self.failures += 1
            self.last = None
            return None

        self.last = cmd
        self.applied += 1
        log.info("applied power=%s target=%s", cmd.power, cmd.target_f)
        return cmd
