"""Unit tests for the relay executor — the Pi's half of Stage 2, where the
ESP32 decides and this machine only carries it out. No broker, no AC."""
import pytest

from thermostat.control import ACCommand, ACMode
from thermostat.executor import CommandError, CommandExecutor, parse_command


class RecordingAC:
    """Minimal adapter double. `fail` makes apply() raise, like a Duo that has
    dropped off WiFi mid-command."""

    def __init__(self, fail=False):
        self.applied = []
        self.fail = fail

    def apply(self, command):
        if self.fail:
            raise RuntimeError("AC unreachable")
        self.applied.append(command)


class TestParseCommand:
    def test_power_off(self):
        assert parse_command('{"power": false}') == ACCommand(
            power=False, mode=ACMode.OFF, target_f=None)

    def test_power_on_with_target(self):
        assert parse_command('{"power": true, "target_f": 61.0}') == ACCommand(
            power=True, mode=ACMode.COOL, target_f=61.0)

    def test_accepts_bytes(self):
        assert parse_command(b'{"power": false}').power is False

    def test_accepts_an_integer_target(self):
        assert parse_command('{"power": true, "target_f": 61}').target_f == 61.0

    @pytest.mark.parametrize("payload", [
        "not json",
        "[]",                                    # not an object
        "{}",                                    # no power
        '{"power": "yes"}',                      # power not a bool
        '{"power": 1}',                          # 1 is not True here
        '{"power": true}',                       # on without a target
        '{"power": true, "target_f": "cold"}',
        '{"power": true, "target_f": true}',     # bool is not a number
        '{"power": true, "target_f": 20}',       # below the plausible band
        '{"power": true, "target_f": 200}',      # above it
    ])
    def test_rejects_malformed(self, payload):
        with pytest.raises(CommandError):
            parse_command(payload)

    def test_rejects_non_utf8(self):
        with pytest.raises(CommandError):
            parse_command(b"\xff\xfe")


class TestCommandExecutor:
    def test_applies_a_valid_command(self):
        ac = RecordingAC()
        ex = CommandExecutor(ac)
        assert ex.handle('{"power": true, "target_f": 61.0}') is not None
        assert len(ac.applied) == 1
        assert ac.applied[0].target_f == 61.0
        assert ex.applied == 1

    def test_skips_an_identical_repeat(self):
        # The node restates periodically so a dropped message self-heals; most
        # arrivals therefore say nothing new.
        ac = RecordingAC()
        ex = CommandExecutor(ac)
        ex.handle('{"power": true, "target_f": 61.0}')
        ex.handle('{"power": true, "target_f": 61.0}')
        assert len(ac.applied) == 1

    def test_applies_a_changed_command(self):
        ac = RecordingAC()
        ex = CommandExecutor(ac)
        ex.handle('{"power": true, "target_f": 61.0}')
        ex.handle('{"power": false}')
        assert len(ac.applied) == 2
        assert ac.applied[1].power is False

    def test_a_failed_apply_is_retried_not_suppressed(self):
        # The critical one. If a failure were remembered as "applied", the next
        # restatement would be skipped as a duplicate and the AC would sit in
        # the wrong state until something else changed.
        ac = RecordingAC(fail=True)
        ex = CommandExecutor(ac)
        ex.handle('{"power": true, "target_f": 61.0}')
        assert ex.last is None
        assert ex.failures == 1

        ac.fail = False
        assert ex.handle('{"power": true, "target_f": 61.0}') is not None
        assert len(ac.applied) == 1

    def test_rejected_payload_never_reaches_the_ac(self):
        ac = RecordingAC()
        ex = CommandExecutor(ac)
        assert ex.handle('{"power": "maybe"}') is None
        assert ac.applied == []
        assert ex.failures == 1

    def test_observe_only_touches_nothing(self):
        ac = RecordingAC()
        ex = CommandExecutor(ac, observe_only=True)
        assert ex.handle('{"power": true, "target_f": 61.0}') is not None
        assert ac.applied == []


class TestRouting:
    """handle_message must route a command topic without writing to the store."""

    def test_command_topic_reaches_the_callback(self):
        from thermostat.mqtt_ingest import handle_message

        seen = []
        out = handle_message(None, "pilink/thermostat-01/command",
                             b'{"power": false}',
                             on_command=lambda p, ts: seen.append(p) or "ok")
        assert out == "ok"
        assert len(seen) == 1

    def test_command_topic_is_ignored_without_an_executor(self):
        # An ingest-only Pi must not blow up on a retained command message.
        from thermostat.mqtt_ingest import handle_message

        assert handle_message(None, "pilink/thermostat-01/command",
                              b'{"power": false}') is None
