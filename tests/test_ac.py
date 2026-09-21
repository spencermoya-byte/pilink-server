"""Unit tests for the AC adapter's pure translation + the fakes (no msmart, no Duo)."""
import pytest

from thermostat.ac import FakeAC, NullAC, command_to_settings, f_to_c_half
from thermostat.control import ACCommand, ACMode


@pytest.mark.parametrize("f,c", [
    (77.0, 25.0),
    (78.0, 25.5),
    (61.0, 16.0),
    (60.0, 16.0),    # clamps to the 16 C floor
    (100.0, 30.0),   # clamps to the 30 C ceiling
])
def test_f_to_c_half(f, c):
    assert f_to_c_half(f) == pytest.approx(c)


def test_command_to_settings_off():
    cmd = ACCommand(power=False, mode=ACMode.OFF, target_f=None)
    assert command_to_settings(cmd) == {"power_state": False, "fan": "auto"}


def test_command_to_settings_cool():
    cmd = ACCommand(power=True, mode=ACMode.COOL, target_f=61.0)
    s = command_to_settings(cmd, fan="high")
    assert s["power_state"] is True
    assert s["mode"] == "cool"
    assert s["target_temperature"] == pytest.approx(16.0)
    assert s["fan"] == "high"


def test_fake_ac_records_and_reports():
    ac = FakeAC()
    cmd = ACCommand(power=True, mode=ACMode.COOL, target_f=61.0)
    ac.apply(cmd)
    assert ac.commands == [cmd]
    ac.status_value = {"online": True}
    assert ac.refresh() == {"online": True}


def test_null_ac_is_noop():
    NullAC().apply(ACCommand(power=False, mode=ACMode.OFF, target_f=None))  # must not raise
    assert NullAC().refresh() is None
