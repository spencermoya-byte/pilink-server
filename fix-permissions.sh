#!/bin/bash
#
# Grant the PiLink service the narrow permissions its hardware controls need,
# without running the service as root.
#
# Two unrelated problems, two different mechanisms:
#
#   sysfs LEDs (/sys/class/leds/*) are kernel-owned and root-only by default.
#   Raspberry Pi OS hands them to the `gpio` group through its own udev rule;
#   Ubuntu ships no equivalent rule, which is why the LED toggles worked on one
#   and not the other. We install our own group + rule so both behave the same.
#
#   The Ethernet port LEDs are not sysfs LEDs at all -- they are a firmware
#   dtparam, so changing them means writing config.txt on the root-owned boot
#   partition. No group can grant that, so it gets the one privileged path
#   here: a fixed root helper behind a single argument-less sudoers entry.
#   Granting `cp` or `tee` with a wildcard path instead would have been an
#   arbitrary root-owned write, since sudo matches * across / .
#
# Idempotent. Safe to re-run at any time.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  exec sudo -- /bin/bash "$0" "$@"
fi

PILINK_USER="${1:-${SUDO_USER:-}}"
if [ -z "$PILINK_USER" ]; then
  echo "usage: sudo bash $0 <user>" >&2
  exit 1
fi
if ! id "$PILINK_USER" >/dev/null 2>&1; then
  echo "no such user: $PILINK_USER" >&2
  exit 1
fi

PILINK_HOME=$(getent passwd "$PILINK_USER" | cut -d: -f6)
OWNER_UID=$(id -u "$PILINK_USER")
STAGED="$PILINK_HOME/.pilink/boot_config_staged.txt"
HELPER=/usr/local/sbin/pilink-write-boot-config

echo "== PiLink permissions for $PILINK_USER =="

# ---------------------------------------------------------------- sysfs LEDs
groupadd -f pilink
usermod -aG pilink "$PILINK_USER"

cat > /etc/udev/rules.d/60-pilink-leds.rules <<'RULE'
# Installed by PiLink (fix-permissions.sh). Hands the LED sysfs attributes to
# the `pilink` group so the service can toggle them without root. This mirrors
# what Raspberry Pi OS does for its `gpio` group; Ubuntu ships nothing like it.
SUBSYSTEM=="leds", ACTION=="add", RUN+="/bin/chgrp -R pilink /sys%p", RUN+="/bin/chmod -R g=u /sys%p"
RULE

udevadm control --reload-rules
# ACTION=="add" only fires as devices appear, i.e. at boot. Replay it now, or
# the rule changes nothing until the next reboot and the toggles still fail.
udevadm trigger --subsystem-match=leds --action=add || true
echo "  sysfs LEDs: group + udev rule installed"

# --------------------------------------------------- boot config / eth LEDs
cat > "$HELPER" <<HELPEREOF
#!/usr/bin/env python3
"""Apply PiLink's staged Ethernet-LED settings to the boot config.

Reachable through one NOPASSWD sudoers entry that takes no arguments, so this
file IS the privilege boundary: everything that may happen has to be decided
here rather than by the caller.

It therefore does not trust the staged file. The staged copy must be identical
to the live config except for dtparam=eth_led0 / dtparam=eth_led1 lines, whose
values must each be a single digit. Anything else -- an added dtoverlay, an
edited kernel or initramfs line -- is refused, because on a Pi an arbitrary
config.txt write is arbitrary code execution at boot.
"""
import os
import stat
import sys

STAGED = '$STAGED'
OWNER_UID = $OWNER_UID
CANDIDATES = ['/boot/firmware/config.txt', '/boot/config.txt']
KEYS = ('dtparam=eth_led0=', 'dtparam=eth_led1=')


def without_eth_led(text):
    """The config minus its eth_led lines -- the part that must not change."""
    keep = []
    for line in text.splitlines():
        if line.strip().startswith(KEYS):
            continue
        keep.append(line.rstrip())
    while keep and not keep[-1]:
        keep.pop()
    return keep


def eth_led_values(text):
    out = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(KEYS):
            out.append(s.split('=', 2)[2])
    return out


def main():
    dest = None
    for path in CANDIDATES:
        if os.path.exists(path):
            dest = path
            break
    if dest is None:
        sys.exit('pilink: no boot config found')

    try:
        info = os.lstat(STAGED)
    except OSError as exc:
        sys.exit('pilink: cannot read staged config: %s' % exc)
    if not stat.S_ISREG(info.st_mode):
        sys.exit('pilink: staged config is not a regular file')
    if info.st_uid != OWNER_UID:
        sys.exit('pilink: staged config has the wrong owner')
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        sys.exit('pilink: staged config is writable by others')

    with open(STAGED, 'r') as handle:
        staged = handle.read()
    with open(dest, 'r') as handle:
        live = handle.read()

    if without_eth_led(staged) != without_eth_led(live):
        sys.exit('pilink: staged config changes more than the Ethernet LED settings; refusing')
    for value in eth_led_values(staged):
        if not (len(value) == 1 and value.isdigit()):
            sys.exit('pilink: rejected eth_led value %r' % value)

    tmp = dest + '.pilink-new'
    with open(tmp, 'w') as handle:
        handle.write(staged)
    try:
        os.chmod(tmp, 0o755)
    except OSError:
        pass          # boot partition is vfat; permissions come from the mount
    os.replace(tmp, dest)
    print('pilink: updated ' + dest)


main()
HELPEREOF
chmod 0755 "$HELPER"

# ------------------------------------------------------------ power control
# An eth_led dtparam is firmware configuration: writing it above changes
# nothing until the Pi reboots. Without a rule here the server runs
# `sudo -n reboot`, sudo answers "interactive authentication is required", and
# the boot config sits there correctly written and never applied -- which
# looks exactly like the LED toggle silently not working.
#
# Resolved rather than guessed: these live in different places per distro, and
# a sudoers line naming a path that does not exist grants nothing.
POWER=""
for c in /usr/sbin/reboot /sbin/reboot /usr/sbin/shutdown /sbin/shutdown \
         /usr/sbin/poweroff /sbin/poweroff; do
  [ -x "$c" ] && POWER="${POWER:+$POWER, }$c"
done

# -------------------------------------------------------- package updates
# The app's Updates screen shells out to apt through `sudo -n`, so with no
# rule it fails with the same "interactive authentication is required" that
# stopped the Reboot button.
#
# Be clear-eyed about what this grants: passwordless apt IS passwordless root.
# apt runs maintainer scripts as root, and -o APT::Update::Pre-Invoke will
# execute anything handed to it. Naming the exact argv the server uses keeps
# the rule honest about its intent and stops casual misuse, but it is not a
# security boundary the way the boot-config helper is. Delete this block if
# you would rather apply system updates by hand.
APT=$(command -v apt-get || true)
APT_RULES=""
if [ -n "$APT" ]; then
  # Exactly what pilink-server.py runs -- sudoers matches the whole command
  # line, so `apt-get update` alone would NOT permit `apt-get update -qq`.
  APT_RULES="$APT update -y, $APT update -qq, $APT upgrade -y"
fi

{
  echo "# Installed by PiLink (fix-permissions.sh)."
  echo "# The helper takes no arguments and is named by one exact path: sudo"
  echo "# matches * across /, so a wildcard here would be an arbitrary root-owned"
  echo "# file write. The helper itself decides what it is willing to change."
  echo "$PILINK_USER ALL=(root) NOPASSWD: $HELPER"
  if [ -n "$POWER" ]; then
    echo "# Power control: the app's Reboot button, reboot/shutdown schedules, and"
    echo "# applying an Ethernet LED change all depend on this."
    echo "$PILINK_USER ALL=(root) NOPASSWD: $POWER"
  fi
  if [ -n "$APT_RULES" ]; then
    echo "# Package updates for the app's Updates screen. Exact argv only, though"
    echo "# passwordless apt is passwordless root by nature -- see the note above."
    echo "$PILINK_USER ALL=(root) NOPASSWD: $APT_RULES"
  fi
} > /etc/sudoers.d/pilink
chmod 0440 /etc/sudoers.d/pilink

# A malformed drop-in breaks sudo for every user on the box, so validate it and
# roll back rather than leave the machine in that state.
if ! visudo -cf /etc/sudoers.d/pilink >/dev/null; then
  rm -f /etc/sudoers.d/pilink
  echo "  sudoers drop-in rejected and removed; Ethernet LED control unavailable" >&2
  exit 1
fi
echo "  boot config: root helper + validated sudoers rule installed"
if [ -n "$POWER" ]; then
  echo "  power control: granted for $POWER"
else
  echo "  power control: no reboot/shutdown binary found; the Reboot button will fail" >&2
fi

# ------------------------------------------------------------- verification
# This whole script has one job and no output of its own, so check the result
# instead of assuming it. `sudo -l <cmd>` asks whether a command WOULD be
# permitted and never runs it, which matters when the command is `reboot`.
check() {
  if runuser -u "$PILINK_USER" -- "$@" >/dev/null 2>&1; then echo "  ok: $*"
  else echo "  FAILED: $*" >&2; return 1; fi
}
rc=0
FIRST_LED=$(ls /sys/class/leds 2>/dev/null | head -1 || true)
if [ -n "$FIRST_LED" ]; then
  check test -w "/sys/class/leds/$FIRST_LED/trigger" || rc=1
fi
check sudo -n -l "$HELPER" || rc=1
if [ -n "$POWER" ]; then
  check sudo -n -l "${POWER%%,*}" || rc=1
fi
if [ -n "$APT" ]; then
  check sudo -n -l "$APT" update -qq || rc=1
fi
[ "$rc" -eq 0 ] || echo "  one or more checks failed -- see above" >&2

# The running service still holds the group list it started with.
systemctl restart pilink-server 2>/dev/null || true

echo "Done."
