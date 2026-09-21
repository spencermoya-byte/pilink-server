#!/bin/bash
# Deploy PiLink server to a Raspberry Pi over SSH
# Usage: ./deploy.sh user@192.168.x.x

set -e
TARGET="${1:-pi@raspberrypi.local}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Deploying PiLink to $TARGET ==="

ssh "$TARGET" "mkdir -p ~/.pilink"
scp "$SCRIPT_DIR/pilink-server.py" "$TARGET:~/.pilink/pilink-server.py"
scp "$SCRIPT_DIR/requirements.txt" "$TARGET:/tmp/requirements.txt"
scp "$SCRIPT_DIR/install.sh" "$TARGET:/tmp/pilink-install.sh"

ssh "$TARGET" "bash /tmp/pilink-install.sh"

echo ""
echo "✓ Deployment complete! PiLink is running on $TARGET"
