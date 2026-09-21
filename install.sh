#!/bin/bash
set -e

echo "=== PiLink Server Installer ==="

PILINK_USER=$(whoami)
PILINK_HOME=$(getent passwd "$PILINK_USER" | cut -d: -f6)
PILINK_DIR="$PILINK_HOME/.pilink"

echo "Installing for user: $PILINK_USER ($PILINK_HOME)"

# Install system deps
sudo apt-get update -qq
sudo apt-get install -y python3 python3-pip python3-venv bluetooth bluez rfkill

# Create venv + install Python deps
mkdir -p "$PILINK_DIR"
python3 -m venv "$PILINK_DIR/venv"
"$PILINK_DIR/venv/bin/pip" install --upgrade pip
"$PILINK_DIR/venv/bin/pip" install -r "$(dirname "$0")/requirements.txt"

# Copy server and agent
cp "$(dirname "$0")/pilink-server.py" "$PILINK_DIR/pilink-server.py"
cp "$(dirname "$0")/pilink-agent.py"  "$PILINK_DIR/pilink-agent.py"
chmod +x "$PILINK_DIR/pilink-server.py" "$PILINK_DIR/pilink-agent.py"

# Install pilink-server.service
sudo tee /etc/systemd/system/pilink-server.service > /dev/null << SERVICE
[Unit]
Description=PiLink TCP Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$PILINK_USER
ExecStart=$PILINK_DIR/venv/bin/python3 -u $PILINK_DIR/pilink-server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

# Install pilink-agent.service
sudo tee /etc/systemd/system/pilink-agent.service > /dev/null << SERVICE
[Unit]
Description=PiLink Self-Healing Agent
After=network.target pilink-server.service

[Service]
Type=simple
User=$PILINK_USER
ExecStart=$PILINK_DIR/venv/bin/python3 -u $PILINK_DIR/pilink-agent.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable pilink-server pilink-agent
sudo systemctl start pilink-server pilink-agent

echo ""
echo "✓ PiLink server + agent installed and started!"
echo "  Check status: sudo systemctl status pilink-server pilink-agent"
echo "  View logs:    sudo journalctl -u pilink-server -u pilink-agent -f"
