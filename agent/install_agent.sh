#!/bin/bash
# SecureWatch Agent Installer for Linux

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

SIEM_SERVER_IP=${1:-"127.0.0.1"}
AGENT_GROUP=${2:-"linux-servers"}
INSTALL_DIR="/opt/securewatch-agent"

echo "Installing SecureWatch Agent..."
echo "Server IP: $SIEM_SERVER_IP"
echo "Group: $AGENT_GROUP"

# Install dependencies
apt-get update -y && apt-get install -y python3 python3-pip python3-venv

# Create directories
mkdir -p $INSTALL_DIR/collectors
mkdir -p $INSTALL_DIR/core
mkdir -p $INSTALL_DIR/config

# Copy files (assuming running from source dir)
cp core/agent.py $INSTALL_DIR/core/
cp -r collectors/* $INSTALL_DIR/collectors/
cp -r config/* $INSTALL_DIR/config/
cp requirements.txt $INSTALL_DIR/

# Update config with server IP
sed -i "s/host: \"127.0.0.1\"/host: \"$SIEM_SERVER_IP\"/g" $INSTALL_DIR/config/agent.conf
sed -i "s/group: \"default\"/group: \"$AGENT_GROUP\"/g" $INSTALL_DIR/config/agent.conf

# Setup venv
cd $INSTALL_DIR
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# Create systemd service
cat << EOF > /etc/systemd/system/securewatch-agent.service
[Unit]
Description=SecureWatch Security Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python core/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable securewatch-agent
systemctl restart securewatch-agent

echo "SecureWatch Agent installed and started successfully."
systemctl status securewatch-agent --no-pager
