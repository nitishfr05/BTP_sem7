#!/bin/bash
# ==============================================================================
# BTP Testbed Provisioning Script for Ubuntu VM (VMware)
# Installs Zeek, Suricata, Traffic Generation Tools, and configures JSON logging
# ==============================================================================

set -e

echo "=== [1/5] Updating System Packages ==="
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y build-essential git curl wget jq python3 python3-pip python3-venv \
                        net-tools tcpdump tshark hping3 nmap hydra nikto sqlmap dnsutils

echo "=== [2/5] Installing Suricata IDS ==="
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata
sudo suricata-update

# Configure Suricata to write JSON EVE logs
echo "Configuring Suricata EVE JSON logging..."
sudo sed -i 's/enabled: no/enabled: yes/g' /etc/suricata/suricata.yaml || true

echo "=== [3/5] Installing Zeek Network Security Monitor ==="
# Add OpenSUSE OBS repository for Zeek on Ubuntu
UBUNTU_VER=$(lsb_release -rs)
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VER}/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_${UBUNTU_VER}/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt-get update
sudo apt-get install -y zeek

# Enable JSON logging policy in Zeek
ZEEK_LOCAL_SITE="/opt/zeek/share/zeek/site/local.zeek"
if [ -f "$ZEEK_LOCAL_SITE" ]; then
    echo "@load policy/tuning/json-logs.zeek" | sudo tee -a "$ZEEK_LOCAL_SITE"
fi

echo "=== [4/5] Setting up Python Scapy Environment ==="
python3 -m venv ~/btp_testbed_env
source ~/btp_testbed_env/bin/activate
pip install --upgrade pip
pip install scapy requests

echo "=== [5/5] Setup Completed Successfully ==="
echo "You can now run traffic generation via: python3 testbed/generate_traffic.py"
