#!/bin/bash

# Globomantics Defense Protocol Setup Script
# This script sets up the security automation lab environment

echo "==============================================="
echo "  Globomantics Defense Protocol Setup"
echo "  Setting up security automation environment"
echo "==============================================="

# Create necessary directories
echo "[+] Creating security operations directories..."
mkdir -p ./security_ops/logs
mkdir -p ./security_ops/intel
mkdir -p ./security_ops/alerts
mkdir -p ./security_ops/reports

# Set up simulated server environment
echo "[+] Setting up simulated server environment..."
mkdir -p ./server/webroot
mkdir -p ./server/users
mkdir -p ./server/database

# Create sample web files
echo "[+] Creating sample system files..."
echo "<html><body><h1>Globomantics Secure Portal</h1></body></html>" > ./server/webroot/index.html
echo "<html><body><h1>Globomantics Admin Interface</h1></body></html>" > ./server/webroot/admin.html

# Create sample user database
echo "[+] Creating user database..."
echo "admin:$6$salt$hashedpassword" > ./server/users/passwd
echo "operator:$6$salt$hashedpassword2" >> ./server/users/passwd
echo "user1:$6$salt$hashedpassword3" >> ./server/users/passwd

# Create sample log entries
echo "[+] Creating initial system logs..."
echo "$(date -d '1 hour ago' +'%Y-%m-%d %H:%M:%S') [INFO] System startup" > ./security_ops/logs/system.log
echo "$(date -d '50 minutes ago' +'%Y-%m-%d %H:%M:%S') [INFO] User admin logged in" >> ./security_ops/logs/system.log
echo "$(date -d '45 minutes ago' +'%Y-%m-%d %H:%M:%S') [INFO] Configuration updated" >> ./security_ops/logs/system.log
echo "$(date -d '30 minutes ago' +'%Y-%m-%d %H:%M:%S') [INFO] Scheduled backup started" >> ./security_ops/logs/system.log
echo "$(date -d '28 minutes ago' +'%Y-%m-%d %H:%M:%S') [INFO] Backup completed successfully" >> ./security_ops/logs/system.log

# Create network log
echo "[+] Creating initial network logs..."
echo "$(date -d '1 hour ago' +'%Y-%m-%d %H:%M:%S') - SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=45678 DPT=80" > ./security_ops/logs/network.log
echo "$(date -d '55 minutes ago' +'%Y-%m-%d %H:%M:%S') - SRC=192.168.1.15 DST=192.168.1.1 PROTO=TCP SPT=52431 DPT=443" >> ./security_ops/logs/network.log
echo "$(date -d '50 minutes ago' +'%Y-%m-%d %H:%M:%S') - SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=45679 DPT=22" >> ./security_ops/logs/network.log
echo "$(date -d '40 minutes ago' +'%Y-%m-%d %H:%M:%S') - SRC=192.168.1.100 DST=192.168.1.1 PROTO=ICMP TYPE=8" >> ./security_ops/logs/network.log

# Copy configuration files
echo "[+] Copying configuration files..."
cp config.json ./security_ops/
cp threat_intel.json ./security_ops/intel/

# Set up initial alert state
echo "[+] Setting up initial alert state..."
echo "NO_ALERTS" > ./security_ops/alerts/status.txt

# Make scripts executable
echo "[+] Setting execution permissions on scripts..."
chmod +x monitor.py response.sh simulate_attack.py check_status.sh cleanup.sh generate_report.py

echo "[+] Installing required Python packages..."
pip3 install -q json5 tabulate colorama

echo "==============================================="
echo "  Setup Complete!"
echo "  Run 'bash check_status.sh' to start"
echo "==============================================="
