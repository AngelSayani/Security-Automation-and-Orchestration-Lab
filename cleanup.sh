#!/bin/bash

# Globomantics Defense Protocol Cleanup Script
# This script resets the lab environment to its initial state

echo "==============================================="
echo "  Globomantics Defense Protocol Cleanup"
echo "  Resetting the security automation lab"
echo "==============================================="

# Confirm cleanup
echo "This will reset the lab environment to its initial state."
read -p "Are you sure you want to continue? (y/n): " confirm

if [ "$confirm" != "y" ]; then
    echo "Cleanup canceled."
    exit 0
fi

echo "[+] Stopping any running monitoring processes..."
pkill -f "monitor.py" 2>/dev/null || true

echo "[+] Removing security operations directories..."
rm -rf ./security_ops

echo "[+] Removing simulated server environment..."
rm -rf ./server

echo "[+] Setting up clean environment..."
bash setup.sh

echo "==============================================="
echo "  Cleanup Complete!"
echo "  The lab has been reset to its initial state."
echo "==============================================="
