#!/bin/bash

# Globomantics Defense Protocol Status Script
# This script checks the status of the security monitoring system

echo "==============================================="
echo "  Globomantics Defense Protocol Status"
echo "  Checking security monitoring status"
echo "==============================================="

# Check if directories exist
if [ ! -d "./security_ops" ]; then
    echo "[ERROR] Security operations directory not found."
    echo "Did you run the setup script? Try: bash setup.sh"
    exit 1
fi

# Check alert status
if [ -f "./security_ops/alerts/status.txt" ]; then
    status=$(cat ./security_ops/alerts/status.txt)
    echo "[+] Current alert status: $status"
else
    echo "[ERROR] Alert status file not found."
    exit 1
fi

# Check if monitoring is running
monitor_pid=$(pgrep -f "python.*monitor.py" || echo "")
if [ -n "$monitor_pid" ]; then
    echo "[+] Monitoring system is ACTIVE (PID: $monitor_pid)"
else
    echo "[+] Monitoring system is INACTIVE"
    
    # Ask if user wants to start monitoring
    read -p "Would you like to start the monitoring system? (y/n): " choice
    if [ "$choice" = "y" ]; then
                    echo "[+] Starting security monitoring system..."
        python3 monitor.py & 
        echo "[+] Monitoring started in background with PID: $!"
        echo "[+] To stop monitoring, run: pkill -f 'monitor.py'"
        echo "[+] Press Enter to continue..."
        read
    fi
fi

# Report blocked IPs
if [ -f "./security_ops/alerts/blocked_ips.txt" ]; then
    blocked_count=$(wc -l < "./security_ops/alerts/blocked_ips.txt" | tr -d ' ')
    if [ "$blocked_count" -gt 0 ]; then
        echo "[+] Blocked IPs: $blocked_count"
        cat "./security_ops/alerts/blocked_ips.txt"
    else
        echo "[+] No IPs currently blocked."
    fi
else
    echo "[+] No IP block list found."
fi

# Report locked accounts
if [ -f "./security_ops/alerts/locked_accounts.txt" ]; then
    locked_count=$(wc -l < "./security_ops/alerts/locked_accounts.txt" | tr -d ' ')
    if [ "$locked_count" -gt 0 ]; then
        echo "[+] Locked accounts: $locked_count"
        cat "./security_ops/alerts/locked_accounts.txt"
    else
        echo "[+] No accounts currently locked."
    fi
else
    echo "[+] No account lock list found."
fi

# Check log files
system_log_size=$(du -h "./security_ops/logs/system.log" 2>/dev/null | cut -f1 || echo "0")
network_log_size=$(du -h "./security_ops/logs/network.log" 2>/dev/null | cut -f1 || echo "0")

echo "[+] System log size: $system_log_size"
echo "[+] Network log size: $network_log_size"

echo "==============================================="
echo "  Status check complete"
echo "==============================================="
