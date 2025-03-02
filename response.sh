#!/bin/bash

# Globomantics Automated Response Script
# This script performs automated responses to security alerts

# Get alert information from parameters
ALERT_TYPE=$1
ALERT_PATTERN=$2
ALERT_SEVERITY=$3

echo "==============================================="
echo "  Globomantics Automated Response System"
echo "  Responding to: $ALERT_PATTERN (Severity: $ALERT_SEVERITY)"
echo "==============================================="

# Log the response action
log_action() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - RESPONSE: $1" >> ./security_ops/alerts/response.log
}

# Simulate blocking an IP address
block_ip() {
    IP=$1
    echo "[+] Blocking malicious IP: $IP"
    log_action "Blocked IP $IP"
    
    # In a real environment, this would use iptables, firewalld, or similar
    echo "$IP" >> ./security_ops/alerts/blocked_ips.txt
    
    # Simulate changes to firewall
    echo "iptables -A INPUT -s $IP -j DROP" >> ./security_ops/alerts/firewall_changes.log
}

# Simulate killing a suspicious process
kill_process() {
    PROCESS=$1
    echo "[+] Terminating suspicious process: $PROCESS"
    log_action "Terminated process $PROCESS"
    
    # In a real environment, this would use kill or pkill
    echo "$PROCESS" >> ./security_ops/alerts/terminated_processes.txt
}

# Simulate locking a user account
lock_account() {
    USER=$1
    echo "[+] Locking suspicious user account: $USER"
    log_action "Locked account $USER"
    
    # In a real environment, this would use passwd -l or similar
    echo "$USER" >> ./security_ops/alerts/locked_accounts.txt
}

# Simulate backing up critical data
backup_data() {
    echo "[+] Creating emergency backup of critical data"
    log_action "Created emergency backup"
    
    # In a real environment, this would use rsync, tar, or similar
    BACKUP_ID=$(date +%Y%m%d%H%M%S)
    echo "Backup ID: $BACKUP_ID" >> ./security_ops/alerts/backups.log
}

# Respond based on alert type and pattern
case "$ALERT_TYPE" in
    "network")
        case "$ALERT_PATTERN" in
            "Port Scan")
                # Extract attacker IP from logs (simulated)
                ATTACKER_IP="10.0.0.$(( RANDOM % 255 ))"
                block_ip "$ATTACKER_IP"
                ;;
            "Brute Force")
                # Extract attacker IP from logs (simulated)
                ATTACKER_IP="192.168.1.$(( RANDOM % 255 ))"
                block_ip "$ATTACKER_IP"
                
                # Lock the targeted account
                TARGET_USER="admin"
                lock_account "$TARGET_USER"
                ;;
            "Data Exfiltration")
                # Extract attacker IP from logs (simulated)
                ATTACKER_IP="172.16.0.$(( RANDOM % 255 ))"
                block_ip "$ATTACKER_IP"
                
                # Kill the process responsible
                PROCESS_ID=$((1000 + RANDOM % 9000))
                kill_process "$PROCESS_ID"
                
                # Backup data in case of compromise
                backup_data
                ;;
            *)
                echo "[!] Unknown network pattern: $ALERT_PATTERN"
                log_action "Unknown network pattern: $ALERT_PATTERN"
                ;;
        esac
        ;;
    "system")
        case "$ALERT_PATTERN" in
            "Privilege Escalation")
                # Extract user from logs (simulated)
                SUSPICIOUS_USER="user$(( RANDOM % 5 ))"
                lock_account "$SUSPICIOUS_USER"
                
                # Kill suspicious processes
                PROCESS_ID=$((1000 + RANDOM % 9000))
                kill_process "$PROCESS_ID"
                ;;
            "File Tampering")
                # Backup affected files
                backup_data
                
                # Kill suspicious processes
                PROCESS_ID=$((1000 + RANDOM % 9000))
                kill_process "$PROCESS_ID"
                ;;
            "Unauthorized Access")
                # Extract attacker IP from logs (simulated)
                ATTACKER_IP="10.0.0.$(( RANDOM % 255 ))"
                block_ip "$ATTACKER_IP"
                
                # Lock compromised account
                COMPROMISED_USER="user$(( RANDOM % 5 ))"
                lock_account "$COMPROMISED_USER"
                ;;
            *)
                echo "[!] Unknown system pattern: $ALERT_PATTERN"
                log_action "Unknown system pattern: $ALERT_PATTERN"
                ;;
        esac
        ;;
    *)
        echo "[!] Unknown alert type: $ALERT_TYPE"
        log_action "Unknown alert type: $ALERT_TYPE"
        ;;
esac

echo "==============================================="
echo "  Response completed"
echo "  See ./security_ops/alerts/response.log for details"
echo "==============================================="
