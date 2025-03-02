#!/usr/bin/env python3

"""
Dark Kittens Attack Simulation Script
This script simulates various attack patterns from the Dark Kittens hacking group
to test Globomantics' automated detection and response capabilities.
"""

import os
import time
import random
import json
from datetime import datetime, timedelta

def load_config():
    """Load simulation configuration"""
    try:
        with open('./security_ops/config.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load configuration: {e}")
        return None

def simulate_port_scan():
    """Simulate a port scan attack"""
    print("[+] Simulating Dark Kittens port scan attack...")
    
    # Create attacker IP
    attacker_ip = f"45.33.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    # Generate port scan log entries
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with open('./security_ops/logs/network.log', 'a') as f:
        # Write multiple port connection attempts
        for port in [22, 23, 80, 443, 445, 3389, 8080]:
            log_entry = f"{timestamp} - SRC={attacker_ip} DST=192.168.1.1 PROTO=TCP SPT={random.randint(40000, 65000)} DPT={port}\n"
            f.write(log_entry)
            time.sleep(0.1)  # Small delay between entries
    
    print(f"[+] Port scan simulation completed (Attacker IP: {attacker_ip})")
    return attacker_ip

def simulate_brute_force():
    """Simulate a brute force login attack"""
    print("[+] Simulating Dark Kittens brute force attack...")
    
    # Create attacker IP
    attacker_ip = f"192.168.{random.randint(1, 10)}.{random.randint(1, 255)}"
    
    # Generate failed login attempts
    base_time = datetime.now()
    
    with open('./security_ops/logs/system.log', 'a') as f:
        # Write multiple failed login attempts
        for i in range(5):
            timestamp = (base_time + timedelta(seconds=i*2)).strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"{timestamp} [ERROR] Failed login attempt for user admin from {attacker_ip}\n"
            f.write(log_entry)
            time.sleep(0.2)  # Small delay between entries
    
    print(f"[+] Brute force simulation completed (Attacker IP: {attacker_ip})")
    return attacker_ip

def simulate_data_exfiltration():
    """Simulate a data exfiltration attack"""
    print("[+] Simulating Dark Kittens data exfiltration...")
    
    # Create attacker IP
    attacker_ip = f"104.24.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    # Generate suspicious outbound connections
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Log large outbound data transfer
    with open('./security_ops/logs/network.log', 'a') as f:
        log_entry = f"{timestamp} - SRC=192.168.1.25 DST={attacker_ip} PROTO=TCP SPT=52123 DPT=443 SIZE=150000000\n"
        f.write(log_entry)
    
    # Log suspicious file access
    with open('./security_ops/logs/system.log', 'a') as f:
        file_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"{file_timestamp} [WARN] Unusual file access: /var/www/html/database/customers.db by process 12345\n"
        f.write(log_entry)
    
    print(f"[+] Data exfiltration simulation completed (Attacker IP: {attacker_ip})")
    return attacker_ip

def simulate_privilege_escalation():
    """Simulate a privilege escalation attack"""
    print("[+] Simulating Dark Kittens privilege escalation...")
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with open('./security_ops/logs/system.log', 'a') as f:
        # Log suspicious sudo usage
        log_entry = f"{timestamp} [WARN] User operator executed 'sudo su -' with NOPASSWD option\n"
        f.write(log_entry)
        
        # Log suspicious binary execution
        time.sleep(0.5)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"{timestamp} [CRITICAL] Execution of unexpected SUID binary: /tmp/.hidden/priv\n"
        f.write(log_entry)
    
    print("[+] Privilege escalation simulation completed")

def main():
    print("\n===============================================")
    print("  Dark Kittens Attack Simulation")
    print("  Testing Globomantics security automation")
    print("===============================================\n")
    
    config = load_config()
    if not config:
        print("[ERROR] Failed to load configuration. Exiting.")
        return
    
    # Reset alert status
    with open('./security_ops/alerts/status.txt', 'w') as f:
        f.write("NO_ALERTS")
    
    # Let the user choose which attack to simulate
    print("Choose an attack pattern to simulate:")
    print("1. Port Scan")
    print("2. Brute Force Login")
    print("3. Data Exfiltration")
    print("4. Privilege Escalation")
    print("5. All of the above")
    
    choice = input("\nEnter your choice (1-5): ")
    
    try:
        if choice == '1':
            simulate_port_scan()
        elif choice == '2':
            simulate_brute_force()
        elif choice == '3':
            simulate_data_exfiltration()
        elif choice == '4':
            simulate_privilege_escalation()
        elif choice == '5':
            print("[+] Simulating all attack patterns sequentially...\n")
            simulate_port_scan()
            time.sleep(1)
            simulate_brute_force()
            time.sleep(1)
            simulate_data_exfiltration()
            time.sleep(1)
            simulate_privilege_escalation()
        else:
            print("[ERROR] Invalid choice. Please enter a number between 1 and 5.")
            return
    except Exception as e:
        print(f"[ERROR] Simulation failed: {e}")
        return
    
    print("\n[+] Attack simulation completed successfully!")
    print("[+] Now run the monitoring system to see if it detects the attacks:")
    print("    python3 monitor.py")
    print("\n===============================================")
    
    print("Press Enter to exit...")
    input()

if __name__ == "__main__":
    main()
