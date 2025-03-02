#!/usr/bin/env python3

"""
Globomantics Security Monitoring System
This script monitors log files for suspicious activities matching
known Dark Kittens attack patterns and triggers automated responses.
"""

import os
import json
import time
import re
import subprocess
from datetime import datetime

def load_config():
    """Load monitoring configuration"""
    try:
        with open('./security_ops/config.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load configuration: {e}")
        return None

def load_threat_intel():
    """Load threat intelligence data"""
    try:
        with open('./security_ops/intel/threat_intel.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load threat intelligence: {e}")
        return None

def check_system_logs(config, threat_intel):
    """Monitor system logs for suspicious activity"""
    alerts = []
    try:
        with open('./security_ops/logs/system.log', 'r') as f:
            log_lines = f.readlines()
            
        # Check for suspicious patterns
        for pattern in threat_intel['system_patterns']:
            for line in log_lines:
                if re.search(pattern['pattern'], line):
                    timestamp = line.split()[0] + " " + line.split()[1]
                    alert = {
                        'timestamp': timestamp,
                        'type': 'system',
                        'pattern': pattern['name'],
                        'severity': pattern['severity'],
                        'log': line.strip()
                    }
                    alerts.append(alert)
    except Exception as e:
        print(f"[ERROR] Failed to check system logs: {e}")
    
    return alerts

def check_network_logs(config, threat_intel):
    """Monitor network logs for suspicious activity"""
    alerts = []
    try:
        with open('./security_ops/logs/network.log', 'r') as f:
            log_lines = f.readlines()
            
        # Check for suspicious patterns
        for pattern in threat_intel['network_patterns']:
            for line in log_lines:
                if re.search(pattern['pattern'], line):
                    timestamp = line.split()[0] + " " + line.split()[1]
                    alert = {
                        'timestamp': timestamp,
                        'type': 'network',
                        'pattern': pattern['name'],
                        'severity': pattern['severity'],
                        'log': line.strip()
                    }
                    alerts.append(alert)
    except Exception as e:
        print(f"[ERROR] Failed to check network logs: {e}")
    
    return alerts

def trigger_response(alert):
    """Trigger automated response based on alert"""
    try:
        print(f"[ALERT] Triggering response for {alert['pattern']}")
        # Call the response script with alert information
        cmd = ["./response.sh", alert['type'], alert['pattern'], str(alert['severity'])]
        subprocess.run(cmd)
        
        # Log the alert
        with open('./security_ops/alerts/alerts.log', 'a') as f:
            f.write(json.dumps(alert) + "\n")
            
        # Update alert status
        with open('./security_ops/alerts/status.txt', 'w') as f:
            f.write("ACTIVE_ALERTS")
    except Exception as e:
        print(f"[ERROR] Failed to trigger response: {e}")

def main():
    print("\n[INFO] Starting Globomantics Security Monitoring System")
    print("[INFO] Loading configuration and threat intelligence...")
    
    config = load_config()
    threat_intel = load_threat_intel()
    
    if not config or not threat_intel:
        print("[ERROR] Failed to load required data. Exiting.")
        return
    
    print(f"[INFO] Monitoring interval: {config['monitoring_interval']} seconds")
    print(f"[INFO] Alert threshold: {config['alert_threshold']}")
    print(f"[INFO] Loaded {len(threat_intel['system_patterns'])} system patterns and {len(threat_intel['network_patterns'])} network patterns")
    
    print("[INFO] Monitoring started. Press Ctrl+C to stop.\n")
    
    # Count monitoring loops to prevent infinite running
    max_cycles = 20  # Will run for about ~2 minutes with default 5-second interval
    current_cycle = 0
    
    try:
        while current_cycle < max_cycles:
            # Check for suspicious activities
            system_alerts = check_system_logs(config, threat_intel)
            network_alerts = check_network_logs(config, threat_intel)
            
            all_alerts = system_alerts + network_alerts
            
            # Process any detected alerts
            for alert in all_alerts:
                print(f"[DETECTION] {alert['timestamp']} - {alert['pattern']} (Severity: {alert['severity']})")
                if alert['severity'] >= config['alert_threshold']:
                    trigger_response(alert)
            
            if not all_alerts:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No suspicious activities detected.")
            
            # Increment cycle counter
            current_cycle += 1
            
            # Sleep until next check
            time.sleep(config['monitoring_interval'])
            
        print("\n[INFO] Monitoring completed. To restart monitoring, run 'bash check_status.sh'")
            
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped by user.")

if __name__ == "__main__":
    main()
