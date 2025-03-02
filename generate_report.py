#!/usr/bin/env python3

"""
Globomantics Security Report Generator
This script analyzes security alerts and responses to generate a
comprehensive security report.
"""

import os
import json
import time
from datetime import datetime
import re
from tabulate import tabulate
from colorama import init, Fore, Style

# Initialize colorama
init()

def load_config():
    """Load configuration data"""
    try:
        with open('./security_ops/config.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load configuration: {e}")
        return None

def load_alerts():
    """Load recorded security alerts"""
    alerts = []
    try:
        if os.path.exists('./security_ops/alerts/alerts.log'):
            with open('./security_ops/alerts/alerts.log', 'r') as f:
                for line in f:
                    try:
                        alert = json.loads(line.strip())
                        alerts.append(alert)
                    except:
                        continue
    except Exception as e:
        print(f"[ERROR] Failed to load alerts: {e}")
    
    return alerts

def load_responses():
    """Load response actions taken"""
    responses = []
    try:
        if os.path.exists('./security_ops/alerts/response.log'):
            with open('./security_ops/alerts/response.log', 'r') as f:
                for line in f:
                    match = re.match(r'([\d-]+ [\d:]+) - RESPONSE: (.*)', line.strip())
                    if match:
                        timestamp, action = match.groups()
                        responses.append({
                            'timestamp': timestamp,
                            'action': action
                        })
    except Exception as e:
        print(f"[ERROR] Failed to load responses: {e}")
    
    return responses

def load_blocked_ips():
    """Load list of blocked IP addresses"""
    blocked_ips = []
    try:
        if os.path.exists('./security_ops/alerts/blocked_ips.txt'):
            with open('./security_ops/alerts/blocked_ips.txt', 'r') as f:
                blocked_ips = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[ERROR] Failed to load blocked IPs: {e}")
    
    return blocked_ips

def load_locked_accounts():
    """Load list of locked user accounts"""
    locked_accounts = []
    try:
        if os.path.exists('./security_ops/alerts/locked_accounts.txt'):
            with open('./security_ops/alerts/locked_accounts.txt', 'r') as f:
                locked_accounts = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[ERROR] Failed to load locked accounts: {e}")
    
    return locked_accounts

def generate_summary(alerts, responses, blocked_ips, locked_accounts):
    """Generate a summary of security events"""
    if not alerts:
        return None
    
    # Count alerts by type and severity
    alert_types = {}
    severity_counts = {
        "Low (1-3)": 0,
        "Medium (4-6)": 0,
        "High (7-8)": 0,
        "Critical (9-10)": 0
    }
    
    for alert in alerts:
        # Count by type
        alert_type = alert.get('pattern', 'Unknown')
        if alert_type in alert_types:
            alert_types[alert_type] += 1
        else:
            alert_types[alert_type] = 1
        
        # Count by severity
        severity = alert.get('severity', 0)
        if 1 <= severity <= 3:
            severity_counts["Low (1-3)"] += 1
        elif 4 <= severity <= 6:
            severity_counts["Medium (4-6)"] += 1
        elif 7 <= severity <= 8:
            severity_counts["High (7-8)"] += 1
        elif 9 <= severity <= 10:
            severity_counts["Critical (9-10)"] += 1
    
    summary = {
        'total_alerts': len(alerts),
        'total_responses': len(responses),
        'blocked_ips': len(blocked_ips),
        'locked_accounts': len(locked_accounts),
        'alert_types': alert_types,
        'severity_counts': severity_counts
    }
    
    return summary

def print_report(summary, alerts, responses, blocked_ips, locked_accounts):
    """Print a formatted security report"""
    print("\n" + "="*70)
    print(f"{Fore.CYAN}GLOBOMANTICS SECURITY OPERATIONS CENTER{Style.RESET_ALL}")
    print(f"{Fore.CYAN}SECURITY INCIDENT REPORT{Style.RESET_ALL}")
    print("="*70)
    
    # Print report header
    print(f"\nReport generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Reporting period: All recorded events")
    print("-"*70)
    
    if not summary:
        print(f"\n{Fore.YELLOW}No security alerts have been recorded.{Style.RESET_ALL}")
        print("Run 'python simulate_attack.py' to simulate Dark Kittens attacks.")
        print("-"*70)
        return
    
    # Print summary statistics
    print(f"\n{Fore.GREEN}SUMMARY STATISTICS{Style.RESET_ALL}")
    print(f"Total alerts detected: {summary['total_alerts']}")
    print(f"Total response actions: {summary['total_responses']}")
    print(f"IPs blocked: {summary['blocked_ips']}")
    print(f"Accounts locked: {summary['locked_accounts']}")
    
    # Print severity distribution
    print(f"\n{Fore.GREEN}ALERT SEVERITY DISTRIBUTION{Style.RESET_ALL}")
    severity_table = []
    for level, count in summary['severity_counts'].items():
        color = Fore.GREEN
        if "Medium" in level:
            color = Fore.YELLOW
        elif "High" in level:
            color = Fore.RED
        elif "Critical" in level:
            color = Fore.RED + Style.BRIGHT
        
        severity_table.append([f"{color}{level}{Style.RESET_ALL}", count])
    
    print(tabulate(severity_table, headers=["Severity", "Count"], tablefmt="simple"))
    
    # Print alert types
    print(f"\n{Fore.GREEN}ALERT TYPES{Style.RESET_ALL}")
    types_table = [[alert_type, count] for alert_type, count in summary['alert_types'].items()]
    print(tabulate(types_table, headers=["Attack Pattern", "Count"], tablefmt="simple"))
    
    # Print latest alerts
    print(f"\n{Fore.GREEN}LATEST ALERTS (up to 5){Style.RESET_ALL}")
    if alerts:
        alerts_table = []
        for alert in alerts[-5:]:
            severity = alert.get('severity', 0)
            color = Fore.GREEN
            if 4 <= severity <= 6:
                color = Fore.YELLOW
            elif 7 <= severity <= 8:
                color = Fore.RED
            elif 9 <= severity <= 10:
                color = Fore.RED + Style.BRIGHT
                
            alerts_table.append([
                alert.get('timestamp', 'Unknown'),
                alert.get('type', 'Unknown'),
                alert.get('pattern', 'Unknown'),
                f"{color}{severity}{Style.RESET_ALL}"
            ])
        
        print(tabulate(alerts_table, headers=["Timestamp", "Type", "Pattern", "Severity"], tablefmt="simple"))
    else:
        print("No alerts recorded.")
    
    # Print latest responses
    print(f"\n{Fore.GREEN}LATEST RESPONSES (up to 5){Style.RESET_ALL}")
    if responses:
        responses_table = []
        for response in responses[-5:]:
            responses_table.append([
                response.get('timestamp', 'Unknown'),
                response.get('action', 'Unknown')
            ])
        
        print(tabulate(responses_table, headers=["Timestamp", "Action"], tablefmt="simple"))
    else:
        print("No responses recorded.")
    
    # Print blocked IPs
    print(f"\n{Fore.GREEN}BLOCKED IP ADDRESSES{Style.RESET_ALL}")
    if blocked_ips:
        for ip in blocked_ips:
            print(f"- {ip}")
    else:
        print("No IP addresses have been blocked.")
    
    # Print locked accounts
    print(f"\n{Fore.GREEN}LOCKED USER ACCOUNTS{Style.RESET_ALL}")
    if locked_accounts:
        for account in locked_accounts:
            print(f"- {account}")
    else:
        print("No user accounts have been locked.")
    
    print("\n" + "="*70)
    print(f"{Fore.CYAN}END OF REPORT{Style.RESET_ALL}")
    print("="*70 + "\n")

def save_report(summary, alerts, responses, blocked_ips, locked_accounts):
    """Save the report to a file"""
    try:
        os.makedirs('./security_ops/reports', exist_ok=True)
        
        report_filename = f"./security_ops/reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_filename, 'w') as f:
            f.write("="*70 + "\n")
            f.write("GLOBOMANTICS SECURITY OPERATIONS CENTER\n")
            f.write("SECURITY INCIDENT REPORT\n")
            f.write("="*70 + "\n\n")
            
            # Report header
            f.write(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Reporting period: All recorded events\n")
            f.write("-"*70 + "\n")
            
            if not summary:
                f.write("\nNo security alerts have been recorded.\n")
                f.write("Run 'python simulate_attack.py' to simulate Dark Kittens attacks.\n")
                f.write("-"*70 + "\n")
                return report_filename
            
            # Summary statistics
            f.write("\nSUMMARY STATISTICS\n")
            f.write(f"Total alerts detected: {summary['total_alerts']}\n")
            f.write(f"Total response actions: {summary['total_responses']}\n")
            f.write(f"IPs blocked: {summary['blocked_ips']}\n")
            f.write(f"Accounts locked: {summary['locked_accounts']}\n")
            
            # Severity distribution
            f.write("\nALERT SEVERITY DISTRIBUTION\n")
            severity_table = []
            for level, count in summary['severity_counts'].items():
                severity_table.append([level, count])
            
            f.write(tabulate(severity_table, headers=["Severity", "Count"], tablefmt="simple") + "\n")
            
            # Alert types
            f.write("\nALERT TYPES\n")
            types_table = [[alert_type, count] for alert_type, count in summary['alert_types'].items()]
            f.write(tabulate(types_table, headers=["Attack Pattern", "Count"], tablefmt="simple") + "\n")
            
            # Latest alerts
            f.write("\nLATEST ALERTS (up to 5)\n")
            if alerts:
                alerts_table = []
                for alert in alerts[-5:]:
                    alerts_table.append([
                        alert.get('timestamp', 'Unknown'),
                        alert.get('type', 'Unknown'),
                        alert.get('pattern', 'Unknown'),
                        alert.get('severity', 0)
                    ])
                
                f.write(tabulate(alerts_table, headers=["Timestamp", "Type", "Pattern", "Severity"], tablefmt="simple") + "\n")
            else:
                f.write("No alerts recorded.\n")
            
            # Latest responses
            f.write("\nLATEST RESPONSES (up to 5)\n")
            if responses:
                responses_table = []
                for response in responses[-5:]:
                    responses_table.append([
                        response.get('timestamp', 'Unknown'),
                        response.get('action', 'Unknown')
                    ])
                
                f.write(tabulate(responses_table, headers=["Timestamp", "Action"], tablefmt="simple") + "\n")
            else:
                f.write("No responses recorded.\n")
            
            # Blocked IPs
            f.write("\nBLOCKED IP ADDRESSES\n")
            if blocked_ips:
                for ip in blocked_ips:
                    f.write(f"- {ip}\n")
            else:
                f.write("No IP addresses have been blocked.\n")
            
            # Locked accounts
            f.write("\nLOCKED USER ACCOUNTS\n")
            if locked_accounts:
                for account in locked_accounts:
                    f.write(f"- {account}\n")
            else:
                f.write("No user accounts have been locked.\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*70 + "\n")
        
        return report_filename
    except Exception as e:
        print(f"[ERROR] Failed to save report: {e}")
        return None

def main():
    print("\n[INFO] Generating Globomantics Security Report...")
    
    # Load data
    config = load_config()
    alerts = load_alerts()
    responses = load_responses()
    blocked_ips = load_blocked_ips()
    locked_accounts = load_locked_accounts()
    
    # Generate report summary
    summary = generate_summary(alerts, responses, blocked_ips, locked_accounts)
    
    # Print the report
    print_report(summary, alerts, responses, blocked_ips, locked_accounts)
    
    # Save the report
    report_file = save_report(summary, alerts, responses, blocked_ips, locked_accounts)
    if report_file:
        print(f"[INFO] Report saved to {report_file}")

if __name__ == "__main__":
    main()
