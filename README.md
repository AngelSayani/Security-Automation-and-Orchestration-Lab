# Security-Automation-and-Orchestration-Lab
# Globomantics Defense Protocol - Anomaly Detection and Security Automation 

This lab provides a hands-on opportunity to learn security automation and orchestration concepts through a simulated scenario. It's like a flight simulator for security operations - it creates a controlled environment where learners can practice skills safely. You'll deploy a security monitoring and response system to detect and counter attacks from the notorious "Dark Kittens" hacking group.

## Scenario

Globomantics runs an artificial island in the Gulf of Mexico that has been repeatedly targeted by the notorious hacking group Dark Kittens. As a SOC analyst and security engineer at Globomantics, you've been tasked with implementing automated security monitoring and response capabilities to detect and thwart these attacks.

Intelligence reports suggest the Dark Kittens use specific patterns in their attacks, including port scanning, brute force login attempts, unusual file access patterns, and data exfiltration techniques. Your job is to set up a system that automatically detects these patterns and responds appropriately.

## Lab Environment

This lab simulates the Globomantics' security operations center (SOC) using:

- Python-based monitoring system
- Bash-based automated response scripts
- Simulated log files and attack patterns
- Reporting capabilities

This interactive lab provides valuable hands-on experience with security concepts. It allows learners to understand the principles of security monitoring and automation.

## Network Diagram

![Network Diagram](network_diagram.png)

The lab environment consists of:

1. A simulated attacker (Dark Kittens) - represented by the `simulate_attack.py` script
2. A security monitoring system - implemented in `monitor.py`
3. An automated response system - implemented in `response.sh`
4. Log files and configuration data

## Prerequisites

- Ubuntu, Kali Linux or any Unix-based system (or a Windows machine configured with Windows Subsystem for Linux (WSL))
- Python 3.6 or higher
- Bash shell
- Basic packages: `pip3`, `tabulate`, `colorama`, `json5`

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/AngelSayani/Security-Automation-and-Orchestration-Lab.git
   cd Security-Automation-and-Orchestration-Lab
   ```

2. Run the setup script to create the lab environment:
   ```bash
   bash setup.sh
   ```

3. The setup will create necessary directories, deploy monitoring scripts, and prepare the test environment.

## Lab Tasks

### Task 1: Configure the Security Monitoring System
1. Examine the `config.json` file
2. **YOUR TASK**: Modify the `alert_threshold` value in `config.json` from 6 to 5 to increase detection sensitivity
3. Start the monitoring system:
   ```bash
   bash check_status.sh
   ```
   When prompted, choose "y" to start monitoring

### Task 2: Review Threat Intelligence Data
1. Examine the `threat_intel.json` file
2. **YOUR TASK**: Add a new indicator to the `ip_ranges` array in `threat_intel.json`:
   ```json
   "98.76.54.0/24"
   ```
3. List three TTPs (Tactics, Techniques, and Procedures) used by Dark Kittens in your notes

### Task 3: Test the Automated Response System
1. Open a new terminal window (keep the monitoring system running)
2. Run the attack simulation:
   ```bash
   python3 simulate_attack.py
   ```
3. **YOUR TASK**: Choose option #2 (Brute Force Login) for your first test
4. Observe the monitoring system's response in real-time, in the first terminal.
5. Check if the automated response script (`response.sh`) successfully mitigated the threat
6. Verify the contents of `./security_ops/alerts/blocked_ips.txt` to see the automated response:
   ```bash
   cat ./security_ops/alerts/blocked_ips.txt
   ```

### Task 4: Analyze the Security Report 
Observe detection and response (in the monitoring terminal): You would see real-time alerts as the monitoring system detects the simulated attack.
1. Generate a security report:
   ```bash
   python3 generate_report.py
   ```
2. **YOUR TASK**: Open the report file in the `./security_ops/reports/` directory:
   ```bash
   ls -la ./security_ops/reports/
   cat ./security_ops/reports/security_report_*.txt
   ```
3. Answer these questions in your notes:
   - How many alerts were detected?
   - What was the highest severity alert?
   - What automatic response actions were taken?

### Task 5: Customize a Detection Rule
1. **YOUR TASK**: Edit the `threat_intel.json` file to modify the "Data Exfiltration" pattern:
   ```bash
   nano threat_intel.json
   ```
2. Change the severity of the "Data Exfiltration" pattern from 9 to 10
3. Run another attack simulation, this time choosing option #3 (Data Exfiltration)
4. Generate a new report and observe how your change affected the results.
5. Review the findings - Identify any gaps in detection or response


## Task 6: Enhance the Security Automation (Optional)**
1. Modify the monitor.py script to improve detection capabilities
2. Update the response.sh script to implement more effective countermeasures


## File Structure

- `README.md` - Main instructions and scenario
- `setup.sh` - Main setup script for the environment
- `monitor.py` - Python script for monitoring suspicious activities
- `response.sh` - Bash script to automatically respond to detected threats
- `simulate_attack.py` - Script to simulate Dark Kittens attacks
- `threat_intel.json` - Data file containing known Dark Kittens attack signatures
- `cleanup.sh` - Script to reset the lab environment
- `check_status.sh` - Script to check the security monitoring status
- `config.json` - Configuration file for monitoring parameters
- `generate_report.py` - Script to generate security reports

## Completion Criteria

You've successfully completed this lab when:
1. The monitoring system correctly identifies all simulated attack patterns
2. The automated response system effectively contains the threats
3. The security report accurately reflects all detected activities

## Reset the Lab

To reset the lab environment to its initial state:
```bash
bash cleanup.sh
```

## Learning Objectives

- Understand security monitoring and automation concepts
- Learn to detect common attack patterns in logs
- Practice implementing automated security responses
- Experience the full security operations workflow
- Analyze security reports and metrics
  

## Important Notes

- All Python scripts should be executed with python3 explicitly (not just python which might point to Python 2.x on some systems).
- The Bash scripts need to be executed with bash (e.g., bash setup.sh), not with sh which might use a different shell interpreter.
- All files must be in the same directory for the relative paths to work correctly.
- Make sure all scripts have executable permissions: 
```bash
chmod +x *.sh *.py
```

