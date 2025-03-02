# Globomantics Defense Protocol - Anomaly Detection Lab

This lab provides a hands-on opportunity to learn security automation and orchestration concepts through a simulated scenario. You'll deploy a security monitoring and response system to detect and counter attacks from the notorious "Dark Kittens" hacking group.

## Scenario

Globomantics runs an artificial island in the Gulf of Mexico that has been repeatedly targeted by the notorious hacking group Dark Kittens. As a security engineer at Globomantics, you've been tasked with implementing automated security monitoring and response capabilities to detect and thwart these attacks.

Intelligence reports suggest the Dark Kittens use specific patterns in their attacks, including port scanning, brute force login attempts, unusual file access patterns, and data exfiltration techniques. Your job is to set up a system that automatically detects these patterns and responds appropriately.

## Lab Environment

This lab simulates a simplified version of Globomantics' security operations center using:

- Python-based monitoring system
- Bash-based automated response scripts
- Simulated log files and attack patterns
- Reporting capabilities

The lab runs entirely locally and doesn't require any cloud resources or internet connectivity.

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
   git clone https://github.com/your-username/globomantics-defense-protocol.git
   cd globomantics-defense-protocol
   ```

2. Run the setup script to create the lab environment:
   ```bash
   bash setup.sh
   ```

3. The setup will create necessary directories, deploy monitoring scripts, and prepare the test environment.

## Lab Tasks

### Task 1: Configure the Security Monitoring System
1. Examine the `config.json` file
2. Update the monitoring parameters to align with Globomantics' security policy
3. Start the monitoring system:
   ```bash
   bash check_status.sh
   ```

### Task 2: Review Threat Intelligence Data
1. Examine the `threat_intel.json` file
2. Identify the Dark Kittens' TTPs (Tactics, Techniques, and Procedures)
3. Note key indicators of compromise to watch for

### Task 3: Test the Automated Response System
1. Run the attack simulation:
   ```bash
   python3 simulate_attack.py
   ```
2. Monitor the system's response in real-time
3. Check if the automated response script (`response.sh`) successfully mitigated the threat

### Task 4: Analyze the Security Report
1. Generate a security report:
   ```bash
   python3 generate_report.py
   ```
2. Review the findings
3. Identify any gaps in detection or response

### Task 5: Enhance the Security Automation
1. Modify the `monitor.py` script to improve detection capabilities
2. Update the `response.sh` script to implement more effective countermeasures

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

## License

This project is licensed under the MIT License - see the LICENSE file for details.
   
