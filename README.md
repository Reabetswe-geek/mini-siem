# Mini Siem (SECURITY INFORMATIOM AND EVENT MANAGEMENT)

## Overview
This project is a basic SIEM system built in python that analyzes authentication logs to detect potential brute-force attacks.

## Features
- Detects failed logins attempts
- Identified brute-force attacks (threshold-based)
- Parser log files
- Generates alerts

## Example Detection
 - 3x failed login attempts trigger an alert

## Technologies Used
- Python
- Regular Expressions
- Login Analysis

## Usage 
1. Run the script:
    python3 siem.py

2. The script analyzes 'sample.log' and output alerts.

## Future improvements
- IP-based tracking
- Time-based detection
- SOAR automation
