import argparse
import time
from collections import defaultdict

print("=" * 50)
print("  MINI SIEM/LOG Analyzer v2")
print("=" * 50)

parser = argparse.ArgumentParser(description="MINI SIEM TOOL")
parser.add_argument("--file", default="sample", help="log file to analyze")
parser.add_argument("--live", action="store_true", help="Enable real time-time monitoring")

args = parser.parse_args()

failed_logins = defaultdict(int)
suspicious_ips = set()

def analyze_line(line):
    line = line.strip()

    if "Failed password" in line:
        ip = line.split()[-1]
        failed_logins[ip] += 1

        if failed_logins[ip] == 3:
            print(f"[ALERT] Brute force suspected from {ip} (3 failed attempts)")

    if "Port scan" in line:
        ip = line.split()[-1]
        if ip not in suspicious_ips:
            suspicious_ips.add(ip)
            print(f"[ALERT] Port scanning detected from {ip}")

def analyze_file():
    with open(args.file, "r") as file:
        for line in file:
            analyze_line(line)

def monitor_live():
    print("\n[+] Monitoring log file in real time...\n")
    with open(args.file, "r") as file:
        file.seek(0, 2)

    while True:
        line = file.readline()
        if not line:
            time.sleep(1)
            continue
        analyze_line(line)

if args.live:
    monitor_live()
else:
    print("\n[+} Analyzing log file...\n")
    analyze_file()
