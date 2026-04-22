import re
from collections import defaultdict
from datetime import datetime, timedelta

def extract_ip(line):
    match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
    return match.group() if match else  None

def extract_user(line):
    match = re.search(r'for (?:invalid user )?(\w+)', line)
    return match.group(1) if match else "unknown"

def extract_time(line):
    try:
        timestamp_str = line.split()[0]
        return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None

def analyze_logs(file_path, windows_minutes=10, threshold=3):
    failed_logins = defaultdict(list)

    with open(file_path, "r") as file:
        for line in file:
            if "failed password" not in line.lower():
                continue

            ip = extract_ip(line)
            timestamp = extract_time(line)
            user = extract_user(line)

            if not ip or not timestamp:
                continue

            failed_logins[(ip, user)].append(timestamp)

    print("\n==== SIEM REPORT ====\n")
    print(f"Window: {windows_minutes} minutes | Threshold: {threshold} attempts\n")

    alerts = []

    LOG_FILE = "sample.log"
    THRESHOLD = 3
    WINDOW = timedelta(seconds=60)

    for ( ip, user ), times in failed_logins.items():
        times.sort()

        for i in range(len(times) - THRESHOLD + 1):
            window = times[i:i+THRESHOLD]
            if window[-1] - window[0] <= WINDOW:
                alerts.append({
                    "ip": ip,
                    "users": user,
                    "count": THRESHOLD,
                    "start": window[0].isoformat(),
                    "end": window[-1].isoformat(),
                    "detection": "brute_force_window",
                    "severity": "high"
                })
                break

    if not alerts:
        print("Np brute force detected")
    else:
        print(f"Window: {WINDOW} | Threshold: {THRESHOLD}")
        for alert in sorted(alerts, key=lambda x: x['count'], reverse=True):
            print(f"ALERT: {alert['ip']} | users '{alert['users']}' | {alert['count']} fails | {alert['start']} -> {alert['end']}")

def main():
    file_path = input("Enter log file path: ")
    analyze_logs(file_path)

if __name__ == "__main__":
    main()
