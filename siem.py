import re
from collections import defaultdict
from datetime import datetime, timedelta

def extract_ip(line):
    match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
    return match.group() if match else  None

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

            if not ip or not timestamp:
                continue

            failed_logins[ip].append(timestamp)

    print("\n==== SIEM REPORT ====\n")
    print(f"Window: {windows_minutes} minutes | Threshold: {threshold} attempts\n")

    alerts = []

    for ip,  times in failed_logins.items():
        times.sort()

        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(minutes=windows_minutes)

            count_in_window = sum(1 for t in times[i:] if window_start <= t <= window_end)

            if count_in_window >= threshold:
                alerts.append((ip, count_in_window, window_start,window_end))
                break

    if not alerts:
        print("No alerts triggered.")
    else:
        for ip, count,start, end in sorted(alerts, key=lambda x: x[1], reverse=True):
            print(f"ALERT: {ip} -> {count} failed attempts")
            print(f"Window: {start.strftime('%H:%M:%S')} to {end.strftime('%H:%M:%S')}\n")

def main():
    file_path = input("Entet log file path: ")
    analyze_logs(file_path)

if __name__ == "__main__":
    main()
