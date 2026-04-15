import re
from collections import defaultdict

def extract_ip(line):
    print("CHECKING LINE FOR IP:", line)
    return None

def analyze_logs(file_path):
    failed = 0
    successful = 0
    with open(file_path, "r") as file:
       for line in file:
            clean_line = line.strip().lower()
            if "failed password" in clean_line:
                failed += 1
            elif "accepted password" in clean_line:
                successful += 1

    print("\n=== SIEM REPORT ===\n")
    print(f"Failed login attempts: {failed}")
    print(f" Successful logins: {successful}")

    if failed >= 3:
        print("\n[ALERT] Possible brute-force attack detected!")

def main():
    file_path = "sample.log"
    analyze_logs(file_path)

if __name__ == "__main__":
    main()
