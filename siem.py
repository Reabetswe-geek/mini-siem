from collections import defaultdict

print("=" * 50)
print("    Mini SIEM log analyzer")
print("=" * 50)

failed_logins = defaultdict(int)
suspicious_ips = set()

with open("sample.log", "r") as file:
    for line in file:
        line = line.strip()

        if "Failed password" in line:
            ip = line.split()[-1]
            failed_logins[ip] += 1

        if "Port scan" in line:
            ip = line.split()[-1]
            suspicious_ips.add(ip)

print("\n[!] Suspicious Activity Report\n")

for ip, count in failed_logins.items():
    if count >= 3:
        print(f"ALERT: Possible brute force from {ip} ({count} failed attempts)")

for ip in suspicious_ips:
    print(f"ALERT: Port scanning detected from {ip}")
