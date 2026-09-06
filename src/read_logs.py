import re

log_file = "data/sample_logs/auth.log"

failed_counts = {}   # har IP ka count yahan store hoga

with open(log_file, "r") as f:
    for line in f:
        if "Failed password" in line:
            # line se IP address nikaalo (regex se)
            ip = re.findall(r"\d+\.\d+\.\d+\.\d+", line)[0]
            # us IP ka count badhao
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

print("=== Failed Login Attempts (IP-wise) ===")
for ip, count in failed_counts.items():
    print(f"{ip} : {count} attempts")

print()
print("=== ALERTS ===")
for ip, count in failed_counts.items():
    if count >= 3:
        print(f"ALERT! {ip} ne {count} failed attempts kiye — possible brute force!")