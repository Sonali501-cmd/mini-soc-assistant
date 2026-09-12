import re

LOG_FILE = "data/sample_logs/auth.log"
BRUTE_FORCE_THRESHOLD = 3


def parse_log_line(line):
    """Ek log line se IP nikaalta hai. Failed login na ho toh None deta hai."""
    if "Failed password" in line or "Invalid user" in line:
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
        if ips:
            return ips[0]
    return None


def count_failed_logins(log_file):
    """Poori file padhkar har IP ka failed login count banata hai."""
    failed_counts = {}
    with open(log_file, "r") as f:
        for line in f:
            ip = parse_log_line(line)
            if ip:
                failed_counts[ip] = failed_counts.get(ip, 0) + 1
    return failed_counts


def detect_brute_force(failed_counts, threshold):
    """Counts check karke alerts ki list banata hai."""
    alerts = []
    for ip, count in failed_counts.items():
        if count >= threshold:
            alerts.append((ip, count))
    return alerts


def main():
    failed_counts = count_failed_logins(LOG_FILE)

    print("=== Failed Login Attempts (IP-wise) ===")
    for ip, count in failed_counts.items():
        print(f"{ip} : {count} attempts")

    print()
    print("=== ALERTS ===")
    alerts = detect_brute_force(failed_counts, BRUTE_FORCE_THRESHOLD)
    for ip, count in alerts:
        print(f"ALERT! {ip} ne {count} failed attempts kiye — possible brute force!")


main()