#!/usr/bin/env python3

"""
log_parser.py - SSH Brute Force Detection Tool
Usage: python3 log_parser.py [logfile] [threshold]
INPUT - path to auth.log file, threshold number (default 5)
PROCESS - read each line, find "Failed password" lines, extract IP and username, count per IP, identify suspicious IPs
OUTPUT - formatted report with timestamp, total counts, sorted attacker list, and a final verdict
"""

import sys
import re
from collections import Counter, defaultdict
from datetime import datetime
# re = regex module (pattern matching)
# Counter = dictionary that counts items
# defaultdict = dict with default value for missing keys

def parse_failed_logins(log_content):
    """Extract failed login attempts from auth.log content"""
    failed_attempts = []
    # Regex pattern to match: "Failed password for USERNAME from IP port PORT ssh2"
    pattern = r'Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)'
    # \S+ = one or more non-whitespace characters (the username)
    # \d+\.\d+\.\d+\.\d+ = IP address pattern (four groups of digits with dots)

    for line in log_content.split('\n'):
        match = re.search(pattern, line)
        if match:
            username = match.group(1) # First capture group = username
            ip_address = match.group(2) # Second capture group = IP
            failed_attempts.append({'username': username, 'ip': ip_address, 'line': line.strip()})
    return failed_attempts

def analyse_attacks(failed_attempts, threshold):
    """Count attacks per IP and identify suspicious ones"""
    ip_counter = Counter() # Count attacks per IP
    user_counter = Counter() # Count by target username
    ip_users = defaultdict(set) # Map IP to set of usernames tried

    for attempt in failed_attempts:
        ip_counter[attempt['ip']] +=  1
        user_counter[attempt['username']] += 1
        ip_users[attempt['ip']].add(attempt['username'])

    # Seperate suspicious (above threshold) from low-activity IPs
    suspicious = {ip: count for ip, count in ip_counter.items() if count >= threshold}
    normal = {ip: count for ip, count in ip_counter.items() if count < threshold}

    return ip_counter, user_counter, ip_users, suspicious, normal

def generate_report(filepath, threshold, failed_attempts, ip_counter, user_counter, ip_users, suspicious):
    """Print a formatted security report"""
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"SSH BRUTE FORCE DETECTION REPORT")
    print(f"{sep}")
    print(f" Log file : {filepath}")
    print(f" Analysis : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Threshold: {threshold} attempts = SUSPICIOUS")
    print(f"{sep}\n")

    print(f"[SUMMARY]")
    print(f" Total failed attempts : {len(failed_attempts)}")
    print(f" Unique attacker IPs : {len(ip_counter)}")
    print(f" Username targeted : {len(user_counter)}")
    print(f" SUSPICIOUS IPs : {len(suspicious)}")
    print()

    print(f"[TOP ATTACKING IPs] (sorted by attempts)")
    print(f" {'IP Address':<20} {'Attempts':>8} {'Users Tried':<30} {'Status'}")
    print(f" {'-'*20} {'-'*8} {'-'*30} {'-'*10}")
    for ip, count in ip_counter.most_common(10): # Show top 10
        users = ', '.join(sorted(ip_users[ip]))[:30]
        status = "⚠ SUSPICIOUS" if count >= threshold else " normal"
        print(f" {ip:<20} {count:>8} {users:<30} {status}")
    print()

    print(f"[TOP TARGETED USERNAMES]")
    for username, count in user_counter.most_common(5):
        bar = "█" * min(count, 30) # Visual bar (capped at 30)
        print(f" {username:<15} {count:>5} {bar}")
    print()

    if suspicious:
        print(f"[ALERT — BRUTE FORCE ATTACK DETECTED]")
        print(f" The following IPs exceeded the threshold of {threshold} attempts:")
        for ip, count in sorted(suspicious.items(), key=lambda x: -x[1]):
            print(f" -> {ip} ({count} attempts) — RECOMMEND BLOCKING")
    else:
        print(f"[NO BRUTE FORCE DETECTED]")
        print(f" No IP exceeded the threshold of {threshold} attempts.")
    print(f"\n{sep}\n")

def main():
    # Handle command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 log_parser.py <logfile> [threshold]")
        print("Example: python3 log_parser.py /var/log/auth.log 5")
        sys.exit(1)

    filepath = sys.argv[1]
    threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 5 # Default threshold: 5

    # Read the log file
    try:
        with open(filepath, 'r', errors='ignore') as f:
            log_content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied. Try: sudo python3 log_parser.py {filepath}")
        sys.exit(1)

    # Run analysis
    failed_attempts = parse_failed_logins(log_content)
    if not failed_attempts:
        print("No failed login attempts found in log file.")
        sys.exit(0)

    ip_counter, user_counter, ip_users, suspicious, normal = analyse_attacks(failed_attempts, threshold)
    generate_report(filepath, threshold, failed_attempts, ip_counter, user_counter, ip_users, suspicious)

if __name__ == "__main__":
    main()
