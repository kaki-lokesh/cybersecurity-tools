#!/usr/bin/env python3

"""
network_scanner.py - TCP Port Scanner with Banner Grabbing
Usage - python3 network_scanner.py -t 127.0.0.1 -p 1-1024 -o report.txt
"""

import socket
import argparse
import sys
import concurrent.futures
from datetime import datetime
# socket = TCP connection handling (the core of our scanner)
# concurrent.futures = threading to scan multiple ports simultaneously (fast)

# Common port to service name mapping
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Core functions
def get_service_name(port):
    """Return service name from our dict, or try socket library, or 'unknown'."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port) # Python's built-in port->service lookup
    except OSError:
        return "unknown"

def grab_banner(sock, timeout=2):
    """Try to read service banner from an open socket."""
    try:
        sock.settimeout(timeout)
        # For HTTP, send a request to get a response
        try:
            sock.send(b"HEAD / HTTP/1.0\r\nHOST: target\r\n\r\n")
        except Exception:
            pass
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

        # Clean banner: take first line only, remove control chars
        first_line = banner.split('\n')[0][:80]
        return first_line if first_line else none
    except Exception:
        return None

def scan_port(target_ip, port, timeout=1):
    """
    Attempt TCP connection to one port.
    Returns dict if open, None if closed/filtered.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # AF_INET = IPv4, SOCK_STREAM = TCP (vs SOCK_DGRAM for UDP)
    sock.settimeout(timeout) # Don't wait forever for filtered ports

    result = sock.connect_ex((target_ip, port))
    # connect_ex returns 0 if connection succeeds (port OPEN)
    # Returns error code (non-zero) if connection fails (port CLOSED or FILTERED)
    # This is the TCP 3-way handshake happening in one line

    if result == 0:
        service = get_service_name(port)
        banner = grab_banner(sock)
        sock.close()
        return {'port': port, 'state': 'open', 'service': service, 'banner': banner}
    sock.close()
    return None # Port closed or filtered

def scan_host(target_ip, start_port, end_port, threads=100, timeout=1):
    """Scan a range of ports using threading for speed."""
    open_ports = []
    ports_to_scan = range(start_port, end_port + 1)

    print(f"\n[*] Scanning {target_ip} ports {start_port}-{end_port}...")
    print(f"[*] Using {threads} threads | Timeout: {timeout}s\n")

    # ThreadPoolExecutor runs scan_port on multiple ports simultaneously
    # Without threading: scanning 1000 ports with 1s timeout = 1000 seconds (16 min)
    # With 100 threads: same scan takes ~10 seconds
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, target_ip, port, timeout): port
            for port in ports_to_scan
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result: # Port was open
                open_ports.append(result)
                service = result['service']
                banner = f" | {result['banner']}" if result['banner'] else ""
                print(f" [OPEN] {result['port']:>5}/tcp {service:<15}{banner}")
    return sorted(open_ports, key=lambda x: x['port'])

def generate_report(target_ip, open_ports, start_port, end_port, output_file=None):
    """Generate a formatted scan report."""
    report = []
    report.append("=" * 65)
    report.append(f" PORT SCAN REPORT")
    report.append("=" * 65)
    report.append(f" Target : {target_ip}")
    report.append(f" Ports : {start_port}-{end_port}")
    report.append(f" Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f" Open : {len(open_ports)} port(s) found")
    report.append("=" * 65)
    report.append(f"\n{'PORT':<10} {'STATE':<8} {'SERVICE':<15} {'BANNER'}")
    report.append(f"{'-'*10} {'-'*8} {'-'*15} {'-'*30}")
    for p in open_ports:
        port_str = f"{p['port']}/tcp"
        banner = p['banner'] or "-"
        report.append(f"{port_str:<10} {'open':<8} {p['service']:<15} {banner[:40]}")
    report.append(f"\n{'=' * 65}")
    report_text = '\n'.join(report)
    print("\n" + report_text)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report_text)
        print(f"\n[+] Report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner with Banner Grabbing",
        epilog="Only scan targets you have explicit permission to scan!"
    )
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port range (default: 1-1024)')
    parser.add_argument('-T', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('-o', '--output', help='Save report to file')
    parser.add_argument('--timeout', type=float, default=1.0, help='Connection timeout in seconds (default: 1.0)')
    args = parser.parse_args()

    # Parse port range "1-1024" into start=1, end=1024
    try:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        else:
            start_port = end_port = int(args.ports)  # Single port
    except ValueError:
        print("Error: Invalid port format. Use: 80 or 1-1024")
        sys.exit(1)

    # Validate IP address
    try:
        socket.inet_aton(args.target)  # Raises OSError if invalid IP
    except socket.error:
        # Try to resolve as hostname
        try:
            args.target = socket.gethostbyname(args.target)
        except socket.gaierror:
            print(f"Error: Cannot resolve '{args.target}'");
            sys.exit(1)

    start_time = datetime.now()
    open_ports = scan_host(args.target, start_port, end_port, args.threads, args.timeout)
    elapsed = (datetime.now() - start_time).total_seconds()
    generate_report(args.target, open_ports, start_port, end_port, args.output)
    print(f"\n[*] Scan completed in {elapsed:.2f} seconds")

if __name__ == "__main__":
    main()
