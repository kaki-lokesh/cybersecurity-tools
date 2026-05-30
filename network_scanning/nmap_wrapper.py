#!/usr/bin/env python3
"""
nmap_wrapper.py — Python-Driven Nmap Scanner
Runs Nmap, parses XML output, generates security-focused report
Usage: python3 nmap_wrapper.py 127.0.0.1
       python3 nmap_wrapper.py scanme.nmap.org --ports 1-1024 --save-report
NOTE: Requires Nmap installed
"""
import subprocess
import argparse
import sys
import os
import xml.etree.ElementTree as ET
from datetime import datetime

# Services that are HIGH RISK if exposed (internet-facing)
HIGH_RISK_PORTS = {
    21:   'FTP - clear text, brute forceable',
    23:   'Telnet - completely unencrypted, legacy!',
    25:   'SMTP - potential open relay or spam abuse',
    135:  'MSRPC - Windows RPC, many exploits (MS08-067, EternalBlue)',
    139:  'NetBIOS - SMB legacy, information disclosure',
    445:  'SMB - EternalBlue, ransomware propagation target',
    1433: 'MSSQL - database exposed to internet',
    3306: 'MySQL - database exposed to internet',
    3389: 'RDP - brute force target, BlueKeep CVE-2019-0708',
    5900: 'VNC - remote access, often weak auth',
    6379: 'Redis - often no auth by default, remote code execution',
    27017:'MongoDB - often no auth by default, data exposure',
}

def check_nmap():
    """Verify Nmap is installed and accessible"""
    result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
    if result.returncode != 0:
        print("[ERROR] Nmap not found. Install with: sudo apt install nmap")
        sys.exit(1)
    version_line = result.stdout.split('\n')[0]
    print(f"[+] {version_line}")

def run_nmap_scan(target, ports, fast, output_file):
    """Run Nmap with version detection and XML output"""
    cmd = [
        'nmap',
        '-sV',               # Service/version detection
        '-sC',               # Default NSE scripts
        '-p', ports,         # Port range
        '-oX', output_file,  # XML output (we'll parse this)
        target
    ]
    if fast:
        cmd.insert(1, '--min-rate')
        cmd.insert(2, '3000')
    print(f"[*] Running: {' '.join(cmd)}\n")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=300
        )
        if result.returncode != 0:
            print(f"[WARN] Nmap returned non-zero: {result.stderr[:200]}")
        return result.returncode == 0 or os.path.exists(output_file)
    except subprocess.TimeoutExpired:
        print("[ERROR] Nmap timed out after 5 minutes")
        return False
    except FileNotFoundError:
        print("[ERROR] Nmap not found in PATH")
        return False

def parse_nmap_xml(xml_file):
    """Parse Nmap XML output into structured data"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"[ERROR] Could not parse Nmap XML: {e}")
        return []

    scan_results = []
    for host in root.findall('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue

        # Get IP address
        addr = host.find("address[@addrtype='ipv4']")
        ip = addr.get('addr') if addr is not None else 'unknown'

        # Get hostname
        hn_elem = host.find('.//hostname')
        hostname = hn_elem.get('name') if hn_elem is not None else 'N/A'

        # Get OS guess
        osmatch = host.find('.//osmatch')
        os_guess = osmatch.get('name') if osmatch is not None else 'Unknown'

        # Parse open ports
        ports_data = []
        for port in host.findall('.//port'):
            state_elem = port.find('state')
            if state_elem is None or state_elem.get('state') != 'open':
                continue
            portid   = int(port.get('portid', 0))
            protocol = port.get('protocol', 'tcp')
            svc      = port.find('service')
            svc_name = svc.get('name', 'unknown') if svc is not None else 'unknown'
            svc_ver  = svc.get('product', '') + ' ' + svc.get('version', '') if svc is not None else ''
            risk     = HIGH_RISK_PORTS.get(portid)
            ports_data.append({
                'port':     portid,
                'protocol': protocol,
                'service':  svc_name,
                'version':  svc_ver.strip(),
                'risk':     risk
            })

        scan_results.append({
            'ip': ip, 'hostname': hostname,
            'os': os_guess, 'ports': sorted(ports_data, key=lambda x: x['port'])
        })
    return scan_results

def print_report(results, target, save=False):
    """Print security-focused scan report"""
    lines = []
    lines.append(f"\n{'═'*65}")
    lines.append(f"  NMAP SECURITY SCAN REPORT")
    lines.append(f"  Target: {target}")
    lines.append(f"  Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append('═'*65)

    if not results:
        lines.append("\n  No hosts found (down or blocked)")

    for host in results:
        lines.append(f"\n[HOST] {host['ip']} ({host['hostname']})")
        lines.append(f"  OS Guess: {host['os']}")
        lines.append(f"  Open Ports: {len(host['ports'])}\n")
        lines.append(f"  {'PORT':<12} {'SERVICE':<15} {'VERSION':<30} {'RISK'}")
        lines.append(f"  {'-'*12} {'-'*15} {'-'*30} {'-'*20}")

        high_risks = []
        for p in host['ports']:
            port_str = f"{p['port']}/{p['protocol']}"
            risk_str = " HIGH RISK" if p['risk'] else ""
            lines.append(f"  {port_str:<12} {p['service']:<15} {p['version'][:30]:<30} {risk_str}")
            if p['risk']:
                high_risks.append(p)

        if high_risks:
            lines.append(f"\n  [ RISK FINDINGS]")
            for p in high_risks:
                lines.append(f"  Port {p['port']}: {p['risk']}")

    lines.append(f"\n{'═'*65}\n")
    report = '\n'.join(lines)
    print(report)

    if save:
        fname = f"nmap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fname, 'w') as f:
            f.write(report)
        print(f"[+] Report saved to: {fname}")

def main():
    parser = argparse.ArgumentParser(description='Python-Driven Nmap Security Scanner')
    parser.add_argument('target',   help='Target IP or hostname')
    parser.add_argument('--ports',  default='1-1024', help='Port range (default: 1-1024)')
    parser.add_argument('--fast',   action='store_true', help='Fast scan (--min-rate 3000)')
    parser.add_argument('--save-report', action='store_true', help='Save report to file')
    args = parser.parse_args()

    check_nmap()
    xml_output = '/tmp/nmap_scan.xml'

    success = run_nmap_scan(args.target, args.ports, args.fast, xml_output)
    if not success:
        print("[ERROR] Nmap scan failed"); sys.exit(1)

    results = parse_nmap_xml(xml_output)
    print_report(results, args.target, args.save_report)

    # Cleanup temp file
    if os.path.exists(xml_output):
        os.remove(xml_output)

if __name__ == '__main__':
    main()
