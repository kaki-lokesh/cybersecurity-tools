#!/usr/bin/env python3
"""
osint_ti_tool.py - OSINT Threat Intelligence Investigator
=========================================================
Queries multiple free security APIs to build an intelligence profile
for IP addresses, domains, and file hashes.

Author  : Lokesh Kaki | Phase 1 Week 6 | June 2026
GitHub  : github.com/kaki-lokesh/cybersecurity-tools
Docs    : see README.md
"""
import argparse
import json
import csv
import re
import sys
import time
from datetime import datetime

from env_config         import load_env
from aggregator         import investigate_ip, calculate_risk_score
from virustotal_module  import query_vt_hash
from whois_module       import query_whois
from reporter           import generate_ip_report, generate_hash_report

load_env()

BANNER = """
+--------------------------------------------------------+
|          OSINT Threat Intelligence Tool v1.0           |
|       github.com/kaki-lokesh/cybersecurity-tools       |
|         For authorised security research only          |
+--------------------------------------------------------+"""

# Input type detection
def detect_ioc_type(ioc):
    """Detect whether input is an IP, domain, or file hash"""
    ioc = ioc.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        return 'ip'
    if re.match(r'^[0-9a-fA-F]{32}$', ioc):
        return 'md5'
    if re.match(r'^[0-9a-fA-F]{40}$', ioc):
        return 'sha1'
    if re.match(r'^[0-9a-fA-F]{64}$', ioc):
        return 'sha256'
    if '.' in ioc and not ioc.startswith('http'):
        return 'domain'
    return 'unknown'

# Investigation dispatchers
def investigate(ioc, quiet=False):
    """Route to appropriate investigation function based on IOC type"""
    ioc_type = detect_ioc_type(ioc)
    if not quiet:
        print(f'\n[*] Investigating: {ioc}  (type: {ioc_type})')
    if ioc_type == 'ip':
        results = investigate_ip(ioc)
        risk    = calculate_risk_score(results)
        report  = generate_ip_report(ioc, results, risk)
        return ioc_type, results, risk, report
    elif ioc_type in {'md5', 'sha1', 'sha256'}:
        vt_result = query_vt_hash(ioc)
        report    = generate_hash_report(ioc, vt_result)
        risk = {'level': 'MALICIOUS' if vt_result.get('detection_stats', {}).get('malicious', 0) > 3 else 'LOW', 'score': 0, 'evidence': []}
        return ioc_type, {'virustotal': vt_result}, risk, report
    elif ioc_type == 'domain':
        whois_data = query_whois(ioc)
        report = f"WHOIS Report for {ioc}\n{json.dumps(whois_data, indent=2, default=str)}"
        return ioc_type, {'whois': whois_data}, {'level': 'UNKNOWN', 'score': 0, 'evidence': []}, report
    else:
        return 'unknown', {}, {}, f"Could not determine IOC type for: {ioc}"

# Batch file processing
def process_batch_file(filepath, csv_output=None):
    """Process a file of IOCs, one per line. Rate-limited"""
    try:
        with open(filepath) as f:
            iocs = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except FileNotFoundError:
        print(f'[ERROR] File not found: {filepath}'); sys.exit(1)

    summary_rows = []
    for i, ioc in enumerate(iocs, 1):
        print(f'\n[{i}/{len(iocs)}] {ioc}')
        ioc_type, results, risk, report = investigate(ioc, quiet=True)
        print(report)
        summary_rows.append({
            'ioc':       ioc,
            'type':      ioc_type,
            'risk_level': risk.get('level', 'UNKNOWN'),
            'risk_score': risk.get('score', 0),
        })
        if i < len(iocs):
            time.sleep(1.5)  # Rate limiting between batch items

    if csv_output:
        with open(csv_output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['ioc', 'type', 'risk_level', 'risk_score'])
            writer.writeheader()
            writer.writerows(summary_rows)
        print(f'\n[+] CSV summary saved to: {csv_output}')

# CLI entry point
def main():
    parser = argparse.ArgumentParser(
        description='OSINT Threat Intelligence Investigator',
        epilog='Example: python3 osint_ti_tool.py --ip 185.220.101.34 --json report.json'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--ip',     help='IPv4 address to investigate')
    group.add_argument('--domain', help='Domain name to investigate')
    group.add_argument('--hash',   help='File hash (MD5/SHA1/SHA256) to investigate')
    group.add_argument('--file',   help='Text file with one IOC per line (batch mode)')
    parser.add_argument('--json',   help='Save full JSON results to file')
    parser.add_argument('--csv',    help='Save CSV summary to file (batch mode only)')
    parser.add_argument('--quiet',  action='store_true', help='Suppress banner and progress messages')
    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    if args.file:
        process_batch_file(args.file, args.csv)
    else:
        target = args.ip or args.domain or args.hash
        ioc_type, results, risk, report = investigate(target, args.quiet)
        print(report)
        if args.json:
            payload = {'target': target, 'type': ioc_type, 'risk': risk, 'data': results}
            with open(args.json, 'w') as jf:
                json.dump(payload, jf, indent=2, default=str)
            print(f'\n[+] JSON results saved to: {args.json}')

if __name__ == '__main__':
    main()
