#!/usr/bin/env python3
"""
ioc_extractor.py - Indicators of Compromise Extractor
Parses any text file and extracts security-relevant IOCs
Usage: python3 ioc_extractor.py threat_report.txt
       python3 ioc_extractor.py report.txt --csv output.csv
"""
import re
import argparse
import sys
import csv
from collections import defaultdict
from datetime import datetime

# Compiled IOC Patterns
PATTERNS = {
    'ipv4': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    'domain': re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|ru|cn|info|biz|io|co|uk|de|fr|jp|onion|xyz|tk|ml)\b',
        re.IGNORECASE
    ),
    'email': re.compile(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
    ),
    'md5': re.compile(
        r'\b[0-9a-fA-F]{32}\b'
    ),
    'sha1': re.compile(
        r'\b[0-9a-fA-F]{40}\b'
    ),
    'sha256': re.compile(
        r'\b[0-9a-fA-F]{64}\b'
    ),
    'url': re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+[^\s<>"{}|\\^`\[\].,;:)]'
    ),
    'cve': re.compile(
        r'\bCVE-\d{4}-\d{4,7}\b',
        re.IGNORECASE
    ),
    'registry_key': re.compile(
        r'\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[\w\\]+',
        re.IGNORECASE
    ),
    'windows_path': re.compile(
        r'[A-Za-z]:\\(?:[\w\s\-\.]+\\)*[\w\s\-\.]+\.(?:exe|dll|bat|ps1|vbs|tmp)',
        re.IGNORECASE
    ),
}

# Known benign values to filter out (reduce false positives)
FALSE_POSITIVE_IPS = {'0.0.0.0', '127.0.0.1', '255.255.255.255'}
FALSE_POSITIVE_DOMAINS = {'example.com', 'test.com', 'localhost.com'}

def extract_iocs(text):
    """Extract all IOCs from the provided text string"""
    iocs = defaultdict(set)

    for ioc_type, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        for match in matches:
            match = match.strip()
            # Apply false positive filtering
            if ioc_type == 'ipv4' and match in FALSE_POSITIVE_IPS:
                continue
            if ioc_type == 'domain' and match.lower() in FALSE_POSITIVE_DOMAINS:
                continue
            # Deduplicate with set
            iocs[ioc_type].add(match)

    return {k: sorted(v) for k, v in iocs.items() if v}

def print_report(iocs, filename):
    """Print formatted IOC report to stdout"""
    total = sum(len(v) for v in iocs.values())
    print(f"\n{'═'*60}")
    print(f"  IOC EXTRACTION REPORT")
    print(f"  Source: {filename}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total IOCs: {total}")
    print('═'*60)

    type_icons = {
        'ipv4': ' IPv4',        'domain': ' Domains',
        'email': ' Emails',       'url': ' URLs',
        'md5': ' MD5 Hashes',     'sha1': ' SHA1 Hashes',
        'sha256': ' SHA256 Hashes', 'cve': ' CVEs',
        'registry_key': ' Registry Keys',
        'windows_path': ' Windows Paths'
    }

    for ioc_type, values in iocs.items():
        label = type_icons.get(ioc_type, ioc_type)
        print(f"\n[{label}] - {len(values)} found")
        for v in values[:20]:  # Cap at 20 per type
            print(f"  {v}")
        if len(values) > 20:
            print(f"  ... and {len(values)-20} more")
    print(f"\n{'═'*60}\n")

def save_csv(iocs, filepath):
    """Save IOCs to CSV for importing into threat intel platforms"""
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['type', 'value'])
        for ioc_type, values in iocs.items():
            for v in values:
                writer.writerow([ioc_type, v])
    print(f"[+] IOCs saved to CSV: {filepath}")

def main():
    parser = argparse.ArgumentParser(description='IOC Extractor - Threat Intelligence Tool')
    parser.add_argument('file',   help='Text file to analyse (threat report, log, etc.)')
    parser.add_argument('--csv',   help='Export IOCs to CSV file')
    parser.add_argument('--stdin', action='store_true', help='Read from stdin instead of file')
    args = parser.parse_args()

    if args.stdin:
        text = sys.stdin.read()
        filename = 'stdin'
    else:
        try:
            with open(args.file, 'r', errors='ignore') as f:
                text = f.read()
                filename = args.file
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.file}")
            sys.exit(1)

    print(f"[*] Extracting IOCs from: {filename} ({len(text):,} chars)")
    iocs = extract_iocs(text)
    print_report(iocs, filename)

    if args.csv:
        save_csv(iocs, args.csv)

if __name__ == '__main__':
    main()
