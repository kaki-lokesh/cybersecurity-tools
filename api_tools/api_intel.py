#!/usr/bin/env python3
"""
api_intel.py - Multi-Source IP Intelligence Tool
Queries free APIs to build threat profile for IP addresses.
Usage: python3 api_intel.py 8.8.8.8
       python3 api_intel.py 1.1.1.1 --json output.json
"""
import requests
import argparse
import json
import sys
import time
from datetime import datetime

HEADERS = {'User-Agent': 'Security-Research-Tool/1.0 (Educational)'}

def query_ipinfo(ip):
    """Query ipinfo.io for geolocation and network info (free, no key)"""
    try:
        r = requests.get(
            f'https://ipinfo.io/{ip}/json',
            headers=HEADERS, timeout=8
        )
        data = r.json()
        return {
            'source':     'IPinfo.io',
            'ip':         data.get('ip'),
            'hostname':   data.get('hostname', 'N/A'),
            'org':        data.get('org', 'N/A'),
            'city':       data.get('city', 'N/A'),
            'region':     data.get('region', 'N/A'),
            'country':    data.get('country', 'N/A'),
            'timezone':   data.get('timezone', 'N/A'),
            'is_bogon':   data.get('bogon', False)
        }
    except Exception as e:
        return {'source': 'IPinfo.io', 'error': str(e)}

def query_ipapi(ip):
    """Query ip-api.com for additional geolocation data (free, no key)"""
    try:
        r = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,isp,org,as,proxy,hosting,query',
            headers=HEADERS, timeout=8
        )
        data = r.json()
        if data.get('status') != 'success':
            return {'source': 'ip-api.com', 'error': data.get('message', 'Failed')}
        return {
            'source':     'ip-api.com',
            'isp':        data.get('isp'),
            'asn':        data.get('as'),
            'is_proxy':   data.get('proxy', False),
            'is_hosting': data.get('hosting', False),
        }
    except Exception as e:
        return {'source': 'ip-api.com', 'error': str(e)}

def query_github_public(ip):
    """Check if IP appears in any public GitHub repo (credential leak check)"""
    try:
        r = requests.get(
            'https://api.github.com/search/code',
            params={'q': f'{ip} password OR secret OR credential', 'per_page': 5},
            headers={**HEADERS, 'Accept': 'application/vnd.github.v3+json'},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            total = data.get('total_count', 0)
            items = data.get('items', [])
            return {
                'source':  'GitHub Code Search',
                'repo_mentions':  total,
                'top_repos': [i.get('repository', {}).get('full_name') for i in items[:3]]
            }
        elif r.status_code == 403:
            return {'source': 'GitHub', 'error': 'Rate limited - try again in 60s'}
        else:
            return {'source': 'GitHub', 'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'source': 'GitHub', 'error': str(e)}

def assess_risk(ipinfo, ipapi):
    """Simple heuristic risk assessment based on collected data"""
    risk_score = 0
    reasons = []

    if ipapi.get('is_proxy'):
        risk_score += 30
        reasons.append("IP is a known proxy/VPN")
    if ipapi.get('is_hosting'):
        risk_score += 15
        reasons.append("IP is a hosting/datacenter address")
    if ipinfo.get('is_bogon'):
        risk_score += 50
        reasons.append("IP is a bogon (spoofed/private range on internet)")

    if risk_score >= 50:   level = "HIGH"
    elif risk_score >= 20: level = "MEDIUM"
    else:                  level = "LOW"

    return {'score': risk_score, 'level': level, 'reasons': reasons}

def print_report(ip, results):
    """Print a formatted intelligence report"""
    sep = "═"*62
    print(f"\n{sep}")
    print(f"  THREAT INTELLIGENCE REPORT - {ip}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(sep)

    ipinfo = results.get('ipinfo', {})
    ipapi  = results.get('ipapi', {})
    github = results.get('github', {})
    risk   = results.get('risk', {})

    print("\n[GEOLOCATION]")
    print(f"  IP        : {ipinfo.get('ip', ip)}")
    print(f"  Hostname  : {ipinfo.get('hostname', 'N/A')}")
    print(f"  City      : {ipinfo.get('city')}, {ipinfo.get('region')}")
    print(f"  Country   : {ipinfo.get('country')}")
    print(f"  Timezone  : {ipinfo.get('timezone')}")

    print("\n[NETWORK]")
    print(f"  Org/ISP   : {ipinfo.get('org', ipapi.get('isp', 'N/A'))}")
    print(f"  ASN       : {ipapi.get('asn', 'N/A')}")
    print(f"  Is Proxy  : {'YES' if ipapi.get('is_proxy') else 'No'}")
    print(f"  Is Hosting: {'YES' if ipapi.get('is_hosting') else 'No'}")

    print("\n[EXPOSURE CHECK]")
    if 'error' not in github:
        print(f"  GitHub mentions: {github.get('repo_mentions', 0)} repositories")
        if github.get('top_repos'):
            for repo in github['top_repos']:
                if repo: print(f"    -> {repo}")
    else:
        print(f"  GitHub: {github['error']}")

    print("\n[RISK ASSESSMENT]")
    print(f"  Risk Level: {risk.get('level', 'UNKNOWN')} (score: {risk.get('score', 0)}/100)")
    for reason in risk.get('reasons', []):
        print(f"  -> {reason}")
    if not risk.get('reasons'):
        print("  No risk indicators detected")

    print(f"\n{sep}\n")

def main():
    parser = argparse.ArgumentParser(description='IP Intelligence Gathering Tool')
    parser.add_argument('ip',          help='IP address to investigate')
    parser.add_argument('--json',      help='Save full results as JSON to file')
    args = parser.parse_args()

    print(f"[*] Investigating {args.ip} - querying {3} sources...")

    results = {
        'target':    args.ip,
        'timestamp': datetime.now().isoformat(),
        'ipinfo':    query_ipinfo(args.ip),
        'ipapi':     query_ipapi(args.ip),
        'github':    query_github_public(args.ip),
    }
    results['risk'] = assess_risk(results['ipinfo'], results['ipapi'])

    print_report(args.ip, results)

    if args.json:
        with open(args.json, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Full results saved to: {args.json}")

if __name__ == '__main__':
    main()
