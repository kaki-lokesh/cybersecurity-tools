#!/usr/bin/env python3
"""
Queries Shodan API for host intelligence data.
Handles: geolocation, open ports, banners, vulnerabilities, organisation info.
"""
import requests
import os
import json
from datetime import datetime

SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')

def query_shodan_host(ip):
    """Query Shodan for complete host intelligence on an IP address"""
    if not SHODAN_API_KEY:
        return {'error': 'SHODAN_API_KEY not set', 'source': 'Shodan'}

    try:
        r = requests.get(
            f'https://api.shodan.io/shodan/host/{ip}',
            params={'key': SHODAN_API_KEY},
            timeout=12
        )
        if r.status_code == 404:
            return {'source': 'Shodan', 'error': 'No data for this IP in Shodan'}
        if r.status_code == 401:
            return {'source': 'Shodan', 'error': 'Invalid API key'}

        data = r.json()
        # Parse open ports with service banners
        ports_info = []
        for service in data.get('data', []):
            port_entry = {
                'port':     service.get('port'),
                'transport': service.get('transport', 'tcp'),
                'product':  service.get('product', ''),
                'version':  service.get('version', ''),
                'banner':   service.get('data', '')[:120],
            }
            # Check for embedded CVEs in this service data
            cves = service.get('vulns', {})
            if cves:
                port_entry['vulnerabilities'] = list(cves.keys())
            ports_info.append(port_entry)

        # Extract top-level vulnerability list
        all_vulns = list(data.get('vulns', {}).keys())

        return {
            'source':       'Shodan',
            'ip':           data.get('ip_str'),
            'organisation': data.get('org', 'Unknown'),
            'asn':          data.get('asn', 'Unknown'),
            'country':      data.get('country_name', 'Unknown'),
            'city':         data.get('city', 'Unknown'),
            'isp':          data.get('isp', 'Unknown'),
            'hostnames':    data.get('hostnames', []),
            'domains':      data.get('domains', []),
            'open_ports':   [s['port'] for s in ports_info],
            'services':     ports_info,
            'tags':         data.get('tags', []),
            'vulnerabilities': all_vulns,
            'last_update':  data.get('last_update'),
        }
    except requests.exceptions.Timeout:
        return {'source': 'Shodan', 'error': 'Request timed out'}
    except Exception as e:
        return {'source': 'Shodan', 'error': str(e)}


def query_abuseipdb(ip, max_age_days=90):
    """Query AbuseIPDB for abuse reports on an IP address"""
    key = os.environ.get('ABUSEIPDB_API_KEY')
    if not key:
        return {'error': 'ABUSEIPDB_API_KEY not set', 'source': 'AbuseIPDB'}
    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={
                'Key':    key,
                'Accept': 'application/json'
            },
            params={
                'ipAddress': ip,
                'maxAgeInDays': max_age_days,
                'verbose': True
            },
            timeout=10
        )
        d = r.json().get('data', {})
        # Abuse category codes -> human-readable names
        CATEGORY_NAMES = {
            3: 'Fraud Orders', 4: 'DDoS Attack', 5: 'FTP Brute-Force',
            6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
            9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam',
            12: 'Blog Spam', 13: 'VPN IP', 14: 'Port Scan',
            15: 'Hacking', 16: 'SQL Injection', 17: 'Spoofing',
            18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
            21: 'Web App Attack', 22: 'SSH Brute-Force', 23: 'IoT Targeted'
        }
        # Translate numeric category IDs to names
        raw_cats = d.get('usageType', [])  # categories in verbose reports
        categories = [CATEGORY_NAMES.get(c, f'Category {c}') for c in d.get('reports', [])]
        return {
            'source':             'AbuseIPDB',
            'ip':                 d.get('ipAddress'),
            'abuse_confidence':   d.get('abuseConfidenceScore', 0),
            'total_reports':      d.get('totalReports', 0),
            'num_distinct_users': d.get('numDistinctUsers', 0),
            'last_reported':      d.get('lastReportedAt'),
            'country':            d.get('countryCode'),
            'isp':                d.get('isp'),
            'usage_type':         d.get('usageType'),
            'is_public':          d.get('isPublic', True),
            'is_whitelisted':     d.get('isWhitelisted', False),
        }
    except Exception as e:
        return {'source': 'AbuseIPDB', 'error': str(e)}