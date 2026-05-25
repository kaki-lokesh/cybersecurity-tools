#!/usr/bin/env python3
"""
http_requester.py - Security-focused HTTP Request Tool
Sends GET/POST requests with custom headers, shows full request/response detail
Usage: python3 http_requester.py https://example.com -o response.html
"""
import requests
import argparse
import json
import sys
from datetime import datetime

# Default browser-like User-Agent to avoid blocks
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

def print_request_details(response):
    """Print full request and response details for analysis"""
    req = response.request
    print("\n" + "="*60)
    print("  REQUEST")
    print("-"*60)
    print(f"{req.method} {req.url}")
    for k, v in req.headers.items():
        print(f"  {k}: {v}")
    if req.body:
        print(f"\nBody: {req.body[:200]}")
    print("\n  RESPONSE")
    print("-"*60)
    print(f"Status : {response.status_code} {response.reason}")
    print(f"Time   : {response.elapsed.total_seconds():.3f}s")
    print(f"Size   : {len(response.content)} bytes")
    print("\nResponse Headers:")
    for k, v in response.headers.items():
        # Highlight security-relevant headers
        flag = ""
        if k.lower() in ['server', 'x-powered-by']:
            flag = " <- INFO DISCLOSURE"
        elif k.lower() in ['x-frame-options', 'content-security-policy', 'strict-transport-security']:
            flag = " <- SECURITY HEADER"
        print(f"  {k}: {v}{flag}")
    print("="*60)

def send_request(url, method='GET', data=None, headers=None, cookies=None, follow_redirects=True, timeout=10):
    """Send an HTTP request and return the response"""
    default_headers = {'User-Agent': DEFAULT_UA}
    if headers:
        default_headers.update(headers)
    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            data=data,
            headers=default_headers,
            cookies=cookies,
            allow_redirects=follow_redirects,
            timeout=timeout,
            verify=True
        )
        return response
    except requests.exceptions.Timeout:
        print(f"[ERROR] Request timed out after {timeout}s"); sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] Connection failed: {e}"); sys.exit(1)
    except requests.exceptions.SSLError:
        print("[ERROR] SSL certificate verification failed"); sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Security HTTP Requester')
    parser.add_argument('url',            help='Target URL')
    parser.add_argument('-X', '--method', default='GET', help='HTTP method (default: GET)')
    parser.add_argument('-d', '--data',   help='POST body data (key=value&key=value)')
    parser.add_argument('-H', '--header', action='append', help='Header (Key: Value) repeatable')
    parser.add_argument('-c', '--cookie', help='Cookies (name=value;name2=value2)')
    parser.add_argument('--no-redirect',  action='store_true', help="Don't follow redirects")
    parser.add_argument('-o', '--output', help='Save response body to file')
    args = parser.parse_args()

    # Parse headers from -H "Key: Value" format
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()

    # Parse cookies from "name=value;name2=value2" format
    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(';'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                cookies[k.strip()] = v.strip()

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending {args.method} -> {args.url}")
    response = send_request(
        args.url, args.method, args.data, headers, cookies, not args.no_redirect
    )
    print_request_details(response)

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(response.content)
        print(f"[+] Response saved to {args.output}")

if __name__ == '__main__':
    main()