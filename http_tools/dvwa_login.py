#!/usr/bin/env python3
"""
dvwa_login.py - Automated DVWA Authentication
Demonstrates: session management, CSRF token extraction, authenticated requests
This is the core mechanism behind automated web security scanning
Usage: python3 dvwa_login.py
"""
import requests
from bs4 import BeautifulSoup
import sys

BASE_URL  = 'http://localhost'
LOGIN_URL = f'{BASE_URL}/login.php'
USERNAME  = 'admin'
PASSWORD  = 'password'

def get_csrf_token(session, url):
    """Fetch a page and extract the CSRF token from a hidden input field"""
    print(f"[*] Fetching login page: {url}")
    response = session.get(url, timeout=10)

    if response.status_code != 200:
        print(f"[ERROR] Could not reach login page: HTTP {response.status_code}")
        print(" -> Is DVWA running? Try: docker start dvwa")
        sys.exit(1)

    # Parse the HTML response with BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # DVWA uses 'user_token' as the CSRF token field name
    token_input = soup.find('input', {'name': 'user_token'})

    if not token_input:
        # Some DVWA versions use 'Login' differently - check all hidden inputs
        hidden_inputs = soup.select('input[type="hidden"]')
        print("  Hidden inputs found:", [i.get('name') for i in hidden_inputs])
        return None  # DVWA DB may need reset

    token = token_input.get('value')
    print(f"[+] CSRF Token extracted: {token[:20]}...")
    return token

def login(session, username, password):
    """Perform login: get CSRF token -> POST credentials -> verify success"""
    # Step 1: GET the login page to obtain CSRF token
    token = get_csrf_token(session, LOGIN_URL)

    # Step 2: Build the POST data with credentials + CSRF token
    login_data = {
        'username':   username,
        'password':   password,
        'Login':      'Login',    # The submit button value
        'user_token': token or '' # CSRF token (empty if not found)
    }

    print(f"[*] Posting credentials for '{username}'...")
    response = session.post(
        LOGIN_URL,
        data=login_data,
        allow_redirects=True  # Follow the redirect after successful login
    )

    # Step 3: Verify login by checking the response
    # After successful login, DVWA redirects to index.php and shows 'Logout'
    if 'Login' not in response.text or 'logout' in response.text.lower():
        print(f" Login successful  Current URL: {response.url}")
        print(f"    Session cookies: {dict(session.cookies)}")
        return True
    else:
        print(" Login failed - still seeing login page")
        return False

def make_authenticated_request(session, path):
    """Make a request using the authenticated session"""
    url = f'{BASE_URL}/{path}'
    print(f"\n[*] Making authenticated GET to: {url}")
    response = session.get(url)
    print(f"    Status: {response.status_code}")
    soup = BeautifulSoup(response.text, 'html.parser')
    page_title = soup.find('title')
    if page_title:
        print(f"    Page title: {page_title.text.strip()}")
    return response

def main():
    print("=== DVWA Automated Login Demo ===")
    print("Demonstrates: session management + CSRF extraction + authenticated access\n")

    # Create a persistent session - this holds cookies across all requests
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'
    })

    # Attempt login
    success = login(session, USERNAME, PASSWORD)

    if success:
        # Visit authenticated pages — session cookie carries the auth
        make_authenticated_request(session, 'vulnerabilities/sqli/')
        make_authenticated_request(session, 'vulnerabilities/xss_r/')
        make_authenticated_request(session, 'security.php')
        print("\n Demonstration complete.")
        print("    This session cookie works for any further requests to DVWA.")
        print("    This is how automated web scanners maintain authentication")

if __name__ == '__main__':
    main()


