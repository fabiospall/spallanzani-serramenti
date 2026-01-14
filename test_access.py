#!/usr/bin/env python3
"""
Penetration testing script for authorized security assessment
Target: spallanzani-serramenti.onrender.com
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
import json

# Create session with browser-like characteristics
session = requests.Session()

# Configure retries
retry = Retry(total=3, backoff_factor=0.5)
adapter = HTTPAdapter(max_retries=retry)
session.mount('http://', adapter)
session.mount('https://', adapter)

# Browser-like headers
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
}

base_url = 'https://spallanzani-serramenti.onrender.com'

print("[*] Starting authorized penetration test")
print(f"[*] Target: {base_url}\n")

# Test 1: Basic access with session
print("[TEST 1] Basic homepage access with full browser headers")
try:
    r = session.get(base_url, headers=headers, timeout=15)
    print(f"Status Code: {r.status_code}")
    print(f"Content-Length: {len(r.content)}")

    if r.status_code == 403:
        print("[BLOCKED] Access denied - scanner detection active")
    elif r.status_code == 200:
        print("[SUCCESS] Homepage accessible")
        print(f"Page title: {r.text[r.text.find('<title>')+7:r.text.find('</title>')]}")

    # Check for Set-Cookie
    if 'Set-Cookie' in r.headers:
        print(f"Cookies set: {r.headers['Set-Cookie']}")

    print()
except Exception as e:
    print(f"[ERROR] {e}\n")

# Test 2: Try with delay (simulate human behavior)
print("[TEST 2] Delayed request (simulating human behavior)")
time.sleep(3)
try:
    r = session.get(base_url, headers=headers, timeout=15)
    print(f"Status Code: {r.status_code}")
    if r.status_code == 200:
        print("[SUCCESS] Access granted after delay")
    else:
        print(f"[BLOCKED] Still blocked: {r.status_code}")
    print()
except Exception as e:
    print(f"[ERROR] {e}\n")

# Test 3: Try different endpoints
endpoints = [
    '/',
    '/robots.txt',
    '/.env',
    '/.git/config',
    '/config',
    '/admin',
    '/login',
    '/register',
    '/contact',
    '/static/css/style.css',
    '/api',
    '/debug',
]

print("[TEST 3] Endpoint enumeration")
for endpoint in endpoints:
    try:
        url = base_url + endpoint
        r = session.get(url, headers=headers, timeout=10, allow_redirects=False)
        status = r.status_code
        length = len(r.content)

        if status == 200:
            result = "[ACCESSIBLE]"
        elif status == 403:
            result = "[BLOCKED]"
        elif status == 404:
            result = "[NOT FOUND]"
        elif status in [301, 302, 303, 307, 308]:
            result = f"[REDIRECT to {r.headers.get('Location', 'unknown')}]"
        else:
            result = f"[{status}]"

        print(f"{endpoint:30s} {result:20s} Size: {length}")
        time.sleep(0.5)  # Rate limiting consideration

    except Exception as e:
        print(f"{endpoint:30s} [ERROR] {str(e)[:50]}")

print("\n[*] Initial reconnaissance complete")
