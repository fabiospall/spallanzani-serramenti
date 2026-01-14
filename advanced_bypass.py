#!/usr/bin/env python3
"""
Advanced bypass techniques for authorized security assessment
"""

import requests
import time
from urllib.parse import urlencode

base_url = 'https://spallanzani-serramenti.onrender.com'

# Test different referrer patterns
print("[TEST] Referrer-based bypass attempts")
print("-" * 60)

referrers = [
    None,
    base_url,
    'https://www.google.com/search?q=spallanzani+serramenti',
    'https://www.facebook.com/',
    'https://www.linkedin.com/',
    'android-app://com.google.android.googlequicksearchbox',
]

for ref in referrers:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }
    if ref:
        headers['Referer'] = ref

    try:
        r = requests.get(base_url, headers=headers, timeout=10)
        ref_str = ref if ref else "None"
        print(f"Referer: {ref_str[:50]:50s} => Status: {r.status_code}")
        if r.status_code == 200:
            print(f"[SUCCESS] Access granted with referrer: {ref}")
            break
    except Exception as e:
        print(f"Error: {e}")
    time.sleep(1)

# Test cookie manipulation
print("\n[TEST] Cookie-based bypass attempts")
print("-" * 60)

cookies_tests = [
    {'session': 'test123'},
    {'bot_check': 'passed'},
    {'verified': 'true'},
    {'human': '1'},
    {'cf_clearance': 'test'},
]

for cookies in cookies_tests:
    try:
        r = requests.get(base_url, cookies=cookies, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }, timeout=10)
        print(f"Cookies: {cookies} => Status: {r.status_code}")
        if r.status_code == 200:
            print(f"[SUCCESS] Access granted with cookies: {cookies}")
            break
    except Exception as e:
        print(f"Error: {e}")
    time.sleep(1)

# Test query parameter bypass
print("\n[TEST] Query parameter bypass attempts")
print("-" * 60)

params_tests = [
    {'debug': '1'},
    {'admin': 'true'},
    {'verify': 'skip'},
    {'bot_check': 'disabled'},
    {'key': 'test'},
    {'access': 'granted'},
]

for params in params_tests:
    try:
        url = f"{base_url}?{urlencode(params)}"
        r = requests.get(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }, timeout=10)
        print(f"Params: {params} => Status: {r.status_code}")
        if r.status_code == 200:
            print(f"[SUCCESS] Access granted with params: {params}")
            break
    except Exception as e:
        print(f"Error: {e}")
    time.sleep(1)

# Test HTTP method variations
print("\n[TEST] HTTP method variations")
print("-" * 60)

methods = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT']

for method in methods:
    try:
        r = requests.request(method, base_url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }, timeout=10)
        print(f"Method: {method:8s} => Status: {r.status_code}")
    except Exception as e:
        print(f"Method: {method:8s} => Error: {str(e)[:50]}")
    time.sleep(1)

# Test protocol downgrade
print("\n[TEST] Protocol variations")
print("-" * 60)

urls = [
    'https://spallanzani-serramenti.onrender.com/',
    'http://spallanzani-serramenti.onrender.com/',
]

for url in urls:
    try:
        r = requests.get(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }, timeout=10, allow_redirects=False)
        print(f"{url:60s} => Status: {r.status_code}")
    except Exception as e:
        print(f"{url:60s} => Error: {str(e)[:40]}")
    time.sleep(1)

print("\n" + "=" * 60)
print("All bypass attempts tested")
print("=" * 60)
