#!/usr/bin/env python3
from flask import Flask, render_template_string, request, jsonify, redirect, session, abort, g, send_from_directory
from markupsafe import escape
from functools import wraps
import sqlite3
import secrets
import re
import time
import hashlib
import os
import json
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Chiave segreta sicura generata dinamicamente
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# ============================================
# CONFIGURAZIONE ADMIN E AI
# ============================================

# Admin users (password hashate con SHA256)
ADMIN_USERS = {
    'fabio': hashlib.sha256('fabio2024!'.encode()).hexdigest(),
    'papa': hashlib.sha256('papa2024!'.encode()).hexdigest(),
    'mamma': hashlib.sha256('mamma2024!'.encode()).hexdigest()
}

# Gemini AI Configuration (API gratuita)
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent'

# Email Configuration (TEST: fabiospalla31 - poi rimettere spallanzanirappresentanze)
EMAIL_SENDER = 'fabiospalla31@gmail.com'
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')  # App password Gmail
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# Pending confirmations storage
pending_confirmations = {}

# Anti-brute force storage
login_attempts = defaultdict(list)  # IP -> list of timestamps
failed_logins = defaultdict(int)    # IP -> count of consecutive failures
locked_accounts = {}                # username -> unlock_time
ip_login_blocks = {}                # IP -> unlock_time

# ============================================
# SISTEMA DI SICUREZZA AVANZATO
# ============================================

# Rate limiting storage
request_counts = defaultdict(list)
blocked_ips = {}
suspicious_ips = defaultdict(int)
scan_detection = defaultdict(list)

# Security log file
SECURITY_LOG = 'security.log'

def log_security_event(event_type, ip, details=""):
    """Log eventi di sicurezza"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{event_type}] IP: {ip} - {details}\n"
    with open(SECURITY_LOG, 'a') as f:
        f.write(log_entry)
    print(f"\033[91m[SECURITY ALERT]\033[0m {event_type}: {ip} - {details}")

def detect_nmap_scan(ip, path, user_agent):
    """Rileva scansioni nmap e altri scanner"""
    now = time.time()
    scan_detection[ip].append(now)

    # Pulisci vecchie entries (ultimi 10 secondi)
    scan_detection[ip] = [t for t in scan_detection[ip] if now - t < 10]

    # Patterns sospetti
    suspicious_patterns = [
        'nmap', 'nikto', 'sqlmap', 'masscan', 'zap', 'burp', 'scanner',
        'dirbuster', 'gobuster', 'wfuzz', 'hydra', 'metasploit'
    ]

    suspicious_paths = [
        '/admin', '/wp-admin', '/phpmyadmin', '/.env', '/.git',
        '/config', '/backup', '/shell', '/cmd', '/eval',
        '/.htaccess', '/web.config', '/.svn', '/.hg',
        '/cgi-bin', '/manager', '/console', '/actuator'
    ]

    # Check user agent
    ua_lower = (user_agent or '').lower()
    for pattern in suspicious_patterns:
        if pattern in ua_lower:
            log_security_event("SCANNER_DETECTED", ip, f"User-Agent: {user_agent}")
            return True

    # Check path probing - solo path esattamente sospetti
    if path.lower() in suspicious_paths:
        suspicious_ips[ip] += 1
        if suspicious_ips[ip] >= 5:
            log_security_event("PATH_PROBING", ip, f"Path: {path} (count: {suspicious_ips[ip]})")
            return True

    # Check rapid requests (port scan behavior)
    if len(scan_detection[ip]) > 20:
        log_security_event("RAPID_REQUESTS", ip, f"{len(scan_detection[ip])} requests in 10s")
        return True

    return False

def is_blocked(ip):
    """Verifica se IP è bloccato"""
    if ip in blocked_ips:
        if time.time() < blocked_ips[ip]:
            return True
        else:
            del blocked_ips[ip]
    return False

def block_ip(ip, duration=3600):
    """Blocca IP per durata specificata (default 1 ora)"""
    blocked_ips[ip] = time.time() + duration
    log_security_event("IP_BLOCKED", ip, f"Duration: {duration}s")

def rate_limit(max_requests=60, window=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get real IP behind proxy
            ip = request.headers.get('CF-Connecting-IP') or \
                 request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or \
                 request.remote_addr
            now = time.time()

            # Pulisci vecchie richieste
            request_counts[ip] = [t for t in request_counts[ip] if now - t < window]

            if len(request_counts[ip]) >= max_requests:
                log_security_event("RATE_LIMIT_EXCEEDED", ip, f"{len(request_counts[ip])} requests")
                suspicious_ips[ip] += 5
                if suspicious_ips[ip] >= 10:
                    block_ip(ip)
                abort(429)

            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

def sanitize_input(text, max_length=500):
    """Sanitizza input utente - PREVIENE SSTI e XSS"""
    if not text:
        return ""
    # Converti a stringa e limita lunghezza
    text = str(text)[:max_length]
    # Escape HTML e caratteri pericolosi
    text = str(escape(text))
    # Rimuovi pattern Jinja2/SSTI
    dangerous_patterns = ['{{', '}}', '{%', '%}', '{#', '#}', '__', 'config', 'class', 'mro', 'subclasses']
    for pattern in dangerous_patterns:
        text = text.replace(pattern, '')
    return text.strip()

def validate_email(email):
    """Valida formato email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email)) if email else False

def validate_phone(phone):
    """Valida formato telefono"""
    if not phone:
        return True  # Opzionale
    # Rimuovi spazi e caratteri comuni
    phone = re.sub(r'[\s\-\.\(\)]', '', phone)
    return bool(re.match(r'^\+?[0-9]{6,15}$', phone))

def generate_csrf_token():
    """Genera token CSRF"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Valida token CSRF"""
    return token and token == session.get('csrf_token')

def check_honeypot(form_data):
    """Controlla campi honeypot (anti-bot)"""
    honeypot_fields = ['website', 'url', 'fax', 'company_url']
    for field in honeypot_fields:
        if form_data.get(field):
            return False  # Bot detected
    return True

# ============================================
# SISTEMA ADMIN
# ============================================

def admin_required(f):
    """Decorator per richiedere autenticazione admin"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_user' not in session:
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated

def verify_admin(username, password):
    """Verifica credenziali admin"""
    if username in ADMIN_USERS:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if ADMIN_USERS[username] == password_hash:
            return True
    return False

# ============================================
# ANTI-BRUTE FORCE SYSTEM
# ============================================

MAX_LOGIN_ATTEMPTS = 5          # Max tentativi prima del blocco
LOGIN_BLOCK_DURATION = 1800     # 30 minuti di blocco
ATTEMPT_WINDOW = 300            # Finestra di 5 minuti per contare tentativi
PROGRESSIVE_DELAY = True        # Delay progressivo tra tentativi

def is_ip_blocked_login(ip):
    """Controlla se IP è bloccato per troppi tentativi login"""
    if ip in ip_login_blocks:
        if time.time() < ip_login_blocks[ip]:
            return True
        else:
            del ip_login_blocks[ip]
            failed_logins[ip] = 0
    return False

def is_account_locked(username):
    """Controlla se account è bloccato"""
    if username in locked_accounts:
        if time.time() < locked_accounts[username]:
            return True
        else:
            del locked_accounts[username]
    return False

def record_login_attempt(ip, username, success):
    """Registra tentativo di login"""
    now = time.time()

    # Pulisci vecchi tentativi
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < ATTEMPT_WINDOW]
    login_attempts[ip].append(now)

    if success:
        # Reset contatori su login riuscito
        failed_logins[ip] = 0
        if username in locked_accounts:
            del locked_accounts[username]
        log_security_event("ADMIN_LOGIN_SUCCESS", ip, f"User: {username}")
    else:
        failed_logins[ip] += 1
        log_security_event("ADMIN_LOGIN_FAILED", ip, f"User: {username} (attempt {failed_logins[ip]})")

        # Blocca IP dopo troppi tentativi
        if failed_logins[ip] >= MAX_LOGIN_ATTEMPTS:
            ip_login_blocks[ip] = now + LOGIN_BLOCK_DURATION
            log_security_event("ADMIN_IP_BLOCKED", ip, f"Blocked for {LOGIN_BLOCK_DURATION}s after {failed_logins[ip]} failures")

        # Blocca anche l'account specifico se esiste
        if username in ADMIN_USERS:
            if username not in locked_accounts:
                locked_accounts[username] = 0
            # Incrementa tempo di blocco progressivamente
            locked_accounts[username] = now + (60 * failed_logins[ip])  # 1 min per ogni tentativo

def get_login_delay(ip):
    """Calcola delay progressivo per rallentare brute force"""
    if not PROGRESSIVE_DELAY:
        return 0
    failures = failed_logins.get(ip, 0)
    if failures == 0:
        return 0
    # Delay esponenziale: 1s, 2s, 4s, 8s, 16s...
    return min(2 ** failures, 30)  # Max 30 secondi

def get_remaining_lockout(ip, username=None):
    """Ritorna secondi rimanenti di blocco"""
    now = time.time()
    ip_remaining = 0
    account_remaining = 0

    if ip in ip_login_blocks:
        ip_remaining = int(ip_login_blocks[ip] - now)

    if username and username in locked_accounts:
        account_remaining = int(locked_accounts[username] - now)

    return max(ip_remaining, account_remaining, 0)

# ============================================
# GEMINI AI FUNCTIONS
# ============================================

def generate_preventivo_ai(cliente_nome, prodotti, richiesta):
    """Genera preventivo usando Gemini AI"""
    if not GEMINI_API_KEY:
        return None, "API Key Gemini non configurata"

    prompt = f"""Sei un esperto preventivista per Spallanzani Rappresentanze, azienda che vende:
- Flessya: Porte per interni (da €300 a €1500 per porta)
- Di.Bi.: Porte blindate (da €800 a €3500 per porta)
- Arieni: Maniglie di design (da €50 a €400 per set)

Cliente: {cliente_nome}
Prodotti richiesti: {prodotti}
Dettagli richiesta: {richiesta}

Genera un preventivo professionale in italiano con:
1. Elenco prodotti con prezzi stimati
2. Eventuali opzioni/varianti
3. Totale stimato
4. Note sulla posa in opera
5. Tempi di consegna stimati

Formatta in modo chiaro e professionale."""

    try:
        headers = {'Content-Type': 'application/json'}
        data = {
            'contents': [{'parts': [{'text': prompt}]}],
            'generationConfig': {'temperature': 0.7, 'maxOutputTokens': 2000}
        }

        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            headers=headers,
            json=data,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            text = result['candidates'][0]['content']['parts'][0]['text']
            return text, None
        else:
            return None, f"Errore API: {response.status_code}"
    except Exception as e:
        return None, str(e)

# ============================================
# EMAIL FUNCTIONS
# ============================================

def send_email(to_email, subject, html_body):
    """Invia email tramite Gmail SMTP"""
    if not EMAIL_PASSWORD:
        return False, "Password email non configurata"

    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = EMAIL_SENDER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, to_email, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)

def send_confirmation_request(preventivo_id, admin_email):
    """Invia richiesta di conferma all'admin"""
    token = secrets.token_urlsafe(32)
    pending_confirmations[token] = {
        'preventivo_id': preventivo_id,
        'created': datetime.now(),
        'expires': datetime.now() + timedelta(hours=24)
    }

    # Aggiorna token nel DB
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE preventivi SET token_conferma = ? WHERE id = ?', (token, preventivo_id))
    c.execute('SELECT * FROM preventivi WHERE id = ?', (preventivo_id,))
    prev = c.fetchone()
    conn.commit()
    conn.close()

    base_url = os.environ.get('RENDER_EXTERNAL_URL', 'https://spallanzani-serramenti.onrender.com')
    confirm_url = f"{base_url}/admin/conferma/{token}"
    reject_url = f"{base_url}/admin/rifiuta/{token}"

    html = f"""
    <html><body style="font-family: Arial, sans-serif; padding: 20px;">
    <h2>🔔 Nuovo Preventivo da Approvare</h2>
    <p><strong>Cliente:</strong> {prev['cliente_nome']}</p>
    <p><strong>Email:</strong> {prev['cliente_email']}</p>
    <p><strong>Prodotti:</strong> {prev['prodotti']}</p>
    <hr>
    <h3>Preventivo Generato dall'AI:</h3>
    <pre style="background: #f5f5f5; padding: 15px; border-radius: 5px;">{prev['preventivo_ai']}</pre>
    <hr>
    <p>
        <a href="{confirm_url}" style="background: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin-right: 10px;">✅ APPROVA E INVIA</a>
        <a href="{reject_url}" style="background: #dc3545; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px;">❌ RIFIUTA</a>
    </p>
    <p style="color: #666; font-size: 12px;">Link valido per 24 ore</p>
    </body></html>
    """

    return send_email(EMAIL_SENDER, f"[CONFERMA] Preventivo #{preventivo_id} - {prev['cliente_nome']}", html)

# ============================================
# MIDDLEWARE DI SICUREZZA
# ============================================

def get_real_ip():
    """Ottieni IP reale anche dietro proxy/Cloudflare"""
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP')
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

@app.before_request
def security_middleware():
    """Middleware di sicurezza eseguito prima di ogni richiesta"""
    ip = get_real_ip()
    path = request.path
    user_agent = request.headers.get('User-Agent', '')

    # Check se IP è bloccato
    if is_blocked(ip):
        log_security_event("BLOCKED_ACCESS_ATTEMPT", ip, path)
        abort(403)

    # Rileva scansioni
    if detect_nmap_scan(ip, path, user_agent):
        block_ip(ip, 1800)  # Blocca 30 minuti
        abort(403)

    # Genera CSRF token per la sessione
    g.csrf_token = generate_csrf_token()

@app.after_request
def security_headers(response):
    """Aggiunge security headers a ogni risposta"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; img-src 'self' https: data:; font-src 'self' https: data:;"
    # Nascondi info server
    response.headers['Server'] = 'Spallanzani-Secure'
    return response

@app.errorhandler(403)
def forbidden(e):
    return '''<!DOCTYPE html><html><head><title>Accesso Negato</title>
    <style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a1a;color:#fff;}
    .box{text-align:center;padding:50px;}.icon{font-size:80px;margin-bottom:20px;}h1{margin:0;}</style></head>
    <body><div class="box"><div class="icon">🛡️</div><h1>Accesso Negato</h1><p>La tua richiesta è stata bloccata per motivi di sicurezza.</p></div></body></html>''', 403

@app.errorhandler(429)
def too_many_requests(e):
    return '''<!DOCTYPE html><html><head><title>Troppe Richieste</title>
    <style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a1a;color:#fff;}
    .box{text-align:center;padding:50px;}.icon{font-size:80px;margin-bottom:20px;}h1{margin:0;}</style></head>
    <body><div class="box"><div class="icon">⏱️</div><h1>Troppe Richieste</h1><p>Attendi qualche secondo prima di riprovare.</p></div></body></html>''', 429

@app.errorhandler(404)
def not_found(e):
    return '''<!DOCTYPE html><html><head><title>Pagina Non Trovata</title>
    <style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f8f9fa;color:#1a1a1a;}
    .box{text-align:center;padding:50px;}h1{margin:0 0 20px;font-size:100px;opacity:0.2;}a{color:#1a1a1a;}</style></head>
    <body><div class="box"><h1>404</h1><p>Pagina non trovata</p><a href="/">Torna alla Home</a></div></body></html>''', 404

# ============================================
# DATABASE SICURO
# ============================================

def get_db():
    """Connessione database sicura"""
    conn = sqlite3.connect('contatti.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS richieste (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT, email TEXT, telefono TEXT, messaggio TEXT, prodotto TEXT,
        ip TEXT, user_agent TEXT, data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT, cognome TEXT, email TEXT UNIQUE, telefono TEXT, azienda TEXT,
        ip TEXT, data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    # Tabella preventivi
    c.execute('''CREATE TABLE IF NOT EXISTS preventivi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cliente_nome TEXT,
        cliente_email TEXT,
        cliente_telefono TEXT,
        prodotti TEXT,
        richiesta TEXT,
        preventivo_ai TEXT,
        preventivo_finale TEXT,
        stato TEXT DEFAULT 'nuovo',
        token_conferma TEXT,
        creato_da TEXT,
        data_creazione TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        data_invio TIMESTAMP,
        note TEXT
    )''')

    # Tabella admin sessions
    c.execute('''CREATE TABLE IF NOT EXISTS admin_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        session_token TEXT UNIQUE,
        ip TEXT,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT, ip TEXT, details TEXT, data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()

init_db()

EMAIL_CONFIG = {
    'ordini': 'spallamm@gmail.com',
    'commerciale': 'commercialegolinellidaniela@gmail.com'
}

MAIN_PAGE = '''
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Spallanzani Rappresentanze | Infissi e Serramenti Premium</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Playfair+Display:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        :root {
            /* Clean White & Grey Palette */
            --primary: #ffffff;
            --secondary: #f8f9fa;
            --tertiary: #f1f3f5;
            --dark: #1a1a1a;
            --grey: #6c757d;
            --grey-light: #adb5bd;
            --border: #e9ecef;
            --text: #212529;
            --text-muted: #6c757d;
            --accent: #343a40;
            --smart: rgba(70, 130, 180, 0.9);
            --transition-fast: 0.2s ease;
            --transition-medium: 0.4s ease;
            --shadow-sm: 0 2px 8px rgba(0,0,0,0.08);
            --shadow-md: 0 8px 24px rgba(0,0,0,0.12);
            --shadow-lg: 0 16px 48px rgba(0,0,0,0.16);
        }

        /* Dark Mode Variables */
        [data-theme="dark"] {
            --primary: #121212;
            --secondary: #1e1e1e;
            --tertiary: #2d2d2d;
            --dark: #ffffff;
            --grey: #a0a0a0;
            --grey-light: #707070;
            --border: #3d3d3d;
            --text: #e8e8e8;
            --text-muted: #a0a0a0;
            --accent: #e0e0e0;
        }

        [data-theme="dark"] .hero {
            background: linear-gradient(180deg, #1e1e1e 0%, #121212 50%, #1a1a1a 100%);
        }

        [data-theme="dark"] header {
            background: #121212;
        }

        [data-theme="dark"] .header-top {
            background: #0a0a0a;
        }

        [data-theme="dark"] .product-3d-box {
            background: linear-gradient(135deg, #2d2d2d 0%, #1e1e1e 100%);
        }

        [data-theme="dark"] .door-3d-panel::before {
            filter: brightness(0.7);
        }

        [data-theme="dark"] .modal-ai-box {
            background: linear-gradient(135deg, #2d2d2d 0%, #1e1e1e 100%);
        }

        [data-theme="dark"] .modal-ai-text {
            color: #e8e8e8;
        }

        [data-theme="dark"] #map {
            filter: saturate(0.5) brightness(0.9);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html { scroll-behavior: auto; }
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--primary);
            color: var(--text);
            overflow-x: hidden;
        }
        /* 120fps Optimizations */
        * { -webkit-tap-highlight-color: transparent; }
        .gpu { transform: translateZ(0); will-change: transform; backface-visibility: visible; }
        img { content-visibility: auto; }
        /* Italic animated text */
        .italic-animate {
            font-style: italic;
            opacity: 0;
            transform: translateY(20px);
            animation: fadeInUp 0.8s ease forwards;
        }
        @keyframes fadeInUp {
            to { opacity: 1; transform: translateY(0); }
        }
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        .delay-3 { animation-delay: 0.3s; }
        .delay-4 { animation-delay: 0.4s; }

        /* Scroll Reveal Animations */
        .reveal {
            opacity: 0;
            transform: translateY(40px);
            transition: opacity 0.8s cubic-bezier(0.16, 1, 0.3, 1),
                        transform 0.8s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .reveal.active {
            opacity: 1;
            transform: translateY(0);
        }
        .reveal-left {
            opacity: 0;
            transform: translateX(-60px);
            transition: opacity 0.8s cubic-bezier(0.16, 1, 0.3, 1),
                        transform 0.8s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .reveal-left.active {
            opacity: 1;
            transform: translateX(0);
        }
        .reveal-right {
            opacity: 0;
            transform: translateX(60px);
            transition: opacity 0.8s cubic-bezier(0.16, 1, 0.3, 1),
                        transform 0.8s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .reveal-right.active {
            opacity: 1;
            transform: translateX(0);
        }
        .reveal-scale {
            opacity: 0;
            transform: scale(0.9);
            transition: opacity 0.8s cubic-bezier(0.16, 1, 0.3, 1),
                        transform 0.8s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .reveal-scale.active {
            opacity: 1;
            transform: scale(1);
        }
        .stagger-1 { transition-delay: 0.1s; }
        .stagger-2 { transition-delay: 0.2s; }
        .stagger-3 { transition-delay: 0.3s; }
        .stagger-4 { transition-delay: 0.4s; }
        .stagger-5 { transition-delay: 0.5s; }

        /* Dark Mode Toggle */
        .theme-toggle {
            position: fixed;
            top: 50%;
            left: 20px;
            transform: translateY(-50%);
            z-index: 9998;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .theme-btn {
            width: 48px;
            height: 48px;
            background: var(--primary);
            border: 1px solid var(--border);
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            color: var(--dark);
            transition: all var(--transition-fast);
            box-shadow: var(--shadow-sm);
        }
        .theme-btn:hover {
            transform: scale(1.1);
            box-shadow: var(--shadow-md);
        }
        .theme-btn.active {
            background: var(--dark);
            color: var(--primary);
        }
        @media (max-width: 768px) {
            .theme-toggle {
                left: 10px;
                top: auto;
                bottom: 100px;
            }
            .theme-btn {
                width: 40px;
                height: 40px;
                font-size: 1rem;
            }
        }

        /* Welcome Modal - Fixed */
        .welcome-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            z-index: 99999;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 1;
            transition: opacity 0.5s ease;
        }
        .welcome-overlay.fade-out {
            opacity: 0;
            pointer-events: none;
        }
        .welcome-box {
            text-align: center;
            position: relative;
            z-index: 100000;
        }
        .welcome-logo-big {
            width: 100px; height: 100px;
            background: var(--dark);
            border-radius: 20px;
            margin: 0 auto 30px;
            display: flex; align-items: center; justify-content: center;
            font-size: 2.5rem; font-weight: 900; color: #fff;
        }
        .welcome-title {
            font-family: 'Playfair Display', serif;
            font-size: 3rem;
            font-style: italic;
            margin-bottom: 12px;
            color: var(--dark);
        }
        .welcome-sub {
            font-size: 1.05rem;
            font-style: italic;
            color: var(--grey);
            margin-bottom: 35px;
            line-height: 1.7;
        }
        .welcome-enter-btn {
            background: var(--dark);
            color: #fff;
            border: none;
            padding: 16px 50px;
            font-size: 0.95rem;
            font-weight: 600;
            font-style: italic;
            border-radius: 8px;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: opacity 0.15s ease;
            position: relative;
            z-index: 100001;
        }
        .welcome-enter-btn:hover { opacity: 0.85; background: #333; }

        /* Header - White/Grey */
        header {
            position: fixed;
            width: 100%;
            top: 0;
            z-index: 1000;
            background: #fff;
            border-bottom: 1px solid var(--border);
        }
        .header-top {
            background: var(--dark);
            padding: 10px 0;
            display: flex;
            justify-content: center;
            gap: 50px;
        }
        .header-top a {
            color: #fff;
            text-decoration: none;
            font-weight: 500;
            font-size: 0.85rem;
            font-style: italic;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .header-top a:hover { opacity: 0.8; }
        .header-main {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 18px 60px;
            max-width: 1700px;
            margin: 0 auto;
        }
        .logo { display: flex; align-items: center; gap: 18px; }
        .logo-icon {
            width: 45px; height: 45px;
            background: var(--dark);
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-weight: 900; font-size: 1rem; color: #fff;
        }
        .logo-text h1 { font-size: 1.15rem; font-weight: 700; color: var(--dark); }
        .logo-text span {
            font-size: 0.7rem;
            font-style: italic;
            color: var(--grey);
            letter-spacing: 2px;
            text-transform: uppercase;
        }
        nav { display: flex; gap: 5px; }
        nav a {
            color: var(--grey);
            text-decoration: none;
            padding: 10px 16px;
            font-size: 0.9rem;
            font-weight: 500;
            font-style: italic;
        }
        nav a:hover { color: var(--dark); }
        .cta-btn {
            display: flex; align-items: center; gap: 8px;
            background: var(--dark);
            color: #fff;
            padding: 11px 22px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            font-style: italic;
            transition: opacity 0.15s ease;
        }
        .cta-btn:hover { opacity: 0.85; }

        /* Hero - White/Grey */
        .hero {
            min-height: 100vh;
            display: flex;
            align-items: center;
            padding: 160px 60px 100px;
            position: relative;
            background: linear-gradient(180deg, #f8f9fa 0%, #fff 50%, #f1f3f5 100%);
        }
        .wood-texture, .fire-glow, .floating-doors { display: none; }
        .hero-grid {
            display: grid;
            grid-template-columns: 1.1fr 0.9fr;
            gap: 80px;
            max-width: 1600px;
            margin: 0 auto;
            align-items: center;
            position: relative;
            z-index: 2;
        }
        .hero-text h1 {
            font-family: 'Playfair Display', serif;
            font-size: 3.5rem;
            font-style: italic;
            line-height: 1.15;
            margin-bottom: 25px;
            color: var(--dark);
            opacity: 0;
            transform: translateY(30px);
            animation: fadeInUp 0.8s ease 0.2s forwards;
        }
        .hero-text h1 span {
            color: var(--grey);
        }
        .hero-text p {
            font-size: 1.1rem;
            font-style: italic;
            color: var(--grey);
            line-height: 1.8;
            margin-bottom: 35px;
            opacity: 0;
            transform: translateY(20px);
            animation: fadeInUp 0.8s ease 0.4s forwards;
        }
        .hero-btns { display: flex; gap: 20px; flex-wrap: wrap; }
        .hero-btns {
            opacity: 0;
            transform: translateY(20px);
            animation: fadeInUp 0.8s ease 0.6s forwards;
        }
        .btn-primary {
            background: var(--dark);
            color: #fff;
            padding: 14px 35px;
            border: none;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 600;
            font-style: italic;
            text-transform: uppercase;
            letter-spacing: 1px;
            cursor: pointer;
            text-decoration: none;
            transition: opacity 0.15s ease;
        }
        .btn-primary:hover { opacity: 0.85; }
        .btn-secondary {
            background: transparent;
            color: var(--dark);
            padding: 14px 35px;
            border: 2px solid var(--dark);
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 600;
            font-style: italic;
            cursor: pointer;
            text-decoration: none;
            transition: background 0.15s ease;
        }
        .btn-secondary:hover { background: rgba(0,0,0,0.05); }

        /* 3D Door Showcase - Mouse Follow */
        .showcase-3d {
            display: flex;
            justify-content: center;
            align-items: center;
            perspective: 1000px;
        }
        .door-showcase-3d {
            position: relative;
            width: 320px;
            height: 450px;
            transform-style: preserve-3d;
            transition: transform 0.1s ease-out;
        }
        .door-3d-frame {
            position: absolute;
            inset: 0;
            background: linear-gradient(145deg, #3a3a3a, #2a2a2a);
            border-radius: 8px;
            transform: translateZ(-20px);
            box-shadow: 0 30px 60px rgba(0,0,0,0.3);
        }
        .door-3d-panel {
            position: absolute;
            inset: 12px;
            background: linear-gradient(180deg, #d4a574 0%, #b8956a 50%, #a68560 100%);
            border-radius: 4px;
            transform: translateZ(0px);
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        .door-3d-panel::before {
            content: '';
            position: absolute;
            inset: 0;
            background: url('https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-KIKKA_immagine_K00_001-scaled.jpg') center/cover;
            opacity: 0.9;
        }
        .door-3d-decor {
            position: absolute;
            left: 15px; right: 15px;
            height: 120px;
            background: rgba(0,0,0,0.1);
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 4px;
        }
        .door-3d-decor.top { top: 30px; }
        .door-3d-decor.bottom { bottom: 30px; }
        .door-3d-handle {
            position: absolute;
            right: 25px;
            top: 50%;
            transform: translateY(-50%) translateZ(15px);
            width: 12px;
            height: 80px;
            background: linear-gradient(90deg, #c0c0c0, #e8e8e8, #c0c0c0);
            border-radius: 6px;
            box-shadow: 2px 2px 8px rgba(0,0,0,0.3);
        }
        .door-3d-handle::after {
            content: '';
            position: absolute;
            top: 50%;
            left: -8px;
            transform: translateY(-50%);
            width: 20px;
            height: 8px;
            background: linear-gradient(180deg, #d0d0d0, #a0a0a0);
            border-radius: 4px;
        }
        .rotate-hint-3d {
            position: absolute;
            bottom: -45px;
            left: 50%;
            transform: translateX(-50%);
            color: var(--grey);
            font-size: 0.85rem;
            font-style: italic;
            display: flex;
            align-items: center;
            gap: 8px;
            white-space: nowrap;
        }

        /* Sections - White/Grey */
        .section { padding: 100px 60px; background: #fff; }
        .section-alt { background: #f8f9fa; }
        .section-header { text-align: center; margin-bottom: 60px; }
        .section-header h2 {
            font-family: 'Playfair Display', serif;
            font-size: 2.5rem;
            font-style: italic;
            margin-bottom: 15px;
            color: var(--dark);
        }
        .section-header h2 span { color: var(--grey); }
        .section-header p {
            color: var(--grey);
            font-size: 1rem;
            font-style: italic;
            max-width: 550px;
            margin: 0 auto;
        }
        .accent-bar {
            width: 60px;
            height: 2px;
            background: var(--dark);
            margin: 20px auto;
        }

        /* Brands */
        .brands-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 30px;
            max-width: 1500px;
            margin: 0 auto;
        }
        .brand-card {
            background: var(--primary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 35px 25px;
            text-align: center;
            cursor: pointer;
            transition: all var(--transition-medium);
            position: relative;
            overflow: hidden;
        }
        .brand-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, transparent 0%, rgba(0,0,0,0.03) 100%);
            opacity: 0;
            transition: opacity var(--transition-fast);
        }
        .brand-card:hover {
            transform: translateY(-8px);
            box-shadow: var(--shadow-lg);
            border-color: var(--dark);
        }
        .brand-card:hover::before {
            opacity: 1;
        }
        .brand-title {
            font-size: 1.4rem;
            font-weight: 700;
            font-style: italic;
            color: var(--dark);
            margin-bottom: 12px;
            letter-spacing: 1px;
        }
        .brand-name { font-size: 1rem; font-weight: 600; margin-bottom: 8px; color: var(--dark); }
        .brand-desc { font-size: 0.85rem; font-style: italic; color: var(--grey); line-height: 1.6; }

        /* Product Filters - Modern Design */
        .filter-bar {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 50px;
            padding: 20px;
            background: linear-gradient(135deg, rgba(255,255,255,0.9), rgba(248,249,250,0.9));
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.05);
            max-width: 900px;
            margin-left: auto;
            margin-right: auto;
        }
        .filter-btn {
            background: transparent;
            border: 2px solid var(--border);
            color: var(--grey);
            padding: 12px 24px;
            border-radius: 30px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        .filter-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(26,26,26,0.1), transparent);
            transition: left 0.5s;
        }
        .filter-btn:hover::before {
            left: 100%;
        }
        .filter-btn:hover {
            border-color: var(--dark);
            color: var(--dark);
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .filter-btn.active {
            background: var(--dark);
            border-color: var(--dark);
            color: #fff;
            box-shadow: 0 4px 15px rgba(26,26,26,0.3);
        }
        .filter-btn.active:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(26,26,26,0.4);
        }
        @media (max-width: 768px) {
            .filter-bar { padding: 15px; gap: 8px; }
            .filter-btn { padding: 10px 18px; font-size: 0.8rem; }
        }

        /* Products */
        .products-container { max-width: 1500px; margin: 0 auto; }
        .brand-section {
            margin-bottom: 100px;
            transition: opacity 0.3s ease, transform 0.3s ease;
        }
        .brand-section-title {
            font-family: 'Playfair Display', serif;
            font-size: 2.2rem;
            font-style: italic;
            margin-bottom: 45px;
            padding-left: 20px;
            border-left: 4px solid var(--dark);
            display: flex;
            align-items: center;
            gap: 15px;
            color: var(--dark);
        }
        .brand-section-title span {
            font-size: 0.85rem;
            color: var(--text-muted);
            font-family: 'Inter', sans-serif;
            font-weight: 400;
            font-style: italic;
        }
        .products-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 30px;
        }
        .product-card {
            background: var(--primary);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
            cursor: pointer;
            transition: all var(--transition-medium);
            position: relative;
        }
        .product-card::after {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: 12px;
            box-shadow: 0 0 0 0 var(--dark);
            transition: box-shadow var(--transition-fast);
            pointer-events: none;
        }
        .product-card:hover {
            transform: translateY(-10px) scale(1.02);
            box-shadow: var(--shadow-lg);
        }
        .product-card:hover::after {
            box-shadow: inset 0 0 0 2px var(--dark);
        }
        .product-3d-box {
            height: 260px;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            cursor: pointer;
            perspective: 800px;
            overflow: hidden;
        }
        .product-tag {
            position: absolute;
            top: 12px;
            left: 12px;
            background: var(--dark);
            color: #fff;
            padding: 5px 12px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            font-style: italic;
            text-transform: uppercase;
            z-index: 10;
        }
        .product-3d-wrapper {
            width: 65%;
            height: 85%;
            position: relative;
            transform-style: preserve-3d;
            transition: transform 0.15s ease-out;
            will-change: transform;
        }
        .product-3d-wrapper img {
            width: 100%;
            height: 100%;
            object-fit: contain;
            filter: drop-shadow(0 10px 20px rgba(0,0,0,0.2));
        }
        .product-3d-box:hover .product-3d-wrapper img {
            filter: drop-shadow(0 20px 40px rgba(0,0,0,0.3));
        }
        .product-depth { display: none; }
        .dbl-hint {
            position: absolute;
            bottom: 10px;
            right: 10px;
            background: rgba(0,0,0,0.6);
            color: var(--text-muted);
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 0.7rem;
            opacity: 0;
            transition: opacity 0.15s;
        }
        .product-3d-box:hover .dbl-hint { opacity: 1; }
        .product-info { padding: 25px; }
        .product-cat {
            color: var(--accent);
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }
        .product-name {
            font-family: 'Playfair Display', serif;
            font-size: 1.2rem;
            font-style: italic;
            margin-bottom: 10px;
            color: var(--dark);
        }
        .product-desc {
            color: var(--text-muted);
            font-size: 0.85rem;
            font-style: italic;
            line-height: 1.6;
            margin-bottom: 18px;
        }
        .product-btn {
            display: inline-block;
            background: var(--accent);
            color: var(--primary);
            padding: 10px 24px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 700;
            font-size: 0.8rem;
            text-transform: uppercase;
            transition: opacity 0.15s;
        }
        .product-btn:hover { opacity: 0.85; }

        /* Map - 120fps */
        .map-grid {
            display: grid;
            grid-template-columns: 1.2fr 1fr;
            gap: 60px;
            max-width: 1400px;
            margin: 0 auto;
            align-items: center;
        }
        .map-wrap {
            height: 450px;
            border-radius: 20px;
            overflow: hidden;
            border: 2px solid var(--dark);
            box-shadow: 0 25px 50px rgba(0,0,0,0.15), 0 10px 20px rgba(0,0,0,0.1);
            position: relative;
            background: var(--dark);
        }
        .map-wrap::before {
            content: 'TERRITORIO';
            position: absolute;
            top: 15px;
            left: 20px;
            background: var(--dark);
            color: #fff;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 2px;
            z-index: 1000;
            font-style: italic;
        }
        .map-wrap::after {
            content: '';
            position: absolute;
            inset: 0;
            border: 3px solid transparent;
            border-radius: 20px;
            pointer-events: none;
            z-index: 999;
            background: linear-gradient(135deg, rgba(255,255,255,0.1), transparent) border-box;
        }
        #map { width: 100%; height: 100%; filter: saturate(0.8) contrast(1.1); }
        .map-text h2 {
            font-family: 'Playfair Display', serif;
            font-size: 2.8rem;
            font-style: italic;
            margin-bottom: 25px;
            color: var(--dark);
        }
        .map-text h2 span { color: var(--grey); }
        .map-text > p {
            color: var(--text-muted);
            font-style: italic;
            line-height: 1.9;
            margin-bottom: 35px;
            font-size: 1.05rem;
        }
        .cities-list {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }
        .city-item {
            background: #fff;
            border: 1px solid var(--border);
            padding: 16px 22px;
            border-radius: 12px;
            font-weight: 600;
            font-style: italic;
            display: flex;
            align-items: center;
            gap: 12px;
            color: var(--dark);
            transition: all 0.2s ease;
            box-shadow: 0 2px 8px rgba(0,0,0,0.04);
        }
        .city-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.08);
            border-color: var(--dark);
        }
        .city-item::before {
            content: '';
            width: 10px;
            height: 10px;
            background: var(--dark);
            border-radius: 50%;
            flex-shrink: 0;
            box-shadow: 0 0 0 3px rgba(26,26,26,0.15);
        }

        /* About */
        .about-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 100px;
            max-width: 1500px;
            margin: 0 auto;
            align-items: center;
        }
        .about-text h2 {
            font-family: 'Playfair Display', serif;
            font-size: 2.8rem;
            font-style: italic;
            margin-bottom: 30px;
            color: var(--dark);
        }
        .about-text h2 span { color: var(--grey); }
        .about-text p {
            color: var(--text-muted);
            font-style: italic;
            line-height: 2;
            margin-bottom: 25px;
            font-size: 1.05rem;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 25px;
            margin-top: 50px;
        }
        .stat-card {
            background: var(--tertiary);
            border: 1px solid var(--border);
            padding: 28px;
            border-radius: 12px;
        }
        .stat-num {
            font-size: 3rem;
            font-weight: 900;
            color: var(--dark);
            margin-bottom: 8px;
        }
        .stat-label {
            color: var(--text-muted);
            font-size: 0.9rem;
            font-style: italic;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .team-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 30px; }
        .team-card {
            background: var(--tertiary);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 40px 30px;
            text-align: center;
        }
        .team-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.2rem;
            font-weight: 900;
            color: var(--text);
        }
        .team-avatar.copper { background: var(--walnut); }
        .team-avatar.rose { background: #a855f7; }
        .team-name {
            font-family: 'Playfair Display', serif;
            font-size: 1.5rem;
            font-style: italic;
            color: var(--dark);
            margin-bottom: 8px;
        }
        .team-role {
            color: var(--text-muted);
            font-size: 0.85rem;
            font-style: italic;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 20px;
        }
        .team-bio { color: var(--text-muted); font-style: italic; line-height: 1.8; font-size: 0.92rem; }

        /* Contact - 120fps */
        .contact-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 60px;
            max-width: 1400px;
            margin: 0 auto;
        }
        .contact-form-box {
            background: var(--tertiary);
            border: 1px solid var(--border);
            padding: 40px;
            border-radius: 16px;
        }
        .form-row { margin-bottom: 20px; }
        .form-row label { display: block; font-weight: 600; font-style: italic; margin-bottom: 8px; font-size: 0.9rem; color: var(--dark); }
        .form-row input, .form-row textarea, .form-row select {
            width: 100%;
            padding: 14px 18px;
            background: var(--secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-family: inherit;
            font-size: 1rem;
        }
        .form-row input:focus, .form-row textarea:focus, .form-row select:focus {
            outline: none;
            border-color: var(--accent);
        }
        .form-row textarea { height: 120px; resize: none; }
        .form-submit {
            width: 100%;
            background: var(--accent);
            color: var(--primary);
            padding: 16px;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            cursor: pointer;
            transition: opacity 0.15s;
        }
        .form-submit:hover { opacity: 0.85; }
        .contact-info h3 {
            font-family: 'Playfair Display', serif;
            font-size: 2rem;
            font-style: italic;
            margin-bottom: 40px;
            color: var(--dark);
        }
        .info-card {
            background: var(--tertiary);
            border: 1px solid var(--border);
            padding: 20px 25px;
            border-radius: 12px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 18px;
        }
        .info-icon {
            width: 50px;
            height: 50px;
            background: var(--dark);
            color: #fff;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.3rem;
            flex-shrink: 0;
        }
        .info-content h4 { font-weight: 700; font-style: italic; margin-bottom: 5px; color: var(--dark); }
        .info-content p { color: var(--text-muted); font-style: italic; font-size: 0.95rem; }

        /* Smart AI - 120fps */
        .smart-ai { position: fixed; bottom: 25px; right: 25px; z-index: 9999; }
        .smart-toggle {
            width: 60px;
            height: 60px;
            background: var(--smart);
            border-radius: 50%;
            border: none;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.6rem;
            transition: transform 0.15s ease;
        }
        .smart-toggle:hover { transform: scale(1.08); }
        .smart-chat {
            position: absolute;
            bottom: 75px;
            right: 0;
            width: 380px;
            height: 520px;
            background: var(--primary);
            border: 1px solid var(--border);
            border-radius: 16px;
            display: none;
            flex-direction: column;
            overflow: hidden;
        }
        .smart-chat.active { display: flex; }
        .smart-header {
            background: #ffffff;
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 1px solid var(--border);
        }
        .smart-avatar {
            width: 50px;
            height: 50px;
            background: var(--smart);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: #fff;
        }
        .smart-info h4 { font-weight: 800; margin-bottom: 3px; color: var(--dark); }
        .smart-info span { font-size: 0.82rem; color: var(--grey); }
        .smart-close {
            margin-left: auto;
            background: var(--secondary);
            border: none;
            width: 38px;
            height: 38px;
            border-radius: 50%;
            color: var(--dark);
            font-size: 1.2rem;
            cursor: pointer;
            transition: all 0.3s;
        }
        .smart-close:hover { background: var(--border); transform: rotate(90deg); }
        .smart-messages {
            flex: 1;
            padding: 25px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 18px;
        }
        .smart-msg {
            max-width: 85%;
            padding: 14px 18px;
            border-radius: 12px;
            font-size: 0.9rem;
            line-height: 1.6;
        }
        .smart-msg.bot {
            background: var(--tertiary);
            align-self: flex-start;
        }
        .smart-msg.user {
            background: rgba(70, 130, 180, 0.15);
            color: var(--dark);
            align-self: flex-end;
            border: 1px solid rgba(70, 130, 180, 0.3);
        }
        .smart-msg.typing { display: flex; gap: 6px; padding: 20px; }
        .smart-msg.typing span {
            width: 10px;
            height: 10px;
            background: var(--smart);
            border-radius: 50%;
            animation: typeDot 1.4s infinite;
        }
        .smart-msg.typing span:nth-child(2) { animation-delay: 0.2s; }
        .smart-msg.typing span:nth-child(3) { animation-delay: 0.4s; }
        @keyframes typeDot {
            0%, 60%, 100% { transform: translateY(0); opacity: 0.4; }
            30% { transform: translateY(-10px); opacity: 1; }
        }
        .quick-btns { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 15px; }
        .quick-btn {
            background: var(--glass);
            border: 1px solid var(--glass-border);
            color: var(--text);
            padding: 10px 18px;
            border-radius: 20px;
            font-size: 0.82rem;
            cursor: pointer;
            transition: all 0.3s;
        }
        .quick-btn:hover { background: var(--smart); border-color: transparent; }
        .smart-input-wrap { padding: 20px; border-top: 1px solid var(--glass-border); display: flex; gap: 12px; }
        .smart-input {
            flex: 1;
            padding: 14px 22px;
            background: var(--glass);
            border: 1px solid var(--glass-border);
            border-radius: 28px;
            color: var(--text);
            font-family: inherit;
            font-size: 0.95rem;
            transition: all 0.3s;
        }
        .smart-input:focus { outline: none; border-color: var(--smart); }
        .smart-send {
            width: 52px;
            height: 52px;
            background: linear-gradient(145deg, var(--smart), #3a7ca5);
            border: none;
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            transition: all 0.3s;
        }
        .smart-send:hover { transform: scale(1.1); }

        /* Footer - 120fps */
        footer {
            background: var(--primary);
            border-top: 1px solid var(--border);
            padding: 60px 60px 30px;
        }
        .footer-grid {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr;
            gap: 50px;
            max-width: 1400px;
            margin: 0 auto 40px;
        }
        .footer-brand p { color: var(--text-muted); font-style: italic; line-height: 1.8; margin-top: 15px; }
        footer h4 { color: var(--dark); font-style: italic; margin-bottom: 20px; font-size: 1rem; }
        .footer-links a {
            display: block;
            color: var(--text-muted);
            font-style: italic;
            text-decoration: none;
            margin-bottom: 12px;
        }
        .footer-links a:hover { color: var(--dark); }
        .footer-bottom {
            border-top: 1px solid var(--border);
            padding-top: 25px;
            text-align: center;
            color: var(--text-muted);
            font-style: italic;
            font-size: 0.85rem;
        }
        .footer-bottom a { color: var(--dark); text-decoration: none; }

        /* Product Detail Modal - 120fps */
        .product-modal {
            position: fixed; inset: 0;
            background: rgba(0,0,0,0.9);
            z-index: 99999;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 30px;
        }
        .product-modal.active { display: flex; }
        .modal-content {
            background: var(--secondary);
            border: 1px solid var(--border);
            border-radius: 16px;
            max-width: 1000px;
            width: 100%;
            max-height: 90vh;
            overflow: hidden;
            display: grid;
            grid-template-columns: 1fr 1fr;
        }
        .modal-3d-area {
            background: var(--tertiary);
            padding: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        .modal-3d-wrapper {
            width: 80%;
            height: 400px;
            perspective: 1500px;
            cursor: grab;
        }
        .modal-3d-wrapper:active { cursor: grabbing; }
        .modal-3d-product {
            width: 100%;
            height: 100%;
            transform-style: preserve-3d;
            transition: transform 0.1s;
        }
        .modal-3d-product img {
            width: 100%;
            height: 100%;
            object-fit: contain;
            filter: drop-shadow(0 30px 60px rgba(0,0,0,0.5));
        }
        .modal-rotate-hint {
            position: absolute;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            color: var(--text-muted);
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .modal-info-area {
            padding: 45px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
        }
        .modal-close {
            position: absolute;
            top: 15px;
            right: 15px;
            width: 44px;
            height: 44px;
            background: rgba(255,255,255,0.1);
            border: none;
            border-radius: 50%;
            color: var(--text);
            font-size: 1.4rem;
            cursor: pointer;
            z-index: 10;
            transition: opacity 0.15s;
        }
        .modal-close:hover { opacity: 0.7; }
        .modal-brand-tag {
            display: inline-block;
            background: var(--accent);
            color: var(--primary);
            padding: 6px 16px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            margin-bottom: 12px;
        }
        .modal-title {
            font-family: 'Playfair Display', serif;
            font-size: 2.2rem;
            font-style: italic;
            margin-bottom: 20px;
            color: var(--dark);
        }
        .modal-ai-box {
            background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 25px;
            position: relative;
            overflow: hidden;
        }
        .modal-ai-box::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(0,0,0,0.02) 0%, transparent 70%);
            animation: aiGlow 3s ease-in-out infinite;
        }
        @keyframes aiGlow {
            0%, 100% { transform: translate(0, 0); }
            50% { transform: translate(10%, 10%); }
        }
        .modal-ai-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 15px;
            position: relative;
            z-index: 1;
        }
        .modal-ai-avatar {
            width: 45px;
            height: 45px;
            background: linear-gradient(135deg, #1a1a1a, #333);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.3rem;
            color: #fff;
            animation: avatarPulse 2s ease-in-out infinite;
        }
        @keyframes avatarPulse {
            0%, 100% { box-shadow: 0 0 0 0 rgba(0,0,0,0.2); }
            50% { box-shadow: 0 0 0 10px rgba(0,0,0,0); }
        }
        .modal-ai-name { font-weight: 700; font-style: italic; color: var(--dark); font-size: 1rem; }
        .modal-ai-status { font-size: 0.75rem; color: var(--grey); display: flex; align-items: center; gap: 5px; }
        .modal-ai-status::before { content: ''; width: 8px; height: 8px; background: var(--grey); border-radius: 50%; animation: blink 1s infinite; }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .modal-ai-text { color: #1a1a1a; font-style: italic; line-height: 1.8; font-size: 0.95rem; position: relative; z-index: 1; }
        .modal-ai-text.typing::after { content: '|'; animation: cursorBlink 0.8s infinite; color: var(--dark); }
        @keyframes cursorBlink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
        .modal-specs { margin-bottom: 25px; }
        .modal-specs h4 { font-size: 1.1rem; font-style: italic; margin-bottom: 18px; color: var(--dark); display: flex; align-items: center; gap: 10px; }
        .modal-specs h4::before { content: ''; width: 4px; height: 20px; background: var(--dark); border-radius: 2px; }
        .spec-row {
            display: flex;
            justify-content: space-between;
            padding: 14px 0;
            border-bottom: 1px solid var(--border);
            font-size: 0.92rem;
        }
        .spec-row span:first-child { color: var(--grey); font-style: italic; }
        .spec-row span:last-child { font-weight: 600; color: var(--dark); }
        .modal-cta {
            margin-top: auto;
            display: flex;
            gap: 15px;
        }
        .modal-cta a {
            flex: 1;
            text-align: center;
            padding: 16px;
            border-radius: 10px;
            font-weight: 700;
            font-style: italic;
            text-decoration: none;
            transition: all 0.2s ease;
        }
        .modal-cta .primary {
            background: var(--dark);
            color: #fff;
        }
        .modal-cta .primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.2); }
        .modal-cta .secondary {
            background: transparent;
            border: 2px solid var(--dark);
            color: var(--dark);
        }
        .modal-cta .secondary:hover { background: var(--dark); color: #fff; }
        @media (max-width: 900px) {
            .modal-content { grid-template-columns: 1fr; max-height: 95vh; }
            .modal-3d-area { height: 300px; padding: 30px; }
        }

        /* Leaflet */
        .leaflet-popup-content-wrapper { background: var(--dark); border: none; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        .leaflet-popup-content { color: #fff; font-family: 'Playfair Display', serif; font-size: 1rem; font-style: italic; padding: 5px 10px; }
        .leaflet-popup-tip { background: var(--dark); }
        .leaflet-marker-icon { transition: transform 0.2s ease; }
        .leaflet-marker-icon:hover { transform: scale(1.2); }

        /* Responsive */
        @media (max-width: 1200px) {
            .brands-grid { grid-template-columns: repeat(3, 1fr); }
            .products-grid { grid-template-columns: repeat(3, 1fr); }
        }
        @media (max-width: 992px) {
            .hero-grid, .about-grid, .map-grid, .contact-grid { grid-template-columns: 1fr; }
            .header-main { padding: 15px 30px; }
            nav { display: none; }
            .brands-grid { grid-template-columns: repeat(2, 1fr); }
            .products-grid { grid-template-columns: repeat(2, 1fr); }
            .team-grid { grid-template-columns: 1fr; }
            .footer-grid { grid-template-columns: 1fr 1fr; }
        }
        @media (max-width: 600px) {
            .products-grid, .brands-grid { grid-template-columns: 1fr; }
            .footer-grid { grid-template-columns: 1fr; }
            .hero-text h1 { font-size: 2.5rem; }
            .smart-chat { width: 100%; right: -30px; height: 70vh; }
            .cities-list { grid-template-columns: 1fr; }
            .section { padding: 80px 30px; }
        }

        /* Video Showcase Section */
        .video-showcase {
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 50%, #1a1a1a 100%);
            padding: 100px 60px;
            position: relative;
            overflow: hidden;
        }
        .video-showcase::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="1" fill="rgba(201,162,39,0.1)"/></svg>');
            background-size: 30px 30px;
            opacity: 0.5;
        }
        .video-showcase .section-header h2 {
            color: #fff;
        }
        .video-showcase .section-header h2 span {
            color: #c9a227;
        }
        .video-showcase .section-header p {
            color: rgba(255,255,255,0.7);
        }
        .video-container {
            max-width: 1200px;
            margin: 0 auto;
            position: relative;
            z-index: 1;
        }
        .video-wrapper {
            position: relative;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 30px 80px rgba(0,0,0,0.5), 0 0 0 1px rgba(201,162,39,0.3);
            background: #000;
            transform: perspective(1000px) rotateX(2deg);
            transition: transform 0.5s ease, box-shadow 0.5s ease;
        }
        .video-wrapper:hover {
            transform: perspective(1000px) rotateX(0deg) scale(1.02);
            box-shadow: 0 40px 100px rgba(0,0,0,0.6), 0 0 0 2px rgba(201,162,39,0.5), 0 0 60px rgba(201,162,39,0.2);
        }
        .video-wrapper video {
            width: 100%;
            display: block;
            border-radius: 20px;
            filter: brightness(1.05) contrast(1.08) saturate(1.15);
            transition: filter 0.3s ease;
        }
        .video-wrapper:hover video {
            filter: brightness(1.1) contrast(1.1) saturate(1.2);
        }
        .video-overlay {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(to bottom, transparent 60%, rgba(0,0,0,0.8) 100%);
            pointer-events: none;
            border-radius: 20px;
        }
        .video-badge {
            position: absolute;
            top: 20px;
            left: 20px;
            background: linear-gradient(135deg, #c9a227, #d4af37);
            color: #1a1a1a;
            padding: 10px 20px;
            border-radius: 30px;
            font-weight: 700;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            z-index: 2;
            box-shadow: 0 5px 20px rgba(201,162,39,0.4);
        }
        .video-info {
            position: absolute;
            bottom: 30px;
            left: 30px;
            right: 30px;
            z-index: 2;
            color: #fff;
        }
        .video-info h3 {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 10px;
            text-shadow: 0 2px 10px rgba(0,0,0,0.5);
        }
        .video-info p {
            font-size: 1rem;
            opacity: 0.9;
            text-shadow: 0 1px 5px rgba(0,0,0,0.5);
        }
        .video-controls-hint {
            text-align: center;
            margin-top: 20px;
            color: rgba(255,255,255,0.5);
            font-size: 0.9rem;
        }
        .video-controls-hint i {
            margin-right: 8px;
            color: #c9a227;
        }
        .video-brand-watermark {
            position: absolute;
            bottom: 15px;
            right: 15px;
            background: linear-gradient(135deg, rgba(26,26,26,0.95), rgba(45,45,45,0.95));
            color: #c9a227;
            padding: 12px 25px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            z-index: 10;
            border: 1px solid rgba(201,162,39,0.5);
            box-shadow: 0 5px 25px rgba(0,0,0,0.5);
            backdrop-filter: blur(10px);
            font-family: 'Playfair Display', serif;
        }
        .video-brand-watermark span {
            color: #fff;
            font-weight: 400;
        }
        @media (max-width: 768px) {
            .video-showcase { padding: 60px 15px; }
            .video-wrapper {
                transform: none;
                border-radius: 12px;
                aspect-ratio: 16/9;
                overflow: hidden;
            }
            .video-wrapper:hover { transform: none; }
            .video-wrapper video {
                width: 100%;
                height: 100%;
                object-fit: cover;
                border-radius: 12px;
            }
            .video-info {
                bottom: 50px;
                left: 15px;
                right: 15px;
            }
            .video-info h3 {
                font-size: 1.1rem;
                margin-bottom: 5px;
            }
            .video-info p {
                font-size: 0.85rem;
                display: none;
            }
            .video-badge {
                top: 10px;
                left: 10px;
                padding: 6px 12px;
                font-size: 0.7rem;
            }
            .video-brand-watermark {
                bottom: 10px;
                right: 10px;
                padding: 8px 15px;
                font-size: 0.75rem;
                letter-spacing: 1px;
            }
            .video-controls-hint {
                font-size: 0.8rem;
                margin-top: 15px;
            }
            .video-overlay {
                border-radius: 12px;
            }
        }
    </style>
</head>
<body>
    <!-- Welcome -->
    <div class="welcome-overlay" id="welcomeOverlay">
        <div class="welcome-box">
            <div class="welcome-logo-big">SR</div>
            <h1 class="welcome-title">Benvenuto</h1>
            <p class="welcome-sub">Spallanzani Rappresentanze<br>Infissi e Serramenti Premium<br>Emilia Romagna</p>
            <button class="welcome-enter-btn" id="enterBtn">Esplora i Prodotti</button>
        </div>
    </div>
    <script>
        document.getElementById('enterBtn').addEventListener('click', function() {
            var overlay = document.getElementById('welcomeOverlay');
            overlay.classList.add('fade-out');
            document.body.style.overflow = 'auto';
            setTimeout(function() {
                overlay.style.display = 'none';
            }, 500);
        });
    </script>

    <!-- Theme Toggle -->
    <div class="theme-toggle">
        <button class="theme-btn" id="themeToggle" title="Cambia tema">
            <i class="fas fa-moon" id="themeIcon"></i>
        </button>
    </div>

    <header>
        <div class="header-top">
            <a href="tel:+393356928280"><i class="fas fa-phone"></i> +39 335 692 8280</a>
            <a href="mailto:spallamm@gmail.com"><i class="fas fa-envelope"></i> spallamm@gmail.com</a>
        </div>
        <div class="header-main">
            <div class="logo">
                <div class="logo-icon">SR</div>
                <div class="logo-text">
                    <h1>SPALLANZANI RAPPRESENTANZE</h1>
                    <span>Infissi e Serramenti</span>
                </div>
            </div>
            <nav>
                <a href="#marchi">Marchi</a>
                <a href="#prodotti">Prodotti</a>
                <a href="#territorio">Territorio</a>
                <a href="#chi-siamo">Chi Siamo</a>
                <a href="#contatti">Contatti</a>
                <a href="/registrati" style="color:var(--accent)">Registrati</a>
            </nav>
            <a href="tel:+393356928280" class="cta-btn"><i class="fas fa-phone"></i> Chiamaci</a>
        </div>
    </header>

    <section class="hero">
        <div class="wood-texture"></div>
        <div class="fire-glow"></div>
        <div class="floating-doors">
            <div class="float-door">&#128682;</div>
            <div class="float-door">&#128682;</div>
            <div class="float-door">&#128682;</div>
        </div>
        <div class="hero-grid">
            <div class="hero-text">
                <h1>Rappresentanze <span>Infissi e Serramenti</span> di Eccellenza</h1>
                <p>Da oltre 25 anni rappresentiamo i migliori marchi italiani del settore porte, serramenti e infissi in Emilia Romagna. Qualita, design e innovazione al servizio dei professionisti.</p>
                <div class="hero-btns">
                    <a href="#prodotti" class="btn-primary">Scopri i Prodotti</a>
                    <a href="/registrati" class="btn-secondary">Area Riservata</a>
                </div>
            </div>
            <div class="showcase-3d">
                <div class="door-showcase-3d">
                    <div class="door-3d-frame"></div>
                    <div class="door-3d-panel">
                        <div class="door-3d-decor top"></div>
                        <div class="door-3d-decor bottom"></div>
                    </div>
                    <div class="door-3d-handle"></div>
                </div>
                <div class="rotate-hint-3d">
                    <i class="fas fa-hand-pointer"></i> Muovi il mouse per ruotare
                </div>
            </div>
        </div>
    </section>

    <!-- Video Showcase Section -->
    <section class="video-showcase" id="video">
        <div class="section-header reveal">
            <h2>Serramenti <span>in Azione</span></h2>
            <div class="accent-bar"></div>
            <p>Scopri la qualita e l'eleganza dei nostri serramenti in questo video esclusivo</p>
        </div>
        <div class="video-container">
            <div class="video-wrapper">
                <div class="video-badge"><i class="fas fa-play-circle"></i> Video HD</div>
                <video controls playsinline poster="">
                    <source src="/static/Serramenti_Moderni_per_Casa_Alpina.mp4" type="video/mp4">
                    Il tuo browser non supporta il tag video.
                </video>
                <div class="video-overlay"></div>
                <div class="video-brand-watermark">Spallanzani <span>Rappresentanze</span></div>
                <div class="video-info">
                    <h3>Serramenti Moderni per Casa Alpina</h3>
                    <p>Design contemporaneo, isolamento termico superiore e massima luminosita</p>
                </div>
            </div>
            <div class="video-controls-hint">
                <i class="fas fa-volume-up"></i> Clicca sul video per riprodurre con audio
            </div>
        </div>
    </section>

    <section class="section section-alt" id="marchi">
        <div class="section-header reveal">
            <h2>I Marchi che <span>Rappresentiamo</span></h2>
            <div class="accent-bar"></div>
            <p>Partner esclusivi dei migliori brand italiani nel settore porte e serramenti</p>
        </div>
        <div class="brands-grid">
            <div class="brand-card reveal-scale stagger-1"><div class="brand-title">FLESSYA</div><div class="brand-name">Flessya</div><div class="brand-desc">Porte per interni Made in Italy. Linee Nidio, Kikka, Vetra con oltre 100 finiture.</div></div>
            <div class="brand-card reveal-scale stagger-2"><div class="brand-title">MONDOCASA</div><div class="brand-name">Mondocasa</div><div class="brand-desc">Serramenti in PVC ad alto isolamento termico e acustico.</div></div>
            <div class="brand-card reveal-scale stagger-3"><div class="brand-title">EPROD</div><div class="brand-name">Eproditalia</div><div class="brand-desc">Infissi in alluminio a taglio termico di ultima generazione.</div></div>
            <div class="brand-card reveal-scale stagger-4"><div class="brand-title">ARIENI</div><div class="brand-name">Arieni Maniglie</div><div class="brand-desc">Maniglieria di design in ottone e acciaio dal 1997.</div></div>
            <div class="brand-card reveal-scale stagger-5"><div class="brand-title">Di.Bi.</div><div class="brand-name">Di.Bi. Blindate</div><div class="brand-desc">Porte blindate certificate classe 3, 4 e 5 dal 1976.</div></div>
        </div>
    </section>

    <section class="section" id="prodotti">
        <div class="section-header reveal">
            <h2>I Nostri <span>Prodotti</span></h2>
            <div class="accent-bar"></div>
            <p>Catalogo completo diviso per brand - Doppio click per rotazione 3D</p>
        </div>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterProducts('all')">Tutti</button>
            <button class="filter-btn" onclick="filterProducts('flessya')">Flessya</button>
            <button class="filter-btn" onclick="filterProducts('dibi')">Di.Bi.</button>
            <button class="filter-btn" onclick="filterProducts('arieni')">Arieni</button>
            <button class="filter-btn" onclick="filterProducts('mondocasa')">Mondocasa</button>
            <button class="filter-btn" onclick="filterProducts('eproditalia')">Eproditalia</button>
        </div>
        <div class="products-container">
            <div class="brand-section">
                <h3 class="brand-section-title">Flessya <span>Porte per Interni</span></h3>
                <div class="products-grid">
                    <div class="product-card">
                        <div class="product-3d-box" data-product="f1" onclick="openProductModal('f1')" onmousemove="rotate3D(event, 'f1')" onmouseleave="reset3D('f1')">
                            <span class="product-tag">Flessya</span>
                            <div class="product-3d-wrapper gpu" id="f1">
                                <img src="https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-KIKKA_immagine_K00_001-scaled.jpg" alt="Kikka">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea Kikka</div>
                            <h4 class="product-name">Kikka K00</h4>
                            <p class="product-desc">Design pulito e contemporaneo, superficie liscia per ambienti moderni.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="f2" onclick="openProductModal('f2')" onmousemove="rotate3D(event, 'f2')" onmouseleave="reset3D('f2')">
                            <span class="product-tag">Flessya</span>
                            <div class="product-3d-wrapper gpu" id="f2">
                                <img src="https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-Vetra03_HD300-scaled.jpg" alt="Vetra">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea Vetra</div>
                            <h4 class="product-name">Vetra 03</h4>
                            <p class="product-desc">Porta con vetrata centrale per massima luminosita degli spazi.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="f3" onclick="openProductModal('f3')" onmousemove="rotate3D(event, 'f3')" onmouseleave="reset3D('f3')">
                            <span class="product-tag">Flessya</span>
                            <div class="product-3d-wrapper gpu" id="f3">
                                <img src="https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-N50E_HD300_OK-scaled.jpg" alt="Nidio">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea Nidio</div>
                            <h4 class="product-name">Nidio N50E</h4>
                            <p class="product-desc">Best-seller tamburata con finitura effetto legno naturale.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="f4" onclick="openProductModal('f4')" onmousemove="rotate3D(event, 'f4')" onmouseleave="reset3D('f4')">
                            <span class="product-tag">Flessya</span>
                            <div class="product-3d-wrapper gpu" id="f4">
                                <img src="https://www.flessya.com/site/wp-content/uploads/2022/07/Rasomuro_01_HD300_i16-scaled.jpg" alt="Rasomuro">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea Rasomuro</div>
                            <h4 class="product-name">Rasomuro 01</h4>
                            <p class="product-desc">Filo muro minimal che si integra perfettamente con la parete.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="f5" onclick="openProductModal('f5')" onmousemove="rotate3D(event, 'f5')" onmouseleave="reset3D('f5')">
                            <span class="product-tag">Flessya</span>
                            <div class="product-3d-wrapper gpu" id="f5">
                                <img src="https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-Vetra05_HD300-scaled.jpg" alt="Vetra 05">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea Vetra</div>
                            <h4 class="product-name">Vetra 05</h4>
                            <p class="product-desc">Vetrata full-height per massima luminosita e design contemporaneo.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="f6" onclick="openProductModal('f6')" onmousemove="rotate3D(event, 'f6')" onmouseleave="reset3D('f6')">
                            <span class="product-tag">Flessya</span>
                            <div class="product-3d-wrapper gpu" id="f6">
                                <img src="https://www.flessya.com/site/wp-content/uploads/2022/07/S-nziale_Mono_Inglesina.jpg" alt="S-nziale Mono">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea S-nziale</div>
                            <h4 class="product-name">S-nziale Mono</h4>
                            <p class="product-desc">Porta tutto vetro con telaio alluminio, stile inglese raffinato.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="f7" onclick="openProductModal('f7')" onmousemove="rotate3D(event, 'f7')" onmouseleave="reset3D('f7')">
                            <span class="product-tag">Flessya</span>
                            <div class="product-3d-wrapper gpu" id="f7">
                                <img src="https://www.flessya.com/site/wp-content/uploads/2022/07/S-nziale_Duo_SD00-scaled.jpg" alt="S-nziale Duo">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea S-nziale</div>
                            <h4 class="product-name">S-nziale Duo</h4>
                            <p class="product-desc">Doppia anta vetrata per aperture ampie e scenografiche.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="f8" onclick="openProductModal('f8')" onmousemove="rotate3D(event, 'f8')" onmouseleave="reset3D('f8')">
                            <span class="product-tag">Flessya</span>
                            <div class="product-3d-wrapper gpu" id="f8">
                                <img src="https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-NL15_HD300_OK-scaled.jpg" alt="Nidio NL15">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea Nidio</div>
                            <h4 class="product-name">Nidio NL15</h4>
                            <p class="product-desc">Tamburata con pantografature geometriche eleganti.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="f9" onclick="openProductModal('f9')" onmousemove="rotate3D(event, 'f9')" onmouseleave="reset3D('f9')">
                            <span class="product-tag">Flessya</span>
                            <div class="product-3d-wrapper gpu" id="f9">
                                <img src="https://www.flessya.com/site/wp-content/uploads/2022/07/Flessya-P31_P50_HD300-scaled.jpg" alt="Plenia P31">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea Plenia</div>
                            <h4 class="product-name">Plenia P31</h4>
                            <p class="product-desc">Legno massello impiallacciato con venature naturali a vista.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="f10" onclick="openProductModal('f10')" onmousemove="rotate3D(event, 'f10')" onmouseleave="reset3D('f10')">
                            <span class="product-tag">Flessya</span>
                            <div class="product-3d-wrapper gpu" id="f10">
                                <img src="https://www.flessya.com/site/wp-content/uploads/2022/07/Rasomuro_05_N00_HD300-scaled.jpg" alt="Rasomuro 05">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea Rasomuro</div>
                            <h4 class="product-name">Rasomuro 05</h4>
                            <p class="product-desc">Filo muro con inserti decorativi, perfetta integrazione architettonica.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                </div>
            </div>
            <div class="brand-section">
                <h3 class="brand-section-title">Di.Bi. <span>Porte Blindate</span></h3>
                <div class="products-grid">
                    <div class="product-card">
                        <div class="product-3d-box" data-product="d1" onclick="openProductModal('d1')" onmousemove="rotate3D(event, 'd1')" onmouseleave="reset3D('d1')">
                            <span class="product-tag">Di.Bi.</span>
                            <div class="product-3d-wrapper gpu" id="d1">
                                <img src="https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_argoplus_est_noce_nazionale_sx_amb_11.jpg" alt="Argo Plus">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Classe 3</div>
                            <h4 class="product-name">Argo Plus</h4>
                            <p class="product-desc">Blindata certificata classe 3, finitura noce nazionale.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="d2" onclick="openProductModal('d2')" onmousemove="rotate3D(event, 'd2')" onmouseleave="reset3D('d2')">
                            <span class="product-tag">Di.Bi.</span>
                            <div class="product-3d-wrapper gpu" id="d2">
                                <img src="https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_883_est_all_ia_ral_6005_sx_amb_2.jpg" alt="883">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Classe 4</div>
                            <h4 class="product-name">883 Premium</h4>
                            <p class="product-desc">Massima sicurezza classe 4, design moderno RAL personalizzabile.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="d3" onclick="openProductModal('d3')" onmousemove="rotate3D(event, 'd3')" onmouseleave="reset3D('d3')">
                            <span class="product-tag">Di.Bi.</span>
                            <div class="product-3d-wrapper gpu" id="d3">
                                <img src="https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_vetrata_est_ii_white_sx_amb_4.jpg" alt="Vetrata">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Classe 3</div>
                            <h4 class="product-name">Blindata Vetrata</h4>
                            <p class="product-desc">Sicurezza e luce, vetro blindato per ingressi luminosi.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="d4" onclick="openProductModal('d4')" onmousemove="rotate3D(event, 'd4')" onmouseleave="reset3D('d4')">
                            <span class="product-tag">Di.Bi.</span>
                            <div class="product-3d-wrapper gpu" id="d4">
                                <img src="https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/a/r/argo_bianca_pianerottolo_2_1_3.jpg" alt="Argo Bianca">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Classe 3</div>
                            <h4 class="product-name">Argo Bianca</h4>
                            <p class="product-desc">Eleganza in bianco per interni moderni e luminosi.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="d5" onclick="openProductModal('d5')" onmousemove="rotate3D(event, 'd5')" onmouseleave="reset3D('d5')">
                            <span class="product-tag">Di.Bi.</span>
                            <div class="product-3d-wrapper gpu" id="d5">
                                <img src="https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_poker2_est_sd_white_sx_amb_54.jpg" alt="Poker2 White">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Classe 3</div>
                            <h4 class="product-name">Poker2 White</h4>
                            <p class="product-desc">Design contemporaneo bianco con pannello decorativo.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="d6" onclick="openProductModal('d6')" onmousemove="rotate3D(event, 'd6')" onmouseleave="reset3D('d6')">
                            <span class="product-tag">Di.Bi.</span>
                            <div class="product-3d-wrapper gpu" id="d6">
                                <img src="https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_argoplus_est_tx_golden_oak_sx_amb_10.jpg" alt="Argo Plus Golden">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Classe 3</div>
                            <h4 class="product-name">Argo Plus Golden</h4>
                            <p class="product-desc">Finitura Golden Oak calda ed elegante per ingressi prestigiosi.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="d7" onclick="openProductModal('d7')" onmousemove="rotate3D(event, 'd7')" onmouseleave="reset3D('d7')">
                            <span class="product-tag">Di.Bi.</span>
                            <div class="product-3d-wrapper gpu" id="d7">
                                <img src="https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_884_est_tanganika_05_sx_amb_8.jpg" alt="884 Tanganika">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Classe 4</div>
                            <h4 class="product-name">884 Tanganika</h4>
                            <p class="product-desc">Alta sicurezza classe 4 con finitura legno tanganika pregiato.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="d8" onclick="openProductModal('d8')" onmousemove="rotate3D(event, 'd8')" onmouseleave="reset3D('d8')">
                            <span class="product-tag">Di.Bi.</span>
                            <div class="product-3d-wrapper gpu" id="d8">
                                <img src="https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_883_2a_est_pz_golden_oak_sx_amb_12.jpg" alt="883 2A Golden">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Classe 4</div>
                            <h4 class="product-name">883 2A Golden</h4>
                            <p class="product-desc">Doppia anta blindata per ingressi ampi e signorili.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="d9" onclick="openProductModal('d9')" onmousemove="rotate3D(event, 'd9')" onmouseleave="reset3D('d9')">
                            <span class="product-tag">Di.Bi.</span>
                            <div class="product-3d-wrapper gpu" id="d9">
                                <img src="https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_argo_est_mogano_sx_amb_27.jpg" alt="Argo Mogano">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Classe 3</div>
                            <h4 class="product-name">Argo Mogano</h4>
                            <p class="product-desc">Classica eleganza mogano per abitazioni di prestigio.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="d10" onclick="openProductModal('d10')" onmousemove="rotate3D(event, 'd10')" onmouseleave="reset3D('d10')">
                            <span class="product-tag">Di.Bi.</span>
                            <div class="product-3d-wrapper gpu" id="d10">
                                <img src="https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_poker2_est_all_pz_bianco_9010_sx_amb_28.jpg" alt="Poker2 Bianco">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Classe 3</div>
                            <h4 class="product-name">Poker2 RAL 9010</h4>
                            <p class="product-desc">Bianco RAL 9010 opaco per ambienti minimal e luminosi.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                </div>
            </div>
            <div class="brand-section">
                <h3 class="brand-section-title">Arieni <span>Maniglie di Design</span></h3>
                <div class="products-grid">
                    <div class="product-card">
                        <div class="product-3d-box" data-product="a1" onclick="openProductModal('a1')" onmousemove="rotate3D(event, 'a1')" onmouseleave="reset3D('a1')">
                            <span class="product-tag">Arieni</span>
                            <div class="product-3d-wrapper gpu" id="a1">
                                <img src="https://www.arienisrl.com/wp-content/uploads/Laser-obm.png" alt="Laser">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea Laser</div>
                            <h4 class="product-name">Laser OBM</h4>
                            <p class="product-desc">Design minimalista, finitura ottone brunito opaco.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="a2" onclick="openProductModal('a2')" onmousemove="rotate3D(event, 'a2')" onmouseleave="reset3D('a2')">
                            <span class="product-tag">Arieni</span>
                            <div class="product-3d-wrapper gpu" id="a2">
                                <img src="https://www.arienisrl.com/wp-content/uploads/2020/09/Vera-1200x600-1-1-1.png" alt="Vera">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Contemporary</div>
                            <h4 class="product-name">Vera CRS</h4>
                            <p class="product-desc">Linee squadrate moderne, cromato satinato elegante.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="a3" onclick="openProductModal('a3')" onmousemove="rotate3D(event, 'a3')" onmouseleave="reset3D('a3')">
                            <span class="product-tag">Arieni</span>
                            <div class="product-3d-wrapper gpu" id="a3">
                                <img src="https://www.arienisrl.com/wp-content/uploads/2020/06/Dea-1200x600-1.png" alt="Dea">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Contemporary</div>
                            <h4 class="product-name">Dea PVD</h4>
                            <p class="product-desc">Alluminio massiccio con rivestimento PVD antigraffio.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="a4" onclick="openProductModal('a4')" onmousemove="rotate3D(event, 'a4')" onmouseleave="reset3D('a4')">
                            <span class="product-tag">Arieni</span>
                            <div class="product-3d-wrapper gpu" id="a4">
                                <img src="https://www.arienisrl.com/wp-content/uploads/2020/09/Area51-1200x600-nera.png" alt="Area51">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Contemporary</div>
                            <h4 class="product-name">Area 51 Nera</h4>
                            <p class="product-desc">Total black per interni di tendenza contemporanea.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="a5" onclick="openProductModal('a5')" onmousemove="rotate3D(event, 'a5')" onmouseleave="reset3D('a5')">
                            <span class="product-tag">Arieni</span>
                            <div class="product-3d-wrapper gpu" id="a5">
                                <img src="https://www.arienisrl.com/wp-content/uploads/2020/09/Piego-1200.png" alt="Piego CRS">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Contemporary</div>
                            <h4 class="product-name">Piego CRS</h4>
                            <p class="product-desc">Linee arrotondate morbide, cromato satinato elegante.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="a6" onclick="openProductModal('a6')" onmousemove="rotate3D(event, 'a6')" onmouseleave="reset3D('a6')">
                            <span class="product-tag">Arieni</span>
                            <div class="product-3d-wrapper gpu" id="a6">
                                <img src="https://www.arienisrl.com/wp-content/uploads/Ares-ocr.png" alt="Ares OCR">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Linea Laser</div>
                            <h4 class="product-name">Ares OCR</h4>
                            <p class="product-desc">Design geometrico minimalista, ottone cromato raffinato.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="a7" onclick="openProductModal('a7')" onmousemove="rotate3D(event, 'a7')" onmouseleave="reset3D('a7')">
                            <span class="product-tag">Arieni</span>
                            <div class="product-3d-wrapper gpu" id="a7">
                                <img src="https://www.arienisrl.com/wp-content/uploads/Quasar-crs.png" alt="Quasar CRS">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Contemporary</div>
                            <h4 class="product-name">Quasar CRS</h4>
                            <p class="product-desc">Design futuristico con finitura cromo satinato brillante.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="a8" onclick="openProductModal('a8')" onmousemove="rotate3D(event, 'a8')" onmouseleave="reset3D('a8')">
                            <span class="product-tag">Arieni</span>
                            <div class="product-3d-wrapper gpu" id="a8">
                                <img src="https://www.arienisrl.com/wp-content/uploads/Duna-olv.png" alt="Duna OLV">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Contemporary</div>
                            <h4 class="product-name">Duna OLV</h4>
                            <p class="product-desc">Linee ondulate eleganti, finitura ottone lucido vintage.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="a9" onclick="openProductModal('a9')" onmousemove="rotate3D(event, 'a9')" onmouseleave="reset3D('a9')">
                            <span class="product-tag">Arieni</span>
                            <div class="product-3d-wrapper gpu" id="a9">
                                <img src="https://www.arienisrl.com/wp-content/uploads/Venus-ocr.png" alt="Venus OCR">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Contemporary</div>
                            <h4 class="product-name">Venus OCR</h4>
                            <p class="product-desc">Eleganza classica rivisitata, ottone cromato lucido.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="a10" onclick="openProductModal('a10')" onmousemove="rotate3D(event, 'a10')" onmouseleave="reset3D('a10')">
                            <span class="product-tag">Arieni</span>
                            <div class="product-3d-wrapper gpu" id="a10">
                                <img src="https://www.arienisrl.com/wp-content/uploads/2020/06/Chic-1200x600-1-1-1.png" alt="Chic">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Atelier</div>
                            <h4 class="product-name">Chic OBM</h4>
                            <p class="product-desc">Stile raffinato per interni di prestigio, ottone brunito.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                </div>
            </div>
            <div class="brand-section">
                <h3 class="brand-section-title">Mondocasa <span>Serramenti PVC</span></h3>
                <div class="products-grid">
                    <div class="product-card">
                        <div class="product-3d-box" data-product="m1" onclick="openProductModal('m1')" onmousemove="rotate3D(event, 'm1')" onmouseleave="reset3D('m1')">
                            <span class="product-tag">Mondocasa</span>
                            <div class="product-3d-wrapper gpu" id="m1">
                                <img src="https://www.oknoplast.it/media/prolux-evolution_3RiRmAh.jpg" alt="Evolution 70">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Serie Evolution</div>
                            <h4 class="product-name">Evolution 70</h4>
                            <p class="product-desc">Finestra PVC 70mm con triplo vetro. Isolamento termico Uw 0.9 W/m2K.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="m2" onclick="openProductModal('m2')" onmousemove="rotate3D(event, 'm2')" onmouseleave="reset3D('m2')">
                            <span class="product-tag">Mondocasa</span>
                            <div class="product-3d-wrapper gpu" id="m2">
                                <img src="https://www.oknoplast.it/media/platinium-plus_TITEs3q.jpg" alt="Platinium Plus">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Serie Premium</div>
                            <h4 class="product-name">Platinium Plus</h4>
                            <p class="product-desc">Sistema 85mm con 6 camere. Massimo isolamento termoacustico.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="m3" onclick="openProductModal('m3')" onmousemove="rotate3D(event, 'm3')" onmouseleave="reset3D('m3')">
                            <span class="product-tag">Mondocasa</span>
                            <div class="product-3d-wrapper gpu" id="m3">
                                <img src="https://www.oknoplast.it/media/squareline_F4H1tAJ.jpg" alt="Squareline">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Design Minimal</div>
                            <h4 class="product-name">Squareline</h4>
                            <p class="product-desc">Profilo squadrato minimal per architetture moderne e contemporanee.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="m4" onclick="openProductModal('m4')" onmousemove="rotate3D(event, 'm4')" onmouseleave="reset3D('m4')">
                            <span class="product-tag">Mondocasa</span>
                            <div class="product-3d-wrapper gpu" id="m4">
                                <img src="https://www.oknoplast.it/media/prismatic_iXGjyFa.jpg" alt="Prismatic">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Alta Efficienza</div>
                            <h4 class="product-name">Prismatic</h4>
                            <p class="product-desc">Finestra scorrevole alzante con vetrata panoramica fino a 6 metri.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="m5" onclick="openProductModal('m5')" onmousemove="rotate3D(event, 'm5')" onmouseleave="reset3D('m5')">
                            <span class="product-tag">Mondocasa</span>
                            <div class="product-3d-wrapper gpu" id="m5">
                                <img src="https://www.oknoplast.it/media/winergetic-premium.jpg" alt="Winergetic">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Casa Passiva</div>
                            <h4 class="product-name">Winergetic Premium</h4>
                            <p class="product-desc">Certificato casa passiva. Uw 0.6 W/m2K per massimo risparmio energetico.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="m6" onclick="openProductModal('m6')" onmousemove="rotate3D(event, 'm6')" onmouseleave="reset3D('m6')">
                            <span class="product-tag">Mondocasa</span>
                            <div class="product-3d-wrapper gpu" id="m6">
                                <img src="https://www.oknoplast.it/media/bilico_Y0R5Trp.jpg" alt="Bilico">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Speciale</div>
                            <h4 class="product-name">Finestra Bilico</h4>
                            <p class="product-desc">Apertura a bilico orizzontale. Ideale per mansarde e sottotetti.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="m7" onclick="openProductModal('m7')" onmousemove="rotate3D(event, 'm7')" onmouseleave="reset3D('m7')">
                            <span class="product-tag">Mondocasa</span>
                            <div class="product-3d-wrapper gpu" id="m7">
                                <img src="https://www.oknoplast.it/media/prolux-swing_CcqILC9.jpg" alt="Prolux Swing">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Serie Prolux</div>
                            <h4 class="product-name">Prolux Swing</h4>
                            <p class="product-desc">Apertura a vasistas con cerniere nascoste. Design pulito e moderno.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="m8" onclick="openProductModal('m8')" onmousemove="rotate3D(event, 'm8')" onmouseleave="reset3D('m8')">
                            <span class="product-tag">Mondocasa</span>
                            <div class="product-3d-wrapper gpu" id="m8">
                                <img src="https://www.oknoplast.it/media/prismatic-evolution.jpg" alt="Prismatic Evolution">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Scorrevole Premium</div>
                            <h4 class="product-name">Prismatic Evolution</h4>
                            <p class="product-desc">Scorrevole evoluta con profilo ultra-sottile. Massima luminosita.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="m9" onclick="openProductModal('m9')" onmousemove="rotate3D(event, 'm9')" onmouseleave="reset3D('m9')">
                            <span class="product-tag">Mondocasa</span>
                            <div class="product-3d-wrapper gpu" id="m9">
                                <img src="https://www.oknoplast.it/media/winergetic-premium-passive.jpg" alt="Passive House">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Casa Passiva Plus</div>
                            <h4 class="product-name">Passive House Plus</h4>
                            <p class="product-desc">Certificazione PHI. Il top per edifici a energia quasi zero.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="m10" onclick="openProductModal('m10')" onmousemove="rotate3D(event, 'm10')" onmouseleave="reset3D('m10')">
                            <span class="product-tag">Mondocasa</span>
                            <div class="product-3d-wrapper gpu" id="m10">
                                <img src="https://www.oknoplast.it/media/prolux-plus-hero-04.jpg" alt="Prolux Plus">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Serie Prolux</div>
                            <h4 class="product-name">Prolux Plus</h4>
                            <p class="product-desc">Evoluzione Prolux con ferramenta premium e vetro selettivo.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                </div>
            </div>
            <div class="brand-section">
                <h3 class="brand-section-title">Eproditalia <span>Infissi Alluminio</span></h3>
                <div class="products-grid">
                    <div class="product-card">
                        <div class="product-3d-box" data-product="e1" onclick="openProductModal('e1')" onmousemove="rotate3D(event, 'e1')" onmouseleave="reset3D('e1')">
                            <span class="product-tag">Eproditalia</span>
                            <div class="product-3d-wrapper gpu" id="e1">
                                <img src="https://images.ctfassets.net/hd6763cyzwa4/3j4SWNX23pT0g9xXjKJeF3/6f28f41ad2c867b8b6353d1a2fc21eff/Maison_Sentinelle_-_Droits_jusqu-en_février_2032_-_Photographe_et_architecte_Aurélien_Chen__2_.jpg" alt="TT65 Next">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Taglio Termico 65</div>
                            <h4 class="product-name">TT65 Next</h4>
                            <p class="product-desc">Alluminio a taglio termico 65mm. Design minimal con profilo sottile.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="e2" onclick="openProductModal('e2')" onmousemove="rotate3D(event, 'e2')" onmouseleave="reset3D('e2')">
                            <span class="product-tag">Eproditalia</span>
                            <div class="product-3d-wrapper gpu" id="e2">
                                <img src="https://images.ctfassets.net/hd6763cyzwa4/1CITmzFHp05yaHYd0cAunG/2c79362f407ecd2086a6a1d0246f8e3c/Alpina-wood85_1-copia---modificata-ridotto.jpg" alt="TT85 Wood">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Effetto Legno</div>
                            <h4 class="product-name">TT85 Wood</h4>
                            <p class="product-desc">Alluminio con rivestimento effetto legno. Eleganza e resistenza.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="e3" onclick="openProductModal('e3')" onmousemove="rotate3D(event, 'e3')" onmouseleave="reset3D('e3')">
                            <span class="product-tag">Eproditalia</span>
                            <div class="product-3d-wrapper gpu" id="e3">
                                <img src="https://images.ctfassets.net/hd6763cyzwa4/7BF16hQR10jid6b28Lyipz/87c43f925e71483a6d4b323e082b34fb/Still_Alluminio_TOP_TB_65.jpg" alt="TB65 Top">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Top Performance</div>
                            <h4 class="product-name">TB65 Top</h4>
                            <p class="product-desc">Sistema top performance con isolamento termico superiore.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="e4" onclick="openProductModal('e4')" onmousemove="rotate3D(event, 'e4')" onmouseleave="reset3D('e4')">
                            <span class="product-tag">Eproditalia</span>
                            <div class="product-3d-wrapper gpu" id="e4">
                                <img src="https://www.metrabuilding.com/media/catalog/product/cache/3/image/9df78eab33525d08d6e5fb8d27136e95/n/c/nc-s_65_sti_he_finestra_2_ante_con_traverso_e_sopraluce_a_vasistas.jpg" alt="NC65 STI">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Standard</div>
                            <h4 class="product-name">NC65 STI</h4>
                            <p class="product-desc">Sistema standard a taglio termico. Ottimo rapporto qualita-prezzo.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="e5" onclick="openProductModal('e5')" onmousemove="rotate3D(event, 'e5')" onmouseleave="reset3D('e5')">
                            <span class="product-tag">Eproditalia</span>
                            <div class="product-3d-wrapper gpu" id="e5">
                                <img src="https://www.finstral.com/fileadmin/_processed_/b/0/csm_nova-line_ad1f96e0c0.jpg" alt="Scorrevole S80">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Scorrevole</div>
                            <h4 class="product-name">Scorrevole S80</h4>
                            <p class="product-desc">Porta scorrevole alzante in alluminio. Vetrate fino a 3 metri.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="e6" onclick="openProductModal('e6')" onmousemove="rotate3D(event, 'e6')" onmouseleave="reset3D('e6')">
                            <span class="product-tag">Eproditalia</span>
                            <div class="product-3d-wrapper gpu" id="e6">
                                <img src="https://www.schuco.com/resource/image/1039420/landscape_ratio3x2/585/390/52e1c3edcba2cb57af97d56a4fa0baaa/80C1D5E5E8F1AC67A9B37A0E5BC8D2BA/aws-75-hi-si-green.jpg" alt="Facciata Continua">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Facciata</div>
                            <h4 class="product-name">Facciata Continua FC50</h4>
                            <p class="product-desc">Sistema facciata continua per edifici commerciali e residenziali.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="e7" onclick="openProductModal('e7')" onmousemove="rotate3D(event, 'e7')" onmouseleave="reset3D('e7')">
                            <span class="product-tag">Eproditalia</span>
                            <div class="product-3d-wrapper gpu" id="e7">
                                <img src="https://www.metrabuilding.com/media/catalog/product/cache/3/image/9df78eab33525d08d6e5fb8d27136e95/m/i/minimal_porta_2_ante_vetro.jpg" alt="Minimal Glass">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Minimal</div>
                            <h4 class="product-name">Minimal Glass</h4>
                            <p class="product-desc">Porta vetrata minimal con profilo invisibile. Design contemporaneo.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="e8" onclick="openProductModal('e8')" onmousemove="rotate3D(event, 'e8')" onmouseleave="reset3D('e8')">
                            <span class="product-tag">Eproditalia</span>
                            <div class="product-3d-wrapper gpu" id="e8">
                                <img src="https://www.metrabuilding.com/media/catalog/product/cache/3/image/9df78eab33525d08d6e5fb8d27136e95/n/c/nc-s_75_sti_he_porta_finestra_1_anta_con_traverso.jpg" alt="NC75 Premium">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Premium 75</div>
                            <h4 class="product-name">NC75 Premium</h4>
                            <p class="product-desc">Portafinestra 75mm ad alte prestazioni. Isolamento classe A.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="e9" onclick="openProductModal('e9')" onmousemove="rotate3D(event, 'e9')" onmouseleave="reset3D('e9')">
                            <span class="product-tag">Eproditalia</span>
                            <div class="product-3d-wrapper gpu" id="e9">
                                <img src="https://www.metrabuilding.com/media/catalog/product/cache/3/image/9df78eab33525d08d6e5fb8d27136e95/p/o/polaris_hi_porta_1_anta_con_traverso_e_sopraluce_fisso.jpg" alt="Polaris HI">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">High Insulation</div>
                            <h4 class="product-name">Polaris HI</h4>
                            <p class="product-desc">Sistema High Insulation per climi estremi. Uw 0.8 W/m2K.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                    <div class="product-card">
                        <div class="product-3d-box" data-product="e10" onclick="openProductModal('e10')" onmousemove="rotate3D(event, 'e10')" onmouseleave="reset3D('e10')">
                            <span class="product-tag">Eproditalia</span>
                            <div class="product-3d-wrapper gpu" id="e10">
                                <img src="https://www.metrabuilding.com/media/catalog/product/cache/3/image/9df78eab33525d08d6e5fb8d27136e95/n/c/nc-s_65_sti_scorrevole_2_ante_con_sopraluce_fisso.jpg" alt="Scorrevole NC65">
                                <div class="product-depth"></div>
                            </div>
                            <div class="dbl-hint">&#8635; Doppio click</div>
                        </div>
                        <div class="product-info">
                            <div class="product-cat">Scorrevole STI</div>
                            <h4 class="product-name">Scorrevole NC65 STI</h4>
                            <p class="product-desc">Scorrevole parallelo a taglio termico. Ampia superficie vetrata.</p>
                            <a href="#contatti" class="product-btn">Preventivo</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <section class="section section-alt" id="territorio">
        <div class="map-grid">
            <div class="map-wrap"><div id="map"></div></div>
            <div class="map-text">
                <h2>Operiamo in <span>Emilia Romagna</span></h2>
                <p>La nostra rete commerciale copre capillarmente le province di Modena, Reggio Emilia, Parma e Ferrara con visite regolari e assistenza tecnica continua.</p>
                <div class="cities-list">
                    <div class="city-item">Modena</div>
                    <div class="city-item">Reggio Emilia</div>
                    <div class="city-item">Parma</div>
                    <div class="city-item">Ferrara</div>
                </div>
            </div>
        </div>
    </section>

    <section class="section" id="chi-siamo">
        <div class="about-grid">
            <div class="about-text">
                <h2>Chi <span>Siamo</span></h2>
                <p>Spallanzani Rappresentanze e il punto di riferimento per rivenditori e professionisti del settore serramenti in Emilia Romagna.</p>
                <p>Da oltre 25 anni operiamo come agenti dei migliori marchi italiani: Flessya, Mondocasa, Eproditalia, Arieni Maniglie e Di.Bi. Porte Blindate.</p>
                <div class="stats-grid">
                    <div class="stat-card"><div class="stat-num">25+</div><div class="stat-label">Anni Esperienza</div></div>
                    <div class="stat-card"><div class="stat-num">5</div><div class="stat-label">Marchi Partner</div></div>
                    <div class="stat-card"><div class="stat-num">200+</div><div class="stat-label">Rivenditori</div></div>
                    <div class="stat-card"><div class="stat-num">4</div><div class="stat-label">Province</div></div>
                </div>
            </div>
            <div class="team-grid">
                <div class="team-card">
                    <div class="team-avatar copper">MS</div>
                    <h3 class="team-name">Massimo Spallanzani</h3>
                    <div class="team-role">Titolare</div>
                    <p class="team-bio">30+ anni di esperienza nel settore serramenti. Una rete solida con i migliori produttori italiani.</p>
                </div>
                <div class="team-card">
                    <div class="team-avatar rose">DG</div>
                    <h3 class="team-name">Daniela Golinelli</h3>
                    <div class="team-role">Commerciale</div>
                    <p class="team-bio">Responsabile commerciale con profonda conoscenza del mercato e delle esigenze dei clienti.</p>
                </div>
            </div>
        </div>
    </section>

    <section class="section section-alt" id="contatti">
        <div class="section-header">
            <h2>Contattaci</h2>
            <div class="accent-bar"></div>
            <p>Richiedi informazioni o un preventivo personalizzato</p>
        </div>
        <div class="contact-grid">
            <div class="contact-form-box">
                <form method="POST" action="/contatti">
                    <div class="form-row"><label>Nome e Cognome *</label><input type="text" name="nome" required placeholder="Il tuo nome"></div>
                    <div class="form-row"><label>Email *</label><input type="email" name="email" required placeholder="La tua email"></div>
                    <div class="form-row"><label>Telefono</label><input type="tel" name="telefono" placeholder="Il tuo numero"></div>
                    <div class="form-row"><label>Marchio</label>
                        <select name="prodotto">
                            <option value="">Seleziona un marchio</option>
                            <option value="flessya">Flessya</option>
                            <option value="mondocasa">Mondocasa</option>
                            <option value="eproditalia">Eproditalia</option>
                            <option value="arieni">Arieni Maniglie</option>
                            <option value="dibi">Di.Bi. Porte Blindate</option>
                        </select>
                    </div>
                    <div class="form-row"><label>Messaggio *</label><textarea name="messaggio" required placeholder="Descrivi la tua richiesta..."></textarea></div>
                    <button type="submit" class="form-submit">Invia Richiesta</button>
                </form>
            </div>
            <div class="contact-info">
                <h3>Informazioni</h3>
                <div class="info-card"><div class="info-icon"><i class="fas fa-phone"></i></div><div class="info-content"><h4>Telefono</h4><p>+39 335 692 8280</p></div></div>
                <div class="info-card"><div class="info-icon"><i class="fas fa-envelope"></i></div><div class="info-content"><h4>Email Ordini</h4><p>spallamm@gmail.com</p></div></div>
                <div class="info-card"><div class="info-icon"><i class="fas fa-briefcase"></i></div><div class="info-content"><h4>Commerciale</h4><p>commercialegolinellidaniela@gmail.com</p></div></div>
                <div class="info-card"><div class="info-icon"><i class="fas fa-map-marker-alt"></i></div><div class="info-content"><h4>Zone</h4><p>Modena, Reggio Emilia, Parma, Ferrara</p></div></div>
            </div>
        </div>
    </section>

    <!-- Product Detail Modal -->
    <div class="product-modal" id="productModal">
        <button class="modal-close" onclick="closeModal()">&times;</button>
        <div class="modal-content">
            <div class="modal-3d-area">
                <div class="modal-3d-wrapper" id="modal3dWrapper">
                    <div class="modal-3d-product" id="modal3dProduct">
                        <img id="modalProductImg" src="" alt="Prodotto">
                    </div>
                </div>
                <div class="modal-rotate-hint">&#8635; Trascina per ruotare in 3D</div>
            </div>
            <div class="modal-info-area">
                <span class="modal-brand-tag" id="modalBrand"></span>
                <h2 class="modal-title" id="modalTitle"></h2>
                <div class="modal-ai-box">
                    <div class="modal-ai-header">
                        <div class="modal-ai-avatar"><i class="fas fa-robot"></i></div>
                        <div>
                            <span class="modal-ai-name">Spallanzani Smart AI</span>
                            <div class="modal-ai-status">Analisi in corso...</div>
                        </div>
                    </div>
                    <p class="modal-ai-text" id="modalAiText"></p>
                </div>
                <div class="modal-specs" id="modalSpecs"></div>
                <div class="modal-cta">
                    <a href="#contatti" class="primary" onclick="closeModal()">Richiedi Preventivo</a>
                    <a href="tel:+393356928280" class="secondary">Chiama Ora</a>
                </div>
            </div>
        </div>
    </div>

    <footer>
        <div class="footer-grid">
            <div class="footer-brand">
                <div class="logo"><div class="logo-icon">SR</div><div class="logo-text"><h1 style="color:var(--accent)">SPALLANZANI RAPPRESENTANZE</h1></div></div>
                <p>Rappresentanze infissi e serramenti in Emilia Romagna. Partner ufficiale dei migliori brand italiani.</p>
            </div>
            <div><h4>Marchi</h4><div class="footer-links"><a href="#marchi">Flessya</a><a href="#marchi">Mondocasa</a><a href="#marchi">Eproditalia</a><a href="#marchi">Arieni</a><a href="#marchi">Di.Bi.</a></div></div>
            <div><h4>Link</h4><div class="footer-links"><a href="#chi-siamo">Chi Siamo</a><a href="#prodotti">Prodotti</a><a href="#territorio">Territorio</a><a href="#contatti">Contatti</a><a href="/registrati">Registrati</a></div></div>
            <div><h4>Contatti</h4><div class="footer-links"><a href="tel:+393356928280"><i class="fas fa-phone"></i> +39 335 692 8280</a><a href="mailto:spallamm@gmail.com"><i class="fas fa-envelope"></i> spallamm@gmail.com</a></div></div>
        </div>
        <div class="footer-bottom">
            <p>&copy; 2024 Spallanzani Rappresentanze</p>
            <p style="margin-top:10px;font-size:0.85rem;">Web Design by <a href="#" style="color:var(--accent);font-weight:600;">Fabio Spallanzani</a></p>
        </div>
    </footer>

    <!-- Smart AI -->
    <div class="smart-ai">
        <div class="smart-chat" id="smartChat">
            <div class="smart-header">
                <div class="smart-avatar"><i class="fas fa-robot"></i></div>
                <div class="smart-info"><h4>Spallanzani Smart AI</h4><span>Assistente Intelligente</span></div>
                <button class="smart-close" onclick="toggleSmart()"><i class="fas fa-times"></i></button>
            </div>
            <div class="smart-messages" id="smartMessages">
                <div class="smart-msg bot">
                    Ciao! Sono <strong>Spallanzani Smart AI</strong>. Come posso aiutarti?
                    <div class="quick-btns">
                        <button class="quick-btn" onclick="quickMsg('Flessya')">Flessya</button>
                        <button class="quick-btn" onclick="quickMsg('Di.Bi.')">Di.Bi.</button>
                        <button class="quick-btn" onclick="quickMsg('Mondocasa')">Mondocasa</button>
                        <button class="quick-btn" onclick="quickMsg('Eproditalia')">Eproditalia</button>
                        <button class="quick-btn" onclick="quickMsg('Arieni')">Arieni</button>
                        <button class="quick-btn" onclick="quickMsg('Preventivo')">Preventivo</button>
                    </div>
                </div>
            </div>
            <div class="smart-input-wrap">
                <input type="text" class="smart-input" id="smartInput" placeholder="Scrivi..." onkeypress="if(event.key==='Enter')sendSmart()">
                <button class="smart-send" onclick="sendSmart()">&#10148;</button>
            </div>
        </div>
        <button class="smart-toggle" onclick="toggleSmart()"><i class="fas fa-robot"></i></button>
    </div>

    <script>
    // ============================================
    // SPALLANZANI - JAVASCRIPT COMPLETO E PULITO
    // ============================================

    // Dati prodotti
    var productData = {
        f1: { brand: 'Flessya', name: 'Kikka K00', img: 'https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-KIKKA_immagine_K00_001-scaled.jpg', ai: "La Kikka K00 e il fiore all'occhiello della linea Flessya. Design pulito e contemporaneo, superficie liscia per ambienti moderni. Eccellente isolamento acustico e durabilita superiore. Disponibile in oltre 50 finiture.", specs: [['Tipo', 'Porta Interna'], ['Linea', 'Kikka'], ['Finiture', '50+'], ['Garanzia', '10 anni']] },
        f2: { brand: 'Flessya', name: 'Vetra 03', img: 'https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-Vetra03_HD300-scaled.jpg', ai: "La Vetra 03 combina eleganza e funzionalita con vetrata centrale per massima luminosita. Vetro temperato di sicurezza e telaio in legno massello.", specs: [['Tipo', 'Porta Vetrata'], ['Vetro', 'Temperato 4mm'], ['Telaio', 'Legno Massello'], ['Garanzia', '10 anni']] },
        f3: { brand: 'Flessya', name: 'Nidio N50E', img: 'https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-N50E_HD300_OK-scaled.jpg', ai: "La Nidio N50E e il nostro best-seller: porta tamburata con finitura effetto legno naturale. Anima a nido d'ape per leggerezza e resistenza.", specs: [['Tipo', 'Tamburata'], ['Finitura', 'Effetto Legno'], ['Peso', 'Leggera'], ['Garanzia', '5 anni']] },
        f4: { brand: 'Flessya', name: 'Rasomuro 01', img: 'https://www.flessya.com/site/wp-content/uploads/2022/07/Rasomuro_01_HD300_i16-scaled.jpg', ai: "La Rasomuro 01 e l'evoluzione del design minimalista. Porta filo muro con cerniere a scomparsa e telaio invisibile.", specs: [['Tipo', 'Filo Muro'], ['Telaio', 'Invisibile'], ['Cerniere', 'A Scomparsa'], ['Garanzia', '10 anni']] },
        d1: { brand: 'Di.Bi.', name: 'Argo Plus', img: 'https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_argoplus_est_noce_nazionale_sx_amb_11.jpg', ai: "L'Argo Plus e una porta blindata certificata Classe 3. Finitura noce nazionale, serratura a 3 punti, cilindro europeo anti-bumping.", specs: [['Classe', '3 (EN 1627)'], ['Serratura', '3 punti'], ['Finitura', 'Noce Nazionale'], ['Garanzia', '5 anni']] },
        d2: { brand: 'Di.Bi.', name: '883 Premium', img: 'https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_883_est_all_ia_ral_6005_sx_amb_2.jpg', ai: "La 883 Premium offre massima sicurezza con certificazione Classe 4. Struttura in acciaio rinforzato, serratura a 5 punti.", specs: [['Classe', '4 (EN 1627)'], ['Serratura', '5 punti'], ['Struttura', 'Acciaio Rinforzato'], ['Garanzia', '10 anni']] },
        d3: { brand: 'Di.Bi.', name: 'Blindata Vetrata', img: 'https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_vetrata_est_ii_white_sx_amb_4.jpg', ai: "La Blindata Vetrata unisce sicurezza e luce naturale con vetro blindato antisfondamento. Classe 3 certificata.", specs: [['Classe', '3 (EN 1627)'], ['Vetro', 'Blindato'], ['Stile', 'Moderno'], ['Garanzia', '5 anni']] },
        d4: { brand: 'Di.Bi.', name: 'Argo Bianca', img: 'https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/a/r/argo_bianca_pianerottolo_2_1_3.jpg', ai: "L'Argo Bianca porta eleganza minimalista al tuo ingresso. Finitura bianca opaca, certificazione Classe 3.", specs: [['Classe', '3 (EN 1627)'], ['Finitura', 'Bianco Opaco'], ['Stile', 'Minimal'], ['Garanzia', '5 anni']] },
        a1: { brand: 'Arieni', name: 'Laser OBM', img: 'https://www.arienisrl.com/wp-content/uploads/Laser-obm.png', ai: "La Laser OBM rappresenta il design minimalista nella maniglieria. Ottone brunito opaco, presa ergonomica.", specs: [['Materiale', 'Ottone'], ['Finitura', 'Brunito Opaco'], ['Stile', 'Minimalista'], ['Garanzia', '2 anni']] },
        a2: { brand: 'Arieni', name: 'Vera CRS', img: 'https://www.arienisrl.com/wp-content/uploads/2020/09/Vera-1200x600-1-1-1.png', ai: "La Vera CRS sfoggia linee squadrate moderne con finitura cromata satinata. Design contemporaneo e funzionale.", specs: [['Materiale', 'Ottone'], ['Finitura', 'Cromo Satinato'], ['Design', 'Squadrato'], ['Garanzia', '2 anni']] },
        a3: { brand: 'Arieni', name: 'Dea PVD', img: 'https://www.arienisrl.com/wp-content/uploads/2020/06/Dea-1200x600-1.png', ai: "La Dea PVD in alluminio massiccio con rivestimento PVD antigraffio. Durabilita eccezionale.", specs: [['Materiale', 'Alluminio'], ['Trattamento', 'PVD Antigraffio'], ['Durabilita', 'Eccezionale'], ['Garanzia', '5 anni']] },
        a4: { brand: 'Arieni', name: 'Area 51 Nera', img: 'https://www.arienisrl.com/wp-content/uploads/2020/09/Area51-1200x600-nera.png', ai: "L'Area 51 Nera incarna la tendenza total black. Nero opaco per design audace e di tendenza.", specs: [['Materiale', 'Ottone'], ['Finitura', 'Nero Opaco'], ['Stile', 'Total Black'], ['Garanzia', '2 anni']] },
        // Nuovi prodotti Flessya
        f5: { brand: 'Flessya', name: 'Vetra 05', img: 'https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-Vetra05_HD300-scaled.jpg', ai: "La Vetra 05 offre vetrata full-height per massima luminosita. Design contemporaneo che amplifica gli spazi.", specs: [['Tipo', 'Vetrata Full-Height'], ['Vetro', 'Temperato'], ['Stile', 'Contemporaneo'], ['Garanzia', '10 anni']] },
        f6: { brand: 'Flessya', name: 'S-nziale Mono', img: 'https://www.flessya.com/site/wp-content/uploads/2022/07/S-nziale_Mono_Inglesina.jpg', ai: "La S-nziale Mono e una porta tutto vetro con telaio in alluminio. Stile inglese raffinato per ambienti eleganti.", specs: [['Tipo', 'Tutto Vetro'], ['Telaio', 'Alluminio'], ['Stile', 'Inglese'], ['Garanzia', '10 anni']] },
        f7: { brand: 'Flessya', name: 'S-nziale Duo', img: 'https://www.flessya.com/site/wp-content/uploads/2022/07/S-nziale_Duo_SD00-scaled.jpg', ai: "La S-nziale Duo e una doppia anta vetrata per aperture ampie e scenografiche. Ideale per soggiorni e sale.", specs: [['Tipo', 'Doppia Anta'], ['Vetro', 'Acidato'], ['Apertura', 'Ampia'], ['Garanzia', '10 anni']] },
        f8: { brand: 'Flessya', name: 'Nidio NL15', img: 'https://www.flessya.com/site/wp-content/uploads/2022/06/Flessya-NL15_HD300_OK-scaled.jpg', ai: "La Nidio NL15 presenta pantografature geometriche eleganti. Design distintivo su base tamburata leggera.", specs: [['Tipo', 'Tamburata'], ['Decorazione', 'Pantografata'], ['Design', 'Geometrico'], ['Garanzia', '5 anni']] },
        f9: { brand: 'Flessya', name: 'Plenia P31', img: 'https://www.flessya.com/site/wp-content/uploads/2022/07/Flessya-P31_P50_HD300-scaled.jpg', ai: "La Plenia P31 in legno massello impiallacciato esalta le venature naturali. Calore e autenticita per ogni ambiente.", specs: [['Tipo', 'Massello Impiallacciato'], ['Legno', 'Naturale'], ['Venature', 'A Vista'], ['Garanzia', '10 anni']] },
        f10: { brand: 'Flessya', name: 'Rasomuro 05', img: 'https://www.flessya.com/site/wp-content/uploads/2022/07/Rasomuro_05_N00_HD300-scaled.jpg', ai: "La Rasomuro 05 offre perfetta integrazione architettonica con inserti decorativi. Filo muro di ultima generazione.", specs: [['Tipo', 'Filo Muro'], ['Telaio', 'Invisibile'], ['Decorazione', 'Inserti'], ['Garanzia', '10 anni']] },
        // Nuovi prodotti Di.Bi.
        d5: { brand: 'Di.Bi.', name: 'Poker2 White', img: 'https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_poker2_est_sd_white_sx_amb_54.jpg', ai: "La Poker2 White presenta design contemporaneo bianco con pannello decorativo. Sicurezza Classe 3.", specs: [['Classe', '3 (EN 1627)'], ['Finitura', 'Bianco'], ['Pannello', 'Decorativo'], ['Garanzia', '5 anni']] },
        d6: { brand: 'Di.Bi.', name: 'Argo Plus Golden', img: 'https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_argoplus_est_tx_golden_oak_sx_amb_10.jpg', ai: "L'Argo Plus Golden Oak offre finitura calda ed elegante. Perfetta per ingressi prestigiosi.", specs: [['Classe', '3 (EN 1627)'], ['Finitura', 'Golden Oak'], ['Stile', 'Elegante'], ['Garanzia', '5 anni']] },
        d7: { brand: 'Di.Bi.', name: '884 Tanganika', img: 'https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_884_est_tanganika_05_sx_amb_8.jpg', ai: "La 884 Tanganika garantisce alta sicurezza Classe 4 con finitura legno tanganika pregiato.", specs: [['Classe', '4 (EN 1627)'], ['Finitura', 'Tanganika'], ['Serratura', '5 punti'], ['Garanzia', '10 anni']] },
        d8: { brand: 'Di.Bi.', name: '883 2A Golden', img: 'https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_883_2a_est_pz_golden_oak_sx_amb_12.jpg', ai: "La 883 2A Golden e una doppia anta blindata per ingressi ampi e signorili. Massima sicurezza.", specs: [['Classe', '4 (EN 1627)'], ['Tipo', 'Doppia Anta'], ['Finitura', 'Golden Oak'], ['Garanzia', '10 anni']] },
        d9: { brand: 'Di.Bi.', name: 'Argo Mogano', img: 'https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_argo_est_mogano_sx_amb_27.jpg', ai: "L'Argo Mogano porta classica eleganza nelle abitazioni di prestigio. Finitura mogano intramontabile.", specs: [['Classe', '3 (EN 1627)'], ['Finitura', 'Mogano'], ['Stile', 'Classico'], ['Garanzia', '5 anni']] },
        d10: { brand: 'Di.Bi.', name: 'Poker2 RAL 9010', img: 'https://shop.dibigroup.com/media/catalog/product/cache/bf8198ce51d8b2fc6b76a84de965e03c/p/o/porta_blindata_poker2_est_all_pz_bianco_9010_sx_amb_28.jpg', ai: "La Poker2 RAL 9010 in bianco opaco perfetta per ambienti minimal e luminosi. Design pulito.", specs: [['Classe', '3 (EN 1627)'], ['Finitura', 'RAL 9010'], ['Stile', 'Minimal'], ['Garanzia', '5 anni']] },
        // Nuove maniglie Arieni
        a5: { brand: 'Arieni', name: 'Piego CRS', img: 'https://www.arienisrl.com/wp-content/uploads/2020/09/Piego-1200.png', ai: "La Piego CRS presenta linee arrotondate morbide con finitura cromata satinata. Comfort ed eleganza.", specs: [['Materiale', 'Ottone'], ['Finitura', 'Cromo Satinato'], ['Design', 'Arrotondato'], ['Garanzia', '2 anni']] },
        a6: { brand: 'Arieni', name: 'Ares OCR', img: 'https://www.arienisrl.com/wp-content/uploads/Ares-ocr.png', ai: "L'Ares OCR sfoggia design geometrico minimalista con ottone cromato raffinato. Linea Laser premium.", specs: [['Materiale', 'Ottone'], ['Finitura', 'Cromo'], ['Linea', 'Laser'], ['Garanzia', '2 anni']] },
        // Mondocasa Serramenti PVC
        m1: { brand: 'Mondocasa', name: 'Evolution 70', img: 'https://www.oknoplast.it/media/prolux-evolution_3RiRmAh.jpg', ai: "L'Evolution 70 e una finestra in PVC a 5 camere con profilo da 70mm. Triplo vetro per massimo isolamento termico Uw 0.9 W/m2K.", specs: [['Profilo', '70mm 5 camere'], ['Vetro', 'Triplo basso emissivo'], ['Isolamento', 'Uw 0.9 W/m2K'], ['Garanzia', '10 anni']] },
        m2: { brand: 'Mondocasa', name: 'Platinium Plus', img: 'https://www.oknoplast.it/media/platinium-plus_TITEs3q.jpg', ai: "Il Platinium Plus rappresenta il top della gamma con profilo 85mm a 6 camere. Isolamento termoacustico superiore per case ad alta efficienza.", specs: [['Profilo', '85mm 6 camere'], ['Vetro', 'Triplo 48mm'], ['Isolamento', 'Uw 0.7 W/m2K'], ['Garanzia', '15 anni']] },
        m3: { brand: 'Mondocasa', name: 'Squareline', img: 'https://www.oknoplast.it/media/squareline_F4H1tAJ.jpg', ai: "Lo Squareline presenta profili squadrati dal design minimalista. Perfetto per architetture moderne e contemporanee.", specs: [['Design', 'Minimal squadrato'], ['Profilo', '70mm'], ['Colori', 'RAL personalizzabili'], ['Garanzia', '10 anni']] },
        m4: { brand: 'Mondocasa', name: 'Prismatic', img: 'https://www.oknoplast.it/media/prismatic_iXGjyFa.jpg', ai: "Il sistema Prismatic e una scorrevole alzante per grandi vetrate panoramiche fino a 6 metri. Massima luminosita e vista senza ostacoli.", specs: [['Tipo', 'Scorrevole alzante'], ['Larghezza max', '6 metri'], ['Vetro', 'Fino a 52mm'], ['Garanzia', '10 anni']] },
        m5: { brand: 'Mondocasa', name: 'Winergetic Premium', img: 'https://www.oknoplast.it/media/winergetic-premium.jpg', ai: "Winergetic Premium e certificato casa passiva. Con Uw 0.6 W/m2K garantisce il massimo risparmio energetico per edifici NZEB.", specs: [['Certificazione', 'Casa Passiva'], ['Isolamento', 'Uw 0.6 W/m2K'], ['Profilo', '90mm 7 camere'], ['Garanzia', '15 anni']] },
        m6: { brand: 'Mondocasa', name: 'Finestra Bilico', img: 'https://www.oknoplast.it/media/bilico_Y0R5Trp.jpg', ai: "La finestra a bilico orizzontale e ideale per mansarde e sottotetti. Apertura fino a 180 gradi per facile pulizia e manutenzione.", specs: [['Tipo', 'Bilico orizzontale'], ['Apertura', 'Fino a 180 gradi'], ['Ideale per', 'Mansarde'], ['Garanzia', '10 anni']] },
        // Eproditalia Infissi Alluminio
        e1: { brand: 'Eproditalia', name: 'TT65 Next', img: 'https://images.ctfassets.net/hd6763cyzwa4/3j4SWNX23pT0g9xXjKJeF3/6f28f41ad2c867b8b6353d1a2fc21eff/Maison_Sentinelle_-_Droits_jusqu-en_février_2032_-_Photographe_et_architecte_Aurélien_Chen__2_.jpg', ai: "Il TT65 Next e un sistema a taglio termico con profilo da 65mm. Design minimal con linee sottili per massima superficie vetrata.", specs: [['Materiale', 'Alluminio TT'], ['Profilo', '65mm'], ['Uw', '1.2 W/m2K'], ['Garanzia', '10 anni']] },
        e2: { brand: 'Eproditalia', name: 'TT85 Wood', img: 'https://images.ctfassets.net/hd6763cyzwa4/1CITmzFHp05yaHYd0cAunG/2c79362f407ecd2086a6a1d0246f8e3c/Alpina-wood85_1-copia---modificata-ridotto.jpg', ai: "Il TT85 Wood combina la resistenza dell alluminio con l estetica del legno grazie a rivestimenti sublimatici. Manutenzione zero.", specs: [['Materiale', 'Alluminio + Wood'], ['Profilo', '85mm'], ['Finitura', 'Effetto legno'], ['Garanzia', '15 anni']] },
        e3: { brand: 'Eproditalia', name: 'TB65 Top', img: 'https://images.ctfassets.net/hd6763cyzwa4/7BF16hQR10jid6b28Lyipz/87c43f925e71483a6d4b323e082b34fb/Still_Alluminio_TOP_TB_65.jpg', ai: "Il TB65 Top e il sistema top performance con isolamento termico superiore. Ideale per edifici ad alta efficienza energetica.", specs: [['Prestazioni', 'Top'], ['Profilo', '65mm'], ['Uw', '1.0 W/m2K'], ['Garanzia', '10 anni']] },
        e4: { brand: 'Eproditalia', name: 'NC65 STI', img: 'https://www.metrabuilding.com/media/catalog/product/cache/3/image/9df78eab33525d08d6e5fb8d27136e95/n/c/nc-s_65_sti_he_finestra_2_ante_con_traverso_e_sopraluce_a_vasistas.jpg', ai: "Il NC65 STI e il sistema standard a taglio termico. Ottimo rapporto qualita-prezzo per interventi residenziali e commerciali.", specs: [['Tipo', 'Standard'], ['Profilo', '65mm'], ['Uw', '1.4 W/m2K'], ['Garanzia', '10 anni']] },
        e5: { brand: 'Eproditalia', name: 'Scorrevole S80', img: 'https://www.finstral.com/fileadmin/_processed_/b/0/csm_nova-line_ad1f96e0c0.jpg', ai: "Lo Scorrevole S80 e una porta scorrevole alzante in alluminio per grandi vetrate fino a 3 metri. Scorrimento fluido su binari inox.", specs: [['Tipo', 'Scorrevole alzante'], ['Larghezza max', '3 metri'], ['Binari', 'Inox'], ['Garanzia', '10 anni']] },
        e6: { brand: 'Eproditalia', name: 'Facciata Continua FC50', img: 'https://www.schuco.com/resource/image/1039420/landscape_ratio3x2/585/390/52e1c3edcba2cb57af97d56a4fa0baaa/80C1D5E5E8F1AC67A9B37A0E5BC8D2BA/aws-75-hi-si-green.jpg', ai: "Il sistema Facciata Continua FC50 e ideale per facciate di edifici commerciali e residenziali. Montanti e traversi per vetrate strutturali.", specs: [['Tipo', 'Facciata continua'], ['Sistema', 'Montanti/Traversi'], ['Applicazione', 'Commerciale'], ['Garanzia', '15 anni']] },
        // Nuovi prodotti Arieni (a7-a10)
        a7: { brand: 'Arieni', name: 'Quasar CRS', img: 'https://www.arienisrl.com/wp-content/uploads/Quasar-crs.png', ai: "Il Quasar CRS e una maniglia dal design futuristico con finitura cromo satinato brillante. Linee fluide per ambienti contemporanei.", specs: [['Materiale', 'Ottone'], ['Finitura', 'Cromo Satinato'], ['Design', 'Futuristico'], ['Garanzia', '2 anni']] },
        a8: { brand: 'Arieni', name: 'Duna OLV', img: 'https://www.arienisrl.com/wp-content/uploads/Duna-olv.png', ai: "La Duna OLV presenta linee ondulate eleganti con finitura ottone lucido vintage. Ispirazione naturale per design organici.", specs: [['Materiale', 'Ottone'], ['Finitura', 'Ottone Lucido'], ['Design', 'Organico'], ['Garanzia', '2 anni']] },
        a9: { brand: 'Arieni', name: 'Venus OCR', img: 'https://www.arienisrl.com/wp-content/uploads/Venus-ocr.png', ai: "La Venus OCR incarna l eleganza classica rivisitata in chiave moderna. Ottone cromato lucido per ambienti raffinati.", specs: [['Materiale', 'Ottone'], ['Finitura', 'Cromo Lucido'], ['Design', 'Classico Moderno'], ['Garanzia', '2 anni']] },
        a10: { brand: 'Arieni', name: 'Chic OBM', img: 'https://www.arienisrl.com/wp-content/uploads/2020/06/Chic-1200x600-1-1-1.png', ai: "La Chic OBM e una maniglia della linea Atelier in ottone brunito. Stile raffinato per interni di prestigio.", specs: [['Materiale', 'Ottone'], ['Finitura', 'Brunito'], ['Linea', 'Atelier'], ['Garanzia', '2 anni']] },
        // Nuovi prodotti Mondocasa (m7-m10)
        m7: { brand: 'Mondocasa', name: 'Prolux Swing', img: 'https://www.oknoplast.it/media/prolux-swing_CcqILC9.jpg', ai: "Il Prolux Swing offre apertura a vasistas con cerniere nascoste per un design pulito e moderno. Ideale per ventilazione controllata.", specs: [['Tipo', 'Vasistas'], ['Cerniere', 'Nascoste'], ['Design', 'Pulito'], ['Garanzia', '10 anni']] },
        m8: { brand: 'Mondocasa', name: 'Prismatic Evolution', img: 'https://www.oknoplast.it/media/prismatic-evolution.jpg', ai: "Il Prismatic Evolution e la versione evoluta della scorrevole con profilo ultra-sottile. Massima luminosita e minimo ingombro.", specs: [['Tipo', 'Scorrevole'], ['Profilo', 'Ultra-sottile'], ['Luminosita', 'Massima'], ['Garanzia', '10 anni']] },
        m9: { brand: 'Mondocasa', name: 'Passive House Plus', img: 'https://www.oknoplast.it/media/winergetic-premium-passive.jpg', ai: "Il Passive House Plus ha certificazione PHI (Passive House Institute). Il top assoluto per edifici a energia quasi zero NZEB.", specs: [['Certificazione', 'PHI'], ['Standard', 'Casa Passiva'], ['Uw', '0.5 W/m2K'], ['Garanzia', '15 anni']] },
        m10: { brand: 'Mondocasa', name: 'Prolux Plus', img: 'https://www.oknoplast.it/media/prolux-plus-hero-04.jpg', ai: "Il Prolux Plus e l evoluzione della serie Prolux con ferramenta premium e vetro selettivo. Performance superiori.", specs: [['Serie', 'Prolux'], ['Ferramenta', 'Premium'], ['Vetro', 'Selettivo'], ['Garanzia', '10 anni']] },
        // Nuovi prodotti Eproditalia (e7-e10)
        e7: { brand: 'Eproditalia', name: 'Minimal Glass', img: 'https://www.metrabuilding.com/media/catalog/product/cache/3/image/9df78eab33525d08d6e5fb8d27136e95/m/i/minimal_porta_2_ante_vetro.jpg', ai: "Il Minimal Glass e una porta vetrata con profilo quasi invisibile. Design contemporaneo per spazi luminosi.", specs: [['Tipo', 'Porta Vetrata'], ['Profilo', 'Invisibile'], ['Design', 'Minimal'], ['Garanzia', '10 anni']] },
        e8: { brand: 'Eproditalia', name: 'NC75 Premium', img: 'https://www.metrabuilding.com/media/catalog/product/cache/3/image/9df78eab33525d08d6e5fb8d27136e95/n/c/nc-s_75_sti_he_porta_finestra_1_anta_con_traverso.jpg', ai: "Il NC75 Premium e una portafinestra 75mm ad alte prestazioni. Isolamento classe A per massimo comfort.", specs: [['Profilo', '75mm'], ['Classe', 'A'], ['Prestazioni', 'Alte'], ['Garanzia', '10 anni']] },
        e9: { brand: 'Eproditalia', name: 'Polaris HI', img: 'https://www.metrabuilding.com/media/catalog/product/cache/3/image/9df78eab33525d08d6e5fb8d27136e95/p/o/polaris_hi_porta_1_anta_con_traverso_e_sopraluce_fisso.jpg', ai: "Il Polaris HI e il sistema High Insulation per climi estremi. Uw 0.8 W/m2K per massimo risparmio energetico.", specs: [['Sistema', 'High Insulation'], ['Uw', '0.8 W/m2K'], ['Clima', 'Estremo'], ['Garanzia', '15 anni']] },
        e10: { brand: 'Eproditalia', name: 'Scorrevole NC65 STI', img: 'https://www.metrabuilding.com/media/catalog/product/cache/3/image/9df78eab33525d08d6e5fb8d27136e95/n/c/nc-s_65_sti_scorrevole_2_ante_con_sopraluce_fisso.jpg', ai: "Lo Scorrevole NC65 STI e un sistema scorrevole parallelo a taglio termico. Ampia superficie vetrata e facilita d uso.", specs: [['Tipo', 'Scorrevole parallelo'], ['Sistema', 'STI'], ['Vetrata', 'Ampia'], ['Garanzia', '10 anni']] }
    };

    // ===== FUNZIONI GLOBALI (chiamate da onclick) =====

    // Toggle Chat AI
    function toggleSmart() {
        var chat = document.getElementById('smartChat');
        if (chat) {
            chat.classList.toggle('active');
        }
    }

    // Invia messaggio chat con AI Gemini
    function sendSmart() {
        var inp = document.getElementById('smartInput');
        if (!inp) return;
        var msg = inp.value.trim();
        if (!msg) return;
        addMsg(msg, 'user');
        inp.value = '';
        showTyping();

        // Chiama API Gemini
        fetch('/api/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: msg})
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            removeTyping();
            addMsg(data.response || getResponse(msg), 'bot');
        })
        .catch(function() {
            removeTyping();
            addMsg(getResponse(msg), 'bot');
        });
    }

    // Quick message con AI
    function quickMsg(m) {
        addMsg(m, 'user');
        showTyping();

        fetch('/api/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: m})
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            removeTyping();
            addMsg(data.response || getResponse(m), 'bot');
        })
        .catch(function() {
            removeTyping();
            addMsg(getResponse(m), 'bot');
        });
    }

    // Aggiungi messaggio
    function addMsg(t, type) {
        var c = document.getElementById('smartMessages');
        if (!c) return;
        var d = document.createElement('div');
        d.className = 'smart-msg ' + type;
        d.innerHTML = t;
        c.appendChild(d);
        c.scrollTop = c.scrollHeight;
    }

    // Mostra typing
    function showTyping() {
        var c = document.getElementById('smartMessages');
        if (!c) return;
        var d = document.createElement('div');
        d.className = 'smart-msg bot typing';
        d.id = 'typing';
        d.innerHTML = '<span></span><span></span><span></span>';
        c.appendChild(d);
        c.scrollTop = c.scrollHeight;
    }

    // Rimuovi typing
    function removeTyping() {
        var e = document.getElementById('typing');
        if (e) e.remove();
    }

    // Risposte AI
    function getResponse(m) {
        var q = m.toLowerCase();
        if (/ciao|salve|buon/i.test(q)) return "Buongiorno! Sono qui per aiutarti. Cosa ti interessa?";
        if (/catalogo|prodott/i.test(q)) return "<strong>I nostri prodotti:</strong><br>• Flessya - Porte interni<br>• Di.Bi. - Porte blindate<br>• Arieni - Maniglie design";
        if (/preventivo|prezzo|costo/i.test(q)) return "<strong>Per un preventivo:</strong><br>Chiama: 335 692 8280<br>Email: spallamm@gmail.com";
        if (/contatt/i.test(q)) return "<strong>Contatti:</strong><br>Tel: +39 335 692 8280<br>Email: spallamm@gmail.com";
        return "Posso aiutarti con: Prodotti, Preventivi, Contatti. Cosa ti interessa?";
    }

    // 3D Rotation per prodotti
    function rotate3D(event, productId) {
        var wrapper = document.getElementById(productId);
        if (!wrapper) return;
        var box = wrapper.parentElement;
        if (!box) return;
        var rect = box.getBoundingClientRect();
        var x = (event.clientX - rect.left) / rect.width - 0.5;
        var y = (event.clientY - rect.top) / rect.height - 0.5;
        wrapper.style.transform = 'rotateY(' + (x * 45) + 'deg) rotateX(' + (-y * 35) + 'deg) scale(1.1)';
    }

    // Reset 3D
    function reset3D(productId) {
        var wrapper = document.getElementById(productId);
        if (!wrapper) return;
        wrapper.style.transform = 'rotateY(0deg) rotateX(0deg) scale(1)';
    }

    // Apri modal prodotto
    function openProductModal(productId) {
        var data = productData[productId];
        if (!data) {
            alert('Prodotto: ' + productId);
            return;
        }

        var img = document.getElementById('modalProductImg');
        var brand = document.getElementById('modalBrand');
        var title = document.getElementById('modalTitle');
        var aiText = document.getElementById('modalAiText');
        var specs = document.getElementById('modalSpecs');
        var modal = document.getElementById('productModal');

        if (img) img.src = data.img;
        if (brand) brand.textContent = data.brand;
        if (title) title.textContent = data.name;

        // AI Typing Effect
        if (aiText) {
            aiText.innerHTML = '';
            var i = 0;
            var typeIt = setInterval(function() {
                if (i < data.ai.length) {
                    aiText.innerHTML += data.ai.charAt(i);
                    i++;
                } else {
                    clearInterval(typeIt);
                }
            }, 15);
        }

        // Specs
        if (specs && data.specs) {
            var html = '<h4>Specifiche Tecniche</h4>';
            for (var j = 0; j < data.specs.length; j++) {
                html += '<div class="spec-row"><span>' + data.specs[j][0] + '</span><span>' + data.specs[j][1] + '</span></div>';
            }
            specs.innerHTML = html;
        }

        if (modal) {
            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
        }
    }

    // Chiudi modal
    function closeModal() {
        var modal = document.getElementById('productModal');
        if (modal) {
            modal.classList.remove('active');
            document.body.style.overflow = 'auto';
        }
    }

    // Filtro prodotti per brand
    function filterProducts(brand) {
        // Update active button
        var btns = document.querySelectorAll('.filter-btn');
        btns.forEach(function(btn) { btn.classList.remove('active'); });
        event.target.classList.add('active');

        // Get all brand sections
        var sections = document.querySelectorAll('.brand-section');

        sections.forEach(function(section) {
            var title = section.querySelector('.brand-section-title');
            if (!title) return;
            var sectionBrand = title.textContent.toLowerCase();

            if (brand === 'all') {
                section.style.display = 'block';
                section.style.opacity = '1';
                section.style.transform = 'translateY(0)';
            } else {
                var matches = false;
                if (brand === 'flessya' && sectionBrand.includes('flessya')) matches = true;
                if (brand === 'dibi' && sectionBrand.includes('di.bi')) matches = true;
                if (brand === 'arieni' && sectionBrand.includes('arieni')) matches = true;
                if (brand === 'mondocasa' && sectionBrand.includes('mondocasa')) matches = true;
                if (brand === 'eproditalia' && sectionBrand.includes('eproditalia')) matches = true;

                if (matches) {
                    section.style.display = 'block';
                    setTimeout(function() {
                        section.style.opacity = '1';
                        section.style.transform = 'translateY(0)';
                    }, 50);
                } else {
                    section.style.opacity = '0';
                    section.style.transform = 'translateY(20px)';
                    setTimeout(function() {
                        section.style.display = 'none';
                    }, 300);
                }
            }
        });

        // Scroll to products section
        if (brand !== 'all') {
            document.getElementById('prodotti').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    // ===== INIT QUANDO DOM PRONTO =====
    document.addEventListener('DOMContentLoaded', function() {

        // Hero Door 3D
        var heroDoor = document.querySelector('.door-showcase-3d');
        var heroContainer = document.querySelector('.showcase-3d');
        if (heroDoor && heroContainer) {
            heroContainer.onmousemove = function(e) {
                var rect = heroContainer.getBoundingClientRect();
                var x = (e.clientX - rect.left) / rect.width - 0.5;
                var y = (e.clientY - rect.top) / rect.height - 0.5;
                heroDoor.style.transform = 'rotateY(' + (x * 35) + 'deg) rotateX(' + (-y * 25) + 'deg)';
            };
            heroContainer.onmouseleave = function() {
                heroDoor.style.transform = 'rotateY(0deg) rotateX(0deg)';
            };
        }

        // Mappa Leaflet
        try {
            if (typeof L !== 'undefined') {
                var mapEl = document.getElementById('map');
                if (mapEl) {
                    var map = L.map('map', { zoomControl: false }).setView([44.65, 10.92], 9);
                    L.control.zoom({ position: 'bottomright' }).addTo(map);
                    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                        attribution: '', maxZoom: 19
                    }).addTo(map);
                    var cities = [
                        { name: 'Modena', coords: [44.6471, 10.9252], label: 'SEDE' },
                        { name: 'Reggio Emilia', coords: [44.6989, 10.6297], label: 'AREA' },
                        { name: 'Parma', coords: [44.8015, 10.3279], label: 'AREA' },
                        { name: 'Ferrara', coords: [44.8381, 11.6198], label: 'AREA' }
                    ];
                    var customIcon = L.divIcon({
                        className: 'custom-marker',
                        html: '<div style="width:20px;height:20px;background:#fff;border:3px solid #1a1a1a;border-radius:50%;box-shadow:0 4px 15px rgba(0,0,0,0.4);"></div>',
                        iconSize: [20, 20],
                        iconAnchor: [10, 10]
                    });
                    var sedeIcon = L.divIcon({
                        className: 'custom-marker sede',
                        html: '<div style="width:28px;height:28px;background:#1a1a1a;border:3px solid #fff;border-radius:50%;box-shadow:0 4px 20px rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;"><span style="color:#fff;font-size:10px;font-weight:bold;">SR</span></div>',
                        iconSize: [28, 28],
                        iconAnchor: [14, 14]
                    });
                    cities.forEach(function(c) {
                        var icon = c.label === 'SEDE' ? sedeIcon : customIcon;
                        L.marker(c.coords, { icon: icon }).addTo(map).bindPopup('<span style="font-size:0.7rem;opacity:0.7;">' + c.label + '</span><br><strong style="font-size:1.1rem;">' + c.name + '</strong>');
                    });
                }
            }
        } catch(e) {
            console.log('Map error:', e);
        }

        // ESC per chiudere modal
        document.onkeydown = function(e) {
            if (e.key === 'Escape') closeModal();
        };

        // ===== DARK MODE TOGGLE =====
        var themeToggle = document.getElementById('themeToggle');
        var themeIcon = document.getElementById('themeIcon');
        var savedTheme = localStorage.getItem('theme') || 'light';

        // Applica tema salvato
        if (savedTheme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
            themeIcon.classList.remove('fa-moon');
            themeIcon.classList.add('fa-sun');
            themeToggle.classList.add('active');
        }

        if (themeToggle) {
            themeToggle.addEventListener('click', function() {
                var currentTheme = document.documentElement.getAttribute('data-theme');
                if (currentTheme === 'dark') {
                    document.documentElement.removeAttribute('data-theme');
                    localStorage.setItem('theme', 'light');
                    themeIcon.classList.remove('fa-sun');
                    themeIcon.classList.add('fa-moon');
                    themeToggle.classList.remove('active');
                } else {
                    document.documentElement.setAttribute('data-theme', 'dark');
                    localStorage.setItem('theme', 'dark');
                    themeIcon.classList.remove('fa-moon');
                    themeIcon.classList.add('fa-sun');
                    themeToggle.classList.add('active');
                }
            });
        }

        // ===== SCROLL REVEAL ANIMATIONS =====
        var revealElements = document.querySelectorAll('.reveal, .reveal-left, .reveal-right, .reveal-scale');

        function revealOnScroll() {
            var windowHeight = window.innerHeight;
            revealElements.forEach(function(el) {
                var elementTop = el.getBoundingClientRect().top;
                var revealPoint = 150;
                if (elementTop < windowHeight - revealPoint) {
                    el.classList.add('active');
                }
            });
        }

        // Intersection Observer per performance migliori
        if ('IntersectionObserver' in window) {
            var observer = new IntersectionObserver(function(entries) {
                entries.forEach(function(entry) {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('active');
                        observer.unobserve(entry.target);
                    }
                });
            }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });

            revealElements.forEach(function(el) {
                observer.observe(el);
            });
        } else {
            window.addEventListener('scroll', revealOnScroll);
            revealOnScroll();
        }

        // ===== SMOOTH SCROLL PER LINK ANCHOR =====
        document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
            anchor.addEventListener('click', function(e) {
                var targetId = this.getAttribute('href');
                if (targetId !== '#') {
                    var target = document.querySelector(targetId);
                    if (target) {
                        e.preventDefault();
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                }
            });
        });

        // ===== PARALLAX EFFECT SU HERO =====
        var heroSection = document.querySelector('.hero');
        if (heroSection) {
            window.addEventListener('scroll', function() {
                var scrolled = window.pageYOffset;
                if (scrolled < window.innerHeight) {
                    heroSection.style.transform = 'translateY(' + (scrolled * 0.3) + 'px)';
                    heroSection.style.opacity = 1 - (scrolled / (window.innerHeight * 1.2));
                }
            });
        }

    });

    </script>
</body>
</html>
'''

REGISTER_PAGE = '''
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registrati | Spallanzani Rappresentanze</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=Playfair+Display:ital,wght@0,400;0,600;0,700;1,400;1,600;1,700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        :root { --primary: #ffffff; --secondary: #f8f9fa; --dark: #1a1a1a; --grey: #6c757d; --border: #e9ecef; --text: #212529; --muted: #6c757d; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); color: var(--text); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 40px; }
        .register-box { background: var(--primary); border: 1px solid var(--border); border-radius: 16px; padding: 45px 40px; max-width: 450px; width: 100%; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo-icon { width: 65px; height: 65px; background: var(--dark); border-radius: 14px; margin: 0 auto 15px; display: flex; align-items: center; justify-content: center; font-size: 1.6rem; font-weight: 900; color: #fff; }
        h1 { font-family: 'Playfair Display', serif; font-size: 1.8rem; font-style: italic; text-align: center; margin-bottom: 8px; color: var(--dark); }
        .subtitle { text-align: center; color: var(--muted); font-style: italic; margin-bottom: 30px; font-size: 0.95rem; }
        .form-group { margin-bottom: 18px; }
        .form-group label { display: block; font-weight: 600; font-style: italic; margin-bottom: 6px; font-size: 0.85rem; color: var(--dark); }
        .form-group input { width: 100%; padding: 14px 16px; background: var(--secondary); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-family: inherit; font-size: 1rem; }
        .form-group input:focus { outline: none; border-color: var(--dark); }
        .submit-btn { width: 100%; background: var(--dark); color: #fff; padding: 15px; border: none; border-radius: 8px; font-size: 1rem; font-weight: 700; font-style: italic; text-transform: uppercase; letter-spacing: 1px; cursor: pointer; margin-top: 8px; transition: opacity 0.15s; }
        .submit-btn:hover { opacity: 0.85; }
        .back-link { display: block; text-align: center; margin-top: 20px; color: var(--muted); font-style: italic; text-decoration: none; }
        .back-link:hover { color: var(--dark); }
    </style>
</head>
<body>
    <div class="register-box">
        <div class="logo"><div class="logo-icon">SR</div></div>
        <h1>Registrati</h1>
        <p class="subtitle">Accedi all'area riservata con cataloghi e listini</p>
        <form method="POST" action="/registrati">
            <div class="form-group"><label>Nome *</label><input type="text" name="nome" required placeholder="Il tuo nome"></div>
            <div class="form-group"><label>Cognome *</label><input type="text" name="cognome" required placeholder="Il tuo cognome"></div>
            <div class="form-group"><label>Email *</label><input type="email" name="email" required placeholder="La tua email"></div>
            <div class="form-group"><label>Telefono</label><input type="tel" name="telefono" placeholder="Il tuo numero"></div>
            <div class="form-group"><label>Azienda</label><input type="text" name="azienda" placeholder="Nome azienda (opzionale)"></div>
            <button type="submit" class="submit-btn">Registrati</button>
        </form>
        <a href="/" class="back-link">&larr; Torna al sito</a>
    </div>
</body>
</html>
'''

DASHBOARD_PAGE = '''
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Area Riservata | Spallanzani Rappresentanze</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=Playfair+Display:ital,wght@0,400;0,600;0,700;1,400;1,600;1,700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        :root {
            --primary: #ffffff; --secondary: #f8f9fa; --tertiary: #f1f3f5;
            --dark: #1a1a1a; --grey: #6c757d;
            --text: #212529; --muted: #6c757d;
            --border: #e9ecef;
            --success: #28a745;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: var(--secondary); color: var(--text); min-height: 100vh; }

        /* Thank You Animation */
        .thank-overlay {
            position: fixed; inset: 0;
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            z-index: 9999;
            display: flex; align-items: center; justify-content: center;
            animation: thankFade 0.8s ease 3.5s forwards;
        }
        @keyframes thankFade { to { opacity: 0; pointer-events: none; } }
        .thank-content { text-align: center; animation: thankPop 0.8s cubic-bezier(0.34, 1.56, 0.64, 1); }
        @keyframes thankPop { from { transform: scale(0.6) translateY(30px); opacity: 0; } to { transform: scale(1) translateY(0); opacity: 1; } }
        .check-circle {
            width: 120px; height: 120px;
            background: linear-gradient(145deg, var(--success), #3a7ca5);
            border-radius: 50%;
            margin: 0 auto 30px;
            display: flex; align-items: center; justify-content: center;
            font-size: 3.5rem;
            color: #fff;
            animation: checkPulse 1.5s ease-in-out infinite;
            box-shadow: 0 20px 60px rgba(40,167,69,0.3);
        }
        @keyframes checkPulse {
            0%, 100% { transform: scale(1); box-shadow: 0 20px 60px rgba(40,167,69,0.3); }
            50% { transform: scale(1.05); box-shadow: 0 25px 80px rgba(40,167,69,0.4); }
        }
        .thank-content h1 {
            font-family: 'Playfair Display', serif;
            font-size: 2.8rem;
            font-style: italic;
            margin-bottom: 15px;
            color: var(--dark);
        }
        .thank-content p { font-size: 1.15rem; font-style: italic; color: var(--muted); }
        .thank-content .sub { margin-top: 25px; font-size: 0.95rem; font-style: italic; color: var(--grey); }

        /* Dashboard */
        .dashboard { padding: 35px 50px; max-width: 1400px; margin: 0 auto; }
        .dash-header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 40px; padding-bottom: 25px; border-bottom: 1px solid var(--border);
        }
        .dash-logo { display: flex; align-items: center; gap: 15px; }
        .dash-logo-icon { width: 44px; height: 44px; background: var(--dark); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 1rem; color: #fff; }
        .dash-logo h1 { font-size: 1.2rem; font-style: italic; color: var(--dark); }
        .dash-user { display: flex; align-items: center; gap: 12px; }
        .user-avatar { width: 40px; height: 40px; background: var(--dark); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.9rem; color: #fff; }
        .logout-btn { background: var(--primary); border: 1px solid var(--border); color: var(--text); padding: 10px 18px; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-style: italic; }
        .logout-btn:hover { opacity: 0.8; }

        .welcome-banner {
            background: var(--primary);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 40px 45px;
            margin-bottom: 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .welcome-banner h2 { font-family: 'Playfair Display', serif; font-size: 1.9rem; font-style: italic; margin-bottom: 10px; color: var(--dark); }
        .welcome-banner h2 span { color: var(--grey); }
        .welcome-banner p { color: var(--muted); font-style: italic; font-size: 1.05rem; }
        .welcome-actions { display: flex; gap: 15px; }
        .action-btn {
            background: var(--dark);
            color: #fff;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 700;
            font-style: italic;
            font-size: 0.85rem;
            transition: opacity 0.15s;
        }
        .action-btn:hover { opacity: 0.85; }
        .action-btn.outline {
            background: transparent;
            border: 1px solid var(--dark);
            color: var(--dark);
        }
        .action-btn.outline:hover { background: var(--dark); color: #fff; }

        .dash-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 25px; margin-bottom: 45px; }
        .dash-card {
            background: var(--primary);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 32px;
            transition: all 0.15s;
            cursor: pointer;
        }
        .dash-card:hover { transform: translateY(-4px); border-color: var(--grey); }
        .dash-card-icon {
            width: 50px; height: 50px;
            background: var(--dark);
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.4rem;
            color: #fff;
            margin-bottom: 18px;
        }
        .dash-card h3 { font-size: 1.2rem; font-style: italic; margin-bottom: 10px; color: var(--dark); }
        .dash-card p { color: var(--muted); font-style: italic; font-size: 0.92rem; line-height: 1.7; margin-bottom: 18px; }
        .dash-card .card-link {
            color: var(--dark);
            font-size: 0.88rem;
            font-weight: 600;
            font-style: italic;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .dash-card .card-link:hover { text-decoration: underline; }

        .section-title { font-family: 'Playfair Display', serif; font-size: 1.6rem; font-style: italic; margin-bottom: 25px; display: flex; align-items: center; gap: 12px; color: var(--dark); }
        .section-title::before { content: ''; width: 4px; height: 28px; background: var(--dark); border-radius: 2px; }

        .brands-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 18px; margin-bottom: 45px; }
        .brand-item {
            background: var(--primary);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 24px 18px;
            text-align: center;
            cursor: pointer;
            transition: transform 0.15s;
        }
        .brand-item:hover { transform: translateY(-3px); }
        .brand-item .name { font-weight: 700; font-style: italic; color: var(--dark); font-size: 1.05rem; margin-bottom: 6px; }
        .brand-item .desc { font-size: 0.82rem; font-style: italic; color: var(--muted); }

        .quick-links { display: grid; grid-template-columns: repeat(4, 1fr); gap: 18px; }
        .quick-link {
            background: var(--primary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 22px 25px;
            display: flex;
            align-items: center;
            gap: 15px;
            text-decoration: none;
            color: var(--text);
            transition: transform 0.15s;
        }
        .quick-link:hover { transform: translateX(5px); }
        .quick-link .icon {
            width: 42px; height: 42px;
            background: var(--dark);
            border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.1rem;
            color: #fff;
            flex-shrink: 0;
        }
        .quick-link .info h4 { font-size: 0.95rem; font-style: italic; margin-bottom: 3px; color: var(--dark); }
        .quick-link .info p { font-size: 0.8rem; font-style: italic; color: var(--muted); }

        @media (max-width: 992px) {
            .dash-grid { grid-template-columns: repeat(2, 1fr); }
            .brands-grid { grid-template-columns: repeat(3, 1fr); }
            .quick-links { grid-template-columns: repeat(2, 1fr); }
            .welcome-banner { flex-direction: column; text-align: center; gap: 25px; }
        }
        @media (max-width: 600px) {
            .dash-grid, .brands-grid, .quick-links { grid-template-columns: 1fr; }
            .dashboard { padding: 25px 20px; }
        }
    </style>
</head>
<body>
    <!-- Thank You Animation -->
    <div class="thank-overlay">
        <div class="thank-content">
            <div class="check-circle">&#10004;</div>
            <h1>Registrazione Completata!</h1>
            <p>Benvenuto nell'area riservata di Spallanzani Rappresentanze</p>
            <p class="sub">Accedi a cataloghi, listini e richiedi preventivi personalizzati</p>
        </div>
    </div>

    <div class="dashboard">
        <div class="dash-header">
            <div class="dash-logo">
                <div class="dash-logo-icon">SR</div>
                <div><h1>Area Riservata</h1></div>
            </div>
            <div class="dash-user">
                <div class="user-avatar">{{ initials }}</div>
                <span>{{ nome }}</span>
                <a href="/" class="logout-btn">Esci</a>
            </div>
        </div>

        <div class="welcome-banner">
            <div>
                <h2>Benvenuto, <span>{{ nome }}</span>!</h2>
                <p>Hai accesso completo a cataloghi, listini prezzi riservati e preventivi personalizzati.</p>
            </div>
            <div class="welcome-actions">
                <a href="#contatti" class="action-btn">Richiedi Preventivo</a>
                <a href="/" class="action-btn outline">Torna al Sito</a>
            </div>
        </div>

        <div class="dash-grid">
            <div class="dash-card">
                <div class="dash-card-icon"><i class="fas fa-book"></i></div>
                <h3>Cataloghi PDF</h3>
                <p>Scarica i cataloghi completi di Flessya, Di.Bi., Arieni e tutti i nostri marchi partner.</p>
                <a href="#" class="card-link">Sfoglia cataloghi &#8594;</a>
            </div>
            <div class="dash-card">
                <div class="dash-card-icon"><i class="fas fa-euro-sign"></i></div>
                <h3>Listini Prezzi</h3>
                <p>Accedi ai listini prezzi riservati aggiornati per rivenditori autorizzati.</p>
                <a href="#" class="card-link">Vedi listini &#8594;</a>
            </div>
            <div class="dash-card">
                <div class="dash-card-icon"><i class="fas fa-file-invoice"></i></div>
                <h3>Preventivi Online</h3>
                <p>Compila il configuratore per ricevere un preventivo dettagliato entro 24 ore.</p>
                <a href="#" class="card-link">Crea preventivo &#8594;</a>
            </div>
        </div>

        <h3 class="section-title">I Nostri Marchi Partner</h3>
        <div class="brands-grid">
            <div class="brand-item"><div class="name">Flessya</div><div class="desc">Porte Interni</div></div>
            <div class="brand-item"><div class="name">Mondocasa</div><div class="desc">Serramenti PVC</div></div>
            <div class="brand-item"><div class="name">Eproditalia</div><div class="desc">Infissi Alluminio</div></div>
            <div class="brand-item"><div class="name">Arieni</div><div class="desc">Maniglie Design</div></div>
            <div class="brand-item"><div class="name">Di.Bi.</div><div class="desc">Porte Blindate</div></div>
        </div>

        <h3 class="section-title">Accesso Rapido</h3>
        <div class="quick-links">
            <a href="tel:+393356928280" class="quick-link">
                <div class="icon"><i class="fas fa-phone"></i></div>
                <div class="info"><h4>Chiamaci</h4><p>+39 335 692 8280</p></div>
            </a>
            <a href="mailto:spallamm@gmail.com" class="quick-link">
                <div class="icon"><i class="fas fa-envelope"></i></div>
                <div class="info"><h4>Email Ordini</h4><p>spallamm@gmail.com</p></div>
            </a>
            <a href="mailto:commercialegolinellidaniela@gmail.com" class="quick-link">
                <div class="icon"><i class="fas fa-briefcase"></i></div>
                <div class="info"><h4>Commerciale</h4><p>Daniela Golinelli</p></div>
            </a>
            <a href="/" class="quick-link">
                <div class="icon"><i class="fas fa-home"></i></div>
                <div class="info"><h4>Sito Web</h4><p>Torna alla home</p></div>
            </a>
        </div>
    </div>
</body>
</html>
'''

THANKS_PAGE = '''
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Richiesta Inviata | Spallanzani</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=Playfair+Display:ital,wght@0,400;0,600;0,700;1,400;1,600;1,700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        :root { --primary: #ffffff; --dark: #1a1a1a; --grey: #6c757d; --success: #28a745; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); color: var(--dark); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { text-align: center; animation: fadeInUp 0.8s ease; }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
        .success-icon { width: 100px; height: 100px; margin: 0 auto 30px; background: var(--success); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; color: #fff; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.05); } }
        h1 { font-family: 'Playfair Display', serif; font-size: 2.2rem; font-style: italic; margin-bottom: 12px; color: var(--dark); }
        .subtitle { font-size: 1.05rem; font-style: italic; color: var(--grey); margin-bottom: 10px; }
        .name-highlight { color: var(--dark); font-weight: 700; }
        .info { font-size: 0.9rem; font-style: italic; color: var(--grey); margin-bottom: 30px; }
        .home-btn { display: inline-block; background: var(--dark); color: #fff; padding: 14px 40px; border-radius: 8px; text-decoration: none; font-weight: 700; font-style: italic; text-transform: uppercase; letter-spacing: 1px; transition: opacity 0.15s; }
        .home-btn:hover { opacity: 0.85; }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon"><i class="fas fa-check"></i></div>
        <h1>Richiesta Inviata!</h1>
        <p class="subtitle">Grazie <span class="name-highlight">{{ nome }}</span> per averci contattato</p>
        <p class="info">Ti risponderemo entro 24 ore lavorative</p>
        <a href="/" class="home-btn"><i class="fas fa-home"></i> Torna alla Home</a>
    </div>
</body>
</html>
'''

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files (video, images, etc.)"""
    return send_from_directory('static', filename)

@app.route('/')
@rate_limit(max_requests=60, window=60)
def home():
    return render_template_string(MAIN_PAGE, csrf_token=g.csrf_token)

@app.route('/api/chat', methods=['POST'])
@rate_limit(max_requests=30, window=60)
def api_chat():
    """Endpoint chatbot AI con Gemini - RISPOSTA INTELLIGENTE"""
    try:
        data = request.get_json()
        user_message = sanitize_input(data.get('message', ''), 500) if data else ''

        if not user_message:
            return jsonify({'success': False, 'response': 'Messaggio vuoto'})

        # Se Gemini non e configurato, usa risposte locali migliorate
        if not GEMINI_API_KEY:
            response = get_smart_response(user_message)
            return jsonify({'success': True, 'response': response})

        # Prompt contestualizzato per Gemini
        system_prompt = """Sei l'assistente AI di Spallanzani Rappresentanze, azienda che rappresenta questi marchi in Emilia Romagna:

MARCHI RAPPRESENTATI:
1. FLESSYA - Porte per interni Made in Italy (Linee: Nidio, Kikka, Vetra, Rasomuro, Plenia, S-nziale) - Prezzi: 300-1500 euro
2. DI.BI. - Porte blindate certificate classe 3, 4, 5 (dal 1976) - Prezzi: 800-3500 euro
3. ARIENI - Maniglie di design in ottone e acciaio (dal 1997) - Prezzi: 50-400 euro
4. MONDOCASA - Serramenti in PVC ad alto isolamento termico/acustico (5-7 camere, triplo vetro)
5. EPRODITALIA - Infissi in alluminio a taglio termico (65-85mm)

ZONE OPERATIVE: Modena, Reggio Emilia, Parma, Ferrara

CONTATTI:
- Telefono: +39 335 692 8280 (Massimo Spallanzani)
- Email ordini: spallamm@gmail.com
- Email commerciale: commercialegolinellidaniela@gmail.com

ISTRUZIONI:
- Rispondi SEMPRE in italiano
- Sii professionale ma cordiale
- Risposte BREVI e CONCISE (max 2-3 frasi)
- Se chiedono preventivi, invitali a contattare o usare il form
- NON inventare prezzi specifici, dai range indicativi
- Se non sai qualcosa, suggerisci di contattare l'azienda"""

        headers = {'Content-Type': 'application/json'}
        gemini_data = {
            'contents': [
                {'role': 'user', 'parts': [{'text': system_prompt}]},
                {'role': 'model', 'parts': [{'text': 'Capito! Sono pronto ad assistere i clienti di Spallanzani Rappresentanze.'}]},
                {'role': 'user', 'parts': [{'text': user_message}]}
            ],
            'generationConfig': {
                'temperature': 0.7,
                'maxOutputTokens': 300,
                'topP': 0.9
            }
        }

        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            headers=headers,
            json=gemini_data,
            timeout=15
        )

        if response.status_code == 200:
            result = response.json()
            ai_response = result['candidates'][0]['content']['parts'][0]['text']
            return jsonify({'success': True, 'response': ai_response})
        else:
            # Fallback a risposte locali
            return jsonify({'success': True, 'response': get_smart_response(user_message)})

    except Exception as e:
        log_security_event("CHAT_ERROR", request.remote_addr, str(e))
        return jsonify({'success': True, 'response': get_smart_response(user_message if 'user_message' in dir() else '')})

def get_smart_response(message):
    """Risposte smart locali migliorate (fallback)"""
    q = message.lower()

    # Saluti
    if any(w in q for w in ['ciao', 'salve', 'buongiorno', 'buonasera', 'hey', 'saluti']):
        return "Buongiorno! Sono l'assistente di Spallanzani Rappresentanze. Come posso aiutarti? Posso darti info su <strong>Flessya</strong>, <strong>Di.Bi.</strong>, <strong>Mondocasa</strong>, <strong>Eproditalia</strong> o <strong>Arieni</strong>."

    # Flessya
    if 'flessya' in q:
        return "<strong>Flessya</strong> produce porte per interni Made in Italy. Linee disponibili: <em>Nidio, Kikka, Vetra, Rasomuro, Plenia, S-nziale</em>. Oltre 100 finiture. Range prezzi: €300-1500."

    # Di.Bi
    if any(w in q for w in ['dibi', 'di.bi', 'blindat', 'sicurezza']):
        return "<strong>Di.Bi.</strong> produce porte blindate certificate dal 1976. Classi disponibili: 3, 4 e 5. Serrature multipunto. Range prezzi: €800-3500."

    # Mondocasa
    if any(w in q for w in ['mondocasa', 'pvc', 'serramento', 'finestra', 'finestre']):
        return "<strong>Mondocasa</strong> offre serramenti in PVC con isolamento superiore. Profili 5-7 camere, triplo vetro, Uw fino a 0.6 W/m2K. Ideali per risparmio energetico."

    # Eproditalia
    if any(w in q for w in ['eproditalia', 'alluminio', 'infisso', 'infissi', 'taglio termico']):
        return "<strong>Eproditalia</strong> produce infissi in alluminio a taglio termico. Profili 65-85mm, finiture RAL e effetto legno. Perfetti per design moderno."

    # Arieni
    if any(w in q for w in ['arieni', 'manigli', 'ottone', 'acciaio']):
        return "<strong>Arieni</strong> crea maniglie di design dal 1997. Materiali: ottone e acciaio. Finiture: cromo, satinato, brunito, nero. Range prezzi: €50-400."

    # Preventivo
    if any(w in q for w in ['preventivo', 'prezzo', 'costo', 'quanto costa', 'listino']):
        return "Per un <strong>preventivo personalizzato</strong> puoi:<br>• Chiamare: <a href='tel:+393356928280'>335 692 8280</a><br>• Email: spallamm@gmail.com<br>• Compilare il form contatti qui sotto"

    # Zone
    if any(w in q for w in ['zona', 'zone', 'dove', 'territorio', 'provincia', 'citta']):
        return "Operiamo in <strong>Emilia Romagna</strong>: Modena, Reggio Emilia, Parma e Ferrara con visite regolari ai rivenditori."

    # Contatti
    if any(w in q for w in ['contatt', 'telefono', 'email', 'chiamare']):
        return "<strong>Contatti:</strong><br>• Tel: <a href='tel:+393356928280'>+39 335 692 8280</a><br>• Email: spallamm@gmail.com<br>• Commerciale: commercialegolinellidaniela@gmail.com"

    # Marchi
    if any(w in q for w in ['marchi', 'brand', 'aziende', 'rappresentate']):
        return "Rappresentiamo <strong>5 marchi</strong>: Flessya (porte interni), Di.Bi. (blindate), Mondocasa (PVC), Eproditalia (alluminio), Arieni (maniglie). Chiedimi di uno specifico!"

    # Catalogo
    if any(w in q for w in ['catalogo', 'prodott', 'gamma']):
        return "Il nostro <strong>catalogo</strong> include: porte interni, porte blindate, serramenti PVC, infissi alluminio e maniglie design. Scorri la pagina per vedere tutti i prodotti!"

    # Default
    return "Posso aiutarti con info su: <strong>Flessya</strong>, <strong>Di.Bi.</strong>, <strong>Mondocasa</strong>, <strong>Eproditalia</strong>, <strong>Arieni</strong>, preventivi o zone operative. Cosa ti interessa?"

@app.route('/registrati', methods=['GET', 'POST'])
@rate_limit(max_requests=10, window=60)
def registrati():
    if request.method == 'POST':
        # Verifica honeypot (anti-bot)
        if not check_honeypot(request.form):
            log_security_event("BOT_DETECTED", request.remote_addr, "Honeypot triggered")
            abort(403)

        # Sanitizza tutti gli input (PREVIENE SSTI e XSS)
        nome = sanitize_input(request.form.get('nome', ''), 100)
        cognome = sanitize_input(request.form.get('cognome', ''), 100)
        email = sanitize_input(request.form.get('email', ''), 200)
        telefono = sanitize_input(request.form.get('telefono', ''), 20)
        azienda = sanitize_input(request.form.get('azienda', ''), 200)

        # Valida email
        if not validate_email(email):
            return render_template_string(REGISTER_PAGE + '<script>alert("Email non valida")</script>')

        # Valida telefono
        if not validate_phone(telefono):
            return render_template_string(REGISTER_PAGE + '<script>alert("Telefono non valido")</script>')

        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('INSERT INTO utenti (nome, cognome, email, telefono, azienda, ip) VALUES (?, ?, ?, ?, ?, ?)',
                      (nome, cognome, email, telefono, azienda, request.remote_addr))
            conn.commit()
            conn.close()
            log_security_event("USER_REGISTERED", request.remote_addr, f"Email: {email}")
        except sqlite3.IntegrityError:
            pass  # Email già esistente
        except Exception as e:
            log_security_event("DB_ERROR", request.remote_addr, str(e))

        # Usa valori sanitizzati per il template (SICURO)
        initials = (nome[0] if nome else 'U') + (cognome[0] if cognome else 'U')
        return render_template_string(DASHBOARD_PAGE, nome=nome, initials=initials.upper())

    return render_template_string(REGISTER_PAGE, csrf_token=g.csrf_token)

@app.route('/contatti', methods=['POST'])
@rate_limit(max_requests=5, window=60)
def contatti():
    # Verifica honeypot (anti-bot)
    if not check_honeypot(request.form):
        log_security_event("BOT_DETECTED", request.remote_addr, "Honeypot triggered on contact form")
        abort(403)

    # Sanitizza tutti gli input (PREVIENE SSTI e XSS)
    nome = sanitize_input(request.form.get('nome', ''), 100)
    email = sanitize_input(request.form.get('email', ''), 200)
    telefono = sanitize_input(request.form.get('telefono', ''), 20)
    prodotto = sanitize_input(request.form.get('prodotto', ''), 100)
    messaggio = sanitize_input(request.form.get('messaggio', ''), 1000)

    # Valida email
    if not validate_email(email):
        abort(400)

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO richieste (nome, email, telefono, messaggio, prodotto, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)',
                  (nome, email, telefono, messaggio, prodotto, request.remote_addr, request.headers.get('User-Agent', '')[:200]))
        conn.commit()
        conn.close()
        log_security_event("CONTACT_FORM", request.remote_addr, f"From: {email}")
    except Exception as e:
        log_security_event("DB_ERROR", request.remote_addr, str(e))

    # Usa valori sanitizzati (SICURO)
    return render_template_string(THANKS_PAGE, nome=nome)

# ============================================
# ADMIN PAGES TEMPLATES
# ============================================

ADMIN_LOGIN_PAGE = '''<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Spallanzani</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: rgba(255,255,255,0.95);
            border-radius: 20px;
            padding: 50px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.3);
        }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { font-size: 28px; color: #1a1a2e; }
        .logo span { color: #c9a227; }
        .logo p { color: #666; font-size: 14px; margin-top: 5px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #333; font-weight: 600; }
        .form-group input {
            width: 100%;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s;
        }
        .form-group input:focus { border-color: #c9a227; outline: none; }
        .login-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #c9a227, #d4af37);
            border: none;
            border-radius: 10px;
            color: #1a1a2e;
            font-size: 18px;
            font-weight: 700;
            cursor: pointer;
            transition: transform 0.3s;
        }
        .login-btn:hover { transform: scale(1.02); }
        .error { background: #ffe6e6; color: #cc0000; padding: 15px; border-radius: 10px; margin-bottom: 20px; text-align: center; }
        .back-link { text-align: center; margin-top: 20px; }
        .back-link a { color: #666; text-decoration: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>SPALLANZANI<span>®</span></h1>
            <p>Area Riservata Admin</p>
        </div>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required placeholder="Inserisci username">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required placeholder="Inserisci password">
            </div>
            <button type="submit" class="login-btn">🔐 ACCEDI</button>
        </form>
        <div class="back-link"><a href="/">← Torna al sito</a></div>
    </div>
</body>
</html>'''

ADMIN_DASHBOARD_PAGE = '''<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Admin - Spallanzani</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,700;1,400&family=Inter:wght@300;400;500;600;700&display=swap');
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --primary: #1a1a1a;
            --secondary: #f8f9fa;
            --accent: #c9a227;
            --accent-light: rgba(201,162,39,0.1);
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #3b82f6;
        }
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 50%, #f8f9fa 100%);
            min-height: 100vh;
        }
        /* Animazioni */
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        @keyframes shimmer {
            0% { background-position: -1000px 0; }
            100% { background-position: 1000px 0; }
        }
        .navbar {
            background: linear-gradient(135deg, var(--primary) 0%, #2d2d2d 100%);
            padding: 18px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 30px rgba(0,0,0,0.2);
            backdrop-filter: blur(10px);
        }
        .navbar h1 {
            color: #fff;
            font-size: 24px;
            font-family: 'Playfair Display', serif;
            font-weight: 400;
            letter-spacing: 2px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .navbar h1 i { color: var(--accent); font-size: 20px; }
        .navbar h1 span { color: var(--accent); font-style: italic; }
        .navbar-right { display: flex; align-items: center; gap: 15px; }
        .user-badge {
            background: var(--accent-light);
            color: var(--accent);
            padding: 10px 18px;
            border-radius: 30px;
            font-weight: 600;
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            gap: 8px;
            border: 1px solid rgba(201,162,39,0.3);
        }
        .user-badge i { font-size: 14px; }
        .logout-btn {
            background: transparent;
            color: #fff;
            border: 2px solid rgba(255,255,255,0.3);
            padding: 10px 22px;
            border-radius: 30px;
            cursor: pointer;
            text-decoration: none;
            font-weight: 500;
            font-size: 0.85rem;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .logout-btn:hover {
            background: var(--danger);
            border-color: var(--danger);
            transform: translateY(-2px);
        }
        .container { max-width: 1500px; margin: 0 auto; padding: 35px; }
        /* Welcome Banner */
        .welcome-banner {
            background: linear-gradient(135deg, var(--primary) 0%, #333 100%);
            border-radius: 24px;
            padding: 35px 40px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: #fff;
            position: relative;
            overflow: hidden;
            animation: fadeInUp 0.6s ease;
        }
        .welcome-banner::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -10%;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, var(--accent-light) 0%, transparent 70%);
            opacity: 0.5;
        }
        .welcome-banner h2 {
            font-family: 'Playfair Display', serif;
            font-size: 1.8rem;
            font-weight: 400;
            margin-bottom: 8px;
        }
        .welcome-banner h2 span { color: var(--accent); }
        .welcome-banner p { opacity: 0.8; font-size: 0.95rem; }
        .welcome-date {
            background: rgba(255,255,255,0.1);
            padding: 15px 25px;
            border-radius: 16px;
            text-align: right;
            backdrop-filter: blur(5px);
        }
        .welcome-date .day { font-size: 2rem; font-weight: 700; color: var(--accent); }
        .welcome-date .month { font-size: 0.9rem; opacity: 0.8; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
            margin-bottom: 35px;
        }
        .stat-card {
            background: white;
            border-radius: 20px;
            padding: 28px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.04);
            position: relative;
            overflow: hidden;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            animation: fadeInUp 0.6s ease backwards;
            border: 1px solid rgba(0,0,0,0.04);
        }
        .stat-card:nth-child(1) { animation-delay: 0.1s; }
        .stat-card:nth-child(2) { animation-delay: 0.2s; }
        .stat-card:nth-child(3) { animation-delay: 0.3s; }
        .stat-card:nth-child(4) { animation-delay: 0.4s; }
        .stat-card:hover {
            transform: translateY(-8px);
            box-shadow: 0 20px 50px rgba(0,0,0,0.1);
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
        }
        .stat-card:nth-child(1)::before { background: linear-gradient(90deg, var(--success), #34d399); }
        .stat-card:nth-child(2)::before { background: linear-gradient(90deg, var(--info), #60a5fa); }
        .stat-card:nth-child(3)::before { background: linear-gradient(90deg, var(--warning), #fbbf24); }
        .stat-card:nth-child(4)::before { background: linear-gradient(90deg, var(--accent), #d4af37); }
        .stat-card .icon {
            width: 60px;
            height: 60px;
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 18px;
            font-size: 24px;
        }
        .stat-card:nth-child(1) .icon { background: rgba(16,185,129,0.1); color: var(--success); }
        .stat-card:nth-child(2) .icon { background: rgba(59,130,246,0.1); color: var(--info); }
        .stat-card:nth-child(3) .icon { background: rgba(245,158,11,0.1); color: var(--warning); }
        .stat-card:nth-child(4) .icon { background: var(--accent-light); color: var(--accent); }
        .stat-card .number {
            font-size: 38px;
            font-weight: 700;
            color: var(--primary);
            font-family: 'Inter', sans-serif;
            line-height: 1;
        }
        .stat-card .label {
            color: #6b7280;
            margin-top: 10px;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 500;
        }
        .card {
            background: white;
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 25px;
            border: 1px solid rgba(0,0,0,0.04);
            animation: fadeInUp 0.6s ease backwards;
            animation-delay: 0.5s;
            box-shadow: 0 10px 40px rgba(0,0,0,0.08);
        }
        .card h2 {
            color: #1a1a2e;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 12px;
            font-family: 'Playfair Display', serif;
            font-weight: 400;
            font-size: 24px;
        }
        .card h2 em { color: #c9a227; font-style: italic; }
        .welcome-banner {
            background: linear-gradient(135deg, rgba(26,26,46,0.9), rgba(22,33,62,0.9)),
                        url('https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=1200') center/cover;
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 25px;
            color: white;
            position: relative;
            overflow: hidden;
        }
        .welcome-banner h2 {
            font-family: 'Playfair Display', serif;
            font-size: 32px;
            font-weight: 400;
            margin-bottom: 10px;
        }
        .welcome-banner h2 span { color: #c9a227; font-style: italic; }
        .welcome-banner p { opacity: 0.8; font-size: 14px; }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }
        .btn-primary { background: #c9a227; color: #1a1a2e; }
        .btn-success { background: #28a745; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-ai { background: linear-gradient(135deg, #667eea, #764ba2); color: white; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; color: #1a1a2e; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .status-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .status-nuovo { background: #e3f2fd; color: #1976d2; }
        .status-ai { background: #f3e5f5; color: #7b1fa2; }
        .status-attesa { background: #fff3e0; color: #f57c00; }
        .status-approvato { background: #e8f5e9; color: #388e3c; }
        .status-inviato { background: #e0f2f1; color: #00897b; }
        .status-rifiutato { background: #ffebee; color: #c62828; }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal.active { display: flex; }
        .modal-content {
            background: white;
            border-radius: 20px;
            padding: 30px;
            max-width: 700px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-close { background: none; border: none; font-size: 30px; cursor: pointer; color: #666; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 600; color: #333; }
        .form-group input, .form-group textarea, .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
        }
        .form-group textarea { min-height: 100px; resize: vertical; }
        .ai-box {
            background: linear-gradient(135deg, rgba(26,26,46,0.05), rgba(201,162,39,0.08));
            border: 2px solid #c9a227;
            border-radius: 15px;
            padding: 25px;
            margin: 20px 0;
        }
        .ai-box h4 {
            color: #1a1a2e;
            margin-bottom: 15px;
            font-family: 'Playfair Display', serif;
        }
        .ai-box h4 span { color: #c9a227; font-style: italic; }
        .ai-response { background: white; padding: 15px; border-radius: 8px; white-space: pre-wrap; font-family: monospace; font-size: 13px; }
        .loading { display: none; text-align: center; padding: 20px; }
        .loading.active { display: block; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #c9a227; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .navbar { flex-direction: column; gap: 15px; }
        }
        /* ARIA AI Assistant - Floating Button */
        .aria-float {
            position: fixed;
            bottom: 30px;
            right: 30px;
            z-index: 999;
            display: flex;
            align-items: flex-end;
            gap: 15px;
        }
        .aria-bubble {
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            padding: 20px 25px;
            border-radius: 20px 20px 5px 20px;
            box-shadow: 0 10px 40px rgba(201,162,39,0.3);
            max-width: 280px;
            animation: bubblePop 0.5s ease;
            border: 1px solid rgba(201,162,39,0.3);
        }
        .aria-bubble p { margin: 0; color: #fff; font-size: 14px; line-height: 1.5; }
        .aria-bubble .aria-name {
            color: #c9a227;
            font-family: 'Playfair Display', serif;
            font-style: italic;
            font-size: 18px;
            display: block;
            margin-bottom: 8px;
        }
        @keyframes bubblePop {
            0% { opacity: 0; transform: scale(0.8) translateY(20px); }
            100% { opacity: 1; transform: scale(1) translateY(0); }
        }
        .aria-btn {
            width: 75px;
            height: 75px;
            border-radius: 50%;
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            border: 3px solid #c9a227;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 10px 40px rgba(201,162,39,0.4);
            transition: all 0.3s;
            animation: ariaPulse 2s infinite;
            position: relative;
            overflow: hidden;
        }
        .aria-btn::before {
            content: 'ARIA';
            font-family: 'Playfair Display', serif;
            font-style: italic;
            font-size: 16px;
            color: #c9a227;
            font-weight: 600;
        }
        .aria-btn::after {
            content: '';
            position: absolute;
            width: 10px;
            height: 10px;
            background: #28a745;
            border-radius: 50%;
            top: 8px;
            right: 8px;
            animation: statusPulse 1.5s infinite;
        }
        .aria-btn:hover {
            transform: scale(1.1);
            box-shadow: 0 15px 50px rgba(201,162,39,0.5);
            border-color: #d4af37;
        }
        @keyframes ariaPulse {
            0%, 100% { box-shadow: 0 10px 40px rgba(201,162,39,0.4); }
            50% { box-shadow: 0 10px 50px rgba(201,162,39,0.6); }
        }
        @keyframes statusPulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.2); }
        }
        /* Gold accent like main site */
        .gold-accent { color: #c9a227; }
        .card-gold { border-left: 4px solid #c9a227; }
        /* AI Card styling */
        .ai-card {
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 25px;
            color: white;
            position: relative;
            overflow: hidden;
        }
        .ai-card::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle, rgba(201,162,39,0.1) 0%, transparent 70%);
        }
        .ai-card h2 {
            color: #fff;
            font-family: 'Playfair Display', serif;
            margin-bottom: 15px;
        }
        .ai-card h2 em { color: #c9a227; }
        .ai-card p { color: rgba(255,255,255,0.7); margin-bottom: 20px; }
        .ai-card .aria-logo {
            display: inline-flex;
            align-items: center;
            gap: 15px;
            background: rgba(201,162,39,0.1);
            padding: 15px 25px;
            border-radius: 50px;
            border: 1px solid rgba(201,162,39,0.3);
            margin-bottom: 20px;
        }
        .ai-card .aria-logo span {
            font-family: 'Playfair Display', serif;
            font-style: italic;
            font-size: 24px;
            color: #c9a227;
        }
        .ai-card .aria-logo small {
            color: rgba(255,255,255,0.6);
            font-size: 11px;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1><i class="fas fa-shield-alt"></i> SPALLANZANI<span>®</span> Dashboard</h1>
        <div class="navbar-right">
            <div class="user-badge"><i class="fas fa-user-circle"></i> {{ username }}</div>
            <a href="/admin/logout" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
        </div>
    </nav>

    <div class="container">
        <div class="welcome-banner">
            <div>
                <h2>Benvenuto, <span>{{ username }}</span></h2>
                <p>Gestisci preventivi, richieste clienti e genera quotazioni con l'intelligenza artificiale</p>
            </div>
            <div class="welcome-date">
                <div class="day" id="currentDay"></div>
                <div class="month" id="currentMonth"></div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="icon"><i class="fas fa-file-invoice"></i></div>
                <div class="number">{{ stats.totali }}</div>
                <div class="label">Preventivi Totali</div>
            </div>
            <div class="stat-card">
                <div class="icon"><i class="fas fa-plus-circle"></i></div>
                <div class="number">{{ stats.nuovi }}</div>
                <div class="label">Nuovi</div>
            </div>
            <div class="stat-card">
                <div class="icon"><i class="fas fa-clock"></i></div>
                <div class="number">{{ stats.attesa }}</div>
                <div class="label">In Attesa Conferma</div>
            </div>
            <div class="stat-card">
                <div class="icon"><i class="fas fa-check-circle"></i></div>
                <div class="number">{{ stats.inviati }}</div>
                <div class="label">Inviati</div>
            </div>
        </div>

        <div class="ai-card">
            <div class="aria-logo">
                <i class="fas fa-robot" style="font-size:28px;color:#c9a227"></i>
                <span>ARIA</span>
                <small>AI Rapida Intelligente Assistente</small>
            </div>
            <h2>Crea Preventivi con <em>Intelligenza Artificiale</em></h2>
            <p>ARIA analizza le richieste dei clienti e genera preventivi professionali in pochi secondi, con prezzi accurati e descrizioni dettagliate.</p>
            <button class="btn btn-ai" onclick="openModal('nuovo')" style="font-size:16px;padding:15px 35px;background:linear-gradient(135deg,#c9a227,#d4af37);color:#1a1a2e;border:none;border-radius:30px;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:10px"><i class="fas fa-magic"></i> Genera Preventivo con ARIA</button>
        </div>

        <div class="card">
            <h2>📊 Elenco <em>Preventivi</em></h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Cliente</th>
                        <th>Email</th>
                        <th>Prodotti</th>
                        <th>Stato</th>
                        <th>Data</th>
                        <th>Azioni</th>
                    </tr>
                </thead>
                <tbody>
                    {% for p in preventivi %}
                    <tr>
                        <td>#{{ p.id }}</td>
                        <td>{{ p.cliente_nome }}</td>
                        <td>{{ p.cliente_email }}</td>
                        <td>{{ p.prodotti[:30] }}...</td>
                        <td><span class="status-badge status-{{ p.stato }}">{{ p.stato }}</span></td>
                        <td>{{ p.data_creazione[:10] }}</td>
                        <td>
                            <button class="btn btn-primary" onclick="viewPreventivo({{ p.id }})">👁️</button>
                            {% if p.stato == 'ai_generato' %}
                            <button class="btn btn-success" onclick="approvaPreventivo({{ p.id }})">✅</button>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                    {% if not preventivi %}
                    <tr><td colspan="7" style="text-align:center;color:#666;">Nessun preventivo ancora</td></tr>
                    {% endif %}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>📬 Richieste dal <em>Sito</em></h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Nome</th>
                        <th>Email</th>
                        <th>Prodotto</th>
                        <th>Messaggio</th>
                        <th>Data</th>
                        <th>Azioni</th>
                    </tr>
                </thead>
                <tbody>
                    {% for r in richieste %}
                    <tr>
                        <td>#{{ r.id }}</td>
                        <td>{{ r.nome }}</td>
                        <td>{{ r.email }}</td>
                        <td>{{ r.prodotto }}</td>
                        <td>{{ r.messaggio[:40] }}...</td>
                        <td>{{ r.data[:10] if r.data else 'N/A' }}</td>
                        <td>
                            <button class="btn btn-ai" onclick="creaPreventivoDaRichiesta({{ r.id }}, '{{ r.nome }}', '{{ r.email }}', '{{ r.telefono }}', '{{ r.prodotto }}', '{{ r.messaggio|replace("'", "") }}')">🤖 AI</button>
                        </td>
                    </tr>
                    {% endfor %}
                    {% if not richieste %}
                    <tr><td colspan="7" style="text-align:center;color:#666;">Nessuna richiesta</td></tr>
                    {% endif %}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Modal Nuovo Preventivo -->
    <div class="modal" id="modal-nuovo">
        <div class="modal-content">
            <div class="modal-header">
                <h2 style="font-family:'Playfair Display',serif"><span style="color:#c9a227;font-style:italic">ARIA</span> - Nuovo Preventivo</h2>
                <button class="modal-close" onclick="closeModal('nuovo')">&times;</button>
            </div>
            <form id="form-preventivo" onsubmit="submitPreventivo(event)">
                <div class="form-group">
                    <label>Nome Cliente *</label>
                    <input type="text" name="cliente_nome" id="cliente_nome" required>
                </div>
                <div class="form-group">
                    <label>Email Cliente *</label>
                    <input type="email" name="cliente_email" id="cliente_email" required>
                </div>
                <div class="form-group">
                    <label>Telefono</label>
                    <input type="tel" name="cliente_telefono" id="cliente_telefono">
                </div>
                <div class="form-group">
                    <label>Prodotti Richiesti *</label>
                    <select name="prodotti" id="prodotti" multiple style="height:100px">
                        <option value="Flessya - Porte Interni">Flessya - Porte Interni</option>
                        <option value="Di.Bi. - Porte Blindate">Di.Bi. - Porte Blindate</option>
                        <option value="Arieni - Maniglie Design">Arieni - Maniglie Design</option>
                        <option value="Mondocasa">Mondocasa</option>
                        <option value="Eproditalia">Eproditalia</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Dettagli Richiesta *</label>
                    <textarea name="richiesta" id="richiesta" required placeholder="Descrivi la richiesta del cliente: numero porte, dimensioni, finiture, ecc."></textarea>
                </div>
                <button type="submit" class="btn btn-ai" style="width:100%">🤖 Genera Preventivo con Gemini AI</button>
            </form>

            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p style="margin-top:20px;color:#c9a227;font-family:'Playfair Display',serif;font-style:italic;font-size:16px">ARIA sta elaborando il preventivo...</p>
            </div>

            <div class="ai-box" id="ai-result" style="display:none">
                <h4>✨ Preventivo generato da <span>ARIA</span></h4>
                <div class="ai-response" id="ai-response-text"></div>
                <div style="margin-top:25px;display:flex;gap:15px;flex-wrap:wrap">
                    <button class="btn" onclick="inviaConferma()" style="background:linear-gradient(135deg,#28a745,#20c997);color:white;padding:12px 25px;border:none;border-radius:25px;font-weight:600;cursor:pointer">📧 Invia per Conferma</button>
                    <button class="btn" onclick="rigeneraAI()" style="background:linear-gradient(135deg,#c9a227,#d4af37);color:#1a1a2e;padding:12px 25px;border:none;border-radius:25px;font-weight:600;cursor:pointer">🔄 Rigenera con ARIA</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal Visualizza -->
    <div class="modal" id="modal-view">
        <div class="modal-content">
            <div class="modal-header">
                <h2>📋 Dettaglio Preventivo</h2>
                <button class="modal-close" onclick="closeModal('view')">&times;</button>
            </div>
            <div id="view-content"></div>
        </div>
    </div>

    <!-- ARIA AI Assistant - Floating Button -->
    <div class="aria-float">
        <div class="aria-bubble" id="aria-bubble">
            <span class="aria-name">Ciao, sono ARIA</span>
            <p>La tua assistente AI per preventivi.<br>Clicca per creare un preventivo in automatico!</p>
        </div>
        <button class="aria-btn" onclick="openModal('nuovo')" title="ARIA - Crea Preventivo con AI"></button>
    </div>

    <script>
        let currentPreventivoId = null;

        // Nascondi bubble ARIA dopo 8 secondi
        setTimeout(() => {
            const bubble = document.getElementById('aria-bubble');
            if (bubble) {
                bubble.style.opacity = '0';
                bubble.style.transform = 'translateY(20px)';
                bubble.style.transition = 'all 0.5s ease';
                setTimeout(() => bubble.style.display = 'none', 500);
            }
        }, 8000);

        function openModal(id) { document.getElementById('modal-' + id).classList.add('active'); }
        function closeModal(id) { document.getElementById('modal-' + id).classList.remove('active'); }

        function creaPreventivoDaRichiesta(id, nome, email, tel, prodotto, msg) {
            document.getElementById('cliente_nome').value = nome;
            document.getElementById('cliente_email').value = email;
            document.getElementById('cliente_telefono').value = tel || '';
            document.getElementById('richiesta').value = msg;
            openModal('nuovo');
        }

        async function submitPreventivo(e) {
            e.preventDefault();
            document.getElementById('loading').classList.add('active');
            document.getElementById('ai-result').style.display = 'none';

            const formData = new FormData(e.target);
            const prodotti = Array.from(document.getElementById('prodotti').selectedOptions).map(o => o.value).join(', ');
            formData.set('prodotti', prodotti);

            try {
                const response = await fetch('/admin/api/genera-preventivo', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();

                document.getElementById('loading').classList.remove('active');

                if (data.success) {
                    currentPreventivoId = data.preventivo_id;
                    document.getElementById('ai-response-text').textContent = data.preventivo_ai;
                    document.getElementById('ai-result').style.display = 'block';
                } else {
                    alert('Errore: ' + data.error);
                }
            } catch (err) {
                document.getElementById('loading').classList.remove('active');
                alert('Errore di connessione');
            }
        }

        async function inviaConferma() {
            if (!currentPreventivoId) return;
            try {
                const response = await fetch('/admin/api/invia-conferma/' + currentPreventivoId, { method: 'POST' });
                const data = await response.json();
                if (data.success) {
                    alert('✅ Email di conferma inviata a ' + document.getElementById('cliente_email').value);
                    closeModal('nuovo');
                    location.reload();
                } else {
                    alert('Errore: ' + data.error);
                }
            } catch (err) {
                alert('Errore di connessione: ' + err.message);
            }
        }

        function rigeneraAI() {
            // Reset e rigenera
            document.getElementById('ai-result').style.display = 'none';
            document.getElementById('form-preventivo').dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
        }

        async function viewPreventivo(id) {
            try {
                const response = await fetch('/admin/api/preventivo/' + id);
                const data = await response.json();
                if (data.success) {
                    document.getElementById('view-content').innerHTML = `
                        <p><strong>Cliente:</strong> ${data.preventivo.cliente_nome}</p>
                        <p><strong>Email:</strong> ${data.preventivo.cliente_email}</p>
                        <p><strong>Telefono:</strong> ${data.preventivo.cliente_telefono || 'N/A'}</p>
                        <p><strong>Prodotti:</strong> ${data.preventivo.prodotti}</p>
                        <p><strong>Stato:</strong> <span class="status-badge status-${data.preventivo.stato}">${data.preventivo.stato}</span></p>
                        <hr style="margin:20px 0">
                        <h4>Richiesta:</h4>
                        <p>${data.preventivo.richiesta}</p>
                        <hr style="margin:20px 0">
                        <h4>Preventivo AI:</h4>
                        <pre style="background:#f5f5f5;padding:15px;border-radius:8px;white-space:pre-wrap">${data.preventivo.preventivo_ai || 'Non ancora generato'}</pre>
                    `;
                    openModal('view');
                }
            } catch (err) {
                alert('Errore caricamento');
            }
        }

        async function approvaPreventivo(id) {
            if (confirm('Vuoi approvare e inviare questo preventivo al cliente?')) {
                try {
                    const response = await fetch('/admin/api/approva/' + id, { method: 'POST' });
                    const data = await response.json();
                    if (data.success) {
                        alert('✅ Preventivo approvato e inviato!');
                        location.reload();
                    } else {
                        alert('Errore: ' + data.error);
                    }
                } catch (err) {
                    alert('Errore');
                }
            }
        }

        // Mostra data corrente nel welcome banner
        (function() {
            var now = new Date();
            var days = ['Dom', 'Lun', 'Mar', 'Mer', 'Gio', 'Ven', 'Sab'];
            var months = ['Gennaio', 'Febbraio', 'Marzo', 'Aprile', 'Maggio', 'Giugno', 'Luglio', 'Agosto', 'Settembre', 'Ottobre', 'Novembre', 'Dicembre'];
            document.getElementById('currentDay').textContent = now.getDate();
            document.getElementById('currentMonth').textContent = months[now.getMonth()] + ' ' + now.getFullYear();
        })();
    </script>
</body>
</html>'''

# ============================================
# ADMIN ROUTES
# ============================================

@app.route('/admin')
@app.route('/admin/')
def admin_home():
    if 'admin_user' in session:
        return redirect('/admin/dashboard')
    return redirect('/admin/login')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    ip = get_real_ip()
    locked_time = 0

    # Controlla se IP è bloccato
    if is_ip_blocked_login(ip):
        locked_time = get_remaining_lockout(ip)
        error = f"🔒 Troppi tentativi! Riprova tra {locked_time // 60} minuti e {locked_time % 60} secondi"
        log_security_event("BLOCKED_LOGIN_ATTEMPT", ip, f"IP still blocked, {locked_time}s remaining")
        return render_template_string(ADMIN_LOGIN_PAGE, error=error)

    if request.method == 'POST':
        username = request.form.get('username', '').lower().strip()
        password = request.form.get('password', '')

        # Controlla se account specifico è bloccato
        if is_account_locked(username):
            locked_time = get_remaining_lockout(ip, username)
            error = f"🔒 Account temporaneamente bloccato. Riprova tra {locked_time} secondi"
            record_login_attempt(ip, username, False)
            return render_template_string(ADMIN_LOGIN_PAGE, error=error)

        # Applica delay progressivo (anti brute-force)
        delay = get_login_delay(ip)
        if delay > 0:
            time.sleep(min(delay, 5))  # Max 5 sec delay per non bloccare troppo

        if verify_admin(username, password):
            record_login_attempt(ip, username, True)
            session['admin_user'] = username
            session.permanent = True
            return redirect('/admin/dashboard')
        else:
            record_login_attempt(ip, username, False)
            attempts_left = MAX_LOGIN_ATTEMPTS - failed_logins.get(ip, 0)
            if attempts_left > 0:
                error = f"❌ Credenziali non valide ({attempts_left} tentativi rimasti)"
            else:
                locked_time = get_remaining_lockout(ip)
                error = f"🔒 Troppi tentativi! Bloccato per {locked_time // 60} minuti"

    return render_template_string(ADMIN_LOGIN_PAGE, error=error)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_user', None)
    return redirect('/admin/login')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db()
    c = conn.cursor()

    # Stats
    c.execute('SELECT COUNT(*) FROM preventivi')
    totali = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM preventivi WHERE stato = 'nuovo'")
    nuovi = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM preventivi WHERE stato IN ('ai_generato', 'attesa_conferma')")
    attesa = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM preventivi WHERE stato = 'inviato'")
    inviati = c.fetchone()[0]

    # Preventivi
    c.execute('SELECT * FROM preventivi ORDER BY data_creazione DESC LIMIT 50')
    preventivi = [dict(row) for row in c.fetchall()]

    # Richieste dal form contatti
    c.execute('SELECT * FROM richieste ORDER BY data DESC LIMIT 50')
    richieste = [dict(row) for row in c.fetchall()]

    conn.close()

    stats = {'totali': totali, 'nuovi': nuovi, 'attesa': attesa, 'inviati': inviati}

    return render_template_string(ADMIN_DASHBOARD_PAGE,
                                  username=session['admin_user'],
                                  stats=stats,
                                  preventivi=preventivi,
                                  richieste=richieste)

@app.route('/admin/api/genera-preventivo', methods=['POST'])
@admin_required
def api_genera_preventivo():
    cliente_nome = sanitize_input(request.form.get('cliente_nome', ''))
    cliente_email = sanitize_input(request.form.get('cliente_email', ''))
    cliente_telefono = sanitize_input(request.form.get('cliente_telefono', ''))
    prodotti = sanitize_input(request.form.get('prodotti', ''))
    richiesta = sanitize_input(request.form.get('richiesta', ''), 2000)

    if not cliente_nome or not cliente_email or not richiesta:
        return jsonify({'success': False, 'error': 'Campi obbligatori mancanti'})

    # Genera con AI
    preventivo_ai, error = generate_preventivo_ai(cliente_nome, prodotti, richiesta)

    if error:
        return jsonify({'success': False, 'error': error})

    # Salva nel DB
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO preventivi (cliente_nome, cliente_email, cliente_telefono, prodotti, richiesta, preventivo_ai, stato, creato_da)
                 VALUES (?, ?, ?, ?, ?, ?, 'ai_generato', ?)''',
              (cliente_nome, cliente_email, cliente_telefono, prodotti, richiesta, preventivo_ai, session['admin_user']))
    preventivo_id = c.lastrowid
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'preventivo_id': preventivo_id, 'preventivo_ai': preventivo_ai})

@app.route('/admin/api/preventivo/<int:id>')
@admin_required
def api_get_preventivo(id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM preventivi WHERE id = ?', (id,))
    row = c.fetchone()
    conn.close()

    if row:
        return jsonify({'success': True, 'preventivo': dict(row)})
    return jsonify({'success': False, 'error': 'Non trovato'})

@app.route('/admin/api/invia-conferma/<int:id>', methods=['POST'])
@admin_required
def api_invia_conferma(id):
    success, error = send_confirmation_request(id, EMAIL_SENDER)
    if success:
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE preventivi SET stato = 'attesa_conferma' WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': error or 'Errore invio email'})

@app.route('/admin/api/approva/<int:id>', methods=['POST'])
@admin_required
def api_approva_preventivo(id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM preventivi WHERE id = ?', (id,))
    prev = c.fetchone()

    if not prev:
        return jsonify({'success': False, 'error': 'Non trovato'})

    # Invia preventivo al cliente
    html = f"""
    <html><body style="font-family: Arial, sans-serif; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background: #f9f9f9; padding: 30px; border-radius: 10px;">
        <h2 style="color: #1a1a2e;">Preventivo da Spallanzani Rappresentanze</h2>
        <p>Gentile {prev['cliente_nome']},</p>
        <p>Ecco il preventivo richiesto:</p>
        <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <pre style="white-space: pre-wrap; font-family: Arial;">{prev['preventivo_ai']}</pre>
        </div>
        <p>Per qualsiasi domanda non esiti a contattarci:</p>
        <p>📧 spallanzanirappresentanze@gmail.com<br>📞 059 123456</p>
        <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #666; font-size: 12px;">Spallanzani Rappresentanze - Infissi e Serramenti Premium</p>
    </div>
    </body></html>
    """

    success, error = send_email(prev['cliente_email'], "Il tuo Preventivo - Spallanzani Rappresentanze", html)

    if success:
        c.execute("UPDATE preventivi SET stato = 'inviato', data_invio = ? WHERE id = ?",
                  (datetime.now().isoformat(), id))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

    conn.close()
    return jsonify({'success': False, 'error': error or 'Errore invio'})

@app.route('/admin/conferma/<token>')
def conferma_preventivo(token):
    if token not in pending_confirmations:
        return "Token non valido o scaduto", 404

    conf = pending_confirmations[token]
    if datetime.now() > conf['expires']:
        del pending_confirmations[token]
        return "Token scaduto", 404

    preventivo_id = conf['preventivo_id']

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM preventivi WHERE id = ?', (preventivo_id,))
    prev = c.fetchone()

    if not prev:
        return "Preventivo non trovato", 404

    # Invia al cliente
    html = f"""
    <html><body style="font-family: Arial, sans-serif; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background: #f9f9f9; padding: 30px; border-radius: 10px;">
        <h2 style="color: #1a1a2e;">Preventivo da Spallanzani Rappresentanze</h2>
        <p>Gentile {prev['cliente_nome']},</p>
        <p>Ecco il preventivo richiesto:</p>
        <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <pre style="white-space: pre-wrap; font-family: Arial;">{prev['preventivo_ai']}</pre>
        </div>
        <p>Per qualsiasi domanda non esiti a contattarci:</p>
        <p>📧 spallanzanirappresentanze@gmail.com</p>
    </div>
    </body></html>
    """

    success, _ = send_email(prev['cliente_email'], "Il tuo Preventivo - Spallanzani Rappresentanze", html)

    if success:
        c.execute("UPDATE preventivi SET stato = 'inviato', data_invio = ? WHERE id = ?",
                  (datetime.now().isoformat(), preventivo_id))
        conn.commit()
        del pending_confirmations[token]

    conn.close()

    return """<!DOCTYPE html><html><head><title>Confermato!</title>
    <style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#e8f5e9;}
    .box{text-align:center;padding:50px;}.icon{font-size:80px;}</style></head>
    <body><div class="box"><div class="icon">✅</div><h1>Preventivo Inviato!</h1><p>Il cliente riceverà l'email a breve.</p></div></body></html>"""

@app.route('/admin/rifiuta/<token>')
def rifiuta_preventivo(token):
    if token in pending_confirmations:
        preventivo_id = pending_confirmations[token]['preventivo_id']
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE preventivi SET stato = 'rifiutato' WHERE id = ?", (preventivo_id,))
        conn.commit()
        conn.close()
        del pending_confirmations[token]

    return """<!DOCTYPE html><html><head><title>Rifiutato</title>
    <style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#ffebee;}
    .box{text-align:center;padding:50px;}.icon{font-size:80px;}</style></head>
    <body><div class="box"><div class="icon">❌</div><h1>Preventivo Rifiutato</h1><p>Il preventivo non verrà inviato.</p></div></body></html>"""

# Route per monitoraggio sicurezza (protetta)
@app.route('/security-status/<secret_key>')
def security_status(secret_key):
    # Chiave segreta per accesso
    if secret_key != 'spallanzani2024secure':
        abort(404)

    blocked_list = [(ip, datetime.fromtimestamp(exp).strftime("%H:%M:%S")) for ip, exp in blocked_ips.items()]
    suspicious_list = [(ip, count) for ip, count in suspicious_ips.items() if count > 0]

    return f'''<!DOCTYPE html><html><head><title>Security Status</title>
    <style>body{{font-family:monospace;background:#1a1a1a;color:#0f0;padding:40px;}}
    h1{{color:#fff;}}table{{border-collapse:collapse;width:100%;margin:20px 0;}}
    td,th{{border:1px solid #333;padding:10px;text-align:left;}}</style></head>
    <body><h1>🛡️ Security Dashboard</h1>
    <h2>IP Bloccati ({len(blocked_list)})</h2>
    <table><tr><th>IP</th><th>Scade alle</th></tr>
    {''.join(f'<tr><td>{ip}</td><td>{exp}</td></tr>' for ip, exp in blocked_list) or '<tr><td colspan="2">Nessuno</td></tr>'}
    </table>
    <h2>IP Sospetti ({len(suspicious_list)})</h2>
    <table><tr><th>IP</th><th>Score</th></tr>
    {''.join(f'<tr><td>{ip}</td><td>{count}</td></tr>' for ip, count in sorted(suspicious_list, key=lambda x: -x[1])[:20]) or '<tr><td colspan="2">Nessuno</td></tr>'}
    </table>
    <p>Log file: {SECURITY_LOG}</p></body></html>'''

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🛡️  SPALLANZANI SECURE SERVER")
    print("="*50)
    print("✅ SSTI Protection: ACTIVE")
    print("✅ XSS Protection: ACTIVE")
    print("✅ Rate Limiting: ACTIVE")
    print("✅ Nmap Detection: ACTIVE")
    print("✅ Security Headers: ACTIVE")
    print("✅ Input Sanitization: ACTIVE")
    print("✅ Honeypot Anti-Bot: ACTIVE")
    print("="*50)
    print("📊 Security Dashboard: /security-status/spallanzani2024secure")
    print("📝 Security Log: security.log")
    print("="*50 + "\n")
    app.run(host='0.0.0.0', port=3000, debug=False, threaded=True)
