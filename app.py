#!/usr/bin/env python3
from flask import Flask, render_template_string, request, jsonify, redirect, session, abort, g
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
            background: #fff;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 35px 25px;
            text-align: center;
            cursor: pointer;
            transition: transform 0.15s ease;
        }
        .brand-card:hover { transform: translateY(-4px); }
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

        /* Products */
        .products-container { max-width: 1500px; margin: 0 auto; }
        .brand-section { margin-bottom: 100px; }
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
            background: #fff;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
            cursor: pointer;
            transition: transform 0.15s ease;
        }
        .product-card:hover { transform: translateY(-4px); }
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

    <section class="section section-alt" id="marchi">
        <div class="section-header">
            <h2>I Marchi che <span>Rappresentiamo</span></h2>
            <div class="accent-bar"></div>
            <p>Partner esclusivi dei migliori brand italiani nel settore porte e serramenti</p>
        </div>
        <div class="brands-grid">
            <div class="brand-card"><div class="brand-title">FLESSYA</div><div class="brand-name">Flessya</div><div class="brand-desc">Porte per interni Made in Italy. Linee Nidio, Kikka, Vetra con oltre 100 finiture.</div></div>
            <div class="brand-card"><div class="brand-title">MONDOCASA</div><div class="brand-name">Mondocasa</div><div class="brand-desc">Serramenti in PVC ad alto isolamento termico e acustico.</div></div>
            <div class="brand-card"><div class="brand-title">EPROD</div><div class="brand-name">Eproditalia</div><div class="brand-desc">Infissi in alluminio a taglio termico di ultima generazione.</div></div>
            <div class="brand-card"><div class="brand-title">ARIENI</div><div class="brand-name">Arieni Maniglie</div><div class="brand-desc">Maniglieria di design in ottone e acciaio dal 1997.</div></div>
            <div class="brand-card"><div class="brand-title">Di.Bi.</div><div class="brand-name">Di.Bi. Blindate</div><div class="brand-desc">Porte blindate certificate classe 3, 4 e 5 dal 1976.</div></div>
        </div>
    </section>

    <section class="section" id="prodotti">
        <div class="section-header">
            <h2>I Nostri <span>Prodotti</span></h2>
            <div class="accent-bar"></div>
            <p>Catalogo completo diviso per brand - Doppio click per rotazione 3D</p>
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
                        <button class="quick-btn" onclick="quickMsg('Marchi')">Marchi</button>
                        <button class="quick-btn" onclick="quickMsg('Preventivo')">Preventivo</button>
                        <button class="quick-btn" onclick="quickMsg('Zone')">Zone</button>
                        <button class="quick-btn" onclick="quickMsg('Flessya')">Flessya</button>
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
        a4: { brand: 'Arieni', name: 'Area 51 Nera', img: 'https://www.arienisrl.com/wp-content/uploads/2020/09/Area51-1200x600-nera.png', ai: "L'Area 51 Nera incarna la tendenza total black. Nero opaco per design audace e di tendenza.", specs: [['Materiale', 'Ottone'], ['Finitura', 'Nero Opaco'], ['Stile', 'Total Black'], ['Garanzia', '2 anni']] }
    };

    // ===== FUNZIONI GLOBALI (chiamate da onclick) =====

    // Toggle Chat AI
    function toggleSmart() {
        var chat = document.getElementById('smartChat');
        if (chat) {
            chat.classList.toggle('active');
        }
    }

    // Invia messaggio chat
    function sendSmart() {
        var inp = document.getElementById('smartInput');
        if (!inp) return;
        var msg = inp.value.trim();
        if (!msg) return;
        addMsg(msg, 'user');
        inp.value = '';
        showTyping();
        setTimeout(function() {
            removeTyping();
            addMsg(getResponse(msg), 'bot');
        }, 600);
    }

    // Quick message
    function quickMsg(m) {
        addMsg(m, 'user');
        showTyping();
        setTimeout(function() {
            removeTyping();
            addMsg(getResponse(m), 'bot');
        }, 500);
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

@app.route('/')
@rate_limit(max_requests=60, window=60)
def home():
    return render_template_string(MAIN_PAGE, csrf_token=g.csrf_token)

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
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f0f2f5;
            min-height: 100vh;
        }
        .navbar {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .navbar h1 { color: #fff; font-size: 22px; }
        .navbar h1 span { color: #c9a227; }
        .navbar-right { display: flex; align-items: center; gap: 20px; }
        .user-badge {
            background: rgba(201,162,39,0.2);
            color: #c9a227;
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: 600;
        }
        .logout-btn {
            background: #dc3545;
            color: white;
            border: none;
            padding: 8px 20px;
            border-radius: 20px;
            cursor: pointer;
            text-decoration: none;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 30px; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        .stat-card .icon { font-size: 40px; margin-bottom: 10px; }
        .stat-card .number { font-size: 36px; font-weight: 700; color: #1a1a2e; }
        .stat-card .label { color: #666; margin-top: 5px; }
        .card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        .card h2 { color: #1a1a2e; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
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
            background: linear-gradient(135deg, #667eea15, #764ba215);
            border: 2px solid #667eea;
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
        }
        .ai-box h4 { color: #667eea; margin-bottom: 10px; }
        .ai-response { background: white; padding: 15px; border-radius: 8px; white-space: pre-wrap; font-family: monospace; font-size: 13px; }
        .loading { display: none; text-align: center; padding: 20px; }
        .loading.active { display: block; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #667eea; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .navbar { flex-direction: column; gap: 15px; }
        }
        /* Floating Gemini AI Button */
        .gemini-float {
            position: fixed;
            bottom: 30px;
            right: 30px;
            z-index: 999;
            display: flex;
            align-items: flex-end;
            gap: 15px;
        }
        .gemini-bubble {
            background: white;
            padding: 15px 20px;
            border-radius: 20px 20px 5px 20px;
            box-shadow: 0 5px 25px rgba(102,126,234,0.3);
            max-width: 250px;
            animation: bubblePop 0.5s ease;
        }
        .gemini-bubble p { margin: 0; color: #333; font-size: 14px; }
        .gemini-bubble strong { color: #667eea; }
        @keyframes bubblePop {
            0% { opacity: 0; transform: scale(0.8) translateY(20px); }
            100% { opacity: 1; transform: scale(1) translateY(0); }
        }
        .gemini-btn {
            width: 70px;
            height: 70px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border: none;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            box-shadow: 0 5px 25px rgba(102,126,234,0.4);
            transition: all 0.3s;
            animation: pulse 2s infinite;
        }
        .gemini-btn:hover { transform: scale(1.1); box-shadow: 0 8px 35px rgba(102,126,234,0.5); }
        @keyframes pulse {
            0%, 100% { box-shadow: 0 5px 25px rgba(102,126,234,0.4); }
            50% { box-shadow: 0 5px 35px rgba(102,126,234,0.6); }
        }
        /* Gold accent like main site */
        .gold-accent { color: #c9a227; }
        .card-gold { border-left: 4px solid #c9a227; }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>SPALLANZANI<span>®</span> Dashboard</h1>
        <div class="navbar-right">
            <div class="user-badge">👤 {{ username }}</div>
            <a href="/admin/logout" class="logout-btn">Logout</a>
        </div>
    </nav>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="icon">📋</div>
                <div class="number">{{ stats.totali }}</div>
                <div class="label">Preventivi Totali</div>
            </div>
            <div class="stat-card">
                <div class="icon">🆕</div>
                <div class="number">{{ stats.nuovi }}</div>
                <div class="label">Nuovi</div>
            </div>
            <div class="stat-card">
                <div class="icon">⏳</div>
                <div class="number">{{ stats.attesa }}</div>
                <div class="label">In Attesa Conferma</div>
            </div>
            <div class="stat-card">
                <div class="icon">✅</div>
                <div class="number">{{ stats.inviati }}</div>
                <div class="label">Inviati</div>
            </div>
        </div>

        <div class="card">
            <h2>🤖 Nuovo Preventivo con AI</h2>
            <button class="btn btn-ai" onclick="openModal('nuovo')">+ Crea Preventivo con Gemini AI</button>
        </div>

        <div class="card">
            <h2>📊 Elenco Preventivi</h2>
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
            <h2>📬 Richieste dal Sito</h2>
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
                <h2>🤖 Nuovo Preventivo con AI</h2>
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
                <p style="margin-top:15px;color:#667eea">Gemini AI sta elaborando il preventivo...</p>
            </div>

            <div class="ai-box" id="ai-result" style="display:none">
                <h4>🤖 Preventivo Generato dall'AI</h4>
                <div class="ai-response" id="ai-response-text"></div>
                <div style="margin-top:20px;display:flex;gap:10px">
                    <button class="btn btn-success" onclick="inviaConferma()">📧 Invia per Conferma</button>
                    <button class="btn btn-primary" onclick="rigeneraAI()">🔄 Rigenera</button>
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

    <!-- Floating Gemini AI Button -->
    <div class="gemini-float">
        <div class="gemini-bubble" id="gemini-bubble">
            <p>👋 <strong>Ciao!</strong> Sono Gemini AI.<br>Clicca qui per creare un preventivo automatico!</p>
        </div>
        <button class="gemini-btn" onclick="openModal('nuovo')" title="Crea Preventivo con AI">
            🤖
        </button>
    </div>

    <script>
        let currentPreventivoId = null;

        // Nascondi bubble dopo 10 secondi
        setTimeout(() => {
            const bubble = document.getElementById('gemini-bubble');
            if (bubble) bubble.style.display = 'none';
        }, 10000);

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
                    alert('✅ Email di conferma inviata!');
                    closeModal('nuovo');
                    location.reload();
                } else {
                    alert('Errore: ' + data.error);
                }
            } catch (err) {
                alert('Errore di connessione');
            }
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
