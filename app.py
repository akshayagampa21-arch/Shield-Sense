import os, re, io, csv, json, uuid, sqlite3, secrets, smtplib, hashlib, time
from email.mime.text import MIMEText
from datetime import datetime, timezone, timedelta
from functools import wraps
from collections import defaultdict, deque
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, jsonify, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from google import genai

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'shieldsense.db')
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'webp', 'doc', 'docx', 'csv', 'json', 'xml', 'html', 'eml'}
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')

# --- Tunables -----------------------------------------------------------
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 45
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
MAX_BULK_ITEMS = 25


# --- DB -------------------------------------------------------------------
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        profile_image TEXT,
        is_verified INTEGER NOT NULL DEFAULT 0,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        scan_type TEXT NOT NULL,
        input_preview TEXT,
        score INTEGER NOT NULL,
        danger TEXT NOT NULL,
        summary TEXT NOT NULL,
        reasons TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS otp_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        purpose TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        payload TEXT,
        attempts INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    ''')
    # Lightweight migration for DBs created by an older version of this app.
    cols = {r['name'] for r in con.execute('PRAGMA table_info(users)').fetchall()}
    if 'is_verified' not in cols:
        con.execute('ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 1')
    if 'failed_attempts' not in cols:
        con.execute('ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0')
    if 'locked_until' not in cols:
        con.execute('ALTER TABLE users ADD COLUMN locked_until TEXT')
    con.commit(); con.close()


init_db()


def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    con = db(); user = con.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone(); con.close()
    return user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return jsonify({'ok': False, 'error': 'Please log in to continue.'}), 401
        return fn(*args, **kwargs)
    return wrapper


def allowed_file(name):
    return '.' in name and name.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def clamp_score(n):
    return max(0, min(100, int(n)))


# --- CSRF protection --------------------------------------------------------
# Session-backed double-submit token: the frontend reads it from /api/csrf-token
# and echoes it back in the X-CSRF-Token header on every state-changing call.
@app.before_request
def ensure_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(20)


def csrf_protect(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        sent = request.headers.get('X-CSRF-Token', '')
        if not sent or sent != session.get('csrf_token'):
            return jsonify({'ok': False, 'error': 'Your session expired, please refresh the page and try again.'}), 403
        return fn(*args, **kwargs)
    return wrapper


@app.get('/api/csrf-token')
def csrf_token():
    return jsonify({'csrf_token': session['csrf_token']})


# --- Simple in-memory rate limiting -----------------------------------------
# Good enough for a single-process hackathon deployment. For real production
# traffic across multiple workers, swap this for Flask-Limiter + Redis.
_rate_buckets = defaultdict(deque)


def rate_limit(max_calls, window_seconds):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = f'{fn.__name__}:{request.remote_addr}'
            now = time.time()
            bucket = _rate_buckets[key]
            while bucket and now - bucket[0] > window_seconds:
                bucket.popleft()
            if len(bucket) >= max_calls:
                return jsonify({'ok': False, 'error': 'Too many attempts. Please wait a moment and try again.'}), 429
            bucket.append(now)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# --- OTP helpers -------------------------------------------------------------
def generate_otp():
    return ''.join(secrets.choice('0123456789') for _ in range(OTP_LENGTH))


def hash_otp(code):
    return hashlib.sha256(code.encode()).hexdigest()


def send_email(to_email, subject, body):
    """Sends via SMTP if configured, otherwise logs to the console.
    Returns True if an SMTP send happened, False if it fell back to console/dev mode."""
    host = os.environ.get('SMTP_HOST')
    if not host:
        app.logger.info('[DEV MODE - no SMTP configured] Email to %s | %s\n%s', to_email, subject, body)
        return False
    try:
        port = int(os.environ.get('SMTP_PORT', 587))
        user = os.environ.get('SMTP_USER')
        password = os.environ.get('SMTP_PASS')
        sender = os.environ.get('SMTP_FROM', user or 'no-reply@shieldsense.app')
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = to_email
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(sender, [to_email], msg.as_string())
        return True
    except Exception as e:
        app.logger.warning('SMTP send failed, falling back to console log: %s', e)
        app.logger.info('[DEV MODE FALLBACK] Email to %s | %s\n%s', to_email, subject, body)
        return False


def issue_otp(email, purpose, payload=None):
    code = generate_otp()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat()
    con = db()
    con.execute('DELETE FROM otp_codes WHERE email=? AND purpose=?', (email, purpose))
    con.execute(
        'INSERT INTO otp_codes(email,purpose,code_hash,payload,expires_at,created_at) VALUES(?,?,?,?,?,?)',
        (email, purpose, hash_otp(code), json.dumps(payload or {}), expires, datetime.now(timezone.utc).isoformat())
    )
    con.commit(); con.close()
    subject = 'Your ShieldSense verification code' if purpose == 'signup' else 'Your ShieldSense password reset code'
    body = f'Your ShieldSense code is {code}. It expires in {OTP_EXPIRY_MINUTES} minutes. If you did not request this, you can ignore this email.'
    sent_via_smtp = send_email(email, subject, body)
    return code, sent_via_smtp


def verify_otp(email, purpose, code):
    con = db()
    row = con.execute('SELECT * FROM otp_codes WHERE email=? AND purpose=? ORDER BY id DESC LIMIT 1', (email, purpose)).fetchone()
    if not row:
        con.close(); return False, 'No verification code was requested for this email.', None
    if datetime.fromisoformat(row['expires_at']) < datetime.now(timezone.utc):
        con.execute('DELETE FROM otp_codes WHERE id=?', (row['id'],)); con.commit(); con.close()
        return False, 'This code has expired. Please request a new one.', None
    if row['attempts'] >= OTP_MAX_ATTEMPTS:
        con.close(); return False, 'Too many incorrect attempts. Please request a new code.', None
    if hash_otp(code) != row['code_hash']:
        con.execute('UPDATE otp_codes SET attempts=attempts+1 WHERE id=?', (row['id'],)); con.commit(); con.close()
        return False, 'Incorrect code. Please try again.', None
    payload = json.loads(row['payload'] or '{}')
    con.execute('DELETE FROM otp_codes WHERE id=?', (row['id'],)); con.commit(); con.close()
    return True, None, payload


# --- Risk analysis --------------------------------------------------------
# Two layers feed the final verdict:
#   1) heuristic_score()   - deterministic, offline signal-based checks (fast,
#                             always available, good at catching structural
#                             red flags like typosquatting or IP-literal hosts).
#   2) analyze_with_gemini() - contextual/semantic judgement from the model,
#                             grounded with live Google Search so it can check
#                             the *actual* reputation of a domain/brand instead
#                             of guessing from the raw string alone.
# combine_analysis() blends both into one score instead of either one being
# the sole source of truth - this is what makes the verdict resilient even
# when the AI call fails, times out, or returns something malformed.

POPULAR_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook',
    'instagram', 'whatsapp', 'chase', 'bankofamerica', 'wellsfargo', 'irs',
    'dhl', 'fedex', 'ups', 'usps', 'linkedin', 'dropbox', 'adobe', 'coinbase',
    'binance', 'outlook', 'office365', 'icloud', 'steam', 'netflixbilling',
]
SUSPICIOUS_TLDS = {
    'zip', 'mov', 'top', 'xyz', 'work', 'click', 'link', 'support', 'fit',
    'gq', 'cf', 'tk', 'ml', 'ga', 'quest', 'country', 'kim', 'loan', 'men',
}
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy',
}

# Well-known, legitimate security-testing/reference domains. Flagging these as
# "dangerous" would itself be a false positive - they exist specifically so
# scanners and antivirus tools can be tested safely. Instead of a bare,
# unexplained SAFE score (which looks like the scanner failed to understand
# the input), give the user the actual context.
KNOWN_TEST_DOMAINS = {
    'eicar.org': (
        'This is the official EICAR (European Institute for Computer Antivirus '
        'Research) site. It hosts the industry-standard EICAR test file - a '
        'harmless text string every antivirus product is designed to flag as '
        '"malware detected" so you can confirm your scanner is actually working. '
        'The page and the test file cannot damage anything; a good antivirus '
        'SHOULD alert on the downloaded file, and that alert is expected, not a '
        'sign of a real infection.'
    ),
    'testsafebrowsing.appspot.com': (
        'This is Google\'s official test harness for the Safe Browsing API. Its '
        'sub-pages intentionally simulate phishing and malware pages so '
        'developers can verify their Safe Browsing integration reacts correctly. '
        'The site itself is legitimate Google infrastructure and is not '
        'distributing real threats.'
    ),
    'badssl.com': (
        'This is a well-known diagnostic site used to test how browsers handle '
        'various TLS/SSL certificate configurations (expired, self-signed, '
        'wrong-host, etc.). The root site\'s own certificate is valid; specific '
        'labelled sub-pages (e.g. expired.badssl.com) are intentionally '
        'misconfigured for testing and are safe to visit for that purpose.'
    ),
}

# Specific sub-pages that are DELIBERATELY registered on Google's real Safe
# Browsing blocklist as test entries for MALWARE/PHISHING detection - unlike
# the rest of testsafebrowsing.appspot.com, these exact paths SHOULD be
# flagged as dangerous by a working scanner. Content is inert (just an inert
# HTML page), so it is safe to visit, but the verdict must say "flagged" -
# that is the entire point of these URLs existing.
KNOWN_TEST_MALICIOUS_PATHS = {
    ('testsafebrowsing.appspot.com', '/s/malware.html'): 'MALWARE',
    ('testsafebrowsing.appspot.com', '/s/phishing.html'): 'SOCIAL_ENGINEERING / PHISHING',
    ('testsafebrowsing.appspot.com', '/s/social_engineering_extended_coverage.html'): 'SOCIAL_ENGINEERING / PHISHING',
    ('testsafebrowsing.appspot.com', '/s/unwanted_software.html'): 'UNWANTED_SOFTWARE',
    ('testsafebrowsing.appspot.com', '/s/billing.html'): 'BILLING (deceptive)',
}

# The exact 68-byte EICAR antivirus test signature. Any file/text containing
# this string is, by definition, the EICAR test file - flag it as "detected"
# (matching real antivirus behavior) while being clear it is not real malware.
EICAR_SIGNATURE = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def _levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def _domain_of(url):
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        return (parsed.hostname or '').lower()
    except Exception:
        return ''


def _path_of(url):
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        return parsed.path or '/'
    except Exception:
        return '/'


def heuristic_score(scan_type, value):
    text = (value or '').strip()
    lower = text.lower()
    score = 5
    flags = []

    # --- Structural URL checks (highest-signal, lowest false-positive-rate) --
    if scan_type == 'url':
        domain = _domain_of(text)
        if not lower.startswith(('http://', 'https://')):
            score += 15; flags.append('URL does not start with a normal http:// or https:// scheme.')
        if lower.startswith('http://'):
            score += 8; flags.append('The connection is not encrypted (no HTTPS).')
        if '@' in text:
            score += 25; flags.append('URL contains an "@" symbol, a classic trick to hide the real destination.')
        if domain and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            score += 25; flags.append('The link points directly to a raw IP address instead of a domain name.')
        if 'xn--' in domain:
            score += 20; flags.append('Domain uses punycode, often used to spoof lookalike characters (e.g. "pаypal" with a Cyrillic a).')
        if domain.count('-') >= 3:
            score += 8; flags.append('Domain contains an unusually high number of hyphens.')
        if domain.count('.') >= 4:
            score += 8; flags.append('Domain has an unusually deep subdomain chain, often used to bury the real host.')
        tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
        if tld in SUSPICIOUS_TLDS:
            score += 10; flags.append(f'Uses the ".{tld}" top-level domain, which is disproportionately common in scam campaigns.')
        if domain in URL_SHORTENERS:
            score += 12; flags.append('This is a link-shortener - the real destination is hidden until you click it.')
        # Typosquatting / brand-impersonation: is a well-known brand name used
        # somewhere in the hostname without actually being the brand's own
        # registrable domain? (e.g. "paypal.secure-update-account.com" - the
        # word "paypal" is just a deceptive subdomain, the real domain is
        # "secure-update-account.com".)
        labels = [l for l in domain.split('.') if l]
        registrable_root = labels[-2] if len(labels) >= 2 else (labels[0] if labels else '')
        for brand in POPULAR_BRANDS:
            if registrable_root == brand:
                break  # looks like the brand's own domain (e.g. paypal.com) - not flagged
            if brand in labels and registrable_root != brand:
                score += 30
                flags.append(f'"{brand}" appears as a subdomain of "{".".join(labels[-2:]) if len(labels) >= 2 else domain}" instead of being the real domain - a classic impersonation trick.')
                break
            for token in [registrable_root] + registrable_root.split('-'):
                dist = _levenshtein(token, brand)
                if 0 < dist <= 2 and len(token) >= 4:
                    score += 28
                    flags.append(f'Domain "{domain}" closely mimics the brand "{brand}" (looks like typosquatting).')
                    break
            else:
                continue
            break

    # --- Shared keyword / social-engineering language checks -----------------
    urgency_words = ['urgent', 'immediately', 'suspend', 'verify your account', 'act now', 'limited time', 'final notice', 'unusual activity']
    credential_words = ['login', 'password', 'verify', 'confirm your identity', 'social security', 'ssn', 'otp', 'one-time code']
    financial_words = ['wallet', 'bank', 'wire transfer', 'gift card', 'bitcoin', 'crypto', 'invoice overdue', 'refund']
    lure_words = ['free-money', 'you won', 'claim your prize', 'gift', 'lottery']
    hits = []
    for bucket, words, weight in (('urgency', urgency_words, 6), ('credential', credential_words, 6), ('financial', financial_words, 6), ('lure', lure_words, 8)):
        for w in words:
            if w in lower:
                hits.append((bucket, w, weight))
    # Require signal from more than one category before scoring heavily -
    # a single common word like "verify" shouldn't alone tank a score.
    categories_hit = {b for b, _, _ in hits}
    for bucket, w, weight in hits[:6]:
        score += weight if len(categories_hit) > 1 else max(2, weight - 3)
        flags.append(f'Contains suspicious language: "{w}".')

    return clamp_score(score), flags[:8]


def gemini_client():
    key = os.environ.get('GEMINI_API_KEY')
    if not key:
        return None
    return genai.Client(api_key=key)


RESPONSE_SCHEMA = {
    'type': 'OBJECT',
    'properties': {
        'score': {'type': 'INTEGER'},
        'danger': {'type': 'STRING', 'enum': ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']},
        'summary': {'type': 'STRING'},
        'reasons': {'type': 'ARRAY', 'items': {'type': 'STRING'}},
        'recommendation': {'type': 'STRING'},
    },
    'required': ['score', 'danger', 'summary', 'reasons', 'recommendation'],
}


_last_ai_error = {'when': None, 'error': None}


def analyze_with_gemini(scan_type, value=None, uploaded_path=None, mime_type=None, hints=None):
    client = gemini_client()
    if not client:
        _last_ai_error['when'] = datetime.now(timezone.utc).isoformat()
        _last_ai_error['error'] = 'GEMINI_API_KEY is not set in the environment.'
        return None
    from google.genai import types as genai_types
    instruction = '''You are ShieldSense, an expert cybersecurity analyst. Analyze the supplied item (a URL, an email/message, or an uploaded file) for phishing, scam, malicious-download, credential-theft, brand impersonation, or other social-engineering risk.

Use web search to check the real reputation of any domain, sender, or brand mentioned before deciding - do not guess from the raw text alone. Consider: is this the brand's real, official domain? Is there active reporting of this domain/sender being used in scams? Does the file type/behaviour match known malware delivery patterns?

Score honestly on a 0-100 scale where 0 means clearly safe and 100 means confirmed dangerous. Do not default to the middle of the range - use the full scale, and say so plainly in "reasons" when evidence is limited rather than inflating or deflating the score to compensate.
Respond with the required JSON fields only.'''
    if hints:
        instruction += f'\n\nAutomated local scan already flagged these structural signals (verify and weigh them, do not just repeat them): {"; ".join(hints)}'
    try:
        config = genai_types.GenerateContentConfig(
            temperature=0.1,
            tools=[genai_types.Tool(google_search=genai_types.GoogleSearch())],
        )
        if uploaded_path:
            media = client.files.upload(file=uploaded_path)
            response = client.models.generate_content(model='gemini-3.7-flash', contents=[instruction, media], config=config)
        else:
            response = client.models.generate_content(model='gemini-3.7-flash', contents=f'{instruction}\n\nType: {scan_type}\nInput:\n{value}', config=config)
        raw = (response.text or '').strip()
        raw = re.sub(r'^```json\s*|^```\s*|\s*```$', '', raw, flags=re.I | re.M).strip()
        match = re.search(r'\{.*\}', raw, re.S)
        if match:
            raw = match.group(0)
        data = json.loads(raw)
        data['score'] = clamp_score(data.get('score', 50))
        data['danger'] = str(data.get('danger', 'MEDIUM')).upper()
        data['reasons'] = [str(r) for r in (data.get('reasons') or [])][:6]
        data['summary'] = str(data.get('summary', '')).strip() or 'Analysis completed.'
        data['recommendation'] = str(data.get('recommendation', '')).strip() or 'Verify independently before interacting.'
        _last_ai_error['when'] = None
        _last_ai_error['error'] = None
        return data
    except Exception as e:
        app.logger.warning('Gemini analysis failed: %s', e)
        _last_ai_error['when'] = datetime.now(timezone.utc).isoformat()
        _last_ai_error['error'] = f'{type(e).__name__}: {e}'
        return None



def _known_test_domain_result(domain):
    """Look up domain (and its registrable base) against KNOWN_TEST_DOMAINS."""
    if not domain:
        return None
    labels = [l for l in domain.split('.') if l]
    base = '.'.join(labels[-2:]) if len(labels) >= 2 else domain
    for known, note in KNOWN_TEST_DOMAINS.items():
        if domain == known or base == known or domain.endswith('.' + known):
            return known, note
    return None


def _known_test_malicious_result(domain, path):
    """Look up (domain, path) against KNOWN_TEST_MALICIOUS_PATHS - specific
    pages that ARE deliberately registered on a real threat blocklist for
    testing purposes and SHOULD be flagged, unlike the rest of their domain."""
    if not domain:
        return None
    norm_path = (path or '/').rstrip('/') or '/'
    for (d, p), threat_type in KNOWN_TEST_MALICIOUS_PATHS.items():
        if domain == d and norm_path == p.rstrip('/'):
            return threat_type
    return None


def _eicar_result():
    return {
        'score': 30,
        'danger': 'LOW',
        'summary': (
            'This content matches the official EICAR antivirus test signature - '
            'a standardized, harmless string that every antivirus engine is '
            'built to detect. It cannot run, spread, or damage anything. A '
            '"detected" result from an antivirus here is expected and correct, '
            'confirming the scanner works - it is not a sign of a real infection.'
        ),
        'reasons': [
            'Content matches the EICAR-STANDARD-ANTIVIRUS-TEST-FILE signature.',
            'This is an industry-standard test pattern, not functional malware.',
            'Safe to keep for testing purposes; do not treat it as a real threat.',
        ],
        'recommendation': 'No action needed - this is a test file working as designed.',
        'ai_assisted': False,
    }


def _file_contains_eicar(path):
    try:
        if os.path.getsize(path) > 1024 * 1024:
            return False
        with open(path, 'rb') as f:
            data = f.read(1024 * 1024)
        return EICAR_SIGNATURE.encode('ascii', errors='ignore') in data
    except Exception:
        return False


_scan_cache = {}
CACHE_TTL_SECONDS = 600


def combine_analysis(scan_type, value=None, path=None, mime=None):
    cache_key = None
    if not path:
        cache_key = hashlib.sha256(f'{scan_type}:{value}'.encode()).hexdigest()
        cached = _scan_cache.get(cache_key)
        if cached and time.time() - cached[0] < CACHE_TTL_SECONDS:
            return dict(cached[1])

    # --- Known-safe test/reference resources (checked first, deterministic) --
    if scan_type == 'url':
        domain = _domain_of(value or '')
        path = _path_of(value or '')
        # Check the specific-page "should be flagged" list BEFORE the
        # whole-domain "safe" list - a domain can host both.
        threat_type = _known_test_malicious_result(domain, path)
        if threat_type:
            result = {
                'score': 85,
                'danger': 'HIGH',
                'summary': (
                    f'This exact page is deliberately registered on Google\'s real '
                    f'Safe Browsing test blocklist under the "{threat_type}" threat '
                    f'type. It exists specifically so security scanners can verify '
                    f'they correctly detect and flag dangerous pages. A working '
                    f'scanner is SUPPOSED to flag this as dangerous - that is the '
                    f'whole point of the page. The content itself is inert and safe '
                    f'to view; do not treat this the same as a real, live threat.'
                ),
                'reasons': [
                    f'Registered on Google Safe Browsing\'s test list as: {threat_type}.',
                    'This is an official, documented test page (testsafebrowsing.appspot.com/s/...).',
                    'Correctly flagging this confirms the scanner is working as intended.',
                ],
                'recommendation': 'Treat as a successful detection test, not a real incident - no action needed beyond confirming your scanner caught it.',
                'ai_assisted': False,
            }
            if cache_key:
                _scan_cache[cache_key] = (time.time(), result)
            return result
        known = _known_test_domain_result(domain)
        if known:
            key, note = known
            result = {
                'score': 15,
                'danger': 'SAFE',
                'summary': f'This is a recognized, legitimate security-testing resource ({key}), not a real threat.',
                'reasons': [note],
                'recommendation': 'Safe to visit for its intended testing/reference purpose.',
                'ai_assisted': False,
            }
            if cache_key:
                _scan_cache[cache_key] = (time.time(), result)
            return result
    if (value and EICAR_SIGNATURE in value) or (path and _file_contains_eicar(path)):
        result = _eicar_result()
        if cache_key:
            _scan_cache[cache_key] = (time.time(), result)
        return result

    heuristic, flags = heuristic_score(scan_type, value or '')
    ai = analyze_with_gemini(scan_type, value, path, mime, hints=flags)

    if ai:
        # Blend: trust the AI's contextual judgement most, but let strong
        # deterministic structural red flags (typosquatting, IP hosts, etc.)
        # pull the score up if the AI under-weighted them - this is what
        # keeps results accurate even when the model is uncertain.
        blended = round(ai['score'] * 0.75 + heuristic * 0.25)
        if heuristic >= 60 and blended < heuristic:
            blended = round((blended + heuristic) / 2)
        blended = clamp_score(blended)
        if blended >= 75:
            danger = 'CRITICAL' if blended >= 90 else 'HIGH'
        elif blended >= 45:
            danger = 'MEDIUM'
        elif blended >= 20:
            danger = 'LOW'
        else:
            danger = 'SAFE'
        result = {
            'score': blended,
            'danger': danger,
            'summary': ai['summary'],
            'reasons': list(dict.fromkeys((ai.get('reasons') or []) + flags))[:6],
            'recommendation': ai.get('recommendation'),
            'ai_assisted': True,
        }
    else:
        if heuristic >= 70:
            danger = 'HIGH'
        elif heuristic >= 45:
            danger = 'MEDIUM'
        elif heuristic >= 20:
            danger = 'LOW'
        else:
            danger = 'SAFE'
        result = {
            'score': heuristic,
            'danger': danger,
            'summary': 'Based on structural, linguistic, and reputation checks (domain shape, known brand impersonation patterns, TLD reputation, and social-engineering language), here is the assessed risk.',
            'reasons': flags or ['No known high-risk indicator was detected: no brand impersonation, no suspicious domain structure, no urgent/credential-harvesting language.'],
            'recommendation': 'Do not open it if you are unsure; verify the sender or website independently.',
            'ai_assisted': False,
        }

    if cache_key:
        _scan_cache[cache_key] = (time.time(), result)
    return result


# --- Pages -------------------------------------------------------------------
@app.get('/')
def home():
    return render_template('index.html')


@app.get('/api/ai-status')
@rate_limit(10, 300)
def ai_status():
    """Diagnostic endpoint: tells you exactly why live AI analysis is or
    isn't working, instead of failing silently. Does NOT expose the key
    itself. Hit this in your browser or with curl after deploying to debug
    a 'live AI unavailable' situation in seconds instead of digging through
    server logs."""
    key_present = bool(os.environ.get('GEMINI_API_KEY'))
    if not key_present:
        return jsonify({
            'ok': False,
            'ai_enabled': False,
            'reason': 'GEMINI_API_KEY is not set in this environment.',
            'fix': 'Set GEMINI_API_KEY as an environment variable (locally: in your .env file; on Render/Railway: in the dashboard\'s Environment tab), then restart the app.',
        })
    try:
        from google.genai import types as genai_types
        client = gemini_client()
        response = client.models.generate_content(
            model='gemini-3.7-flash',
            contents='Reply with exactly: OK',
            config=genai_types.GenerateContentConfig(temperature=0),
        )
        text = (response.text or '').strip()
        return jsonify({
            'ok': True,
            'ai_enabled': True,
            'reason': f'GEMINI_API_KEY is set and a live test call succeeded (model replied: "{text[:50]}").',
            'last_recorded_error': _last_ai_error if _last_ai_error['error'] else None,
        })
    except Exception as e:
        return jsonify({
            'ok': False,
            'ai_enabled': False,
            'reason': f'GEMINI_API_KEY is set, but the test call failed: {type(e).__name__}: {e}',
            'fix': 'Common causes: invalid/expired API key, no billing enabled on the Google AI Studio project (required for Google Search grounding), the model name is unavailable for your account/region, or outbound network access is blocked on your host.',
        }), 502


@app.get('/api/me')
def me():
    u = current_user()
    if not u:
        return jsonify({'logged_in': False})
    return jsonify({'logged_in': True, 'user': {
        'id': u['id'], 'name': u['name'], 'email': u['email'],
        'profile_image': u['profile_image'], 'is_verified': bool(u['is_verified'])
    }})


# --- Auth ----------------------------------------------------------------
def password_error(password):
    if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
        return 'Password must be at least 8 characters and contain a letter and a number.'
    return None


@app.post('/api/signup')
@csrf_protect
@rate_limit(8, 300)
def signup():
    data = request.get_json(silent=True) or request.form
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    if len(name) < 2:
        return jsonify({'ok': False, 'error': 'Please enter a valid name.'}), 400
    if not EMAIL_RE.fullmatch(email):
        return jsonify({'ok': False, 'error': 'Please enter a valid email address.'}), 400
    perr = password_error(password)
    if perr:
        return jsonify({'ok': False, 'error': perr}), 400

    con = db()
    existing = con.execute('SELECT id, is_verified FROM users WHERE email=?', (email,)).fetchone()
    if existing and existing['is_verified']:
        con.close()
        return jsonify({'ok': False, 'error': 'An account with this email already exists.'}), 409
    pw_hash = generate_password_hash(password)
    if existing:
        con.execute('UPDATE users SET name=?, password_hash=? WHERE id=?', (name, pw_hash, existing['id']))
    else:
        con.execute(
            'INSERT INTO users(name,email,password_hash,is_verified,created_at) VALUES(?,?,?,0,?)',
            (name, email, pw_hash, datetime.now(timezone.utc).isoformat())
        )
    con.commit(); con.close()

    code, sent_via_smtp = issue_otp(email, 'signup')
    resp = {'ok': True, 'requires_otp': True, 'email': email, 'message': 'We sent a 6-digit verification code to your email.'}
    if not sent_via_smtp:
        # No SMTP configured in this environment (typical for a hackathon demo) -
        # surface the code directly so the flow is still fully testable end to end.
        resp['dev_otp'] = code
        resp['dev_mode'] = True
    return jsonify(resp)


@app.post('/api/otp/verify')
@csrf_protect
@rate_limit(10, 300)
def otp_verify():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    purpose = data.get('purpose') or 'signup'
    code = (data.get('code') or '').strip()
    if not EMAIL_RE.fullmatch(email) or not code:
        return jsonify({'ok': False, 'error': 'Missing email or code.'}), 400

    ok, err, _payload = verify_otp(email, purpose, code)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400

    con = db()
    if purpose == 'signup':
        u = con.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if not u:
            con.close(); return jsonify({'ok': False, 'error': 'Account not found.'}), 404
        con.execute('UPDATE users SET is_verified=1, failed_attempts=0, locked_until=NULL WHERE id=?', (u['id'],))
        con.commit(); con.close()
        session['user_id'] = u['id']
        return me()
    con.close()
    return jsonify({'ok': True})


@app.post('/api/otp/resend')
@rate_limit(4, OTP_RESEND_COOLDOWN_SECONDS)
def otp_resend():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    purpose = data.get('purpose') or 'signup'
    if not EMAIL_RE.fullmatch(email):
        return jsonify({'ok': False, 'error': 'Missing email.'}), 400
    con = db(); u = con.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone(); con.close()
    if not u:
        # Don't reveal whether the account exists.
        return jsonify({'ok': True, 'message': 'If that account exists, a new code has been sent.'})
    code, sent_via_smtp = issue_otp(email, purpose)
    resp = {'ok': True, 'message': 'A new code has been sent.'}
    if not sent_via_smtp:
        resp['dev_otp'] = code
        resp['dev_mode'] = True
    return jsonify(resp)


@app.post('/api/login')
@csrf_protect
@rate_limit(10, 300)
def login():
    data = request.get_json(silent=True) or request.form
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    if not EMAIL_RE.fullmatch(email):
        return jsonify({'ok': False, 'error': 'Please enter a valid email address.'}), 400

    con = db()
    u = con.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    if not u:
        con.close()
        return jsonify({'ok': False, 'error': 'Invalid email or password.'}), 401

    if u['locked_until']:
        locked_until = datetime.fromisoformat(u['locked_until'])
        if locked_until > datetime.now(timezone.utc):
            minutes_left = max(1, int((locked_until - datetime.now(timezone.utc)).total_seconds() // 60) + 1)
            con.close()
            return jsonify({'ok': False, 'error': f'Too many failed attempts. Try again in about {minutes_left} minute(s).'}), 423

    if not check_password_hash(u['password_hash'], password):
        failed = u['failed_attempts'] + 1
        locked_until = None
        if failed >= MAX_FAILED_LOGINS:
            locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            failed = 0
        con.execute('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?', (failed, locked_until, u['id']))
        con.commit(); con.close()
        if locked_until:
            return jsonify({'ok': False, 'error': f'Too many failed attempts. Your account is locked for {LOCKOUT_MINUTES} minutes.'}), 423
        return jsonify({'ok': False, 'error': 'Invalid email or password.'}), 401

    if not u['is_verified']:
        con.close()
        code, sent_via_smtp = issue_otp(email, 'signup')
        resp = {'ok': False, 'requires_otp': True, 'email': email, 'error': 'Please verify your email first. We sent you a new code.'}
        if not sent_via_smtp:
            resp['dev_otp'] = code
            resp['dev_mode'] = True
        return jsonify(resp), 403

    con.execute('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?', (u['id'],))
    con.commit(); con.close()
    session['user_id'] = u['id']
    return me()


@app.post('/api/logout')
def logout_api():
    session.clear()
    return jsonify({'ok': True})


@app.post('/api/password/forgot')
@rate_limit(5, 300)
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    if not EMAIL_RE.fullmatch(email):
        return jsonify({'ok': False, 'error': 'Please enter a valid email address.'}), 400
    con = db(); u = con.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone(); con.close()
    resp = {'ok': True, 'message': 'If that account exists, a reset code has been sent.'}
    if u:
        code, sent_via_smtp = issue_otp(email, 'reset')
        if not sent_via_smtp:
            resp['dev_otp'] = code
            resp['dev_mode'] = True
    return jsonify(resp)


@app.post('/api/password/reset')
@csrf_protect
@rate_limit(8, 300)
def reset_password():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    code = (data.get('code') or '').strip()
    new_password = data.get('new_password') or ''
    if not EMAIL_RE.fullmatch(email) or not code:
        return jsonify({'ok': False, 'error': 'Missing email or code.'}), 400
    perr = password_error(new_password)
    if perr:
        return jsonify({'ok': False, 'error': perr}), 400
    ok, err, _payload = verify_otp(email, 'reset', code)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    con = db()
    con.execute('UPDATE users SET password_hash=?, failed_attempts=0, locked_until=NULL WHERE email=?',
                (generate_password_hash(new_password), email))
    con.commit(); con.close()
    return jsonify({'ok': True, 'message': 'Password updated. You can now log in.'})


# --- Profile ---------------------------------------------------------------
@app.put('/api/profile')
@login_required
@csrf_protect
def update_profile():
    u = current_user(); data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip(); email = (data.get('email') or '').strip().lower()
    if len(name) < 2 or not EMAIL_RE.fullmatch(email):
        return jsonify({'ok': False, 'error': 'Please provide a valid name and email.'}), 400
    con = db()
    try:
        con.execute('UPDATE users SET name=?,email=? WHERE id=?', (name, email, u['id'])); con.commit()
    except sqlite3.IntegrityError:
        con.close(); return jsonify({'ok': False, 'error': 'That email is already used by another account.'}), 409
    con.close(); return me()


@app.post('/api/profile/photo')
@login_required
@csrf_protect
def profile_photo():
    f = request.files.get('photo')
    if not f or not f.filename:
        return jsonify({'ok': False, 'error': 'Choose an image first.'}), 400
    if not (f.mimetype or '').startswith('image/'):
        return jsonify({'ok': False, 'error': 'Profile picture must be an image.'}), 400
    ext = (f.filename.rsplit('.', 1)[1].lower() if '.' in f.filename else 'jpg')
    if ext not in {'jpg', 'jpeg', 'png', 'webp'}:
        ext = 'jpg'
    filename = f'{uuid.uuid4().hex}.{ext}'; f.save(os.path.join(UPLOAD_DIR, filename))
    u = current_user(); con = db(); con.execute('UPDATE users SET profile_image=? WHERE id=?', (f'/static/uploads/{filename}', u['id'])); con.commit(); con.close()
    return me()


# --- History -----------------------------------------------------------------
@app.get('/api/history')
@login_required
def history():
    u = current_user(); con = db()
    rows = con.execute('SELECT id,scan_type,input_preview,score,danger,summary,created_at FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 50', (u['id'],)).fetchall()
    con.close()
    return jsonify({'ok': True, 'history': [dict(r) for r in rows]})


@app.get('/api/history/export')
@login_required
def history_export():
    u = current_user(); con = db()
    rows = con.execute('SELECT scan_type,input_preview,score,danger,summary,created_at FROM scans WHERE user_id=? ORDER BY id DESC', (u['id'],)).fetchall()
    con.close()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['Type', 'Input', 'Score', 'Danger Level', 'Summary', 'Date (UTC)'])
    for r in rows:
        writer.writerow([r['scan_type'], r['input_preview'], r['score'], r['danger'], r['summary'], r['created_at']])
    return Response(buf.getvalue(), mimetype='text/csv', headers={
        'Content-Disposition': 'attachment; filename=shieldsense_history.csv'
    })


# --- Scan ----------------------------------------------------------------
@app.post('/api/scan')
@login_required
@csrf_protect
@rate_limit(20, 300)
def scan():
    u = current_user(); scan_type = request.form.get('scan_type', '').lower()
    value = (request.form.get('value') or '').strip(); f = request.files.get('file')
    if scan_type not in {'url', 'email', 'file'}:
        return jsonify({'ok': False, 'error': 'Choose URL, email, or file.'}), 400
    if scan_type in {'url', 'email'} and not value:
        return jsonify({'ok': False, 'error': 'Paste something to analyze.'}), 400
    if scan_type == 'url' and not re.match(r'^https?://[^\s]+$', value, re.I):
        return jsonify({'ok': False, 'error': 'Please enter a valid URL beginning with http:// or https://.'}), 400
    if scan_type == 'file':
        if not f or not f.filename:
            return jsonify({'ok': False, 'error': 'Please upload a file.'}), 400
        if not allowed_file(f.filename):
            return jsonify({'ok': False, 'error': 'This file type is not supported.'}), 400
        filename = f'{uuid.uuid4().hex}_{secure_filename(f.filename)}'; path = os.path.join(UPLOAD_DIR, filename); f.save(path)
        result = combine_analysis('file', f.filename, path, f.mimetype)
        preview = f.filename
        try:
            os.remove(path)
        except OSError:
            pass
    else:
        result = combine_analysis(scan_type, value); preview = value[:300]
    con = db()
    con.execute(
        'INSERT INTO scans(user_id,scan_type,input_preview,score,danger,summary,reasons,created_at) VALUES(?,?,?,?,?,?,?,?)',
        (u['id'], scan_type, preview, result['score'], result['danger'], result['summary'], json.dumps(result.get('reasons', [])), datetime.now(timezone.utc).isoformat())
    )
    con.commit(); con.close()
    result['ok'] = True; result['scan_type'] = scan_type; result['input_preview'] = preview
    return jsonify(result)


# --- Bulk URL scan -----------------------------------------------------------
# Fixes the "pasting more than one link stops working" issue: the single-value
# /api/scan endpoint (and the <input type="url"> it's paired with) can only
# ever hold one URL, since a browser rejects whitespace in a type="url" field
# and the value=... regex on the backend requires a single unbroken URL. This
# endpoint accepts many URLs at once (newline, comma, or space separated),
# validates and dedupes them, and scans every one - each still gets analyzed
# with the same combine_analysis() pipeline (heuristics + grounded AI) and
# saved to history, just run concurrently so a batch doesn't feel slow.
_URL_SPLIT_RE = re.compile(r'[\s,]+')


@app.post('/api/scan/bulk')
@login_required
@csrf_protect
@rate_limit(6, 300)
def scan_bulk():
    u = current_user()
    data = request.get_json(silent=True) or request.form
    raw = (data.get('urls') or data.get('value') or '')
    candidates = [c.strip() for c in _URL_SPLIT_RE.split(raw) if c.strip()]
    seen = set(); urls = []
    for c in candidates:
        if c not in seen:
            seen.add(c); urls.append(c)
    if not urls:
        return jsonify({'ok': False, 'error': 'Paste one or more URLs (one per line works best).'}), 400
    if len(urls) > MAX_BULK_ITEMS:
        return jsonify({'ok': False, 'error': f'Please scan at most {MAX_BULK_ITEMS} links at a time.'}), 400

    valid, invalid = [], []
    for url in urls:
        if re.match(r'^https?://[^\s]+$', url, re.I):
            valid.append(url)
        else:
            invalid.append(url)

    results = {}
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(valid)))) as pool:
        future_map = {pool.submit(combine_analysis, 'url', url): url for url in valid}
        for future in as_completed(future_map):
            url = future_map[future]
            try:
                results[url] = future.result()
            except Exception as e:
                app.logger.warning('Bulk scan failed for %s: %s', url, e)
                results[url] = {'score': 50, 'danger': 'MEDIUM', 'summary': 'This link could not be analyzed due to an internal error.', 'reasons': ['Analysis error - treat with caution and verify manually.'], 'recommendation': 'Try scanning this link individually.'}

    con = db(); now = datetime.now(timezone.utc).isoformat()
    ordered = []
    for url in valid:
        r = results[url]
        con.execute(
            'INSERT INTO scans(user_id,scan_type,input_preview,score,danger,summary,reasons,created_at) VALUES(?,?,?,?,?,?,?,?)',
            (u['id'], 'url', url[:300], r['score'], r['danger'], r['summary'], json.dumps(r.get('reasons', [])), now)
        )
        ordered.append({'url': url, **r})
    con.commit(); con.close()
    ordered.sort(key=lambda x: x['score'], reverse=True)

    return jsonify({
        'ok': True,
        'scanned': len(valid),
        'skipped': invalid,
        'results': ordered,
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
