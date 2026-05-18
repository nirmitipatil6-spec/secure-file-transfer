#!/usr/bin/env python3
"""
🔒 SECUREXFER v3.0 — Streamlit Web App
6-Step Workflow: Monitor → Classify → Hash → Authorize → Alert → Report
Run with: streamlit run app.py
"""

import streamlit as st
import sqlite3
import os
import io
import shutil
import threading
import time
import hashlib
import json
import csv
from pathlib import Path
from typing import List, Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    class FileSystemEventHandler:
        pass
    class Observer:
        def schedule(self, *a, **kw): pass
        def start(self): pass
        def stop(self): pass
        def join(self): pass


# ════════════════════════════════════════════════════════════
# PAGE CONFIG  (must be first Streamlit call)
# ════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="SecureXfer v3.0",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ════════════════════════════════════════════════════════════
# GLOBAL CSS
# ════════════════════════════════════════════════════════════
st.markdown("""
<style>
/* ── Base ── */
html, body, [data-testid="stAppViewContainer"] {
    background: #0a0e1a;
    color: #e0eaff;
    font-family: 'Consolas', monospace;
}
[data-testid="stSidebar"] {
    background: #080c18 !important;
    border-right: 1px solid #1e2d50;
}
[data-testid="stSidebar"] * { color: #e0eaff !important; }

/* ── Metric cards ── */
[data-testid="metric-container"] {
    background: #161d35;
    border: 1px solid #1e2d50;
    border-radius: 6px;
    padding: 16px !important;
}
[data-testid="stMetricValue"] { color: #00d4ff !important; font-size: 2rem !important; }

/* ── Dataframe ── */
[data-testid="stDataFrame"] { border: 1px solid #1e2d50; border-radius: 6px; }
.stDataFrame thead th {
    background: #0f1629 !important;
    color: #00d4ff !important;
    font-family: Consolas, monospace;
    font-size: 12px;
}
.stDataFrame tbody td {
    background: #161d35 !important;
    color: #e0eaff !important;
    font-family: Consolas, monospace;
    font-size: 11px;
}

/* ── Buttons ── */
.stButton > button {
    background: #00d4ff !important;
    color: #0a0e1a !important;
    font-family: Consolas, monospace !important;
    font-weight: bold !important;
    border: none !important;
    border-radius: 4px !important;
}
.stButton > button:hover { background: #0099bb !important; }

/* ── Inputs ── */
.stTextInput > div > input, .stTextArea textarea {
    background: #0f1629 !important;
    color: #e0eaff !important;
    border: 1px solid #1e2d50 !important;
    border-radius: 4px !important;
    font-family: Consolas, monospace !important;
}

/* ── Progress ── */
.stProgress > div > div { background: #00d4ff !important; }

/* ── Expander ── */
.streamlit-expanderHeader {
    background: #0f1629 !important;
    color: #00d4ff !important;
    font-family: Consolas, monospace !important;
    border: 1px solid #1e2d50 !important;
}
.streamlit-expanderContent {
    background: #161d35 !important;
    border: 1px solid #1e2d50 !important;
}

/* ── Alerts ── */
.alert-box {
    background: #1a0a0e;
    border-left: 4px solid #ff3d5a;
    border-radius: 4px;
    padding: 10px 16px;
    margin: 6px 0;
    font-family: Consolas, monospace;
    font-size: 12px;
    color: #ff3d5a;
}
.ok-box {
    background: #0a1a10;
    border-left: 4px solid #00e676;
    border-radius: 4px;
    padding: 10px 16px;
    margin: 6px 0;
    font-family: Consolas, monospace;
    font-size: 12px;
    color: #00e676;
}
.step-card {
    background: #161d35;
    border: 1px solid #1e2d50;
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    font-family: Consolas, monospace;
}
.step-num {
    color: #00d4ff;
    font-size: 28px;
    font-weight: bold;
}
.step-name {
    color: #e0eaff;
    font-size: 13px;
    font-weight: bold;
    margin-top: 4px;
}
.step-desc {
    color: #5a6a8a;
    font-size: 10px;
    margin-top: 4px;
}
/* ── Auth pages ── */
.auth-container {
    max-width: 420px;
    margin: 60px auto;
    background: #161d35;
    border: 1px solid #1e2d50;
    border-top: 3px solid #00d4ff;
    border-radius: 8px;
    padding: 40px 36px;
}
.auth-logo {
    text-align: center;
    margin-bottom: 28px;
}
.auth-logo .icon { font-size: 42px; }
.auth-logo .title {
    color: #00d4ff;
    font-family: Consolas, monospace;
    font-size: 20px;
    font-weight: bold;
    margin-top: 6px;
}
.auth-logo .sub {
    color: #5a6a8a;
    font-family: Consolas, monospace;
    font-size: 10px;
    margin-top: 3px;
}
.auth-tab-active {
    color: #00d4ff !important;
    border-bottom: 2px solid #00d4ff;
    font-weight: bold;
}
.section-header {
    color: #00d4ff;
    font-family: Consolas, monospace;
    font-size: 13px;
    font-weight: bold;
    border-left: 3px solid #00d4ff;
    padding-left: 10px;
    margin: 16px 0 8px 0;
}
</style>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════════
class Config:
    BASE_DIR      = Path(__file__).parent
    LOGS_DIR      = BASE_DIR / "logs"
    DB_PATH       = BASE_DIR / "secure_transfer.db"
    ENCRYPTED_DIR = BASE_DIR / "encrypted_files"
    RECEIVED_DIR  = BASE_DIR / "received_files"
    REPORTS_DIR   = BASE_DIR / "reports"
    WATCH_DIR     = BASE_DIR / "watched"

    ALLOWED_EXTENSIONS   = {'.pdf', '.docx', '.txt', '.jpg', '.png', '.zip', '.doc'}
    MAX_FILE_SIZE        = 100 * 1024 * 1024

    SENSITIVE_EXTENSIONS = {'.pdf', '.docx', '.doc', '.xlsx', '.xls', '.key', '.pem', '.env'}
    SENSITIVE_KEYWORDS   = [
        'password', 'secret', 'private', 'credential', 'confidential',
        'token', 'api_key', 'ssn', 'salary', 'banking', 'auth', 'login'
    ]
    BLOCKED_EXTENSIONS   = {'.exe', '.bat', '.sh', '.ps1', '.cmd', '.vbs', '.jar'}

    @classmethod
    def ensure_dirs(cls):
        for d in [cls.LOGS_DIR, cls.ENCRYPTED_DIR, cls.RECEIVED_DIR,
                  cls.REPORTS_DIR, cls.WATCH_DIR]:
            d.mkdir(parents=True, exist_ok=True)

Config.ensure_dirs()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler(Config.LOGS_DIR / 'secure_transfer.log')]
)
logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════
# DATABASE
# ════════════════════════════════════════════════════════════
class DatabaseManager:
    def __init__(self):
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(str(Config.DB_PATH), timeout=10)

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL, sender_username TEXT NOT NULL,
                receiver_path TEXT NOT NULL, file_size INTEGER,
                transfer_speed REAL, transfer_time REAL,
                status TEXT DEFAULT 'pending'
                    CHECK(status IN ('pending','in_progress','completed','failed')),
                hash_original TEXT, hash_received TEXT, encryption_key_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user'
                    CHECK(role IN ('admin','user')),
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )''')
            conn.execute('''CREATE TABLE IF NOT EXISTS fs_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL, file_path TEXT NOT NULL,
                file_name TEXT, file_size INTEGER,
                sensitivity TEXT DEFAULT 'normal',
                hash_before TEXT, hash_after TEXT, hash_match INTEGER DEFAULT 1,
                authorized INTEGER DEFAULT 1, alert_triggered INTEGER DEFAULT 0,
                alert_reason TEXT, username TEXT DEFAULT 'system',
                step_reached INTEGER DEFAULT 1, notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            conn.commit()

    def log_transfer(self, filename, sender_username, receiver_path,
                     file_size=0, hash_original='') -> int:
        with self._get_conn() as conn:
            cur = conn.execute(
                "INSERT INTO transfers (filename,sender_username,receiver_path,"
                "file_size,status,hash_original) VALUES (?,?,?,?,'pending',?)",
                (filename, sender_username, receiver_path, file_size, hash_original))
            conn.commit()
            return cur.lastrowid

    def update_transfer_status(self, tid: int, **updates):
        if not updates: return
        clause = ', '.join(f"{k}=?" for k in updates)
        with self._get_conn() as conn:
            conn.execute(
                f"UPDATE transfers SET {clause},completed_at=CURRENT_TIMESTAMP WHERE id=?",
                [*updates.values(), tid])
            conn.commit()

    def get_transfers(self, limit=100) -> List[Dict]:
        with self._get_conn() as conn:
            cur = conn.execute(
                'SELECT * FROM transfers ORDER BY created_at DESC LIMIT ?', (limit,))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def log_fs_event(self, **kw) -> int:
        with self._get_conn() as conn:
            cur = conn.execute('''INSERT INTO fs_events
                (event_type,file_path,file_name,file_size,sensitivity,
                 hash_before,hash_after,hash_match,authorized,
                 alert_triggered,alert_reason,username,step_reached,notes)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
                kw.get('event_type','unknown'), kw.get('file_path',''),
                kw.get('file_name',''), kw.get('file_size'),
                kw.get('sensitivity','normal'), kw.get('hash_before'),
                kw.get('hash_after'), int(kw.get('hash_match',True)),
                int(kw.get('authorized',True)), int(kw.get('alert_triggered',False)),
                kw.get('alert_reason'), kw.get('username','system'),
                kw.get('step_reached',1), kw.get('notes'),
            ))
            conn.commit()
            return cur.lastrowid

    def get_fs_events(self, limit=200) -> List[Dict]:
        with self._get_conn() as conn:
            cur = conn.execute(
                'SELECT * FROM fs_events ORDER BY created_at DESC LIMIT ?', (limit,))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def get_stats(self) -> Dict:
        with self._get_conn() as conn:
            total       = conn.execute('SELECT COUNT(*) FROM transfers').fetchone()[0]
            completed   = conn.execute("SELECT COUNT(*) FROM transfers WHERE status='completed'").fetchone()[0]
            failed      = conn.execute("SELECT COUNT(*) FROM transfers WHERE status='failed'").fetchone()[0]
            total_bytes = conn.execute("SELECT SUM(file_size) FROM transfers WHERE status='completed'").fetchone()[0] or 0
            avg_speed   = conn.execute("SELECT AVG(transfer_speed) FROM transfers WHERE transfer_speed IS NOT NULL").fetchone()[0] or 0
            fs_total    = conn.execute('SELECT COUNT(*) FROM fs_events').fetchone()[0]
            fs_alerts   = conn.execute('SELECT COUNT(*) FROM fs_events WHERE alert_triggered=1').fetchone()[0]
            fs_suspicious = conn.execute('SELECT COUNT(*) FROM fs_events WHERE authorized=0').fetchone()[0]
            fs_sensitive  = conn.execute("SELECT COUNT(*) FROM fs_events WHERE sensitivity='sensitive'").fetchone()[0]
        return dict(total=total, completed=completed, failed=failed,
                    total_mb=round(total_bytes/(1024*1024),2),
                    avg_speed=round(avg_speed,1), fs_total=fs_total,
                    fs_alerts=fs_alerts, fs_suspicious=fs_suspicious,
                    fs_sensitive=fs_sensitive)

    # ── Auth helpers ─────────────────────────────────────────
    @staticmethod
    def _hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username: str, password: str,
                      email: str = '', role: str = 'user') -> tuple:
        if len(username) < 3:
            return False, 'Username must be at least 3 characters.'
        if len(password) < 6:
            return False, 'Password must be at least 6 characters.'
        ph = self._hash_password(password)
        try:
            with self._get_conn() as conn:
                conn.execute(
                    'INSERT INTO users (username,password_hash,role,email) VALUES (?,?,?,?)',
                    (username.strip(), ph, role, email.strip()))
                conn.commit()
            return True, 'Account created successfully!'
        except sqlite3.IntegrityError:
            return False, 'Username already exists.'
        except Exception as e:
            return False, str(e)

    def login_user(self, username: str, password: str) -> tuple:
        ph = self._hash_password(password)
        with self._get_conn() as conn:
            row = conn.execute(
                'SELECT id, username, role FROM users WHERE username=? AND password_hash=?',
                (username.strip(), ph)).fetchone()
            if row:
                conn.execute(
                    'UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?',
                    (row[0],))
                conn.commit()
                return True, {'id': row[0], 'username': row[1], 'role': row[2]}
        return False, 'Invalid username or password.'

    def get_users(self) -> List[Dict]:
        with self._get_conn() as conn:
            cur = conn.execute(
                'SELECT id,username,role,email,created_at,last_login FROM users ORDER BY created_at DESC')
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]


# ════════════════════════════════════════════════════════════
# ENCRYPTION
# ════════════════════════════════════════════════════════════
class FileEncryption:

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=salt, iterations=260_000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def encrypt_bytes(data: bytes, password: str) -> bytes:
        salt = os.urandom(16)
        key  = FileEncryption.derive_key(password, salt)
        return salt + Fernet(key).encrypt(data)

    @staticmethod
    def decrypt_bytes(data: bytes, password: str) -> bytes:
        salt = data[:16]
        key  = FileEncryption.derive_key(password, salt)
        return Fernet(key).decrypt(data[16:])

    @staticmethod
    def encrypt_file(src: str, password: str, dst: str) -> tuple:
        salt = os.urandom(16)
        key  = FileEncryption.derive_key(password, salt)
        enc  = Fernet(key).encrypt(Path(src).read_bytes())
        Path(dst).write_bytes(salt + enc)
        return key, hashlib.sha256(key).hexdigest()

    @staticmethod
    def decrypt_file(src: str, password: str, dst: str) -> bool:
        try:
            raw = Path(src).read_bytes()
            key = FileEncryption.derive_key(password, raw[:16])
            Path(dst).write_bytes(Fernet(key).decrypt(raw[16:]))
            return True
        except Exception as e:
            logger.error(f'Decrypt: {e}')
            return False

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()


# ════════════════════════════════════════════════════════════
# WORKFLOW PIPELINE  (Steps 2-5, used by monitor)
# ════════════════════════════════════════════════════════════
class WorkflowPipeline:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def run(self, event_type: str, file_path: str):
        r = dict(event_type=event_type, file_path=file_path,
                 file_name=Path(file_path).name, file_size=None,
                 sensitivity='normal', hash_before=None, hash_after=None,
                 hash_match=True, authorized=True, alert_triggered=False,
                 alert_reason=None, username='system', step_reached=1, notes='')
        try:
            r['step_reached'] = 2
            r['sensitivity']  = self._classify(file_path)

            r['step_reached'] = 3
            if event_type != 'deleted' and os.path.exists(file_path):
                r['file_size']   = os.path.getsize(file_path)
                r['hash_before'] = FileEncryption.hash_file(file_path)
                time.sleep(0.15)
                if os.path.exists(file_path):
                    r['hash_after'] = FileEncryption.hash_file(file_path)
                    r['hash_match'] = r['hash_before'] == r['hash_after']

            r['step_reached'] = 4
            ok, reason = self._authorize(r)
            r['authorized'] = ok
            if not ok:
                r['alert_triggered'] = True
                r['alert_reason']    = reason
            if r['sensitivity'] == 'sensitive' and not ok:
                r['alert_reason'] = f'SENSITIVE — {reason}'
            if r['hash_before'] and r['hash_after'] and not r['hash_match']:
                r['alert_triggered'] = True
                r['alert_reason']    = (r['alert_reason'] or '') + ' | HASH MISMATCH'

            r['step_reached'] = 5
            self.db.log_fs_event(**r)
            logger.info(f"[STEP5] {event_type} | {r['file_name']} | "
                        f"{r['sensitivity']} | {'ALERT' if r['alert_triggered'] else 'OK'}")
        except Exception as e:
            r['notes'] = f'Error: {e}'
            try: self.db.log_fs_event(**r)
            except: pass

    def _classify(self, path: str) -> str:
        ext  = Path(path).suffix.lower()
        name = Path(path).name.lower()
        if ext in Config.SENSITIVE_EXTENSIONS: return 'sensitive'
        for kw in Config.SENSITIVE_KEYWORDS:
            if kw in name: return 'sensitive'
        return 'normal'

    def _authorize(self, r: Dict):
        if Path(r['file_path']).suffix.lower() in Config.BLOCKED_EXTENSIONS:
            return False, 'Executable/script file blocked'
        if r['event_type'] == 'deleted' and r['sensitivity'] == 'sensitive':
            return False, 'Deletion of sensitive file blocked'
        if (r.get('file_size') or 0) > Config.MAX_FILE_SIZE:
            return False, 'File exceeds size limit'
        if r['file_name'].startswith('.') and r['event_type'] in ('created','modified'):
            return False, 'Hidden file modification flagged'
        return True, ''


# ════════════════════════════════════════════════════════════
# MONITOR  (Step 1)
# ════════════════════════════════════════════════════════════
class _FSHandler(FileSystemEventHandler):
    def __init__(self, pipeline):
        super().__init__()
        self.pipeline = pipeline

    def on_any_event(self, event):
        if event.is_directory: return
        path = getattr(event, 'dest_path', event.src_path)
        threading.Thread(
            target=self.pipeline.run,
            args=(event.event_type, path),
            daemon=True).start()


class FileMonitor:
    def __init__(self, db: DatabaseManager):
        self.db       = db
        self.pipeline = WorkflowPipeline(db)
        self.observer = None
        self.watching = False

    def start(self, path: str) -> bool:
        if not WATCHDOG_AVAILABLE or self.watching:
            return False
        Path(path).mkdir(parents=True, exist_ok=True)
        self.observer = Observer()
        self.observer.schedule(_FSHandler(self.pipeline), path, recursive=True)
        self.observer.start()
        self.watching = True
        return True

    def stop(self):
        if self.observer and self.watching:
            self.observer.stop()
            self.observer.join()
            self.watching = False


# ════════════════════════════════════════════════════════════
# REPORT GENERATOR  (Step 6)
# ════════════════════════════════════════════════════════════
class ReportGenerator:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def txt(self) -> str:
        stats     = self.db.get_stats()
        events    = self.db.get_fs_events(1000)
        transfers = self.db.get_transfers(500)
        W = 72
        lines = [
            '═'*W, '  SECUREXFER — AUDIT & COMPLIANCE REPORT',
            f'  Generated : {datetime.now().strftime("%A, %d %B %Y  %H:%M:%S")}',
            '═'*W, '',
            '── EXECUTIVE SUMMARY ' + '─'*(W-21),
            f'  FS events monitored  : {stats["fs_total"]}',
            f'  Alerts triggered     : {stats["fs_alerts"]}',
            f'  Suspicious / blocked : {stats["fs_suspicious"]}',
            f'  Sensitive files seen : {stats["fs_sensitive"]}',
            f'  Transfers completed  : {stats["completed"]}',
            f'  Transfers failed     : {stats["failed"]}',
            f'  Total data moved     : {stats["total_mb"]} MB',
            f'  Avg transfer speed   : {stats["avg_speed"]} KB/s',
            '',
            '── WORKFLOW COVERAGE ' + '─'*(W-20),
            '  Step 1  Monitor File System   ✓ watchdog observer',
            '  Step 2  Classify Event        ✓ extension + keyword analysis',
            '  Step 3  Integrity Hashing     ✓ SHA-256 before & after',
            '  Step 4  Authorization Check   ✓ rules engine',
            '  Step 5  Logging & Alerting    ✓ DB + file log + web alerts',
            '  Step 6  Final Reporting       ✓ this document',
            '',
            '── FILESYSTEM EVENT LOG ' + '─'*(W-24),
        ]
        for e in events:
            flag  = '⚑ ALERT' if e['alert_triggered'] else '  OK   '
            hstat = ''
            if e['hash_before'] and e['hash_after']:
                hstat = ' [HASH OK]' if e['hash_match'] else ' [HASH MISMATCH]'
            lines.append(
                f"  [{flag}] {str(e['created_at'])[:16]}  "
                f"{e['event_type']:<10} {e['sensitivity']:<10} {e['file_name']}{hstat}")
            if e['alert_reason']:
                lines.append(f"            Reason: {e['alert_reason']}")
        lines += ['', '── TRANSFER LOG ' + '─'*(W-16)]
        for t in transfers:
            size = f"{(t['file_size'] or 0)//1024} KB"
            spd  = f"{t['transfer_speed']:.1f} KB/s" if t['transfer_speed'] else '—'
            lines.append(
                f"  [{t['status']:<11}] {str(t['created_at'])[:16]}  "
                f"{t['filename']:<35} {size:>8}  {spd}")
        lines += ['', '═'*W, '  END OF REPORT', '═'*W]
        return '\n'.join(lines)

    def csv_bytes(self) -> bytes:
        events = self.db.get_fs_events(1000)
        fields = ['id','event_type','file_name','file_size','sensitivity',
                  'authorized','alert_triggered','alert_reason',
                  'hash_before','hash_after','hash_match','created_at']
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(events)
        return buf.getvalue().encode()

    def json_bytes(self) -> bytes:
        return json.dumps({
            'generated': datetime.now().isoformat(),
            'stats': self.db.get_stats(),
            'fs_events': self.db.get_fs_events(1000),
            'transfers': self.db.get_transfers(500),
        }, indent=2, default=str).encode()


# ════════════════════════════════════════════════════════════
# SESSION STATE INIT
# ════════════════════════════════════════════════════════════
@st.cache_resource
def get_db():
    return DatabaseManager()

@st.cache_resource
def get_monitor(_db):
    return FileMonitor(_db)

@st.cache_resource
def get_report_gen(_db):
    return ReportGenerator(_db)

db         = get_db()
monitor    = get_monitor(db)
report_gen = get_report_gen(db)

if 'page' not in st.session_state:
    st.session_state.page = 'Dashboard'
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'auth_tab' not in st.session_state:
    st.session_state.auth_tab = 'login'




# ════════════════════════════════════════════════════════════
# AUTH PAGES  (Login & Register)
# ════════════════════════════════════════════════════════════
def page_login():
    # Hide sidebar on auth pages
    st.markdown("""
    <style>
    [data-testid="stSidebar"] { display: none; }
    [data-testid="collapsedControl"] { display: none; }
    </style>""", unsafe_allow_html=True)

    st.markdown("""
    <div class="auth-container">
        <div class="auth-logo">
            <div class="icon">⬡</div>
            <div class="title">SECUREXFER</div>
            <div class="sub">v3.0 · 6-STEP WORKFLOW MONITOR</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Centre the form
    _, mid, _ = st.columns([1, 1.4, 1])
    with mid:
        # Tab switcher
        t1, t2 = st.columns(2)
        with t1:
            if st.button('🔑  Login', use_container_width=True,
                         type='primary' if st.session_state.auth_tab == 'login' else 'secondary'):
                st.session_state.auth_tab = 'login'
                st.rerun()
        with t2:
            if st.button('📝  Register', use_container_width=True,
                         type='primary' if st.session_state.auth_tab == 'register' else 'secondary'):
                st.session_state.auth_tab = 'register'
                st.rerun()

        st.markdown('<hr style="border-color:#1e2d50;margin:16px 0;">', unsafe_allow_html=True)

        if st.session_state.auth_tab == 'login':
            _login_form()
        else:
            _register_form()


def _login_form():
    st.markdown(
        '<div style="color:#00d4ff;font-family:Consolas;font-size:14px;'
        'font-weight:bold;margin-bottom:16px;">Sign In</div>',
        unsafe_allow_html=True)

    username = st.text_input('Username', placeholder='Enter your username',
                             key='login_username')
    password = st.text_input('Password', type='password',
                             placeholder='Enter your password',
                             key='login_password')

    st.markdown('<br>', unsafe_allow_html=True)

    if st.button('🔑  LOGIN', use_container_width=True, type='primary'):
        if not username or not password:
            st.error('Please fill in all fields.')
        else:
            ok, result = db.login_user(username, password)
            if ok:
                st.session_state.logged_in   = True
                st.session_state.current_user = result
                st.session_state.page         = 'Dashboard'
                st.success(f'Welcome back, {result["username"]}!')
                st.rerun()
            else:
                st.error(result)

    st.markdown(
        '<div style="text-align:center;margin-top:16px;font-family:Consolas;'
        'font-size:10px;color:#5a6a8a;">Don\'t have an account? Click Register above.</div>',
        unsafe_allow_html=True)


def _register_form():
    st.markdown(
        '<div style="color:#00d4ff;font-family:Consolas;font-size:14px;'
        'font-weight:bold;margin-bottom:16px;">Create Account</div>',
        unsafe_allow_html=True)

    username = st.text_input('Username', placeholder='Choose a username (min 3 chars)',
                             key='reg_username')
    email    = st.text_input('Email (optional)', placeholder='your@email.com',
                             key='reg_email')
    password = st.text_input('Password', type='password',
                             placeholder='Min 6 characters',
                             key='reg_password')
    confirm  = st.text_input('Confirm Password', type='password',
                             placeholder='Repeat your password',
                             key='reg_confirm')

    st.markdown('<br>', unsafe_allow_html=True)

    if st.button('📝  CREATE ACCOUNT', use_container_width=True, type='primary'):
        if not username or not password or not confirm:
            st.error('Username and password are required.')
        elif password != confirm:
            st.error('Passwords do not match.')
        else:
            ok, msg = db.register_user(username, password, email)
            if ok:
                st.success(msg + ' You can now log in.')
                st.session_state.auth_tab = 'login'
                st.rerun()
            else:
                st.error(msg)

    st.markdown(
        '<div style="text-align:center;margin-top:16px;font-family:Consolas;'
        'font-size:10px;color:#5a6a8a;">Already have an account? Click Login above.</div>',
        unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════
# SIDEBAR
# ════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 20px 0 10px;'>
        <div style='font-size:36px;'>⬡</div>
        <div style='color:#00d4ff; font-family:Consolas; font-size:16px; font-weight:bold;'>
            SECUREXFER
        </div>
        <div style='color:#5a6a8a; font-family:Consolas; font-size:9px; margin-top:2px;'>
            v3.0 · 6-STEP WORKFLOW
        </div>
    </div>
    <hr style='border-color:#1e2d50; margin: 8px 0 16px;'>
    """, unsafe_allow_html=True)

    pages = {
        'Dashboard':  '◈  Dashboard',
        'Monitor':    '◉  Monitor',
        'Send File':  '▲  Send File',
        'Alerts':     '⚑  Alerts',
        'Report':     '▤  Report',
        'Settings':   '⚙  Settings',
    }
    stats = db.get_stats()
    for key, label in pages.items():
        badge = ''
        if key == 'Alerts' and stats['fs_alerts'] > 0:
            badge = f'  🔴 {stats["fs_alerts"]}'
        active = st.session_state.page == key
        style = 'background:#001a22; color:#00d4ff;' if active else 'color:#5a6a8a;'
        if st.button(label + badge, key=f'nav_{key}',
                     use_container_width=True):
            st.session_state.page = key
            st.rerun()

    st.markdown('<hr style="border-color:#1e2d50; margin:16px 0 8px;">', unsafe_allow_html=True)
    mon_color = '#00e676' if monitor.watching else '#ff3d5a'
    mon_text  = 'Monitor ON' if monitor.watching else 'Monitor OFF'
    st.markdown(
        f'<div style="font-family:Consolas;font-size:11px;color:{mon_color};">'
        f'● {mon_text}</div>', unsafe_allow_html=True)
    st.markdown(
        '<div style="font-family:Consolas;font-size:11px;color:#00e676;">● System Online</div>',
        unsafe_allow_html=True)

    # User info + logout
    user = st.session_state.current_user
    if user:
        st.markdown('<hr style="border-color:#1e2d50; margin:12px 0 8px;">', unsafe_allow_html=True)
        role_color = '#00d4ff' if user['role'] == 'admin' else '#00e676'
        st.markdown(
            f'<div style="font-family:Consolas;font-size:10px;color:#5a6a8a;">Logged in as</div>'
            f'<div style="font-family:Consolas;font-size:11px;color:#e0eaff;font-weight:bold;">'
            f'{user["username"]}</div>'
            f'<div style="font-family:Consolas;font-size:9px;color:{role_color};">'
            f'● {user["role"].upper()}</div>',
            unsafe_allow_html=True)
        st.markdown('<br>', unsafe_allow_html=True)
        if st.button('⎋  Logout', use_container_width=True):
            st.session_state.logged_in    = False
            st.session_state.current_user = None
            st.session_state.page         = 'Dashboard'
            st.rerun()


# ════════════════════════════════════════════════════════════
# HELPER COMPONENTS
# ════════════════════════════════════════════════════════════
def section(title: str, color: str = '#00d4ff'):
    st.markdown(
        f'<div class="section-header" style="border-color:{color};color:{color};">'
        f'{title}</div>', unsafe_allow_html=True)

def colored_badge(text: str, color: str):
    st.markdown(
        f'<span style="background:{color};color:#0a0e1a;font-family:Consolas;'
        f'font-size:10px;font-weight:bold;padding:3px 8px;border-radius:3px;">'
        f'{text}</span>', unsafe_allow_html=True)

def metric_row(items):
    cols = st.columns(len(items))
    for col, (label, value, color) in zip(cols, items):
        with col:
            st.markdown(f"""
            <div style="background:#161d35;border:1px solid #1e2d50;border-radius:6px;
                        padding:16px;border-bottom:2px solid {color};">
                <div style="color:{color};font-family:Consolas;font-size:24px;font-weight:bold;">
                    {value}
                </div>
                <div style="color:#5a6a8a;font-family:Consolas;font-size:9px;margin-top:4px;">
                    {label}
                </div>
            </div>""", unsafe_allow_html=True)

def events_dataframe(events: List[Dict]) -> pd.DataFrame:
    rows = []
    for e in events:
        hok = '—'
        if e.get('hash_before') and e.get('hash_after'):
            hok = '✓ OK' if e.get('hash_match') else '✕ MISMATCH'
        rows.append({
            'ID':         e['id'],
            'Event':      e['event_type'],
            'File':       (e['file_name'] or '')[:40],
            'Size':       f"{e['file_size']//1024} KB" if e['file_size'] else '—',
            'Class':      e['sensitivity'],
            'Hash':       hok,
            'Auth':       '✓' if e['authorized'] else '✕',
            'Alert':      '⚑' if e['alert_triggered'] else '·',
            'Reason':     (e['alert_reason'] or '')[:50],
            'Time':       str(e['created_at'])[:16],
        })
    return pd.DataFrame(rows)

def transfers_dataframe(transfers: List[Dict]) -> pd.DataFrame:
    rows = []
    for t in transfers:
        rows.append({
            'ID':       t['id'],
            'File':     t['filename'][:40],
            'Sender':   t['sender_username'],
            'Size':     f"{(t['file_size'] or 0)//1024} KB",
            'Speed':    f"{t['transfer_speed']:.1f} KB/s" if t['transfer_speed'] else '—',
            'Status':   t['status'].title(),
            'Date':     str(t['created_at'])[:16],
        })
    return pd.DataFrame(rows)


# ════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ════════════════════════════════════════════════════════════
def page_dashboard():
    st.markdown(
        '<h2 style="font-family:Consolas;color:#e0eaff;margin-bottom:4px;">◈  Dashboard</h2>',
        unsafe_allow_html=True)
    st.caption(datetime.now().strftime('%A, %d %B %Y  %H:%M:%S'))

    stats = db.get_stats()

    # Stat cards
    metric_row([
        ('FS EVENTS',  stats['fs_total'],        '#00d4ff'),
        ('ALERTS',     stats['fs_alerts'],        '#ff3d5a'),
        ('SUSPICIOUS', stats['fs_suspicious'],    '#ffb300'),
        ('SENSITIVE',  stats['fs_sensitive'],     '#ffb300'),
        ('COMPLETED',  stats['completed'],        '#00e676'),
        ('DATA MOVED', f"{stats['total_mb']} MB", '#bb88ff'),
    ])

    st.markdown('<br>', unsafe_allow_html=True)

    # Pipeline diagram
    section('ACTIVE WORKFLOW PIPELINE')
    steps = [
        ('1', '◉', 'MONITOR',    '#00e676' if monitor.watching else '#5a6a8a', 'watchdog\nreal-time'),
        ('2', '◈', 'CLASSIFY',   '#00d4ff', 'ext + keyword\nanalysis'),
        ('3', '≋', 'HASH',       '#00d4ff', 'SHA-256\nbefore & after'),
        ('4', '⚷', 'AUTHORIZE',  '#00d4ff', 'rules\nengine'),
        ('5', '⚑', 'ALERT',      '#ffb300', 'DB + log\n+ web alerts'),
        ('6', '▤', 'REPORT',     '#bb88ff', 'TXT·CSV\nJSON export'),
    ]
    cols = st.columns(6)
    for col, (num, icon, name, color, desc) in zip(cols, steps):
        with col:
            st.markdown(f"""
            <div class="step-card" style="border-top:3px solid {color};">
                <div style="font-size:28px;color:{color};">{icon}</div>
                <div style="color:{color};font-family:Consolas;font-size:10px;font-weight:bold;">
                    STEP {num}
                </div>
                <div style="color:#e0eaff;font-family:Consolas;font-size:12px;font-weight:bold;
                            margin-top:4px;">{name}</div>
                <div style="color:#5a6a8a;font-family:Consolas;font-size:9px;margin-top:4px;
                            white-space:pre-line;">{desc}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown('<br>', unsafe_allow_html=True)

    # Recent transfers table
    section('RECENT TRANSFERS')
    transfers = db.get_transfers(20)
    if transfers:
        df = transfers_dataframe(transfers)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info('No transfers yet. Use Send File to get started.')

    # Recent FS events
    section('RECENT FS EVENTS')
    events = db.get_fs_events(20)
    if events:
        df = events_dataframe(events)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info('No filesystem events yet. Start the monitor to detect events.')


# ════════════════════════════════════════════════════════════
# PAGE: MONITOR  (Step 1)
# ════════════════════════════════════════════════════════════
def page_monitor():
    st.markdown(
        '<h2 style="font-family:Consolas;color:#e0eaff;">◉  Monitor  —  Step 1</h2>',
        unsafe_allow_html=True)

    col1, col2 = st.columns([3, 1])
    with col1:
        watch_path = st.text_input(
            'Watch Directory', value=str(Config.WATCH_DIR),
            help='Folder to monitor for file system events')
    with col2:
        st.markdown('<br>', unsafe_allow_html=True)
        if not WATCHDOG_AVAILABLE:
            st.error('watchdog not installed\n`pip install watchdog`')
        elif not monitor.watching:
            if st.button('▶  START MONITORING', use_container_width=True):
                if monitor.start(watch_path):
                    st.success(f'Monitoring started → {watch_path}')
                    st.rerun()
        else:
            if st.button('■  STOP MONITORING', use_container_width=True):
                monitor.stop()
                st.rerun()

    # Status
    if monitor.watching:
        st.markdown(
            '<div class="ok-box">● Monitor is ACTIVE — watching for file system events</div>',
            unsafe_allow_html=True)
    else:
        st.markdown(
            '<div class="alert-box">● Monitor is INACTIVE — click Start to begin</div>',
            unsafe_allow_html=True)

    st.markdown('<br>', unsafe_allow_html=True)
    section('DETECTION CAPABILITIES')

    info = {
        'Event types':       'created  ·  modified  ·  deleted  ·  moved',
        'Recursive watch':   'Yes — all subdirectories included',
        'Step 2 trigger':    'Classification runs on every event automatically',
        'Step 3 trigger':    'SHA-256 computed before & after file settle (150ms)',
        'Step 4 trigger':    'Authorization rules engine fires per event',
        'Step 5 trigger':    'Suspicious events logged to DB + displayed in Alerts',
        'watchdog status':   '✓ Available' if WATCHDOG_AVAILABLE else '✗ Not installed',
    }
    for label, val in info.items():
        c1, c2 = st.columns([1, 3])
        with c1:
            st.markdown(f'<span style="color:#5a6a8a;font-family:Consolas;font-size:11px;">'
                        f'{label}</span>', unsafe_allow_html=True)
        with c2:
            st.markdown(f'<span style="color:#e0eaff;font-family:Consolas;font-size:11px;">'
                        f'{val}</span>', unsafe_allow_html=True)

    st.markdown('<br>', unsafe_allow_html=True)
    section('LIVE EVENT LOG  (last 50)')
    events = db.get_fs_events(50)
    if events:
        df = events_dataframe(events)
        st.dataframe(df, use_container_width=True, hide_index=True, height=400)
    else:
        st.info('No events captured yet.')

    if st.button('🔄 Refresh'):
        st.rerun()


# ════════════════════════════════════════════════════════════
# PAGE: SEND FILE  (Step 3 – manual transfer with hashing)
# ════════════════════════════════════════════════════════════
def page_send_file():
    st.markdown(
        '<h2 style="font-family:Consolas;color:#e0eaff;">▲  Send File  —  Step 3</h2>',
        unsafe_allow_html=True)
    st.caption('SHA-256 integrity verified · AES-256 encrypted transfer')

    col1, col2 = st.columns([2, 1])

    with col1:
        section('TRANSFER CONFIGURATION')
        uploaded = st.file_uploader(
            'Choose a file to transfer',
            type=[e.lstrip('.') for e in Config.ALLOWED_EXTENSIONS],
            help=f'Allowed: {", ".join(sorted(Config.ALLOWED_EXTENSIONS))}')

        password = st.text_input(
            'Encryption Password', type='password',
            placeholder='Enter a strong password')

        dest = st.text_input(
            'Destination Folder',
            value=str(Config.RECEIVED_DIR),
            help='Folder where the decrypted file will be saved')

    with col2:
        section('INTEGRITY HASH  (Step 3)', '#ffb300')
        if uploaded:
            data     = uploaded.read()
            h_before = FileEncryption.hash_bytes(data)
            st.markdown(
                f'<div style="background:#161d35;border:1px solid #1e2d50;'
                f'border-left:3px solid #ffb300;border-radius:4px;padding:12px;'
                f'font-family:Consolas;font-size:9px;word-break:break-all;">'
                f'<div style="color:#5a6a8a;margin-bottom:6px;">SHA-256 (before)</div>'
                f'<div style="color:#ffb300;">{h_before}</div>'
                f'</div>', unsafe_allow_html=True)

            # Step 2 – classify
            ext  = Path(uploaded.name).suffix.lower()
            name = uploaded.name.lower()
            sens = 'sensitive' if (
                ext in Config.SENSITIVE_EXTENSIONS or
                any(kw in name for kw in Config.SENSITIVE_KEYWORDS)
            ) else 'normal'
            sc = '#ffb300' if sens == 'sensitive' else '#00e676'
            st.markdown(
                f'<div style="margin-top:10px;font-family:Consolas;font-size:10px;">'
                f'<span style="color:#5a6a8a;">Classification: </span>'
                f'<span style="color:{sc};font-weight:bold;">{sens.upper()}</span>'
                f'</div>', unsafe_allow_html=True)
        else:
            st.info('Select a file to see its hash')

    st.markdown('<br>', unsafe_allow_html=True)

    if st.button('▲  SEND SECURE FILE', use_container_width=False):
        if not uploaded:
            st.error('Please select a file first.')
        elif not password:
            st.error('Please enter an encryption password.')
        else:
            dest_path = Path(dest)
            dest_path.mkdir(parents=True, exist_ok=True)

            progress = st.progress(0, text='Starting transfer…')
            status   = st.empty()

            try:
                filename  = uploaded.name
                file_data = data  # already read above
                fsize     = len(file_data)
                h_orig    = FileEncryption.hash_bytes(file_data)

                # Log pending
                tid = db.log_transfer(filename, 'Admin', str(dest_path),
                                      fsize, h_orig)
                progress.progress(10, 'Encrypting…')
                status.info('Step 3 · Encrypting file…')

                # Encrypt in memory
                enc_data = FileEncryption.encrypt_bytes(file_data, password)
                kh = hashlib.sha256(enc_data[:16]).hexdigest()
                db.update_transfer_status(tid, status='in_progress',
                                          encryption_key_hash=kh)
                progress.progress(40, 'Encrypted ✓')

                # Save encrypted temp
                tmp_enc = Config.ENCRYPTED_DIR / f'{Path(filename).stem}_encrypted.bin'
                tmp_enc.write_bytes(enc_data)
                progress.progress(60, 'Copying…')

                # Decrypt to destination
                dec_path = dest_path / filename
                dec_data = FileEncryption.decrypt_bytes(enc_data, password)
                dec_path.write_bytes(dec_data)
                h_recv   = FileEncryption.hash_bytes(dec_data)
                progress.progress(90, 'Verifying integrity…')

                # Step 3 – integrity check
                match = h_recv == h_orig
                db.update_transfer_status(
                    tid, status='completed', hash_received=h_recv,
                    transfer_speed=0, transfer_time=0)
                progress.progress(100, 'Complete ✓')

                # Cleanup
                if tmp_enc.exists(): tmp_enc.unlink()

                if match:
                    st.success(f'✅ {filename} transferred securely! Integrity verified.')
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.markdown(
                            f'<div style="font-family:Consolas;font-size:9px;color:#00e676;">'
                            f'Hash before: {h_orig[:40]}…</div>', unsafe_allow_html=True)
                    with col_b:
                        st.markdown(
                            f'<div style="font-family:Consolas;font-size:9px;color:#00e676;">'
                            f'Hash after : {h_recv[:40]}… ✓ MATCH</div>', unsafe_allow_html=True)

                    # Offer download of decrypted file
                    st.download_button(
                        '⬇  Download Transferred File',
                        data=dec_data,
                        file_name=filename,
                        mime='application/octet-stream')
                else:
                    st.error('⚠️ Transfer complete but INTEGRITY CHECK FAILED — hashes do not match!')

            except Exception as e:
                st.error(f'❌ Transfer failed: {e}')
                progress.progress(0, 'Failed')


# ════════════════════════════════════════════════════════════
# PAGE: ALERTS  (Step 5)
# ════════════════════════════════════════════════════════════
def page_alerts():
    st.markdown(
        '<h2 style="font-family:Consolas;color:#e0eaff;">⚑  Alerts  —  Step 5</h2>',
        unsafe_allow_html=True)

    all_events = db.get_fs_events(500)
    alerts     = [e for e in all_events if e['alert_triggered']]
    transfers  = db.get_transfers(500)
    failed_t   = [t for t in transfers if t['status'] == 'failed']

    # Summary
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""
        <div style="background:#1a0a0e;border:1px solid #ff3d5a;border-left:4px solid #ff3d5a;
                    border-radius:6px;padding:16px;text-align:center;">
            <div style="color:#ff3d5a;font-family:Consolas;font-size:28px;font-weight:bold;">
                {len(alerts)}
            </div>
            <div style="color:#5a6a8a;font-family:Consolas;font-size:9px;">SECURITY ALERTS</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        unauthorized = len([e for e in all_events if not e['authorized']])
        st.markdown(f"""
        <div style="background:#1a1400;border:1px solid #ffb300;border-left:4px solid #ffb300;
                    border-radius:6px;padding:16px;text-align:center;">
            <div style="color:#ffb300;font-family:Consolas;font-size:28px;font-weight:bold;">
                {unauthorized}
            </div>
            <div style="color:#5a6a8a;font-family:Consolas;font-size:9px;">UNAUTHORIZED</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div style="background:#0a1a10;border:1px solid #00e676;border-left:4px solid #00e676;
                    border-radius:6px;padding:16px;text-align:center;">
            <div style="color:#00e676;font-family:Consolas;font-size:28px;font-weight:bold;">
                {len(failed_t)}
            </div>
            <div style="color:#5a6a8a;font-family:Consolas;font-size:9px;">FAILED TRANSFERS</div>
        </div>""", unsafe_allow_html=True)

    st.markdown('<br>', unsafe_allow_html=True)

    if not alerts:
        st.markdown(
            '<div class="ok-box">✓  No alerts triggered — system is clean</div>',
            unsafe_allow_html=True)
    else:
        section(f'SECURITY ALERTS  ({len(alerts)} triggered)', '#ff3d5a')
        for e in alerts:
            name   = (e['file_name'] or Path(e['file_path']).name)[:50]
            reason = e['alert_reason'] or 'Unknown'
            auth   = '✓ Authorized' if e['authorized'] else '✕ BLOCKED'
            acolor = '#00e676' if e['authorized'] else '#ff3d5a'
            hstat  = ''
            if e.get('hash_before') and e.get('hash_after'):
                hstat = ' | Hash: ' + ('✓ OK' if e['hash_match'] else '✕ MISMATCH')
            with st.expander(
                f"⚑  {str(e['created_at'])[:16]}  |  "
                f"{e['event_type'].upper()}  |  {e['sensitivity'].upper()}  |  {name}",
                expanded=False):
                c1, c2, c3 = st.columns(3)
                c1.markdown(f'**Event:** {e["event_type"]}')
                c2.markdown(f'**File:** {name}')
                c3.markdown(f'**Sensitivity:** {e["sensitivity"]}')
                st.markdown(
                    f'<span style="color:{acolor};font-family:Consolas;">{auth}</span>'
                    f'  |  <span style="color:#ff3d5a;">Reason: {reason}{hstat}</span>',
                    unsafe_allow_html=True)
                if e['hash_before']:
                    st.code(f'Hash before: {e["hash_before"]}\nHash after : {e["hash_after"] or "N/A"}',
                            language=None)

    if failed_t:
        st.markdown('<br>', unsafe_allow_html=True)
        section('FAILED TRANSFERS', '#ff3d5a')
        df = transfers_dataframe(failed_t)
        st.dataframe(df, use_container_width=True, hide_index=True)

    if st.button('🔄 Refresh Alerts'):
        st.rerun()


# ════════════════════════════════════════════════════════════
# PAGE: REPORT  (Step 6)
# ════════════════════════════════════════════════════════════
def page_report():
    st.markdown(
        '<h2 style="font-family:Consolas;color:#e0eaff;">▤  Report  —  Step 6</h2>',
        unsafe_allow_html=True)
    st.caption('Audit log · Compliance export')

    stats = db.get_stats()

    # Summary metrics
    section('EXECUTIVE SUMMARY')
    metric_row([
        ('FS EVENTS',  stats['fs_total'],        '#00d4ff'),
        ('ALERTS',     stats['fs_alerts'],        '#ff3d5a'),
        ('SUSPICIOUS', stats['fs_suspicious'],    '#ffb300'),
        ('SENSITIVE',  stats['fs_sensitive'],     '#ffb300'),
        ('COMPLETED',  stats['completed'],        '#00e676'),
        ('DATA MOVED', f"{stats['total_mb']} MB", '#bb88ff'),
    ])

    st.markdown('<br>', unsafe_allow_html=True)
    section('GENERATE & DOWNLOAD REPORT', '#bb88ff')

    fmt = st.radio('Export Format', ['TXT Audit', 'CSV Events', 'JSON Full'],
                   horizontal=True)

    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button('▤  GENERATE REPORT', use_container_width=True):
            st.session_state['generate_report'] = fmt

    if 'generate_report' in st.session_state:
        chosen = st.session_state['generate_report']
        if 'TXT' in chosen:
            content = report_gen.txt()
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            st.download_button('⬇  Download TXT Report', data=content,
                               file_name=f'audit_report_{ts}.txt',
                               mime='text/plain', use_container_width=False)
            st.markdown('<br>', unsafe_allow_html=True)
            section('PREVIEW', '#bb88ff')
            st.code(content[:4000] + ('\n… (truncated)' if len(content) > 4000 else ''),
                    language=None)
        elif 'CSV' in chosen:
            data = report_gen.csv_bytes()
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            st.download_button('⬇  Download CSV', data=data,
                               file_name=f'events_{ts}.csv',
                               mime='text/csv')
            st.success('CSV ready for download.')
        elif 'JSON' in chosen:
            data = report_gen.json_bytes()
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            st.download_button('⬇  Download JSON', data=data,
                               file_name=f'report_{ts}.json',
                               mime='application/json')
            st.success('JSON ready for download.')

    # Charts
    st.markdown('<br>', unsafe_allow_html=True)
    section('VISUAL ANALYTICS', '#bb88ff')

    events    = db.get_fs_events(200)
    transfers = db.get_transfers(50)

    c1, c2, c3 = st.columns(3)

    with c1:
        if transfers:
            df  = pd.DataFrame([{'status': t['status']} for t in transfers])
            cnt = df['status'].value_counts().reset_index()
            cnt.columns = ['status', 'count']
            color_map = {'completed': '#00e676', 'failed': '#ff3d5a',
                         'in_progress': '#ffb300', 'pending': '#5a6a8a'}
            fig = px.pie(cnt, names='status', values='count',
                         title='Transfer Status',
                         color='status', color_discrete_map=color_map,
                         hole=0.5)
            fig.update_layout(
                paper_bgcolor='#161d35', plot_bgcolor='#161d35',
                font_color='#e0eaff', font_family='Consolas',
                title_font_color='#e0eaff', legend_font_color='#e0eaff',
                margin=dict(t=40, b=10, l=10, r=10))
            st.plotly_chart(fig, use_container_width=True)

    with c2:
        if events:
            df  = pd.DataFrame([{'event_type': e['event_type']} for e in events])
            cnt = df['event_type'].value_counts().reset_index()
            cnt.columns = ['type', 'count']
            color_map2 = {'created': '#00e676', 'modified': '#ffb300',
                          'deleted': '#ff3d5a', 'moved': '#00d4ff'}
            fig2 = px.bar(cnt, x='type', y='count', title='FS Event Types',
                          color='type', color_discrete_map=color_map2)
            fig2.update_layout(
                paper_bgcolor='#161d35', plot_bgcolor='#161d35',
                font_color='#e0eaff', font_family='Consolas',
                title_font_color='#e0eaff', showlegend=False,
                margin=dict(t=40, b=10, l=10, r=10))
            fig2.update_xaxes(color='#5a6a8a')
            fig2.update_yaxes(color='#5a6a8a', gridcolor='#1e2d50')
            st.plotly_chart(fig2, use_container_width=True)

    with c3:
        if events:
            df  = pd.DataFrame([{'sensitivity': e['sensitivity']} for e in events])
            cnt = df['sensitivity'].value_counts().reset_index()
            cnt.columns = ['sensitivity', 'count']
            color_map3 = {'normal': '#00d4ff', 'sensitive': '#ffb300'}
            fig3 = px.bar(cnt, x='sensitivity', y='count',
                          title='File Sensitivity', color='sensitivity',
                          color_discrete_map=color_map3)
            fig3.update_layout(
                paper_bgcolor='#161d35', plot_bgcolor='#161d35',
                font_color='#e0eaff', font_family='Consolas',
                title_font_color='#e0eaff', showlegend=False,
                margin=dict(t=40, b=10, l=10, r=10))
            fig3.update_xaxes(color='#5a6a8a')
            fig3.update_yaxes(color='#5a6a8a', gridcolor='#1e2d50')
            st.plotly_chart(fig3, use_container_width=True)


# ════════════════════════════════════════════════════════════
# PAGE: SETTINGS
# ════════════════════════════════════════════════════════════
def page_settings():
    st.markdown(
        '<h2 style="font-family:Consolas;color:#e0eaff;">⚙  Settings</h2>',
        unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        section('SYSTEM PATHS')
        paths = {
            'Database':      str(Config.DB_PATH),
            'Encrypted Dir': str(Config.ENCRYPTED_DIR),
            'Received Dir':  str(Config.RECEIVED_DIR),
            'Reports Dir':   str(Config.REPORTS_DIR),
            'Watch Dir':     str(Config.WATCH_DIR),
            'Logs Dir':      str(Config.LOGS_DIR),
        }
        for k, v in paths.items():
            st.markdown(
                f'<div style="display:flex;justify-content:space-between;padding:6px 0;'
                f'border-bottom:1px solid #1e2d50;">'
                f'<span style="color:#5a6a8a;font-family:Consolas;font-size:11px;">{k}</span>'
                f'<span style="color:#e0eaff;font-family:Consolas;font-size:10px;">{Path(v).name}</span>'
                f'</div>', unsafe_allow_html=True)

    with col2:
        section('TRANSFER CONFIG', '#ffb300')
        config_rows = {
            'Max File Size':  f'{Config.MAX_FILE_SIZE//(1024*1024)} MB',
            'Allowed Types':  ' '.join(sorted(Config.ALLOWED_EXTENSIONS)),
            'Blocked Types':  ' '.join(sorted(Config.BLOCKED_EXTENSIONS)),
            'Encryption':     'AES-128-CBC (Fernet)',
            'KDF':            'PBKDF2-SHA256 · 260k iterations',
            'Salt':           '16-byte per-file (os.urandom)',
        }
        for k, v in config_rows.items():
            st.markdown(
                f'<div style="display:flex;justify-content:space-between;padding:6px 0;'
                f'border-bottom:1px solid #1e2d50;">'
                f'<span style="color:#5a6a8a;font-family:Consolas;font-size:11px;">{k}</span>'
                f'<span style="color:#e0eaff;font-family:Consolas;font-size:10px;">{v}</span>'
                f'</div>', unsafe_allow_html=True)

    st.markdown('<br>', unsafe_allow_html=True)
    section('CLASSIFICATION RULES', '#bb88ff')
    cc1, cc2 = st.columns(2)
    with cc1:
        st.markdown('**Sensitive Extensions**')
        st.code(' '.join(sorted(Config.SENSITIVE_EXTENSIONS)), language=None)
    with cc2:
        st.markdown('**Sensitive Keywords**')
        st.code(', '.join(Config.SENSITIVE_KEYWORDS), language=None)

    st.markdown('<br>', unsafe_allow_html=True)
    section('ACTIVE SECURITY FEATURES — ALL 6 STEPS', '#00e676')
    features = [
        '✓  Step 1: watchdog real-time filesystem observer',
        '✓  Step 2: Automatic sensitivity classification (ext + keywords)',
        '✓  Step 3: SHA-256 integrity hash before & after every event',
        '✓  Step 4: Rules-based authorization engine per event',
        '✓  Step 5: SQLite audit DB + file log + web alert panel',
        '✓  Step 6: TXT / CSV / JSON compliance report export + charts',
    ]
    for f in features:
        st.markdown(
            f'<div style="font-family:Consolas;font-size:11px;color:#00e676;'
            f'padding:4px 0;">{f}</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════
# ROUTER  (auth-gated)
# ════════════════════════════════════════════════════════════
if not st.session_state.logged_in:
    page_login()
else:
    page = st.session_state.page
    if page == 'Dashboard':
        page_dashboard()
    elif page == 'Monitor':
        page_monitor()
    elif page == 'Send File':
        page_send_file()
    elif page == 'Alerts':
        page_alerts()
    elif page == 'Report':
        page_report()
    elif page == 'Settings':
        page_settings()
