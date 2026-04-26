import os
import sys
import hashlib
import logging
import time
from collections import defaultdict
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import bcrypt

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from main import router as scan_router

# ── Persistent session secret: env var → key file → generate once ──────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_KEY_FILE = os.path.join(BASE_DIR, ".session_key")

def _load_session_secret() -> str:
    env_key = os.environ.get("SESSION_SECRET_KEY")
    if env_key:
        return env_key
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "r") as f:
            return f.read().strip()
    import secrets
    new_key = secrets.token_hex(32)
    with open(_KEY_FILE, "w") as f:
        f.write(new_key)
    logger.warning("[AUTH] New session key generated and saved to %s", _KEY_FILE)
    return new_key

SESSION_SECRET = _load_session_secret()

# ── Simple in-memory rate limiter (5 attempts / 60 s per IP) ───────────────────
_login_attempts: dict = defaultdict(list)
_RATE_WINDOW = 60
_RATE_MAX = 5

def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < _RATE_WINDOW]
    if len(_login_attempts[ip]) >= _RATE_MAX:
        return True
    _login_attempts[ip].append(now)
    return False

# ── Password helpers: bcrypt primary, SHA-256 fallback with auto-migration ──────
def _verify_password(stored_hash: str, plain: str):
    """Returns (is_valid, new_bcrypt_hash_or_None).
    Supports existing bcrypt hashes and legacy SHA-256 hashes (auto-migrates)."""
    if stored_hash.startswith(("$2b$", "$2a$", "$2y$")):
        try:
            valid = bcrypt.checkpw(plain.encode(), stored_hash.encode())
        except Exception:
            valid = False
        return valid, None
    # Legacy SHA-256 check — migrate on success
    if hashlib.sha256(plain.encode()).hexdigest() == stored_hash:
        new_hash = bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()
        return True, new_hash
    return False, None

app = FastAPI()

# ── CORS: restricted to local application origin only ──────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=True,
)

# ── Session middleware with persistent key and SameSite protection ──────────────
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax", https_only=False)

app.include_router(scan_router)

# Setup Jinja2 templates for rendering HTML
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Mount template directories to serve static files (CSS/JS) located alongside HTML
app.mount("/login_static", StaticFiles(directory=os.path.join(BASE_DIR, "templates")), name="login_static")
app.mount("/main_static", StaticFiles(directory=os.path.join(parent_dir, "templates")), name="main_static")

# Database Configuration
DB_FILE = os.path.join(BASE_DIR, "users.db")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS user_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # The database structure is created, but no default users are inserted.
    # Use the `add_user.py` script to add users manually.
    conn.commit()
    conn.close()

# Initialize the db on startup
init_db()

def get_db_connection():
    try:
        conn = sqlite3.connect(DB_FILE)
        # Return rows as dictionaries mapping column names to values
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.error("Error connecting to database: %s", e)
        return None

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("landing.html", {"request": request})


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    # Pass flash messages to template
    messages = request.session.pop("messages", [])
    return templates.TemplateResponse("login.html", {"request": request, "messages": messages})


@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    # Rate limit check
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip):
        request.session["messages"] = [{"category": "danger", "message": "Too many login attempts. Please wait before trying again."}]
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    if conn:
        cur = conn.cursor()
        # Fetch by username only; verify password separately to support bcrypt + migration
        cur.execute("SELECT * FROM user_details WHERE username = ?", (username,))
        user = cur.fetchone()

        if user:
            is_valid, new_hash = _verify_password(user["password"], password)
            if is_valid:
                # Auto-migrate legacy SHA-256 hash to bcrypt
                if new_hash:
                    cur.execute("UPDATE user_details SET password = ? WHERE username = ?", (new_hash, username))
                    conn.commit()
                cur.close()
                conn.close()
                request.session["user"] = username
                return RedirectResponse(url="/dashboard", status_code=303)

        cur.close()
        conn.close()

    # Single generic message — never reveal whether the DB is down or credentials wrong
    request.session["messages"] = [{"category": "danger", "message": "Invalid Username or Password!"}]
    return RedirectResponse(url="/login", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse(url="/login", status_code=303)


if __name__ == "__main__":
    import uvicorn
    print("[*] Starting Login Application on Port 8000...")
    uvicorn.run(app, host="127.0.0.1", port=8000)