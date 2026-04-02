import os
import secrets
import sys
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
import sqlite3

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from main import router as scan_router

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add Session Middleware for storing login state with a random key to force login on restart
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32))

app.include_router(scan_router)

# Setup Jinja2 templates for rendering HTML
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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
    # Insert a default user if empty
    cur.execute("SELECT COUNT(*) FROM user_details")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO user_details (username, password) VALUES (?, ?)", ("admin", "admin123"))
        cur.execute("INSERT INTO user_details (username, password) VALUES (?, ?)", ("yonith.jamad", "yonith"))
        cur.execute("INSERT INTO user_details (username, password) VALUES (?, ?)", ("user", "user123"))
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
        print(f"Error connecting to database: {e}")
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
async def login_post(request: Request, username: str = Form(...), password: str = Form(...) ):
    conn = get_db_connection()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM user_details WHERE username = ? AND password = ?", (username, password))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            request.session["user"] = username
            return RedirectResponse(url="/dashboard", status_code=303)
        else:
            request.session["messages"] = [{"category": "danger", "message": "Invalid Username or Password!"}]
    else:
        request.session["messages"] = [{"category": "danger", "message": "Database connection failed!"}]

    return RedirectResponse(url="/login", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse(url="/login", status_code=303)


if __name__ == "__main__":
    import uvicorn
    print("[*] Starting Login Application on Port 8000...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
