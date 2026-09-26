from fastapi import FastAPI, Form, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
import ssl
import socket
from datetime import datetime
import urllib.request
import dns.resolver
import sqlite3

app = FastAPI()

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            plan TEXT DEFAULT 'Free'
        )
    """)
    # Monitored Websites table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitored_websites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            domain TEXT NOT NULL,
            last_score INTEGER,
            last_status TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- HTML FRONTEND WITH LOGIN & DASHBOARD ---
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Website Security Checker - Full SaaS</title>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
            .card { background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 500px; text-align: center; }
            h2 { color: #38bdf8; margin-bottom: 8px; }
            p { color: #94a3b8; font-size: 14px; margin-bottom: 20px; }
            input { width: 100%; padding: 12px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #fff; box-sizing: border-box; margin-bottom: 12px; font-size: 15px; }
            button { width: 100%; padding: 12px; border-radius: 6px; border: none; background: #0284c7; color: white; font-weight: bold; font-size: 16px; cursor: pointer; margin-top: 5px; }
            button:hover { background: #0369a1; }
            .nav-tabs { display: flex; justify-content: space-around; margin-bottom: 20px; border-bottom: 1px solid #334155; padding-bottom: 10px; }
            .tab { color: #94a3b8; cursor: pointer; font-weight: bold; }
            .tab.active { color: #38bdf8; border-bottom: 2px solid #38bdf8; }
            .section { display: none; }
            .section.active { display: block; }
            .score-box { background: #0f172a; padding: 15px; border-radius: 8px; text-align: center; margin-bottom: 15px; border: 1px solid #334155; }
            .score-num { font-size: 32px; font-weight: bold; color: #4ade80; }
            .item { background: #334155; padding: 10px 15px; border-radius: 6px; margin-bottom: 8px; font-size: 14px; display: flex; justify-content: space-between; }
            .pass { color: #4ade80; font-weight: bold; }
            .fail { color: #f87171; font-weight: bold; }
            .pro-badge { background: #eab308; color: #000; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>🛡️ Security Checker SaaS</h2>
            
            <div class="nav-tabs">
                <span class="tab active" onclick="showTab('scannerTab', this)">Free Scanner</span>
                <span class="tab" onclick="showTab('loginTab', this)">Login / Register</span>
            </div>

            <!-- TAB 1: FREE SCANNER -->
            <div id="scannerTab" class="section active">
                <p>Instant Security Check for Any Website</p>
                <input type="text" id="domainInput" placeholder="e.g. google.com" />
                <button id="scanBtn" onclick="checkSecurity()">Check Security</button>

                <div id="results" style="display:none; margin-top:20px; text-align:left;">
                    <div class="score-box">
                        <div>Overall Security Score</div>
                        <div class="score-num" id="score">0/100</div>
                    </div>
                    <div id="basic-details"></div>
                </div>
            </div>

            <!-- TAB 2: LOGIN / REGISTER -->
            <div id="loginTab" class="section">
                <h3>User Account</h3>
                <p>Register or Login to access 24/7 Monitoring Engine</p>
                <input type="email" id="userEmail" placeholder="Your Email" />
                <input type="password" id="userPassword" placeholder="Your Password" />
                <button onclick="registerUser()">Register Account</button>
                <button style="background:#334155;" onclick="loginUser()">Login</button>
                <div id="authMsg" style="margin-top:10px; font-size:14px; color:#38bdf8;"></div>
            </div>
        </div>

        <script>
            function showTab(tabId, el) {
                document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.getElementById(tabId).classList.add('active');
                el.classList.add('active');
            }

            async function checkSecurity() {
                const domain = document.getElementById('domainInput').value.trim();
                if(!domain) return alert('Enter domain');
                const btn = document.getElementById('scanBtn');
                btn.innerText = 'Scanning...';
                
                try {
                    const res = await fetch('/scan?domain=' + encodeURIComponent(domain));
                    const data = await res.json();
                    document.getElementById('results').style.display = 'block';
                    document.getElementById('score').innerText = data.overall_score + '/100';
                    
                    let html = '<div class="item"><span>SSL Status</span> <span class="' + (data.ssl_check.status === 'PASS' ? 'pass':'fail') + '">' + data.ssl_check.status + '</span></div>';
                    for (const [h, v] of Object.entries(data.headers_check)) {
                        html += '<div class="item"><span>' + h + '</span> <span class="' + (v === 'Present' ? 'pass':'fail') + '">' + v + '</span></div>';
                    }
                    document.getElementById('basic-details').innerHTML = html;
                } catch(e) {
                    alert('Error scanning');
                } finally {
                    btn.innerText = 'Check Security';
                }
            }

            async function registerUser() {
                const email = document.getElementById('userEmail').value;
                const password = document.getElementById('userPassword').value;
                const res = await fetch('/register?email=' + encodeURIComponent(email) + '&password=' + encodeURIComponent(password), {method: 'POST'});
                const data = await res.json();
                document.getElementById('authMsg').innerText = data.message;
            }

            async function loginUser() {
                const email = document.getElementById('userEmail').value;
                const password = document.getElementById('userPassword').value;
                const res = await fetch('/login?email=' + encodeURIComponent(email) + '&password=' + encodeURIComponent(password), {method: 'POST'});
                const data = await res.json();
                document.getElementById('authMsg').innerText = data.message;
            }
        </script>
    </body>
    </html>
    """

# --- BACKEND API ENDPOINTS ---
@app.post("/register")
def register(email: str, password: str):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
        conn.commit()
        return {"message": "Account created successfully! You can now login."}
    except Exception:
        return {"message": "Email already registered!"}
    finally:
        conn.close()

@app.post("/login")
def login(email: str, password: str):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, plan FROM users WHERE email=? AND password=?", (email, password))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"message": f"Welcome back! Logged in as [{user[1]} Plan] User."}
    return {"message": "Invalid Email or Password!"}

@app.get("/scan")
def scan_website(domain: str):
    score = 0
    ssl_status = "FAIL"
    ssl_days = 0
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expire_date_str = cert['notAfter']
                expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                ssl_days = (expire_date - datetime.utcnow()).days
                ssl_status = "PASS"
                score += 50
    except Exception:
        pass

    headers_result = {}
    target_url = f"https://{domain}"
    important_headers = ["Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]
    try:
        req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urllib.request.urlopen(req, timeout=5)
        headers = response.info()
        for header in important_headers:
            if header in headers:
                headers_result[header] = "Present"
                score += 16.6
            else:
                headers_result[header] = "Missing"
    except Exception:
        for header in important_headers:
            headers_result[header] = "Missing"

    return {
        "domain": domain,
        "overall_score": round(score),
        "ssl_check": {"status": ssl_status, "days_remaining": ssl_days},
        "headers_check": headers_result
    }
