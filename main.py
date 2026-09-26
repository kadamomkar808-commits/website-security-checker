from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse
import ssl
import socket
from datetime import datetime
import urllib.request
import sqlite3
import smtplib
from email.mime.text import MIMEText

app = FastAPI()

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            plan TEXT DEFAULT 'Free'
        )
    """)
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

# --- EMAIL ALERT ENGINE ---
def send_security_alert_email(to_email: str, domain: str, score: int, issue_details: str):
    # This function formats and prepares security alert emails for PRO users
    print(f"[EMAIL ENGINE] Alert triggered for {to_email} regarding {domain} (Score: {score})")
    # For live SMTP sending, configure SMTP_SERVER and credentials.

# --- AUTOMATED BACKGROUND SCANNER ---
def run_background_monitoring_job():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT m.id, m.domain, u.email FROM monitored_websites m JOIN users u ON m.user_id = u.id")
    monitored_sites = cursor.fetchall()
    
    for site_id, domain, user_email in monitored_sites:
        score = 0
        ssl_status = "FAIL"
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    expire_date_str = cert['notAfter']
                    expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                    remaining_days = (expire_date - datetime.utcnow()).days
                    if remaining_days > 7:
                        ssl_status = "PASS"
                        score += 50
        except Exception:
            ssl_status = "FAIL"

        if score < 50 or ssl_status == "FAIL":
            send_security_alert_email(user_email, domain, score, "Critical Security Issues or Expiring SSL detected!")

        cursor.execute("UPDATE monitored_websites SET last_score=?, last_status=? WHERE id=?", (score, ssl_status, site_id))
    
    conn.commit()
    conn.close()

# --- HTML FRONTEND WITH FULL SAAS DASHBOARD ---
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Website Security Checker - SaaS</title>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
            .card { background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 550px; text-align: center; }
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
            .pro-banner { background: linear-gradient(135deg, #1e3a8a, #0284c7); padding: 15px; border-radius: 8px; margin-top: 15px; text-align: left; }
            .pro-badge { background: #eab308; color: #000; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>🛡️ Security Checker SaaS</h2>
            
            <div class="nav-tabs">
                <span class="tab active" onclick="showTab('scannerTab', this)">Free Scanner</span>
                <span class="tab" onclick="showTab('loginTab', this)">Account / Monitoring</span>
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

            <!-- TAB 2: USER DASHBOARD & PRO MONITORING -->
            <div id="loginTab" class="section">
                <h3>User Account & 24/7 Alerts</h3>
                <p>Register or Login to manage monitored websites</p>
                <input type="email" id="userEmail" placeholder="Your Email" />
                <input type="password" id="userPassword" placeholder="Your Password" />
                <button onclick="registerUser()">Register Account</button>
                <button style="background:#334155;" onclick="loginUser()">Login</button>
                <div id="authMsg" style="margin-top:10px; font-size:14px; color:#38bdf8;"></div>

                <div class="pro-banner">
                    <span class="pro-badge">PRO PLAN ($5/mo)</span>
                    <h4 style="margin:5px 0;">24/7 Automated Email Security Monitoring</h4>
                    <p style="margin:0; font-size:12px; color:#cbd5e1;">Get instant email alerts when your SSL expires or headers misconfigure.</p>
                </div>
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

# --- API ENDPOINTS ---
@app.post("/register")
def register(email: str, password: str):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
        conn.commit()
        return {"message": "Account created! You can now login."}
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

@app.post("/trigger-monitoring")
def trigger_monitoring(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_background_monitoring_job)
    return {"message": "Background security check job triggered successfully!"}

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
