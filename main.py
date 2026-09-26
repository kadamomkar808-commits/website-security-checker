from fastapi import FastAPI, BackgroundTasks, Response
from fastapi.responses import HTMLResponse
import sqlite3
import csv
import io
import ssl
import socket
from datetime import datetime
import urllib.request
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

app = FastAPI()

# --- CONFIGURATION ---
OWNER_EMAIL = "ok1879553@gmail.com"
SENDER_EMAIL = "ok1879553@gmail.com"
SENDER_PASSWORD = "web2810"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# --- SECRET ADMIN KEY ---
ADMIN_SECRET_KEY = "omkar2812010"

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            plan TEXT DEFAULT 'Free',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

# --- HELPER: GENERATE CSV DATA ---
def generate_clients_csv():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    query = """
        SELECT 
            u.id AS user_id, 
            u.email, 
            u.plan, 
            u.created_at,
            m.domain, 
            m.last_score, 
            m.last_status 
        FROM users u 
        LEFT JOIN monitored_websites m ON u.id = m.user_id 
        ORDER BY u.id ASC
    """
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["User ID", "User Email", "Plan", "Registration Date", "Monitored Domain", "Last Score", "Last Status"])
    for row in rows:
        writer.writerow(row)
    return output.getvalue()

# --- SECURE ADMIN ENDPOINTS ---
@app.get("/admin/export-csv")
def export_clients_csv(key: str = ""):
    if key != ADMIN_SECRET_KEY:
        return Response(content="Unauthorized Access! Invalid Admin Secret Key.", status_code=403)
    
    csv_content = generate_clients_csv()
    filename = f"clients_data_backup_{datetime.now().strftime('%Y%m%d')}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/admin/view-data")
def view_data(key: str = ""):
    if key != ADMIN_SECRET_KEY:
        return {"error": "Unauthorized Access! Invalid Admin Password."}
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, plan, created_at FROM users")
    users = cursor.fetchall()
    
    cursor.execute("SELECT id, user_id, domain, last_score, last_status FROM monitored_websites")
    scans = cursor.fetchall()
    conn.close()
    
    return {
        "status": "success",
        "total_users": len(users),
        "users": users,
        "scans_history": scans
    }

# --- FRONTEND INTERFACE WITH OWNER BUTTON ---
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Website Security Checker</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; display: flex; flex-direction: column; align-items: center; min-height: 100vh; }
            .navbar { width: 100%; max-width: 650px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .logo { font-size: 20px; font-weight: bold; color: #38bdf8; }
            .auth-btns button { background: #334155; color: white; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; margin-left: 6px; font-weight: bold; }
            .auth-btns button.primary { background: #0284c7; }
            .auth-btns button.owner-btn { background: #e11d48; color: white; }
            .card { background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 650px; text-align: center; box-sizing: border-box; }
            h2 { color: #38bdf8; margin-bottom: 8px; }
            p { color: #94a3b8; font-size: 14px; margin-bottom: 20px; }
            input { width: 100%; padding: 12px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #fff; box-sizing: border-box; margin-bottom: 12px; font-size: 15px; }
            button.scan-btn { width: 100%; padding: 12px; border-radius: 6px; border: none; background: #0284c7; color: white; font-weight: bold; font-size: 16px; cursor: pointer; transition: 0.2s; }
            button.scan-btn:hover { background: #0369a1; }
            #results, #ownerDashboard { margin-top: 25px; text-align: left; display: none; }
            .score-box { background: #0f172a; padding: 15px; border-radius: 8px; text-align: center; margin-bottom: 15px; border: 1px solid #334155; }
            .score-num { font-size: 32px; font-weight: bold; color: #4ade80; }
            .item { background: #334155; padding: 10px 15px; border-radius: 6px; margin-bottom: 8px; font-size: 14px; display: flex; justify-content: space-between; }
            .pass { color: #4ade80; font-weight: bold; }
            .fail { color: #f87171; font-weight: bold; }
            .pro-banner { background: linear-gradient(135deg, #1e1b4b, #312e81); border: 1px solid #6366f1; padding: 20px; border-radius: 8px; margin-top: 20px; text-align: center; }
            .pro-banner h3 { margin: 0 0 8px 0; color: #a5b4fc; }
            .pro-banner p { color: #c7d2fe; font-size: 13px; margin-bottom: 15px; }
            .pro-banner button { background: #6366f1; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; cursor: pointer; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
            th, td { border: 1px solid #334155; padding: 8px; text-align: left; }
            th { background: #0f172a; color: #38bdf8; }
        </style>
    </head>
    <body>
        <div class="navbar">
            <div class="logo">🛡️ SecurityChecker</div>
            <div class="auth-btns">
                <button onclick="alert('Login feature coming soon!')">Login</button>
                <button class="primary" onclick="alert('Register feature coming soon!')">Register</button>
                <button class="owner-btn" onclick="accessOwnerDashboard()">👑 Owner</button>
            </div>
        </div>

        <div class="card">
            <h2>Website Security Checker</h2>
            <p>Enter any domain to check basic security posture</p>
            <input type="text" id="domainInput" placeholder="e.g. google.com" />
            <button class="scan-btn" id="scanBtn" onclick="checkSecurity()">Check Security</button>

            <div id="results">
                <div class="score-box">
                    <div>Overall Security Score</div>
                    <div class="score-num" id="score">0/100</div>
                </div>
                <div id="details"></div>

                <div class="pro-banner">
                    <h3>🚀 Upgrade to PRO Plan ($5/mo)</h3>
                    <p>Get 24/7 Automated Monitoring, Vulnerability Alerts & Full PDF Reports.</p>
                    <button onclick="window.open('https://buy.stripe.com/test_link', '_blank')">Upgrade Now</button>
                </div>
            </div>

            <!-- OWNER DASHBOARD CONTAINER -->
            <div id="ownerDashboard">
                <h3 style="color:#e11d48;">👑 Owner Panel Data</h3>
                <button onclick="downloadCSV()" style="background:#10b981; color:white; border:none; padding:8px 12px; border-radius:5px; cursor:pointer; font-weight:bold; margin-bottom:15px;">📥 Download CSV File</button>
                
                <h4 style="margin-bottom:5px; color:#38bdf8;">Registered Users:</h4>
                <div id="usersTable">Loading...</div>

                <h4 style="margin-top:15px; margin-bottom:5px; color:#38bdf8;">Scan History:</h4>
                <div id="scansTable">Loading...</div>
            </div>
        </div>

        <script>
            let currentOwnerKey = "";

            async function checkSecurity() {
                document.getElementById('ownerDashboard').style.display = 'none';
                const domainInput = document.getElementById('domainInput');
                const domain = domainInput.value.trim();
                if(!domain) { alert('Please enter a domain'); return; }
                
                const btn = document.getElementById('scanBtn');
                btn.innerText = 'Scanning...';
                
                try {
                    const res = await fetch('/scan?domain=' + encodeURIComponent(domain));
                    const data = await res.json();
                    
                    document.getElementById('results').style.display = 'block';
                    document.getElementById('score').innerText = data.overall_score + '/100';
                    
                    let detailsHtml = '';
                    detailsHtml += '<div class="item"><span>SSL Status</span> <span class="' + (data.ssl_check.status === 'PASS' ? 'pass':'fail') + '">' + data.ssl_check.status + ' (' + data.ssl_check.days_remaining + ' days)</span></div>';
                    
                    for (const [header, val] of Object.entries(data.headers_check)) {
                        detailsHtml += '<div class="item"><span>' + header + '</span> <span class="' + (val === 'Present' ? 'pass':'fail') + '">' + val + '</span></div>';
                    }
                    
                    document.getElementById('details').innerHTML = detailsHtml;
                } catch(e) {
                    alert('Error checking domain: ' + e);
                } finally {
                    btn.innerText = 'Check Security';
                }
            }

            async function accessOwnerDashboard() {
                const password = prompt("Enter Owner Admin Password:");
                if(!password) return;

                const res = await fetch('/admin/view-data?key=' + encodeURIComponent(password));
                const data = await res.json();

                if(data.error) {
                    alert(data.error);
                    return;
                }

                currentOwnerKey = password;
                document.getElementById('results').style.display = 'none';
                document.getElementById('ownerDashboard').style.display = 'block';

                // Render Users Table
                if(data.users.length === 0) {
                    document.getElementById('usersTable').innerHTML = "<p>No users registered yet.</p>";
                } else {
                    let uHtml = "<table><tr><th>ID</th><th>Email</th><th>Plan</th><th>Date</th></tr>";
                    data.users.forEach(u => {
                        uHtml += <tr><td>${u[0]}</td><td>${u[1]}</td><td>${u[2]}</td><td>${u[3]}</td></tr>;
                    });
                    uHtml += "</table>";
                    document.getElementById('usersTable').innerHTML = uHtml;
                }

                // Render Scans History Table
                if(data.scans_history.length === 0) {
                    document.getElementById('scansTable').innerHTML = "<p>No scans recorded yet.</p>";
                } else {
                    let sHtml = "<table><tr><th>ID</th><th>User ID</th><th>Domain</th><th>Score</th><th>Status</th></tr>";
                    data.scans_history.forEach(s => {
                        sHtml += <tr><td>${s[0]}</td><td>${s[1]}</td><td>${s[2]}</td><td>${s[3]}</td><td>${s[4]}</td></tr>;
                    });
                    sHtml += "</table>";
                    document.getElementById('scansTable').innerHTML = sHtml;
                }
            }

            function downloadCSV() {
                if(currentOwnerKey) {
                    window.open('/admin/export-csv?key=' + encodeURIComponent(currentOwnerKey), '_blank');
                }
            }
        </script>
    </body>
    </html>
    """

# --- SCANNER ENDPOINT ---
@app.get("/scan")
def scan_website(domain: str):
    score = 0
    ssl_status = "FAIL"
    ssl_days = 0
    headers_result = {}

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
        ssl_status = "FAIL"

    target_url = f"https://{domain}"
    important_headers = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]
    points_per_header = 50 / len(important_headers)

    try:
        req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urllib.request.urlopen(req, timeout=5)
        headers = response.info()

        for header in important_headers:
            if header in headers:
                headers_result[header] = "Present"
                score += points_per_header
            else:
                headers_result[header] = "Missing"
    except Exception:
        for header in important_headers:
            headers_result[header] = "Missing"

    return {
        "domain": domain,
        "overall_score": round(score),
        "ssl_check": {
            "status": ssl_status,
            "days_remaining": ssl_days
        },
        "headers_check": headers_result
    }
