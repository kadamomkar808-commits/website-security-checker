from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse
import sqlite3
import csv
import io
import ssl
import socket
from datetime import datetime
import urllib.request

app = FastAPI()

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
        return {"error": "पाहणी नाकारली! पासवर्ड चुकीचा आहे."}
    
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
            .card { background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 650px; box-sizing: border-box; }
            h2 { color: #38bdf8; margin-bottom: 8px; text-align: center; }
            p.sub { color: #94a3b8; font-size: 14px; margin-bottom: 20px; text-align: center; }
            input { width: 100%; padding: 12px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #fff; box-sizing: border-box; margin-bottom: 12px; font-size: 15px; }
            button { width: 100%; padding: 12px; border-radius: 6px; border: none; background: #0284c7; color: white; font-weight: bold; font-size: 16px; cursor: pointer; }
            #results { margin-top: 25px; text-align: left; display: none; }
            .score-box { background: #0f172a; padding: 15px; border-radius: 8px; text-align: center; margin-bottom: 15px; border: 1px solid #334155; }
            .score-num { font-size: 32px; font-weight: bold; color: #4ade80; }
            .item { background: #334155; padding: 10px 15px; border-radius: 6px; margin-bottom: 8px; font-size: 14px; display: flex; justify-content: space-between; }
            .pass { color: #4ade80; font-weight: bold; }
            .fail { color: #f87171; font-weight: bold; }
            
            /* OWNER SECTION STYLES */
            .owner-card { background: #0f172a; border: 1px solid #e11d48; padding: 20px; border-radius: 8px; margin-top: 30px; }
            .owner-title { color: #f43f5e; font-weight: bold; font-size: 16px; margin-bottom: 10px; text-align: center; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
            th, td { border: 1px solid #334155; padding: 8px; text-align: left; word-break: break-all; }
            th { background: #1e293b; color: #38bdf8; }
        </style>
    </head>
    <body>
        <div class="navbar">
            <div class="logo">🛡️ SecurityChecker</div>
        </div>

        <div class="card">
            <h2>Website Security Checker</h2>
            <p class="sub">Enter any domain to check basic security posture</p>
            <input type="text" id="domainInput" placeholder="e.g. google.com" />
            <button id="scanBtn" onclick="checkSecurity()">Check Security</button>

            <!-- SCAN RESULTS -->
            <div id="results">
                <div class="score-box">
                    <div>Overall Security Score</div>
                    <div class="score-num" id="score">0/100</div>
                </div>
                <div id="details"></div>
            </div>

            <!-- PERMANENT OWNER LOGIN & DASHBOARD -->
            <div class="owner-card">
                <div class="owner-title">👑 Owner Admin Login</div>
                <div id="loginForm">
                    <input type="password" id="ownerPassInput" placeholder="Enter Owner Password (omkar2812010)" />
                    <button onclick="loginOwner()" style="background: #e11d48;">Login to Access Client Data</button>
                </div>

                <div id="ownerDashboard" style="display: none;">
                    <div style="color:#4ade80; font-weight:bold; margin-bottom:10px;">✅ Owner Access Granted!</div>
                    <button onclick="downloadCSV()" style="background:#10b981; margin-bottom:15px;">📥 Download Client CSV Backup</button>
                    
                    <div style="color:#38bdf8; font-weight:bold; margin-top:10px;">Registered Users:</div>
                    <div id="usersTable">Loading...</div>

                    <div style="color:#38bdf8; font-weight:bold; margin-top:15px;">Scan History:</div>
                    <div id="scansTable">Loading...</div>
                </div>
            </div>
        </div>

        <script>
            let currentOwnerKey = "";

            async function checkSecurity() {
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

            async function loginOwner() {
                const password = document.getElementById('ownerPassInput').value.trim();
                if(!password) { alert('पासवर्ड टाका!'); return; }

                const res = await fetch('/admin/view-data?key=' + encodeURIComponent(password));
                const data = await res.json();

                if(data.error) {
                    alert(data.error);
                    return;
                }

                currentOwnerKey = password;
                document.getElementById('loginForm').style.display = 'none';
                document.getElementById('ownerDashboard').style.display = 'block';

                // Users Table
                if(data.users.length === 0) {
                    document.getElementById('usersTable').innerHTML = "<p style='color:#94a3b8; font-size:12px;'>No users registered yet.</p>";
                } else {
                    let uHtml = "<table><tr><th>ID</th><th>Email</th><th>Plan</th><th>Date</th></tr>";
                    data.users.forEach(u => {
                        uHtml += <tr><td>${u[0]}</td><td>${u[1]}</td><td>${u[2]}</td><td>${u[3]}</td></tr>;
                    });
                    uHtml += "</table>";
                    document.getElementById('usersTable').innerHTML = uHtml;
                }

                // Scans Table
                if(data.scans_history.length === 0) {
                    document.getElementById('scansTable').innerHTML = "<p style='color:#94a3b8; font-size:12px;'>No scans recorded yet.</p>";
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
