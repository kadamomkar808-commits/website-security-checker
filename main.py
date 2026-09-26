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
OWNER_EMAIL = "ok1879553@gmail.com"       # <-- Tumcha Gmail ID
SENDER_EMAIL = "ok1879553@gmail.com"      # <-- Tumcha Gmail ID
SENDER_PASSWORD = "web2812010" # <-- Gmail App Password (In-built email sathi)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# --- SECRET ADMIN KEY (Aplya data surakshit thevnyasathi) ---
ADMIN_SECRET_KEY = "omkar2812010"   # <-- Ha tumcha secret password ahe

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
    
    # CSV Header
    writer.writerow(["User ID", "User Email", "Plan", "Registration Date", "Monitored Domain", "Last Score", "Last Status"])
    
    for row in rows:
        writer.writerow(row)
        
    return output.getvalue()

# --- DAILY AUTO-EMAIL BACKUP ENGINE ---
def send_daily_backup_email():
    try:
        csv_data = generate_clients_csv()
        
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = OWNER_EMAIL
        msg['Subject'] = f"📊 Daily Client Backup Report - {datetime.now().strftime('%Y-%m-%d')}"
        
        body = "Namaskar Owner,\n\nTumchya SaaS app cha aajcha daily client database backup attachment madhe dila ahe.\n\nDhanyawad!"
        msg.attach(MIMEText(body, 'plain'))
        
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(csv_data.encode('utf-8'))
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="clients_backup_{datetime.now().strftime("%Y%m%d")}.csv"')
        msg.attach(part)
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("[BACKUP ENGINE] Daily backup email sent successfully!")
    except Exception as e:
        print(f"[BACKUP ENGINE ERROR] {e}")

# --- SECURE ADMIN CSV DOWNLOAD ENDPOINT ---
@app.get("/admin/export-csv")
def export_clients_csv(key: str = ""):
    # Key check: Jar secret key barobar nasel tar error dakhva
    if key != ADMIN_SECRET_KEY:
        return Response(content="Unauthorized Access! Invalid Admin Secret Key.", status_code=403)
    
    csv_content = generate_clients_csv()
    filename = f"clients_data_backup_{datetime.now().strftime('%Y%m%d')}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.post("/admin/trigger-email-backup")
def trigger_email_backup(key: str, background_tasks: BackgroundTasks):
    if key != ADMIN_SECRET_KEY:
        return {"error": "Unauthorized Access!"}
    background_tasks.add_task(send_daily_backup_email)
    return {"message": "Backup process triggered! Check your owner email."}

# --- FRONTEND INTERFACE ---
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
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
            .card { background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 500px; text-align: center; }
            h2 { color: #38bdf8; margin-bottom: 8px; }
            p { color: #94a3b8; font-size: 14px; margin-bottom: 20px; }
            input { width: 100%; padding: 12px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #fff; box-sizing: border-box; margin-bottom: 12px; font-size: 15px; }
            button { width: 100%; padding: 12px; border-radius: 6px; border: none; background: #0284c7; color: white; font-weight: bold; font-size: 16px; cursor: pointer; transition: 0.2s; }
            button:hover { background: #0369a1; }
            #results { margin-top: 25px; text-align: left; display: none; }
            .score-box { background: #0f172a; padding: 15px; border-radius: 8px; text-align: center; margin-bottom: 15px; border: 1px solid #334155; }
            .score-num { font-size: 32px; font-weight: bold; color: #4ade80; }
            .item { background: #334155; padding: 10px 15px; border-radius: 6px; margin-bottom: 8px; font-size: 14px; display: flex; justify-content: space-between; }
            .pass { color: #4ade80; font-weight: bold; }
            .fail { color: #f87171; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>🛡️ Website Security Checker</h2>
            <p>Enter any domain to check basic security posture</p>
            <input type="text" id="domainInput" placeholder="e.g. google.com" />
            <button id="scanBtn" onclick="checkSecurity()">Check Security</button>

            <div id="results">
                <div class="score-box">
                    <div>Overall Security Score</div>
                    <div class="score-num" id="score">0/100</div>
                </div>
                <div id="details"></div>
            </div>
        </div>

        <script>
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
