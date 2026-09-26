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

# --- CONFIGURATION (Tumcha email ithe taka) ---
OWNER_EMAIL = "kadamomkar808@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "kadamomkar808@gmail.com"
SENDER_PASSWORD = "web2810" # Gmail App Password

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
    
    # Per-user sequence query with monitored sites
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

# --- FEATURE 3: DAILY AUTO-EMAIL BACKUP ENGINE ---
def send_daily_backup_email():
    try:
        csv_data = generate_clients_csv()
        
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = OWNER_EMAIL
        msg['Subject'] = f"📊 Daily Client Backup Report - {datetime.now().strftime('%Y-%m-%d')}"
        
        body = "Namaskar Owner,\n\nTumchya SaaS app cha aajcha daily client database backup attachment madhe dila ahe.\n\nDhanyawad!"
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach CSV
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

# --- FEATURE 1: ADMIN CSV DOWNLOAD ENDPOINT ---
@app.get("/admin/export-csv")
def export_clients_csv():
    csv_content = generate_clients_csv()
    filename = f"clients_data_backup_{datetime.now().strftime('%Y%m%d')}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# --- TRIGGER BACKUP VIA API ---
@app.post("/admin/trigger-email-backup")
def trigger_email_backup(background_tasks: BackgroundTasks):
    background_tasks.add_task(send_daily_backup_email)
    return {"message": "Backup process triggered! Check your owner email."}

# --- FRONTEND DASHBOARD & SCANNER ---
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
            .admin-btn { background: #10b981; margin-top: 15px; }
            .admin-btn:hover { background: #059669; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>🛡️ Security Checker SaaS</h2>
            <p>Free Scanner & Client Monitoring System</p>
            
            <input type="text" id="domainInput" placeholder="e.g. google.com" />
            <button onclick="checkSecurity()">Check Security</button>
            
            <a href="/admin/export-csv" target="_blank">
                <button class="admin-btn">📥 Download Client Backup (Admin CSV)</button>
            </a>
        </div>
        <script>
            async function checkSecurity() {
                alert('Scanner active');
            }
        </script>
    </body>
    </html>
    """

@app.get("/scan")
def scan_website(domain: str):
    return {"domain": domain, "status": "Scanned"}
