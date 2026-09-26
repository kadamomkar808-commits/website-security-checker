from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import ssl
import socket
from datetime import datetime
import urllib.request

app = FastAPI()

# HTML Frontend Interface
html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Website Security Checker</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #0f172a; color: white; text-align: center; padding: 50px; }
        .card { background: #1e293b; padding: 30px; border-radius: 12px; max-width: 500px; margin: auto; box-shadow: 0 4px 10px rgba(0,0,0,0.3); }
        input { width: 80%; padding: 12px; margin-bottom: 15px; border-radius: 6px; border: none; font-size: 16px; }
        button { background-color: #2563eb; color: white; border: none; padding: 12px 24px; border-radius: 6px; font-size: 16px; cursor: pointer; }
        button:hover { background-color: #1d4ed8; }
        #result { margin-top: 25px; text-align: left; background: #0f172a; padding: 15px; border-radius: 8px; font-family: monospace; white-space: pre-wrap; display: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>🛡️ Website Security Checker</h2>
        <p>Enter any domain to check basic security posture</p>
        <input type="text" id="domainInput" placeholder="e.g. google.com">
        <br>
        <button onclick="scanWebsite()">Check Security</button>
        <div id="result">Scanning...</div>
    </div>

    <script>
        async function scanWebsite() {
            const domain = document.getElementById('domainInput').value;
            const resultDiv = document.getElementById('result');
            if(!domain) { alert('Please enter a domain!'); return; }
            
            resultDiv.style.display = 'block';
            resultDiv.innerText = 'Scanning website... Please wait...';

            try {
                const response = await fetch('/scan?domain=' + domain);
                const data = await response.json();
                resultDiv.innerText = JSON.stringify(data, null, 2);
            } catch (error) {
                resultDiv.innerText = 'Error fetching security data.';
            }
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def home():
    return html_content

@app.get("/scan")
def scan_website(domain: str):
    score = 0
    ssl_status = "FAIL"
    ssl_days = 0
    headers_result = {}

    # SSL Check
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
    except Exception as e:
        ssl_status = f"FAIL ({str(e)})"

    # Headers Check
    target_url = f"https://{domain}"
    important_headers = ["Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]
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
    except Exception as e:
        headers_result["error"] = str(e)

    return {
        "domain": domain,
        "overall_score": round(score),
        "ssl_check": {"status": ssl_status, "days_remaining": ssl_days},
        "headers_check": headers_result
    }