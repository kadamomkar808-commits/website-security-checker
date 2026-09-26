from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse
import ssl
import socket
from datetime import datetime
import urllib.request
import dns.resolver
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io

app = FastAPI()

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
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
            .card { background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 500px; text-align: center; }
            h2 { color: #38bdf8; margin-bottom: 8px; }
            p { color: #94a3b8; font-size: 14px; margin-bottom: 20px; }
            input { width: 100%; padding: 12px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #fff; box-sizing: border-box; margin-bottom: 12px; font-size: 15px; }
            button { width: 100%; padding: 12px; border-radius: 6px; border: none; background: #0284c7; color: white; font-weight: bold; font-size: 16px; cursor: pointer; transition: 0.2s; margin-bottom: 8px; }
            button:hover { background: #0369a1; }
            .pdf-btn { background: #16a34a; }
            .pdf-btn:hover { background: #15803d; }
            #results { margin-top: 25px; text-align: left; display: none; }
            .score-box { background: #0f172a; padding: 15px; border-radius: 8px; text-align: center; margin-bottom: 15px; border: 1px solid #334155; }
            .score-num { font-size: 32px; font-weight: bold; color: #4ade80; }
            .item { background: #334155; padding: 10px 15px; border-radius: 6px; margin-bottom: 8px; font-size: 14px; display: flex; justify-content: space-between; }
            .pass { color: #4ade80; font-weight: bold; }
            .fail { color: #f87171; font-weight: bold; }
            .section-title { font-size: 12px; color: #94a3b8; text-transform: uppercase; margin: 15px 0 5px 0; font-weight: bold; }
            
            /* Pro Banner */
            .pro-banner { margin-top: 25px; padding: 15px; border: 1px dashed #eab308; background: rgba(234, 179, 8, 0.1); border-radius: 8px; text-align: center; }
            .pro-title { color: #eab308; font-weight: bold; margin-bottom: 5px; }
            .pro-btn { background: #eab308; color: #000; font-size: 14px; padding: 8px 15px; margin-top: 10px; border-radius: 4px; font-weight: bold; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>🛡️ Website Security Checker</h2>
            <p>Free Basic Security Scanner</p>
            <input type="text" id="domainInput" placeholder="e.g. google.com" />
            <button id="scanBtn" onclick="checkSecurity()">Check Security</button>

            <div id="results">
                <div class="score-box">
                    <div>Overall Security Score</div>
                    <div class="score-num" id="score">0/100</div>
                </div>
                
                <div class="section-title">SSL & Headers</div>
                <div id="basic-details"></div>
                
                <div class="section-title">Email Security (DNS)</div>
                <div id="dns-details"></div>

                <button class="pdf-btn" onclick="downloadPDF()">📄 Download PDF Report</button>
                
                <div class="pro-banner">
                    <div class="pro-title">🚀 Upgrade to PRO Plan ($5/mo)</div>
                    <div style="font-size: 12px; color: #cbd5e1;">Get 24/7 Automated Monitoring & Vulnerability Email Alerts.</div>
                    <button class="pro-btn" onclick="alert('Subscription Payment Gateway coming soon!')">Upgrade Now</button>
                </div>
            </div>
        </div>

        <script>
            let currentDomain = '';

            async function checkSecurity() {
                const domainInput = document.getElementById('domainInput');
                const domain = domainInput.value.trim();
                if(!domain) { alert('Please enter a domain'); return; }
                
                currentDomain = domain;
                const btn = document.getElementById('scanBtn');
                btn.innerText = 'Scanning...';
                
                try {
                    const res = await fetch('/scan?domain=' + encodeURIComponent(domain));
                    const data = await res.json();
                    
                    document.getElementById('results').style.display = 'block';
                    document.getElementById('score').innerText = data.overall_score + '/100';
                    
                    // Basic Details
                    let basicHtml = '<div class="item"><span>SSL Status</span> <span class="' + (data.ssl_check.status === 'PASS' ? 'pass':'fail') + '">' + data.ssl_check.status + ' (' + data.ssl_check.days_remaining + ' days)</span></div>';
                    for (const [header, val] of Object.entries(data.headers_check)) {
                        basicHtml += '<div class="item"><span>' + header + '</span> <span class="' + (val === 'Present' ? 'pass':'fail') + '">' + val + '</span></div>';
                    }
                    document.getElementById('basic-details').innerHTML = basicHtml;

                    // DNS Details
                    let dnsHtml = '<div class="item"><span>SPF Record</span> <span class="' + (data.dns_check.spf === 'Present' ? 'pass':'fail') + '">' + data.dns_check.spf + '</span></div>';
                    dnsHtml += '<div class="item"><span>DMARC Record</span> <span class="' + (data.dns_check.dmarc === 'Present' ? 'pass':'fail') + '">' + data.dns_check.dmarc + '</span></div>';
                    document.getElementById('dns-details').innerHTML = dnsHtml;

                } catch(e) {
                    alert('Error checking domain: ' + e);
                } finally {
                    btn.innerText = 'Check Security';
                }
            }

            function downloadPDF() {
                if(currentDomain) {
                    window.open('/download-pdf?domain=' + encodeURIComponent(currentDomain), '_blank');
                }
            }
        </script>
    </body>
    </html>
    """

@app.get("/scan")
def scan_website(domain: str):
    return get_security_data(domain)

def get_security_data(domain: str):
    score = 0
    
    # 1. SSL Check
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
                score += 40
    except Exception:
        pass

    # 2. Headers Check
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
                score += 10
            else:
                headers_result[header] = "Missing"
    except Exception:
        for header in important_headers:
            headers_result[header] = "Missing"

    # 3. DNS (SPF & DMARC) Check
    dns_result = {"spf": "Missing", "dmarc": "Missing"}
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                dns_result["spf"] = "Present"
                score += 15
    except Exception:
        pass

    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in dmarc_answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=DMARC1"):
                dns_result["dmarc"] = "Present"
                score += 15
    except Exception:
        pass

    return {
        "domain": domain,
        "overall_score": round(score),
        "ssl_check": {"status": ssl_status, "days_remaining": ssl_days},
        "headers_check": headers_result,
        "dns_check": dns_result
    }

@app.get("/download-pdf")
def download_pdf(domain: str):
    data = get_security_data(domain)
    
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    # Title
    p.setFont("Helvetica-Bold", 18)
    p.drawString(100, 750, "Website Security Audit Report")
    
    p.setFont("Helvetica", 12)
    p.drawString(100, 725, f"Domain: {domain}")
    p.drawString(100, 705, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p.drawString(100, 685, f"Overall Security Score: {data['overall_score']} / 100")
    
    p.line(100, 670, 500, 670)
    
    # Details
    y = 640
    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, y, "1. SSL Certificate")
    y -= 20
    p.setFont("Helvetica", 12)
    p.drawString(120, y, f"SSL Status: {data['ssl_check']['status']} ({data['ssl_check']['days_remaining']} days remaining)")
    
    y -= 40
    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, y, "2. Security Headers")
    y -= 20
    p.setFont("Helvetica", 12)
    for header, status in data['headers_check'].items():
        p.drawString(120, y, f"{header}: {status}")
        y -= 20
        
    y -= 20
    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, y, "3. Email Security (DNS)")
    y -= 20
    p.setFont("Helvetica", 12)
    p.drawString(120, y, f"SPF Record: {data['dns_check']['spf']}")
    y -= 20
    p.drawString(120, y, f"DMARC Record: {data['dns_check']['dmarc']}")
    
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return Response(content=buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={domain}_security_report.pdf"})
