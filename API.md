# smtp-server — API & Usage Guide

## What is smtp-server?

`smtp-server.exe` (Windows) / `smtp-server` (Linux) is a self-hosted outbound mail server.  
It has two parts:

```
smtp-server
│
├── SMTP listener  (port 1069)
│     Accepts email from your app/client using username + password.
│     Puts the email in the queue.
│
├── Delivery engine  (background)
│     Takes emails from the queue and delivers them directly
│     to Gmail / Outlook / Yahoo / any mail server.
│     Retries automatically on failure.
│
└── HTTP API  (port 8069)
      Lets you send email and verify addresses via simple HTTP requests.
      Secured with a Bearer token.
```

---

## Build & Run

### Windows
```powershell
go build -o smtp-server.exe .
.\smtp-server.exe -config config.yaml
```

### Linux
```bash
go build -o smtp-server .
./smtp-server -config config.yaml
```

### Linux — run as background service (systemd)
```bash
# Copy binary
sudo cp smtp-server /usr/local/bin/smtp-server
sudo chmod +x /usr/local/bin/smtp-server

# Create service file
sudo nano /etc/systemd/system/smtp-server.service
```

Paste this into the file:
```ini
[Unit]
Description=SMTP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/smtp-server
ExecStart=/usr/local/bin/smtp-server -config /opt/smtp-server/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable smtp-server
sudo systemctl start smtp-server
sudo systemctl status smtp-server

# View live logs
sudo journalctl -u smtp-server -f
```

---

## HTTP API Reference

**Base URL:** `http://YOUR_SERVER:8069`  
**Auth:** All endpoints (except `/health`) require:
```
Authorization: Bearer change-this-secret-token
```

---

### POST /send — Send an email

**Request body:**
```json
{
  "from":    "info@yourdomain.com",
  "to":      ["recipient@gmail.com", "other@outlook.com"],
  "subject": "Hello",
  "body":    "This is the email body.",
  "html":    false
}
```

| Field | Required | Description |
|---|---|---|
| `from` | yes | Sender address |
| `to` | yes | Array of recipient addresses |
| `subject` | yes | Email subject |
| `body` | yes | Plain text body |
| `html` | no | Set `true` to send HTML body |
| `raw_data` | no | Full RFC 5322 message string (overrides all other fields) |

**Response `202 Accepted`:**
```json
{
  "message_id": "1772746521324574600-864ca1cade40c495",
  "status": "queued"
}
```

**Examples:**

```bash
# Linux / Mac
curl -X POST http://YOUR_SERVER:8069/send \
  -H "Authorization: Bearer change-this-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "info@arrowmarketingesp.com",
    "to": ["customer@gmail.com"],
    "subject": "Welcome!",
    "body": "Thanks for signing up."
  }'
```

```powershell
# Windows PowerShell
Invoke-RestMethod -Method POST -Uri "http://YOUR_SERVER:8069/send" `
  -Headers @{ Authorization = "Bearer change-this-secret-token" } `
  -ContentType "application/json" `
  -Body '{"from":"info@arrowmarketingesp.com","to":["customer@gmail.com"],"subject":"Welcome!","body":"Thanks for signing up."}'
```

```python
# Python
import requests

requests.post("http://YOUR_SERVER:8069/send",
  headers={"Authorization": "Bearer change-this-secret-token"},
  json={
    "from": "info@arrowmarketingesp.com",
    "to": ["customer@gmail.com"],
    "subject": "Welcome!",
    "body": "Thanks for signing up."
  }
)
```

---

### GET /verify — Verify a single email address

Checks if an email address exists **without sending any email**.

**Checks performed:**
1. Email format validation
2. MX DNS record lookup
3. Disposable domain detection
4. SMTP connect to mail server
5. RCPT TO mailbox probe
6. Catch-all domain detection

**Request:**
```
GET /verify?email=someone@gmail.com
Authorization: Bearer change-this-secret-token
```

**Response:**
```json
{
  "email": "someone@gmail.com",
  "valid": true,
  "is_catch_all": false,
  "is_disposable": false,
  "mx_host": "gmail-smtp-in.l.google.com",
  "checks": {
    "format":       "pass",
    "mx_exists":    "pass",
    "smtp_connect": "pass",
    "mailbox":      "pass"
  },
  "verified_at": "2026-03-06T18:00:00Z"
}
```

**Check result values:**

| Value | Meaning |
|---|---|
| `pass` | Check succeeded |
| `fail` | Check failed — address is invalid |
| `unknown` | Server blocked the probe — assume valid |

**Bad address example:**
```json
{
  "email": "fake@fakexyz999.com",
  "valid": false,
  "reason": "no MX records found for domain fakexyz999.com",
  "checks": {
    "format":       "pass",
    "mx_exists":    "fail",
    "smtp_connect": "unknown",
    "mailbox":      "unknown"
  }
}
```

```bash
curl "http://YOUR_SERVER:8069/verify?email=test@gmail.com" \
  -H "Authorization: Bearer change-this-secret-token"
```

---

### POST /verify/bulk — Verify a list of emails

Clean an entire email list in one request. Max 500 emails per request.

**Request body:**
```json
{
  "emails": [
    "good@gmail.com",
    "fake@notarealdomain999.com",
    "temp@mailinator.com",
    "nobody@yahoo.com"
  ],
  "concurrency": 5
}
```

| Field | Required | Description |
|---|---|---|
| `emails` | yes | Array of email addresses (max 500) |
| `concurrency` | no | Parallel verifications (default 5, max recommended 10) |

**Response:**
```json
{
  "total":      4,
  "valid":      1,
  "invalid":    2,
  "unknown":    0,
  "catch_all":  0,
  "disposable": 1,
  "results": [
    {
      "email": "good@gmail.com",
      "valid": true,
      "checks": { "format":"pass","mx_exists":"pass","smtp_connect":"pass","mailbox":"pass" }
    },
    {
      "email": "fake@notarealdomain999.com",
      "valid": false,
      "reason": "no MX records found for domain notarealdomain999.com",
      "checks": { "format":"pass","mx_exists":"fail","smtp_connect":"unknown","mailbox":"unknown" }
    },
    {
      "email": "temp@mailinator.com",
      "valid": false,
      "is_disposable": true,
      "reason": "",
      "checks": { "format":"pass","mx_exists":"pass","smtp_connect":"pass","mailbox":"unknown" }
    },
    {
      "email": "nobody@yahoo.com",
      "valid": false,
      "reason": "mailbox does not exist",
      "checks": { "format":"pass","mx_exists":"pass","smtp_connect":"pass","mailbox":"fail" }
    }
  ]
}
```

**Python — bulk verify and filter:**
```python
import requests

emails = ["user1@gmail.com", "fake@xyz999.com", "user2@outlook.com"]

resp = requests.post("http://YOUR_SERVER:8069/verify/bulk",
  headers={"Authorization": "Bearer change-this-secret-token"},
  json={"emails": emails, "concurrency": 5}
)

data = resp.json()
print(f"Total: {data['total']}  Valid: {data['valid']}  Invalid: {data['invalid']}")

valid_emails = [r["email"] for r in data["results"] if r["valid"]]
print("Clean list:", valid_emails)
```

---

### GET /health — Server health check

No auth required.

```bash
curl http://YOUR_SERVER:8069/health
```

```json
{ "status": "ok" }
```

---

## SMTP Submission (port 1069)

You can also send email using any standard SMTP client pointed at your server.

| Setting | Value |
|---|---|
| Host | `YOUR_SERVER` |
| Port | `1069` |
| Username | `smsohag` |
| Password | `sohag999` |
| Security | None / STARTTLS |
| Auth | PLAIN or LOGIN |

**Python smtplib:**
```python
import smtplib, uuid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate

msg = MIMEMultipart()
msg["From"]       = "info@arrowmarketingesp.com"
msg["To"]         = "recipient@gmail.com"
msg["Subject"]    = "Hello"
msg["Date"]       = formatdate(localtime=True)
msg["Message-ID"] = f"<{uuid.uuid4()}@arrowmarketingesp.com>"
msg.attach(MIMEText("Hello from my SMTP server!", "plain"))

with smtplib.SMTP("YOUR_SERVER", 1069) as s:
    s.login("smsohag", "sohag999")
    s.sendmail(msg["From"], [msg["To"]], msg.as_string())
    print("Sent!")
```

---

## Queue Directory

All emails are stored as JSON files before delivery:

```
queue/
├── <id>.json          ← pending / in-flight / deferred messages
└── failed/
    └── <id>.json      ← permanently failed (review these for bounces)
```

Each file is human-readable JSON with the full error reason, retry count, and timestamps.

---

## Firewall Ports to Open

| Port | Direction | Purpose |
|---|---|---|
| 1069 | Inbound | SMTP submission from your apps |
| 8069 | Inbound | HTTP API |
| 25 | Outbound | Direct delivery to Gmail/Outlook/etc |
| 587 | Outbound | Fallback delivery (when port 25 is blocked) |
