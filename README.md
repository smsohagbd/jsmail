# smtp-server

A production-ready outbound SMTP server written in Go, inspired by KumoMTA.  
Send email from your own server with a persistent queue, retry logic, DKIM signing, and an HTTP injection API.

---

## Features

| Feature | Detail |
|---|---|
| SMTP submission | Port 587 with STARTTLS + AUTH PLAIN |
| Outbound delivery | MX lookup → direct SMTP to recipient servers (port 25) |
| Persistent queue | File-based; survives restarts; deferred messages auto-retry |
| Retry with backoff | Exponential backoff, configurable max retries |
| DKIM signing | RSA key, configurable selector & domain |
| HTTP API | `POST /send` to inject messages programmatically |
| TLS | Optional TLS for the submission listener |

---

## Quick Start

### 1. Edit `config.yaml`

```yaml
smtp:
  domain: "mail.yourdomain.com"   # your sending domain
  auth:
    users:
      - username: "user@yourdomain.com"
        password: "strong-password"

delivery:
  helo_name: "mail.yourdomain.com"

api:
  auth_token: "your-api-secret"
```

### 2. Build & run

```bash

systemctl stop smtp-server
rm smtp-server
git pull
go build -o smtp-server .
./smtp-server -config config.yaml




git add .
git commit -m "fix code "
git push




### 3. Send via SMTP (port 587)

Use any SMTP client, e.g. `swaks`:

```bash
swaks --to recipient@gmail.com \
      --from you@yourdomain.com \
      --server localhost \
      --port 587 \
      --auth PLAIN \
      --auth-user user@yourdomain.com \
      --auth-password strong-password \
      --tls-optional \
      --header "Subject: Hello from my server" \
      --body "This email was sent from my own SMTP server!"
```

### 4. Send via HTTP API

```bash
curl -X POST http://localhost:8080/send \
  -H "Authorization: Bearer your-api-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "you@yourdomain.com",
    "to": ["recipient@gmail.com"],
    "subject": "Hello from smtp-server",
    "body": "Sent via the HTTP API!"
  }'
```

Response:
```json
{"message_id":"1741234567-abcd1234","status":"queued"}
```

---

## DKIM Setup

### 1. Generate RSA key pair

```bash
mkdir dkim
openssl genrsa -out dkim/private.key 2048
openssl rsa -in dkim/private.key -pubout -out dkim/public.key
```

### 2. Add DNS TXT record

Create a TXT record at `default._domainkey.yourdomain.com`:

```
v=DKIM1; k=rsa; p=<base64-public-key>
```

Extract the base64 public key:
```bash
openssl rsa -in dkim/private.key -pubout 2>/dev/null | grep -v -- '-----' | tr -d '\n'
```

### 3. Enable in config

```yaml
delivery:
  dkim:
    enabled: true
    selector: "default"
    private_key_file: "dkim/private.key"
    domain: "yourdomain.com"
```

---

## TLS Setup (for port 587)

```bash
mkdir certs
# Self-signed (dev only):
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
```

Or point to your Let's Encrypt certificate:

```yaml
smtp:
  tls:
    enabled: true
    cert_file: "/etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem"
    key_file:  "/etc/letsencrypt/live/mail.yourdomain.com/privkey.pem"
```

---

## DNS Records required for sending

| Record | Value |
|---|---|
| `A` / `PTR` | `mail.yourdomain.com` → your server IP (and reverse PTR) |
| `MX` | `yourdomain.com MX 10 mail.yourdomain.com` |
| `SPF` | `yourdomain.com TXT "v=spf1 ip4:YOUR_IP ~all"` |
| `DKIM` | `default._domainkey.yourdomain.com TXT "v=DKIM1; k=rsa; p=..."` |
| `DMARC` | `_dmarc.yourdomain.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com"` |

---

## Queue Directory Layout

```
queue/
├── <id>.json          ← pending / deferred / in-flight messages
└── failed/
    └── <id>.json      ← permanently failed messages (kept for inspection)
```

Each message file is plain JSON and human-readable.

---

## Database (MySQL)

By default the server uses SQLite (`smtp-server.db`). For production use MySQL:

```yaml
database:
  driver: "mysql"
  host: "localhost"
  port: 3306
  user: "smtp"
  password: "your-password"
  database: "smtp"
  charset: "utf8mb4"
```

Create the database and user first:

```sql
CREATE DATABASE smtp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'smtp'@'%' IDENTIFIED BY 'your-password';
GRANT ALL ON smtp.* TO 'smtp'@'%';
FLUSH PRIVILEGES;
```

Tables are created automatically on first run. To migrate from SQLite, export the SQLite data and import into MySQL, or start fresh with a new MySQL database.

---

## Configuration Reference

```yaml
smtp:
  listen_addr: ":587"
  domain: "mail.example.com"
  max_message_size: 26214400   # bytes (default 25 MB)
  tls:
    enabled: false
    cert_file: "certs/cert.pem"
    key_file:  "certs/key.pem"
  auth:
    users:
      - username: "user@example.com"
        password: "secret"

delivery:
  workers: 5               # parallel delivery workers
  max_retries: 5           # permanent fail after this many attempts
  retry_interval: "5m"     # base retry interval (doubles each attempt)
  connect_timeout: "30s"
  send_timeout: "5m"
  helo_name: "mail.example.com"
  dkim:
    enabled: false
    selector: "default"
    private_key_file: "dkim/private.key"
    domain: "example.com"

queue:
  dir: "queue"

api:
  listen_addr: ":8080"
  auth_token: "change-this-secret-token"

database:
  driver: "sqlite"   # or "mysql"
  path: "smtp-server.db"   # SQLite file path
  # MySQL (when driver: "mysql"):
  # host: "localhost"
  # port: 3306
  # user: "smtp"
  # password: "secret"
  # database: "smtp"
  # charset: "utf8mb4"
```
