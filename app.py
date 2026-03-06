import smtplib, uuid, time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate

HOST = "server.arrowmarketingesp.com"
PORT = 1069

FROM    = "smsohag@arrowmarketingesp.com"
TO      = "test-4e9ebymx8@srv1.mail-tester.com"          # <-- change to your test address
SUBJECT = "Test from my SMTP server"
BODY    = "Hello! This email was sent from my own SMTP server."

# Build a proper RFC 5322 message with all required headers
msg = MIMEMultipart()
msg["From"]       = FROM
msg["To"]         = TO
msg["Subject"]    = SUBJECT
msg["Date"]       = formatdate(localtime=True)
msg["Message-ID"] = f"<{uuid.uuid4()}@fedcontractingacademy.com>"
msg.attach(MIMEText(BODY, "plain"))

print(f"Connecting to {HOST}:{PORT} ...")
try:
    with smtplib.SMTP(HOST, PORT, timeout=15) as s:
        s.set_debuglevel(1)
        s.ehlo()
        s.login("smsohag", "sohag999")
        s.sendmail(FROM, [TO], msg.as_string())
        print("\n[OK] SUCCESS - email queued for delivery!")
except smtplib.SMTPAuthenticationError as e:
    print(f"\n[FAIL] AUTH failed: {e}")
except smtplib.SMTPConnectError as e:
    print(f"\n[FAIL] Cannot connect to {HOST}:{PORT} - is the server running? firewall open?")
    print(f"  Detail: {e}")
except smtplib.SMTPException as e:
    print(f"\n[FAIL] SMTP error: {e}")
except Exception as e:
    print(f"\n[FAIL] Connection failed: {e}")
    print(f"  -> Check: is smtp-server.exe running on {HOST}?")
    print(f"  -> Check: is port {PORT} open in firewall?")
