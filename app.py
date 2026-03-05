import smtplib, ssl

HOST = "mail.fedcontractingacademy.com"   # e.g. "203.0.113.5"
PORT = 1025

with smtplib.SMTP(HOST, PORT) as s:
    s.set_debuglevel(2)          # show every SMTP command
    s.ehlo()
    # do NOT call s.starttls() — we're testing plain
    s.login("smsohag", "sohag999")
    s.sendmail(
        "smsohag@fedcontractingacademy.com",
        ["sohagbdmt@gmail.com"],
        "Subject: Test\r\n\r\nHello from my server!"
    )
    print("SUCCESS")