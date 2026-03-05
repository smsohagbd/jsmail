import smtplib, ssl

HOST = "mail.fedcontractingacademy.com"   # local test — change to your server IP for remote
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