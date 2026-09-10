import re
import socket
import subprocess
import smtplib
import sys

sys.path.insert(0, r"C:\Users\PreSafu\Desktop\CC\midsig")
from midsig import core

BOX = "127.0.0.1"   # WSL2 localhost relay -> box's Postfix
WSL = ["wsl", "-d", "Ubuntu", "-u", "root", "--", "true"]  # wake the VM, re-arming the relay
PORT = 25
TO = "test@DESKTOP-AIF4NN0"
KEY = r"C:\Users\PreSafu\Desktop\CC\keys\aisp.live.hex.txt"
raw = open(KEY).read()
seed = bytes.fromhex(re.search(r"([0-9a-fA-F]{64})", raw).group(1))

def connect():
    last = None
    for _ in range(3):
        try:
            s = socket.create_connection((BOX, PORT), timeout=15)
            s.recv(256)
            s.close()
            return
        except OSError as e:
            last = e
            subprocess.run(WSL, capture_output=True)
    raise last

def send(ml_from, msg, label):
    s = None
    try:
        connect()
        s = smtplib.SMTP(BOX, PORT, timeout=30, local_hostname="LANPROOFHOST")
        s.mail(ml_from)
        s.rcpt(TO)
        code, resp = s.data(msg.encode())
        verdict = "ACCEPT" if 200 <= code < 300 else "REJECT"
        result = f"{verdict} {code} {resp[:60]}"
    except smtplib.SMTPDataError as e:
        result = f"REJECT {e.smtp_code} {e.smtp_error[:60]}"
    except Exception as e:
        result = f"ERROR {type(e).__name__}: {e}"
    finally:
        if s is not None:
            try:
                s.quit()
            except Exception:
                pass
    print(f"[{label}] {result}")

base = (
    "From: Presale Safe <presale@aisp.live>\r\n"
    f"To: {TO}\r\n"
    "Subject: LAN proof\r\n"
    "Message-ID: <lan-1@aisp.live>\r\n"
    "\r\n"
    "MIDSIG LAN proof from a second machine.\r\n"
)

print(f"Box {BOX}:{PORT}, recipient {TO}")
send("stranger@evil.com", "From: Stranger <stranger@evil.com>\r\n" + base[base.index("To:"):], "1 unsig")
hdr = "From: Presale Safe <presale@aisp.live>\r\n" + base[base.index("To:"):]
hdr = hdr.replace("Message-ID: <lan-1@aisp.live>", "Message-ID: <spoofed-999@aisp.live>")
send("presale@aisp.live", hdr, "2 spoof")
send("presale@aisp.live", core.sign_eml(seed, base, postage_bits=16), "3 signed")