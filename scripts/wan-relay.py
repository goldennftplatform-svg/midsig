import ipaddress
import socket
import subprocess
import threading
import time

# Bridges inbound SMTP arriving on the Windows LAN interface (port 25, from a
# router port-forward) into the WSL guest's Postfix at 127.0.0.1:25 — the WSL2
# localhost forwarder is the only Windows->guest path that works here.
# The guest leg is re-warmed on failed connects (WSL2's forwarder idles out).
LISTEN_IP = "192.168.12.135"
LISTEN_PORT = 25
GUEST = ("127.0.0.1", 25)
WSL_WAKE = ["wsl", "-d", "Ubuntu", "-u", "root", "--", "true"]

def connect_guest():
    last = None
    for _ in range(3):
        try:
            return socket.create_connection(GUEST, timeout=15)
        except OSError as e:
            last = e
            subprocess.run(WSL_WAKE, capture_output=True)
    if last is not None:
        raise last

def pipe(a, b):
    try:
        while True:
            data = a.recv(4096)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass

def relay(client):
    server = None
    try:
        server = connect_guest()
    except OSError as e:
        print(f"[relay] guest leg failed: {e}", flush=True)
        client.close()
        return
    try:
        client.settimeout(120)
        server.settimeout(120)
        for src, dst in ((client, server), (server, client)):
            threading.Thread(target=pipe, args=(src, dst), daemon=True).start()
        time.sleep(0.1)
    finally:
        for s in (client, server):
            try:
                s.close()
            except OSError:
                pass

def main():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LISTEN_IP, LISTEN_PORT))
    listener.listen(32)
    print(f"[relay] listening on {LISTEN_IP}:{LISTEN_PORT} -> {GUEST[0]}:{GUEST[1]}", flush=True)
    while True:
        client, addr = listener.accept()
        print(f"[relay] connection from {addr[0]}", flush=True)
        threading.Thread(target=relay, args=(client,), daemon=True).start()

if __name__ == "__main__":
    main()