"""Minimal TLS responder: the target for the RIPE Atlas sslcert run (phase0/atlas_residential.py).

Completes a TLS handshake with a fixed self-signed cert, answers one tiny HTTP body, closes.
Nothing else. The measurement is entirely on the Atlas side: a probe that completes the
handshake and sees OUR cert fingerprint saw an untampered path; a reset, a stall or a
substituted cert is the finding.

Usage: tls-responder.py <cert.pem> <key.pem> [port]       (installed by deploy/tls-setup.sh)
"""
import socket, ssl, sys, threading

CERT, KEY = sys.argv[1], sys.argv[2]
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 443
BODY = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(CERT, KEY)
SLOTS = threading.BoundedSemaphore(64)   # a scanner can hold slots, never the accept loop

def handle(raw):
    # The handshake happens HERE, in the worker, under a deadline. It used to run on the
    # accept loop with no timeout: on 2026-09-13 a scanner opened connections and sent no
    # ClientHello, wrap_socket blocked forever, and 443 was dead for two weeks while systemd
    # still reported the unit active. A dead listener reads to Atlas exactly like a block.
    try:
        raw.settimeout(10)
        try:
            c = ctx.wrap_socket(raw, server_side=True)
        except Exception:
            try: raw.close()
            except Exception: pass
            return
        try:
            c.settimeout(10)
            try: c.recv(4096)
            except Exception: pass
            try: c.sendall(BODY)
            except Exception: pass
        finally:
            try: c.close()
            except Exception: pass
    finally:
        SLOTS.release()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", PORT)); s.listen(64)
while True:
    try: raw, _ = s.accept()
    except Exception: continue
    SLOTS.acquire()
    try:
        threading.Thread(target=handle, args=(raw,), daemon=True).start()
    except Exception:
        # No worker means nobody else will release this slot or close this socket.
        SLOTS.release()
        try: raw.close()
        except Exception: pass
