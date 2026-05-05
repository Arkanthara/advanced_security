"""
RSA Timing Attack — Server
==========================
Exposes two endpoints:
  GET  /      → public key (e, n, key_bits)
  POST /      → {"y": <int>} → {"time": <float>}  (timed decryption)

The private key d is never transmitted; its bit-length is shared so the
attacker knows how many bits to recover.

The timing vulnerability comes from fast_exp: when exponent bit j == 1 an
extra modular multiplication ``s = (s * y) % n`` is performed, making that
iteration measurably slower. By correlating timing variations across many
inputs an attacker can recover each bit of d one-by-one.
"""

import gc
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from rsa import RSA

# ── Configuration ────────────────────────────────────────────────────────────
PORT     = 8080
KEY_SIZE = 64          # 32-bit primes → ~64-bit n and d  (small = fast demo)

# ── Key generation (once at startup) ─────────────────────────────────────────
_rsa         = RSA()
n, e, d      = _rsa.createKeyPair(KEY_SIZE)
KEY_BITS     = d.bit_length()

print(f"[Server] n        = {n}")
print(f"[Server] e        = {e}")
print(f"[Server] d        = {d}   ← SECRET")
print(f"[Server] key_bits = {KEY_BITS}")
print(f"[Server] Listening on :{PORT}\n")


# ── Timed decryption ──────────────────────────────────────────────────────────

def timed_decrypt(y: int) -> float:
    """
    Decrypt y with the private key and return the wall-clock time.

    GC is disabled to reduce timing noise.

    Parameters
    ----------
    y : int
        Ciphertext to decrypt.

    Returns
    -------
    float
        Decryption time in seconds.
    """
    gc.disable()
    t0 = time.perf_counter()
    _rsa.decrypt(y)
    t1 = time.perf_counter()
    gc.enable()
    return t1 - t0


# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    """Minimal two-endpoint HTTP handler."""

    def do_GET(self):
        """Return the public key and exponent bit-length."""
        self._send({"e": e, "n": n, "key_bits": KEY_BITS})

    def do_POST(self):
        """Accept a ciphertext y and return the decryption time."""
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self._send({"time": timed_decrypt(int(body["y"]))})

    def _send(self, obj: dict):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):  # suppress access logs
        pass


if __name__ == "__main__":
    HTTPServer(("localhost", PORT), Handler).serve_forever()
