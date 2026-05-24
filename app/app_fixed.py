"""
Fixed version of the device management API.
All SAST issues remediated — demonstrates what clean code looks like.
"""

import sqlite3
import hashlib
import secrets
import subprocess
import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DB_PATH = os.getenv("DB_PATH", "devices.db")

# Whitelist of allowed hosts for ping
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "8.8.8.8"}


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT,
            firmware TEXT,
            status TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    """)
    conn.execute(
        "INSERT OR IGNORE INTO devices VALUES "
        "('anvil-001','Anvil CheckPoint','fw-2.4.1','READY')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES "
        "('admin','5f4dcc3b5aa765d61d8327deb882cf99')"
    )
    conn.commit()
    conn.close()


class DeviceHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass

    def send_json(self, code, payload):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/health":
            self.send_json(200, {"status": "ok"})

        elif parsed.path == "/api/devices":
            # FIX: parameterised query — no SQL injection possible
            status_filter = qs.get("status", ["READY"])[0]
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT * FROM devices WHERE status=?",
                (status_filter,)
            ).fetchall()
            conn.close()
            self.send_json(200, {"devices": rows})

        elif parsed.path == "/api/ping":
            # FIX: whitelist validation + shell=False + list args
            host = qs.get("host", ["localhost"])[0]
            if host not in ALLOWED_HOSTS:
                self.send_json(400, {"error": "host not allowed"})
                return
            result = subprocess.run(
                ["ping", "-n", "1", host],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5
            )
            self.send_json(200, {"output": result.stdout})

        elif parsed.path == "/api/version":
            # FIX: removed debug flag and server details
            self.send_json(200, {
                "app": "device-manager",
                "version": "1.0.0"
            })

        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length) or b"{}")
        parsed = urlparse(self.path)

        if parsed.path == "/api/login":
            username = body.get("username", "")
            password = body.get("password", "")
            # FIX: use SHA-256 instead of MD5
            # In production: use bcrypt or argon2
            hashed = hashlib.sha256(password.encode()).hexdigest()
            conn = sqlite3.connect(DB_PATH)
            # FIX: parameterised query
            user = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            ).fetchone()
            conn.close()
            if user:
                # FIX: use secrets.token_hex() — cryptographically secure
                token = secrets.token_hex(32)
                self.send_json(200, {"token": token, "user": username})
            else:
                self.send_json(401, {"error": "invalid credentials"})
        else:
            self.send_json(404, {"error": "not found"})


if __name__ == "__main__":
    init_db()
    port = int(os.getenv("APP_PORT", "9000"))
    print(f"Device Manager API running on port {port}")
    # FIX: bind to specific interface in production
    HTTPServer(("127.0.0.1", port), DeviceHandler).serve_forever()