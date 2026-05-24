"""
Sample industrial device management API.
Intentionally contains security issues for SAST/DAST demo.
DO NOT use in production.
"""

import sqlite3
import hashlib
import subprocess
import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DB_PATH = os.getenv("DB_PATH", "devices.db")


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
            # VULNERABILITY: SQL injection
            status_filter = qs.get("status", ["READY"])[0]
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                f"SELECT * FROM devices WHERE status='{status_filter}'"
            ).fetchall()
            conn.close()
            self.send_json(200, {"devices": rows})

        elif parsed.path == "/api/ping":
            # VULNERABILITY: command injection — shell=True with user input
            host = qs.get("host", ["localhost"])[0]
            result = subprocess.run(
                f"ping -c 1 {host}",
                shell=True,
                capture_output=True,
                text=True
            )
            self.send_json(200, {"output": result.stdout})

        elif parsed.path == "/api/version":
            self.send_json(200, {
                "app": "device-manager",
                "version": "1.0.0",
                "debug": True
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
            # VULNERABILITY: MD5 password hashing (weak)
            hashed = hashlib.md5(password.encode()).hexdigest()
            conn = sqlite3.connect(DB_PATH)
            user = conn.execute(
                f"SELECT * FROM users WHERE username='{username}' "
                f"AND password='{hashed}'"
            ).fetchone()
            conn.close()
            if user:
                # VULNERABILITY: hardcoded secret in token
                token = hashlib.md5(
                    b"supersecretkey123" + username.encode()
                ).hexdigest()
                self.send_json(200, {"token": token, "user": username})
            else:
                self.send_json(401, {"error": "invalid credentials"})
        else:
            self.send_json(404, {"error": "not found"})


if __name__ == "__main__":
    init_db()
    port = int(os.getenv("APP_PORT", "9000"))
    print(f"Device Manager API running on port {port}")
    HTTPServer(("0.0.0.0", port), DeviceHandler).serve_forever()