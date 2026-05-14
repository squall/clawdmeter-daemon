#!/usr/bin/env python3
"""
Clawdmeter token sync server.

Reads the local Claude Code credentials file and exposes the current
accessToken over HTTP on the LAN so the mobile app can fetch a fresh
token without the user having to copy-paste manually.

Security model (intentionally simple, not a public service):
  - Binds to a single LAN IP by default (auto-detected) — not 0.0.0.0
    by default, so opening LAN is opt-in.
  - Requires a shared secret in the Authorization header. The secret is
    auto-generated on first run and stored at
    ~/.config/clawdmeter-token-sync/secret. Print it on stdout for the
    user to enter into the app once.
  - HTTP only (no TLS). Treat the secret like a Wi-Fi password — it's
    fine on a home LAN but never expose this server to the internet.

Usage:
    python3 token-sync-server.py                  # autodetect IP, default port 47821
    python3 token-sync-server.py --host 0.0.0.0   # bind all interfaces
    python3 token-sync-server.py --port 5000      # custom port
    python3 token-sync-server.py --print-secret   # show secret & URL, then exit
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import secrets
import socket
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

CREDENTIALS_PATH = Path.home() / ".claude" / ".credentials.json"
CONFIG_DIR = Path.home() / ".config" / "clawdmeter-token-sync"
SECRET_PATH = CONFIG_DIR / "secret"
DEFAULT_PORT = 47821
MACOS_KEYCHAIN_SERVICE = "Claude Code-credentials"

log = logging.getLogger("clawdmeter-sync")


def load_or_create_secret() -> str:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_PATH.exists():
        return SECRET_PATH.read_text().strip()
    secret = secrets.token_urlsafe(24)
    SECRET_PATH.write_text(secret)
    try:
        os.chmod(SECRET_PATH, 0o600)
    except OSError:
        pass
    return secret


def print_qr(payload: str) -> bool:
    """Print a QR code for `payload` to the terminal. Returns False if the
    qrcode package isn't installed (degrades gracefully)."""
    try:
        import qrcode  # type: ignore
    except ImportError:
        print("[qr] qrcode package not installed — skip. "
              "Run `pip3 install qrcode` to enable.")
        return False
    qr = qrcode.QRCode(border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    qr.print_ascii(invert=True)
    return True


def autodetect_lan_ip() -> str:
    """Return a best-guess LAN IP. Falls back to 127.0.0.1 offline."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually send packets — just resolves the route.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _load_credentials_macos_keychain() -> dict | None:
    """Read Claude Code credentials from macOS Keychain.

    Claude Code on macOS stores the OAuth bundle as a generic password
    under service "Claude Code-credentials". Returns the parsed JSON
    or None if not available.
    """
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s",
             MACOS_KEYCHAIN_SERVICE, "-w"],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    raw = result.stdout.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _load_credentials_file() -> dict | None:
    if not CREDENTIALS_PATH.exists():
        return None
    try:
        with CREDENTIALS_PATH.open("r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def read_token() -> dict:
    """Locate the current Claude Code accessToken.

    Order:
      1. ~/.claude/.credentials.json (Linux / portable layout)
      2. macOS Keychain entry "Claude Code-credentials"
    """
    creds = _load_credentials_file()
    source = "credentials.json"
    if creds is None and platform.system() == "Darwin":
        creds = _load_credentials_macos_keychain()
        source = "macOS Keychain"
    if creds is None:
        raise FileNotFoundError(
            "No Claude Code credentials found. Looked in "
            f"{CREDENTIALS_PATH}"
            + (" and the macOS Keychain" if platform.system() == "Darwin" else "")
            + ". Is Claude Code installed and logged in?"
        )

    access = creds.get("accessToken") or _nested(creds, "claudeAiOauth.accessToken")
    if not access:
        raise ValueError(f"accessToken not found ({source})")

    expires = creds.get("expiresAt") or _nested(creds, "claudeAiOauth.expiresAt")
    return {
        "accessToken": access,
        "expiresAt": expires,
        "source": source,
    }


def _nested(obj: dict, dotted: str):
    cur = obj
    for key in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


class TokenHandler(BaseHTTPRequestHandler):
    secret: str = ""

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self) -> bool:
        header = self.headers.get("Authorization", "")
        expected = f"Bearer {self.secret}"
        # Constant-time compare to avoid timing leak on the secret.
        if len(header) != len(expected):
            return False
        return secrets.compare_digest(header, expected)

    def do_GET(self):  # noqa: N802 — required name
        path = urlparse(self.path).path
        if path == "/health":
            self._json(200, {"ok": True})
            return
        if path != "/token":
            self._json(404, {"error": "not_found"})
            return
        if not self._check_auth():
            self._json(401, {"error": "unauthorized"})
            return
        try:
            payload = read_token()
            self._json(200, payload)
        except FileNotFoundError as e:
            self._json(404, {"error": "no_credentials", "message": str(e)})
        except Exception as e:
            log.exception("Failed to read token")
            self._json(500, {"error": "internal", "message": str(e)})

    def log_message(self, format, *args):  # quieter default logs
        log.info("%s - %s", self.client_address[0], format % args)


def main(argv: list[str]):
    parser = argparse.ArgumentParser(description="Clawdmeter token sync server")
    parser.add_argument("--host", default=None,
                        help="Bind address (default: autodetected LAN IP)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--print-secret", action="store_true",
                        help="Print the shared secret & connection URL, then exit")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s",
                        datefmt="%H:%M:%S")

    secret = load_or_create_secret()
    host = args.host or autodetect_lan_ip()
    url = f"http://{host}:{args.port}/token"
    qr_payload = json.dumps({"url": url, "secret": secret}, separators=(",", ":"))

    if args.print_secret:
        print(f"URL:    {url}")
        print(f"Secret: {secret}")
        print()
        print("Scan this QR with the Clawdmeter app:")
        print_qr(qr_payload)
        return 0

    TokenHandler.secret = secret
    print("=" * 60)
    print("Clawdmeter token sync server")
    print("=" * 60)
    print(f"URL:    {url}")
    print(f"Secret: {secret}")
    print(f"Health: http://{host}:{args.port}/health")
    print()
    print("Scan this QR with the Clawdmeter app, or enter the URL + secret")
    print("manually under Settings → LAN Token Sync.")
    print_qr(qr_payload)
    print("=" * 60)

    server = HTTPServer((host, args.port), TokenHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
