#!/usr/bin/env python3
"""Real-browser end-to-end check: starts the backend on a temporary database, creates two users,
drives the built dashboard in headless Chrome, and prints PASS/FAIL per step.

    python tests/e2e_browser/run.py

What it does, with no manual setup:
  1. builds the frontend if frontend/dist is missing (npm install + npm run build)
  2. installs this folder's two npm packages if missing
  3. starts uvicorn on a free port with a throwaway database, API key and JWT secret
  4. runs e2e.mjs: login, live WebSocket updates, alerts, status change, blocklist, admin page, logout

Browser: set CHROME_PATH to your own Chrome/Chromium (any OS). Otherwise a Linux x64 Chromium is
fetched through npm (@sparticuz/chromium). Screenshots land in tests/e2e_browser/shots/.
Not collected by pytest (it needs Node and a browser); run it before a release or a demo.
"""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ADMIN = ("e2e_admin", "e2e-admin-password-1")
ANALYST = ("e2e_analyst", "e2e-analyst-password-1")


def need(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        sys.exit(f"error: '{tool}' was not found on PATH (Node.js 20+ is required for this check)")
    return path


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    npm, node = need("npm"), need("node")
    if not (ROOT / "frontend" / "dist" / "index.html").is_file():
        print("Building the frontend...")
        subprocess.run([npm, "install"], cwd=ROOT / "frontend", check=True)
        subprocess.run([npm, "run", "build"], cwd=ROOT / "frontend", check=True)
    if not (HERE / "node_modules" / "puppeteer-core").is_dir():
        print("Installing the browser driver (puppeteer-core)...")
        subprocess.run([npm, "install", "--no-audit", "--no-fund"], cwd=HERE, check=True)

    api_key, jwt_secret = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    port = free_port()
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "DATABASE_PATH": str(Path(tmp) / "e2e.db"), "API_KEY": api_key, "JWT_SECRET": jwt_secret,
               "PYTHONPATH": str(ROOT)}
        # Create the users in this process, against the same throwaway database.
        os.environ.update(DATABASE_PATH=env["DATABASE_PATH"], API_KEY=api_key, JWT_SECRET=jwt_secret)
        sys.path.insert(0, str(ROOT))
        from app import passwords, storage
        from app.config import get_settings
        from app.db import open_database

        db = open_database(get_settings().database_path)
        for (name, password), role in ((ADMIN, "admin"), (ANALYST, "analyst")):
            storage.create_user(db, username=name, password_hash=passwords.hash_password(password), role=role)
        db.close()

        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.main:app", "--port", str(port), "--log-level", "warning"],
            cwd=ROOT, env=env,
        )
        try:
            base = f"http://127.0.0.1:{port}"
            for _ in range(100):
                try:
                    urllib.request.urlopen(base + "/docs", timeout=1)
                    break
                except OSError:
                    time.sleep(0.2)
            else:
                print("error: the backend did not start", file=sys.stderr)
                return 1
            result = subprocess.run(
                [node, "e2e.mjs"], cwd=HERE,
                env={**env, "E2E_BASE": base, "E2E_API_KEY": api_key, "E2E_PYTHON": sys.executable,
                     "E2E_DEMO_TOOL": str(ROOT / "tools" / "send_demo_events.py"),
                     "E2E_ADMIN_USER": ADMIN[0], "E2E_ADMIN_PASSWORD": ADMIN[1],
                     "E2E_ANALYST_USER": ANALYST[0], "E2E_ANALYST_PASSWORD": ANALYST[1]},
            )
            return result.returncode
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    raise SystemExit(main())
