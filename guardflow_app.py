#!/usr/bin/env python3
"""GuardFlow bootstrap app.

This is the initial project scaffold for a privacy-first desktop scanner that
integrates with a local MalwareZoo instance.
"""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

APP_NAME = "GuardFlow"
DB_PATH = Path("guardflow_logs.db")
MALWAREZOO_BASE_URL = "http://127.0.0.1:8080"
MALWAREZOO_HEALTH = f"{MALWAREZOO_BASE_URL}/health"

REQUIRED_PACKAGES = {
    "pywebview": "webview",
    "requests": "requests",
    "apscheduler": "apscheduler",
    "send2trash": "send2trash",
}


def check_environment() -> None:
    """Self-healing startup checks for dependencies and local service."""
    missing = [pkg for pkg, mod in REQUIRED_PACKAGES.items() if importlib.util.find_spec(mod) is None]

    if missing:
        print(f"[{APP_NAME}] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])

    # Import after potential install.
    import requests  # pylint: disable=import-outside-toplevel

    if not Path("docker-compose.yml").exists():
        print(f"[{APP_NAME}] Missing docker-compose.yml. Please recreate it from repository root.")

    try:
        resp = requests.get(MALWAREZOO_HEALTH, timeout=3)
        if resp.status_code >= 400:
            raise RuntimeError(f"Unhealthy response: {resp.status_code}")
        print(f"[{APP_NAME}] MalwareZoo is reachable at {MALWAREZOO_BASE_URL}")
    except Exception:
        print(
            f"[{APP_NAME}] MalwareZoo is not reachable.\n"
            "Run: docker compose up -d\n"
            "Then restart GuardFlow."
        )


def ensure_database() -> None:
    """Create base logging table used by the Reports tab."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                result TEXT NOT NULL,
                detail TEXT,
                source TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


class GuardFlowAPI:
    """Minimal API surface for pywebview integration.

    Methods are placeholders for next implementation steps.
    """

    def scan_file(self, file_path: str) -> dict:
        return {"ok": False, "message": "scan_file not implemented yet", "file": file_path}

    def upload_for_deep_scan(self, file_path: str) -> dict:
        return {"ok": False, "message": "upload_for_deep_scan not implemented yet", "file": file_path}

    def delete_file(self, file_path: str) -> dict:
        return {"ok": False, "message": "delete_file not implemented yet", "file": file_path}

    def schedule_scan(self, target_type: str, target_path: str, frequency: str, every_hours: int = 6) -> dict:
        return {
            "ok": False,
            "message": "schedule_scan not implemented yet",
            "target_type": target_type,
            "target_path": target_path,
            "frequency": frequency,
            "every_hours": every_hours,
        }

    def get_reports(self) -> dict:
        return {"ok": True, "summary": {"totalScanned": 0, "threatsNeutralized": 0, "safetyScore": 100}, "logs": []}


def main() -> None:
    check_environment()
    ensure_database()

    # Deferred import so check_environment can install dependency first.
    import webview  # pylint: disable=import-outside-toplevel

    api = GuardFlowAPI()
    webview.create_window(APP_NAME, url="index.html", js_api=api, width=1200, height=820)
    webview.start()


if __name__ == "__main__":
    main()
