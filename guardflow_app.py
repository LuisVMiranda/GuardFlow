#!/usr/bin/env python3
"""GuardFlow - Privacy-First Malware Scanner desktop app.

Frontend: pywebview + index.html SPA
Backend: requests, hashlib, sqlite3, apscheduler, send2trash
"""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

APP_NAME = "GuardFlow"
DB_PATH = Path("guardflow_logs.db")
DOCKER_COMPOSE_PATH = Path("docker-compose.yml")

# MalwareZoo defaults; adjust if your local deployment uses different routes.
MALWAREZOO_BASE_URL = os.getenv("GUARDFLOW_MALWAREZOO_URL", "http://127.0.0.1:8080").rstrip("/")
MALWAREZOO_HEALTH = f"{MALWAREZOO_BASE_URL}/health"
MALWAREZOO_HASH_LOOKUP = f"{MALWAREZOO_BASE_URL}/api/hash_lookup"
MALWAREZOO_UPLOAD = f"{MALWAREZOO_BASE_URL}/api/upload"

REQUIRED_PACKAGES = {
    "pywebview": "webview",
    "requests": "requests",
    "apscheduler": "apscheduler",
    "send2trash": "send2trash",
}


def _is_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def _ensure_docker_compose_file() -> None:
    if DOCKER_COMPOSE_PATH.exists():
        return

    DOCKER_COMPOSE_PATH.write_text(
        """version: \"3.9\"
services:
  malwarezoo:
    image: malwarezoo/local:latest
    container_name: malwarezoo
    ports:
      - \"8080:8080\"
    restart: unless-stopped
""",
        encoding="utf-8",
    )
    print(f"[{APP_NAME}] Created {DOCKER_COMPOSE_PATH}")


def _auto_start_malwarezoo() -> bool:
    """Attempt to bring up MalwareZoo automatically using docker compose."""
    try:
        subprocess.run(
            ["docker", "compose", "up", "-d"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return True
    except Exception:
        return False


def check_environment() -> None:
    """Self-healing startup checks for dependencies and local service."""
    missing = [pkg for pkg, mod in REQUIRED_PACKAGES.items() if not _is_available(mod)]
    if missing:
        print(f"[{APP_NAME}] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])

    # Deferred import after potential install.
    import requests  # pylint: disable=import-outside-toplevel

    _ensure_docker_compose_file()

    def _is_reachable() -> bool:
        try:
            resp = requests.get(MALWAREZOO_HEALTH, timeout=3)
            return resp.status_code < 400
        except Exception:
            return False

    if _is_reachable():
        print(f"[{APP_NAME}] MalwareZoo reachable at {MALWAREZOO_BASE_URL}")
        return

    auto_start_enabled = os.getenv("GUARDFLOW_AUTOSTART_DOCKER", "1") == "1"
    if auto_start_enabled and _auto_start_malwarezoo():
        if _is_reachable():
            print(f"[{APP_NAME}] MalwareZoo started automatically via docker compose.")
            return

    print(
        f"[{APP_NAME}] MalwareZoo is not reachable at {MALWAREZOO_BASE_URL}.\n"
        "Please ensure Docker is running, then execute:\n"
        "  docker compose up -d\n"
        "and relaunch GuardFlow."
    )


def ensure_database() -> None:
    """Create/ensure base logging table."""
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


def sha256_file(file_path: str) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class GuardFlowAPI:
    """pywebview bridge API."""

    def __init__(self) -> None:
        import requests  # pylint: disable=import-outside-toplevel
        from apscheduler.schedulers.background import BackgroundScheduler  # pylint: disable=import-outside-toplevel

        self.requests = requests
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.lock = threading.Lock()
        self.scheduler = BackgroundScheduler(daemon=True)
        self.scheduler.start()

    def _log_scan(self, file_path: str, sha256_hash: str, result: str, detail: str, source: str) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO scan_logs (ts, file_path, sha256, result, detail, source)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (dt.datetime.now(dt.UTC).isoformat(), file_path, sha256_hash, result, detail, source),
            )
            self.conn.commit()

    def _cleanup_old_logs(self) -> None:
        cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(days=30)).isoformat()
        with self.lock:
            self.conn.execute("DELETE FROM scan_logs WHERE ts < ?", (cutoff,))
            self.conn.commit()

    def _call_hash_lookup(self, sha256_hash: str) -> tuple[str, str]:
        """Hash lookup; returns (status, detail)."""
        try:
            resp = self.requests.post(MALWAREZOO_HASH_LOOKUP, json={"sha256": sha256_hash}, timeout=10)
            if resp.status_code >= 400:
                return "ERROR", f"MalwareZoo lookup failed (HTTP {resp.status_code})"
            payload = resp.json() if resp.content else {}
        except Exception as exc:
            return "ERROR", f"MalwareZoo lookup unavailable: {exc}"

        verdict = str(payload.get("verdict", "unknown")).lower()
        detail = str(payload.get("detail", "No additional details."))
        if verdict == "safe":
            return "SAFE", detail
        if verdict == "threat":
            return "THREAT", detail
        return "UNKNOWN", detail

    def scan_file(self, file_path: str) -> dict[str, Any]:
        """Privacy-first scan: only file hash is sent by default."""
        try:
            if not file_path or not os.path.isfile(file_path):
                return {"ok": False, "error": "File path is invalid or not accessible."}

            file_hash = sha256_file(file_path)
            status, detail = self._call_hash_lookup(file_hash)
            self._log_scan(file_path, file_hash, status, detail, "manual")
            self._cleanup_old_logs()
            return {
                "ok": True,
                "file": file_path,
                "sha256": file_hash,
                "status": status,
                "detail": detail,
                "canDelete": status == "THREAT",
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def upload_for_deep_scan(self, file_path: str) -> dict[str, Any]:
        """Explicitly upload file bytes for deep analysis when user confirms."""
        try:
            if not file_path or not os.path.isfile(file_path):
                return {"ok": False, "error": "File path is invalid or missing."}
            with open(file_path, "rb") as fp:
                response = self.requests.post(
                    MALWAREZOO_UPLOAD,
                    files={"file": (Path(file_path).name, fp, "application/octet-stream")},
                    timeout=60,
                )
            if response.status_code >= 400:
                return {"ok": False, "error": f"Upload failed with HTTP {response.status_code}."}
            payload = response.json() if response.content else {}
            verdict = str(payload.get("verdict", "unknown")).upper()
            detail = str(payload.get("detail", "Deep scan completed."))
            return {"ok": True, "status": verdict, "detail": detail}
        except Exception as exc:
            return {"ok": False, "error": f"Deep scan failed: {exc}"}

    def delete_file(self, file_path: str) -> dict[str, Any]:
        """Move a file to trash/recycle bin instead of permanent deletion."""
        try:
            if not file_path or not os.path.exists(file_path):
                return {"ok": False, "error": "File not found."}
            from send2trash import send2trash  # pylint: disable=import-outside-toplevel

            send2trash(file_path)
            return {"ok": True, "message": "File moved to trash."}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _scan_target(self, target_type: str, target_path: str, source: str = "scheduled") -> int:
        scanned_count = 0

        def iter_target_files() -> list[str]:
            if target_type == "file":
                return [target_path]
            if target_type == "folder":
                results: list[str] = []
                for root, _, files in os.walk(target_path):
                    for name in files:
                        results.append(os.path.join(root, name))
                return results
            if target_type == "system":
                roots = ["/"] if os.name != "nt" else [os.environ.get("SystemDrive", "C:") + "\\"]
                results = []
                for root_drive in roots:
                    for root, _, files in os.walk(root_drive):
                        for name in files:
                            results.append(os.path.join(root, name))
                return results
            return []

        for file_path in iter_target_files():
            try:
                if not os.path.isfile(file_path):
                    continue
                file_hash = sha256_file(file_path)
                status, detail = self._call_hash_lookup(file_hash)
                self._log_scan(file_path, file_hash, status, detail, source)
                scanned_count += 1
            except Exception as exc:
                self._log_scan(file_path, "", "ERROR", str(exc), source)

        self._cleanup_old_logs()
        return scanned_count

    def schedule_scan(self, target_type: str, target_path: str, frequency: str, every_hours: int = 6) -> dict[str, Any]:
        """Schedule recurring scan jobs with APScheduler."""
        if target_type not in {"file", "folder", "system"}:
            return {"ok": False, "error": "Invalid target type."}
        if target_type in {"file", "folder"} and not target_path:
            return {"ok": False, "error": "Target path is required."}

        if target_type == "file" and not os.path.isfile(target_path):
            return {"ok": False, "error": "Target file does not exist."}
        if target_type == "folder" and not os.path.isdir(target_path):
            return {"ok": False, "error": "Target folder does not exist."}

        job_id = f"scan:{target_type}:{target_path or 'system'}:{frequency}:{every_hours}"

        def _runner() -> None:
            self._scan_target(target_type=target_type, target_path=target_path, source="scheduled")

        try:
            if frequency == "daily":
                self.scheduler.add_job(_runner, "interval", days=1, id=job_id, replace_existing=True)
            elif frequency == "weekly":
                self.scheduler.add_job(_runner, "interval", weeks=1, id=job_id, replace_existing=True)
            elif frequency == "every_x_hours":
                hours = max(1, int(every_hours))
                self.scheduler.add_job(_runner, "interval", hours=hours, id=job_id, replace_existing=True)
            else:
                return {"ok": False, "error": "Invalid frequency."}
            return {"ok": True, "jobId": job_id}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def list_jobs(self) -> dict[str, Any]:
        jobs = [
            {
                "id": job.id,
                "nextRun": job.next_run_time.isoformat() if job.next_run_time else None,
            }
            for job in self.scheduler.get_jobs()
        ]
        return {"ok": True, "jobs": jobs}

    def remove_job(self, job_id: str) -> dict[str, Any]:
        try:
            self.scheduler.remove_job(job_id)
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def run_scheduled_now(self, target_type: str, target_path: str) -> dict[str, Any]:
        try:
            scanned = self._scan_target(target_type=target_type, target_path=target_path, source="scheduled")
            return {"ok": True, "scanned": scanned}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def get_reports(self) -> dict[str, Any]:
        self._cleanup_old_logs()
        cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(days=30)).isoformat()

        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM scan_logs WHERE ts >= ?", (cutoff,))
            total_scanned = int(cur.fetchone()[0])

            cur.execute("SELECT COUNT(*) FROM scan_logs WHERE ts >= ? AND result = 'THREAT'", (cutoff,))
            threats = int(cur.fetchone()[0])

            cur.execute(
                """
                SELECT ts, file_path, sha256, result, detail, source
                FROM scan_logs
                WHERE ts >= ?
                ORDER BY ts DESC
                LIMIT 1000
                """,
                (cutoff,),
            )
            rows = cur.fetchall()

        safety_score = 100.0 if total_scanned == 0 else max(0.0, (1 - threats / total_scanned) * 100)
        return {
            "ok": True,
            "summary": {
                "totalScanned": total_scanned,
                "threatsNeutralized": threats,
                "safetyScore": round(safety_score, 2),
            },
            "logs": [
                {
                    "timestamp": row[0],
                    "filePath": row[1],
                    "sha256": row[2],
                    "result": row[3],
                    "detail": row[4],
                    "source": row[5],
                }
                for row in rows
            ],
        }


def main() -> None:
    check_environment()
    ensure_database()

    import webview  # pylint: disable=import-outside-toplevel

    api = GuardFlowAPI()
    webview.create_window(APP_NAME, url="index.html", js_api=api, width=1220, height=860, text_select=True)
    webview.start(debug=False)


if __name__ == "__main__":
    main()
