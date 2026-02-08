#!/usr/bin/env python3
"""GuardFlow - Privacy-First Malware Scanner desktop app."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import os
import queue
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

APP_NAME = "GuardFlow"
DB_PATH = Path("guardflow_logs.db")
DOCKER_COMPOSE_PATH = Path("docker-compose.yml")

MALWAREZOO_BASE_URL = os.getenv("GUARDFLOW_MALWAREZOO_URL", "http://127.0.0.1:8080").rstrip("/")

HEALTH_PATH_CANDIDATES = ["/health", "/api/health", "/status", "/"]
HASH_PATH_CANDIDATES = ["/api/hash_lookup", "/api/hash/lookup", "/hash_lookup", "/api/scan/hash"]
UPLOAD_PATH_CANDIDATES = ["/api/upload", "/api/files/upload", "/upload", "/api/scan/file"]

REQUIRED_PACKAGES = {
    "pywebview": "webview",
    "requests": "requests",
    "apscheduler": "apscheduler",
    "send2trash": "send2trash",
}

SCAN_QUEUE_WORKERS = max(1, int(os.getenv("GUARDFLOW_SCAN_WORKERS", "2")))
THROTTLE_SYSTEM_DELAY_S = float(os.getenv("GUARDFLOW_THROTTLE_SYSTEM_DELAY_S", "0.03"))
THROTTLE_FOLDER_DELAY_S = float(os.getenv("GUARDFLOW_THROTTLE_FOLDER_DELAY_S", "0.005"))
MAX_SYSTEM_FILES_PER_RUN = int(os.getenv("GUARDFLOW_SYSTEM_MAX_FILES", "20000"))


def _is_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def _ensure_docker_compose_file() -> None:
    if DOCKER_COMPOSE_PATH.exists():
        return

    DOCKER_COMPOSE_PATH.write_text(
        """version: "3.9"
services:
  malwarezoo:
    image: malwarezoo/local:latest
    container_name: malwarezoo
    ports:
      - "8080:8080"
    restart: unless-stopped
""",
        encoding="utf-8",
    )


def _auto_start_malwarezoo() -> bool:
    try:
        subprocess.run(["docker", "compose", "up", "-d"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return True
    except Exception:
        return False


def check_environment() -> None:
    missing = [pkg for pkg, mod in REQUIRED_PACKAGES.items() if not _is_available(mod)]
    if missing:
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])

    import requests  # pylint: disable=import-outside-toplevel

    _ensure_docker_compose_file()

    def reachable() -> bool:
        for health_path in HEALTH_PATH_CANDIDATES:
            try:
                response = requests.get(f"{MALWAREZOO_BASE_URL}{health_path}", timeout=2)
                if response.status_code < 500:
                    return True
            except Exception:
                continue
        return False

    if reachable():
        return

    if os.getenv("GUARDFLOW_AUTOSTART_DOCKER", "1") == "1" and _auto_start_malwarezoo() and reachable():
        return

    print(
        f"[{APP_NAME}] MalwareZoo may be unavailable at {MALWAREZOO_BASE_URL}.\n"
        "Start Docker and run: docker compose up -d"
    )


def ensure_database() -> None:
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
    def __init__(self) -> None:
        import requests  # pylint: disable=import-outside-toplevel
        from apscheduler.schedulers.background import BackgroundScheduler  # pylint: disable=import-outside-toplevel

        self.requests = requests
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.lock = threading.Lock()
        self.scheduler = BackgroundScheduler(daemon=True)
        self.scheduler.start()

        self.pause_event = threading.Event()
        self.stop_workers = threading.Event()

        self.queue: queue.Queue[tuple[Callable[[], Any], threading.Event, dict[str, Any]]] = queue.Queue()
        self.workers: list[threading.Thread] = []
        for idx in range(SCAN_QUEUE_WORKERS):
            t = threading.Thread(target=self._worker_loop, name=f"scan-worker-{idx}", daemon=True)
            t.start()
            self.workers.append(t)

        self.compatibility = self._probe_malwarezoo_compatibility()

    def _worker_loop(self) -> None:
        while not self.stop_workers.is_set():
            try:
                fn, done_event, payload = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                while self.pause_event.is_set() and not self.stop_workers.is_set():
                    time.sleep(0.1)
                payload["value"] = fn()
            except Exception as exc:  # pragma: no cover
                payload["error"] = str(exc)
            finally:
                done_event.set()
                self.queue.task_done()

    def close(self) -> None:
        self.stop_workers.set()
        self.scheduler.shutdown(wait=False)
        self.conn.close()

    def _enqueue_call(self, fn: Callable[[], Any]) -> Any:
        done = threading.Event()
        payload: dict[str, Any] = {}
        self.queue.put((fn, done, payload))
        done.wait(timeout=90)
        if "error" in payload:
            raise RuntimeError(payload["error"])
        if "value" not in payload:
            raise RuntimeError("Scanner queue timeout.")
        return payload["value"]

    def _probe_malwarezoo_compatibility(self) -> dict[str, Any]:
        info = {
            "baseUrl": MALWAREZOO_BASE_URL,
            "healthPath": None,
            "hashPath": None,
            "uploadPath": None,
            "reachable": False,
            "notes": [],
        }

        for p in HEALTH_PATH_CANDIDATES:
            try:
                r = self.requests.get(f"{MALWAREZOO_BASE_URL}{p}", timeout=2)
                if r.status_code < 500:
                    info["healthPath"] = p
                    info["reachable"] = True
                    break
            except Exception:
                continue

        sample_hash = "0" * 64
        for p in HASH_PATH_CANDIDATES:
            try:
                r = self.requests.post(f"{MALWAREZOO_BASE_URL}{p}", json={"sha256": sample_hash}, timeout=4)
                if r.status_code != 404:
                    info["hashPath"] = p
                    break
            except Exception:
                continue

        for p in UPLOAD_PATH_CANDIDATES:
            try:
                r = self.requests.options(f"{MALWAREZOO_BASE_URL}{p}", timeout=4)
                if r.status_code != 404:
                    info["uploadPath"] = p
                    break
            except Exception:
                continue

        if not info["hashPath"]:
            info["notes"].append("No compatible hash endpoint detected. Edit HASH_PATH_CANDIDATES.")
        if not info["uploadPath"]:
            info["notes"].append("No compatible upload endpoint detected. Edit UPLOAD_PATH_CANDIDATES.")

        return info

    def get_backend_status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "compatibility": self.compatibility,
            "queueSize": self.queue.qsize(),
            "paused": self.pause_event.is_set(),
            "throttle": {
                "systemDelaySec": THROTTLE_SYSTEM_DELAY_S,
                "folderDelaySec": THROTTLE_FOLDER_DELAY_S,
                "systemMaxFiles": MAX_SYSTEM_FILES_PER_RUN,
            },
        }

    def pause_all_scans(self) -> dict[str, Any]:
        self.pause_event.set()
        return {"ok": True, "paused": True}

    def resume_all_scans(self) -> dict[str, Any]:
        self.pause_event.clear()
        return {"ok": True, "paused": False}

    def _log_scan(self, file_path: str, sha256_hash: str, result: str, detail: str, source: str) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO scan_logs (ts, file_path, sha256, result, detail, source) VALUES (?, ?, ?, ?, ?, ?)",
                (dt.datetime.now(dt.UTC).isoformat(), file_path, sha256_hash, result, detail, source),
            )
            self.conn.commit()

    def _cleanup_old_logs(self) -> None:
        cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(days=30)).isoformat()
        with self.lock:
            self.conn.execute("DELETE FROM scan_logs WHERE ts < ?", (cutoff,))
            self.conn.commit()

    def _wait_if_paused(self) -> None:
        while self.pause_event.is_set():
            time.sleep(0.1)

    def _call_hash_lookup(self, sha256_hash: str) -> tuple[str, str]:
        hash_path = self.compatibility.get("hashPath") or HASH_PATH_CANDIDATES[0]
        url = f"{MALWAREZOO_BASE_URL}{hash_path}"

        def _request() -> tuple[str, str]:
            try:
                resp = self.requests.post(url, json={"sha256": sha256_hash}, timeout=12)
                if resp.status_code >= 400:
                    return "ERROR", f"Hash lookup failed (HTTP {resp.status_code}) at {hash_path}"
                payload = resp.json() if resp.content else {}
            except Exception as exc:
                return "ERROR", f"Lookup unavailable: {exc}"

            verdict = str(payload.get("verdict", "unknown")).lower()
            detail = str(payload.get("detail", "No details"))
            if verdict == "safe":
                return "SAFE", detail
            if verdict == "threat":
                return "THREAT", detail
            return "UNKNOWN", detail

        return self._enqueue_call(_request)

    def scan_file(self, file_path: str) -> dict[str, Any]:
        try:
            if not file_path or not os.path.isfile(file_path):
                return {
                    "ok": False,
                    "error": "File path is invalid or not accessible. Use the Browse button and pick a local file path.",
                }

            self._wait_if_paused()
            file_hash = sha256_file(file_path)
            status, detail = self._call_hash_lookup(file_hash)
            self._log_scan(file_path, file_hash, status, detail, "manual")
            self._cleanup_old_logs()
            return {"ok": True, "file": file_path, "sha256": file_hash, "status": status, "detail": detail, "canDelete": status == "THREAT"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def upload_for_deep_scan(self, file_path: str) -> dict[str, Any]:
        try:
            if not file_path or not os.path.isfile(file_path):
                return {"ok": False, "error": "File path is invalid or missing."}

            upload_path = self.compatibility.get("uploadPath") or UPLOAD_PATH_CANDIDATES[0]
            url = f"{MALWAREZOO_BASE_URL}{upload_path}"

            def _request() -> dict[str, Any]:
                with open(file_path, "rb") as fp:
                    response = self.requests.post(url, files={"file": (Path(file_path).name, fp, "application/octet-stream")}, timeout=90)
                if response.status_code >= 400:
                    return {"ok": False, "error": f"Upload failed HTTP {response.status_code} at {upload_path}"}
                payload = response.json() if response.content else {}
                return {
                    "ok": True,
                    "status": str(payload.get("verdict", "unknown")).upper(),
                    "detail": str(payload.get("detail", "Deep scan completed.")),
                }

            return self._enqueue_call(_request)
        except Exception as exc:
            return {"ok": False, "error": f"Deep scan failed: {exc}"}

    def delete_file(self, file_path: str) -> dict[str, Any]:
        try:
            if not file_path or not os.path.exists(file_path):
                return {"ok": False, "error": "File not found."}
            from send2trash import send2trash  # pylint: disable=import-outside-toplevel

            send2trash(file_path)
            return {"ok": True, "message": "File moved to trash."}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def pick_file(self) -> dict[str, Any]:
        try:
            import webview  # pylint: disable=import-outside-toplevel

            files = webview.windows[0].create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False)
            if not files:
                return {"ok": False, "error": "No file selected."}
            return {"ok": True, "path": files[0]}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _scan_target(self, target_type: str, target_path: str, source: str = "scheduled") -> int:
        scanned_count = 0

        def iter_target_files() -> list[str]:
            if target_type == "file":
                return [target_path]
            if target_type == "folder":
                out: list[str] = []
                for root, _, files in os.walk(target_path):
                    for name in files:
                        out.append(os.path.join(root, name))
                return out
            if target_type == "system":
                roots = ["/"] if os.name != "nt" else [os.environ.get("SystemDrive", "C:") + "\\"]
                out = []
                for r in roots:
                    for root, _, files in os.walk(r):
                        for name in files:
                            out.append(os.path.join(root, name))
                            if len(out) >= MAX_SYSTEM_FILES_PER_RUN:
                                return out
                return out
            return []

        throttle_delay = THROTTLE_SYSTEM_DELAY_S if target_type == "system" else THROTTLE_FOLDER_DELAY_S

        for file_path in iter_target_files():
            self._wait_if_paused()
            try:
                if not os.path.isfile(file_path):
                    continue
                file_hash = sha256_file(file_path)
                status, detail = self._call_hash_lookup(file_hash)
                self._log_scan(file_path, file_hash, status, detail, source)
                scanned_count += 1
                if throttle_delay > 0:
                    time.sleep(throttle_delay)
            except Exception as exc:
                self._log_scan(file_path, "", "ERROR", str(exc), source)

        self._cleanup_old_logs()
        return scanned_count

    def schedule_scan(self, target_type: str, target_path: str, frequency: str, every_hours: int = 6) -> dict[str, Any]:
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
            self._scan_target(target_type, target_path, source="scheduled")

        try:
            if frequency == "daily":
                self.scheduler.add_job(_runner, "interval", days=1, id=job_id, replace_existing=True)
            elif frequency == "weekly":
                self.scheduler.add_job(_runner, "interval", weeks=1, id=job_id, replace_existing=True)
            elif frequency == "every_x_hours":
                self.scheduler.add_job(_runner, "interval", hours=max(1, int(every_hours)), id=job_id, replace_existing=True)
            else:
                return {"ok": False, "error": "Invalid frequency."}
            return {"ok": True, "jobId": job_id}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def list_jobs(self) -> dict[str, Any]:
        return {
            "ok": True,
            "jobs": [{"id": j.id, "nextRun": j.next_run_time.isoformat() if j.next_run_time else None} for j in self.scheduler.get_jobs()],
        }

    def remove_job(self, job_id: str) -> dict[str, Any]:
        try:
            self.scheduler.remove_job(job_id)
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def run_scheduled_now(self, target_type: str, target_path: str) -> dict[str, Any]:
        try:
            return {"ok": True, "scanned": self._scan_target(target_type, target_path, source="scheduled")}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def get_reports(self) -> dict[str, Any]:
        self._cleanup_old_logs()
        cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(days=30)).isoformat()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM scan_logs WHERE ts >= ?", (cutoff,))
            total = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM scan_logs WHERE ts >= ? AND result = 'THREAT'", (cutoff,))
            threats = int(cur.fetchone()[0])
            cur.execute(
                "SELECT ts, file_path, sha256, result, detail, source FROM scan_logs WHERE ts >= ? ORDER BY ts DESC LIMIT 1000",
                (cutoff,),
            )
            rows = cur.fetchall()

        safety = 100.0 if total == 0 else max(0.0, (1 - threats / total) * 100)
        return {
            "ok": True,
            "summary": {"totalScanned": total, "threatsNeutralized": threats, "safetyScore": round(safety, 2)},
            "logs": [{"timestamp": r[0], "filePath": r[1], "sha256": r[2], "result": r[3], "detail": r[4], "source": r[5]} for r in rows],
        }


def main() -> None:
    check_environment()
    ensure_database()

    import webview  # pylint: disable=import-outside-toplevel

    api = GuardFlowAPI()
    webview.create_window(APP_NAME, url="index.html", js_api=api, width=1240, height=880, text_select=True)
    webview.start(debug=False)


if __name__ == "__main__":
    main()
