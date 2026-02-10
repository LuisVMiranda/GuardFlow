# GuardFlow

GuardFlow is a privacy-first desktop malware scanning interface for a **local MalwareZoo** instance.

## What is implemented
- **Desktop UI** with `pywebview` + SPA `index.html`.
- Tabs: **Scan**, **Schedule**, **Reports**.
- **Focus-Flow privacy behavior**:
  - default scan computes SHA-256 locally and sends only hash lookup
  - full file upload only happens when user explicitly clicks **Upload for Deep Scan**
- **Threat workflow** includes a **Delete File** action via `send2trash`.
- **Scheduling** via `apscheduler`:
  - target type: file, folder, system
  - frequency: daily, weekly, every X hours
- **30-day report log** in SQLite (`guardflow_logs.db`) with summary card values.
- **Self-healing startup**:
  - auto-installs missing Python deps
  - ensures `docker-compose.yml` exists
  - checks MalwareZoo reachability and attempts auto-start via Docker Compose

## Files
- `guardflow_app.py` - Python backend, scheduler, DB, pywebview API bridge.
- `index.html` - UI (Scan / Schedule / Reports).
- `docker-compose.yml` - local MalwareZoo compose baseline.
- `requirements.txt` - Python dependencies.

## Quick start
```bash
python guardflow_app.py
```

If Docker auto-start is disabled or fails:
```bash
docker compose up -d
```

## Environment variables
- `GUARDFLOW_MALWAREZOO_URL` (default: `http://127.0.0.1:8080`)
- `GUARDFLOW_AUTOSTART_DOCKER` (default: `1`; set to `0` to disable auto-start attempt)

## API route note
MalwareZoo route names vary by deployment. This app uses:
- `GET /health`
- `POST /api/hash_lookup` with body `{ "sha256": "..." }`
- `POST /api/upload` multipart file upload

If your local MalwareZoo uses different routes, edit constants in `guardflow_app.py`.


## Windows double-click launcher
Use `start_guardflow.bat` to run GuardFlow without opening a terminal:

1. Double-click `start_guardflow.bat`.
2. The launcher will:
   - pick `py -3` or `python`
   - optionally run `docker compose up -d` (if Docker exists)
   - start `guardflow_app.py`

If Python is missing, the script will show an error and pause so you can read it.


## Troubleshooting: "file path is invalid or not accessible"
- If you see `WinError 10061` / connection refused during lookup, MalwareZoo is not running on `127.0.0.1:8080`; start it with `docker compose up -d` or set `GUARDFLOW_MALWAREZOO_URL`.
If PDF/ZIP scans show the same red path error:
- Use **Browse…** in the Scan tab instead of drag-drop (some runtimes do not expose absolute path on dropped files).
- Confirm the path is absolute and file exists.
- Open **Refresh Backend Status** and verify detected MalwareZoo compatibility paths (health/hash/upload).

## MalwareZoo compatibility check (important)
GuardFlow now probes candidate paths and reports which endpoints are detected at runtime.
If your MalwareZoo image uses different routes, edit these lists in `guardflow_app.py`:
- `HEALTH_PATH_CANDIDATES`
- `HASH_PATH_CANDIDATES`
- `UPLOAD_PATH_CANDIDATES`

## Queueing, throttling, and pause controls
- API scanner calls run through an internal queue + worker threads.
- System scans are throttled by default to reduce I/O pressure.
- Use **Pause All Scans** / **Resume Scans** in the UI to control all active and queued scanning tasks.

Environment knobs:
- `GUARDFLOW_SCAN_WORKERS` (default `2`)
- `GUARDFLOW_THROTTLE_SYSTEM_DELAY_S` (default `0.03`)
- `GUARDFLOW_THROTTLE_FOLDER_DELAY_S` (default `0.005`)
- `GUARDFLOW_SYSTEM_MAX_FILES` (default `20000`)
