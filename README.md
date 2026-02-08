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
