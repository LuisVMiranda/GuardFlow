# GuardFlow Architecture

## Runtime model
- **Frontend**: `index.html` rendered in `pywebview` as a SPA.
- **Backend**: `guardflow_app.py` (Python 3.10+).
- **Storage**: SQLite table `scan_logs` for 30-day report history.
- **Scheduler**: APScheduler background scheduler in-process.

## Privacy-first Focus-Flow
1. User selects or drops a file.
2. App computes SHA-256 **locally**.
3. App sends only hash to MalwareZoo lookup endpoint.
4. Full file upload occurs only when user explicitly chooses **Upload for Deep Scan**.

## Scan statuses
- `SAFE` (green)
- `UNKNOWN` (yellow)
- `THREAT` (red)
- `ERROR` (operational issues)

## Schedule targets
- Specific file
- Specific folder (recursive scan)
- System-wide scan (recursive scan from OS root)

## Self-healing startup
- install missing Python packages (`pywebview`, `requests`, `apscheduler`, `send2trash`)
- ensure `docker-compose.yml` exists
- verify MalwareZoo health endpoint
- optionally attempt `docker compose up -d` automatically
