# GuardFlow

Privacy-first malware scanning desktop app scaffold.

## Current scaffold
- pywebview desktop host (`guardflow_app.py`)
- SPA shell (`index.html`) with three tabs: Scan, Schedule, Reports
- Dependency/bootstrap checks via `check_environment()`
- SQLite table bootstrap for scan logs
- Docker compose file for local MalwareZoo startup

## Quick start
```bash
python guardflow_app.py
```

If MalwareZoo is not running:
```bash
docker compose up -d
```

## Next implementation steps
- Implement hash scan in `scan_file`
- Implement explicit deep upload action
- Implement APScheduler recurring jobs
- Implement report aggregation and rendering
