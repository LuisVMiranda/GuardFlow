# GuardFlow Architecture (Scaffold)

## Overview
GuardFlow is a privacy-first desktop app that uses `pywebview` for UI and Python for local control logic.

## Planned flow
1. User drops a file in Scan tab.
2. App computes SHA-256 locally.
3. App sends hash to local MalwareZoo API.
4. App displays status (Safe / Unknown / Threat).
5. App only uploads full file when user explicitly clicks **Upload for Deep Scan**.

## Components
- `guardflow_app.py`: startup, environment checks, pywebview host, API bridge placeholders.
- `index.html`: SPA tab layout for Scan/Schedule/Reports.
- `docker-compose.yml`: local MalwareZoo bootstrap.
- `guardflow_logs.db`: SQLite storage for 30-day reporting (created at runtime).
