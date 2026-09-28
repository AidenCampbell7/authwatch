"""
FastAPI service exposing alerts and stats, plus the dashboard.

Kept thin on purpose: every endpoint is a read against Store. Business logic
lives in detections.py so it can be tested without spinning up a web server.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

from .store import Store

DASHBOARD = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"


def create_app(db_path: str = "data/authwatch.db") -> FastAPI:
    app = FastAPI(
        title="authwatch",
        description="SSH authentication log analysis and detection",
        version="1.0.0",
    )
    store = Store(db_path)

    @app.get("/api/alerts")
    def get_alerts(
        severity: str | None = Query(None, pattern="^(high|medium|low)$"),
        limit: int = Query(100, ge=1, le=1000),
    ):
        return store.alerts(severity=severity, limit=limit)

    @app.get("/api/stats")
    def get_stats():
        return store.stats()

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        if not DASHBOARD.exists():
            raise HTTPException(status_code=404, detail="dashboard/index.html not found")
        return DASHBOARD.read_text(encoding="utf-8")

    return app


app = create_app()
