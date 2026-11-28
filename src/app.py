"""FastAPI review & atomic batch export API for id-scam-pipeline."""

from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.db import SupabaseDB, load_dotenv
from src.normalizer import MAX_BATCH_ITEMS


class ExportNextRequest(BaseModel):
    reviewer: Optional[str] = Field(default=None, description="Nama reviewer (default dari REVIEWER_NAME).")
    limit: int = Field(default=MAX_BATCH_ITEMS, ge=1, le=MAX_BATCH_ITEMS)


class ReviewLockRequest(BaseModel):
    reviewer: Optional[str] = None
    url_id: Optional[int] = None
    ttl_minutes: int = Field(default=15, ge=1, le=120)


def _resolve_reviewer(reviewer: Optional[str]) -> str:
    load_dotenv()
    name = (reviewer or os.getenv("REVIEWER_NAME", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="reviewer wajib diisi (body atau REVIEWER_NAME).")
    return name


def create_app(db: Optional[Any] = None) -> FastAPI:
    app = FastAPI(title="id-scam-pipeline API")
    state: dict[str, Any] = {"db": db}

    def get_db() -> Any:
        if state["db"] is None:
            state["db"] = SupabaseDB.from_env()
        return state["db"]

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/export-next-20")
    def export_next_20(payload: Optional[ExportNextRequest] = None) -> dict[str, Any]:
        """Atomically claim up to 20 approved links, create a batch record, and mark exported."""
        req = payload or ExportNextRequest()
        reviewer = _resolve_reviewer(req.reviewer)
        return get_db().export_next_batch(reviewer=reviewer, limit=req.limit)

    @app.post("/api/review/lock")
    def lock_next_for_review(payload: Optional[ReviewLockRequest] = None) -> dict[str, Any]:
        """Atomically lock one URL for a reviewer to prevent collisions among 3 reviewers."""
        req = payload or ReviewLockRequest()
        reviewer = _resolve_reviewer(req.reviewer)
        row = get_db().lock_for_review(
            reviewer=reviewer,
            url_id=req.url_id,
            ttl_minutes=req.ttl_minutes,
        )
        if req.url_id is not None and row is None:
            raise HTTPException(status_code=409, detail="URL tidak ditemukan atau sedang dikunci reviewer lain.")
        return {"locked": row}

    return app


app = create_app()
