"""FastAPI review gallery, pipeline control, & atomic batch export API."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from src.db import SupabaseDB, load_dotenv
from src.normalizer import MAX_BATCH_ITEMS

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = PROJECT_ROOT / "templates"
REVIEWABLE_STATUSES = ("ai_scored", "triaged", "verified")
MAX_NOTE_CHARS = 140


class ExportNextRequest(BaseModel):
    reviewer: Optional[str] = Field(default=None, description="Nama reviewer (default dari REVIEWER_NAME).")
    limit: int = Field(default=MAX_BATCH_ITEMS, ge=1, le=MAX_BATCH_ITEMS)


class ReviewLockRequest(BaseModel):
    reviewer: Optional[str] = None
    url_id: Optional[int] = None
    ttl_minutes: int = Field(default=15, ge=1, le=120)


class ReviewDecisionRequest(BaseModel):
    reviewer: Optional[str] = None
    action: Literal["approve", "approve_note", "skip"]
    note: Optional[str] = Field(default=None, max_length=MAX_NOTE_CHARS)


class SubmissionStatusRequest(BaseModel):
    status: Literal["submitted", "claimed_external"]
    reviewer: Optional[str] = None


class IngestUrlsRequest(BaseModel):
    urls_text: str = Field(..., min_length=1)
    source: str = Field(default="manual", max_length=40)


class CollectRequest(BaseModel):
    mode: Literal["tail", "crtsh"] = "tail"
    limit: int = Field(default=15, ge=1, le=100)
    duration: float = Field(default=15.0, ge=3.0, le=90.0)
    backfill: int = Field(default=2000, ge=100, le=10000)
    keywords: Optional[list[str]] = None
    days: int = Field(default=7, ge=1, le=30)


class VerifyQueueRequest(BaseModel):
    limit: int = Field(default=5, ge=1, le=30)
    concurrency: int = Field(default=3, ge=1, le=6)
    timeout_ms: int = Field(default=15000, ge=3000, le=45000)


class TriagePromptRequest(BaseModel):
    limit: int = Field(default=30, ge=1, le=300)
    batch_size: int = Field(default=30, ge=1, le=50)


class TriageImportRequest(BaseModel):
    raw_text: str = Field(..., min_length=2)


class TriageApiRequest(BaseModel):
    limit: int = Field(default=10, ge=1, le=50)


def _resolve_reviewer(reviewer: Optional[str]) -> str:
    load_dotenv()
    name = (reviewer or os.getenv("REVIEWER_NAME", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="reviewer wajib diisi (body atau REVIEWER_NAME).")
    return name


def _attach_signed_url(db: Any, row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    path = item.get("screenshot_path")
    if path and hasattr(db, "create_signed_url"):
        try:
            item["screenshot_url"] = db.create_signed_url(path, expires_in=3600)
        except Exception:
            item["screenshot_url"] = None
    else:
        item.setdefault("screenshot_url", None)
    return item


def create_app(
    db: Optional[Any] = None,
    *,
    verifier_factory: Optional[Any] = None,
    collector_fn: Optional[Any] = None,
    ai_client: Optional[Any] = None,
) -> FastAPI:
    app = FastAPI(title="id-scam-pipeline Review Dashboard")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    state: dict[str, Any] = {"db": db}

    def get_db() -> Any:
        if state["db"] is None:
            state["db"] = SupabaseDB.from_env()
        return state["db"]

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        load_dotenv()
        default_reviewer = os.getenv("REVIEWER_NAME", "member-1").strip() or "member-1"
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"default_reviewer": default_reviewer},
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # --- Pipeline Control Endpoints (100% controllable from UI) ---

    @app.post("/api/pipeline/ingest")
    def pipeline_ingest(payload: IngestUrlsRequest) -> dict[str, Any]:
        """Normalisasi & simpan daftar URL manual (1 per baris) dengan ON CONFLICT DO NOTHING."""
        lines = [ln.strip() for ln in payload.urls_text.splitlines() if ln.strip()]
        inserted = get_db().insert_urls(lines, source=payload.source.strip() or "manual", status="new")
        return {
            "submitted_lines": len(lines),
            "inserted_count": len(inserted),
            "skipped_or_dup": max(0, len(lines) - len(inserted)),
            "inserted": inserted,
        }

    @app.post("/api/pipeline/collect")
    async def pipeline_collect(payload: Optional[CollectRequest] = None) -> dict[str, Any]:
        """Berburu domain baru secara pasif via Certificate Transparency (CT Log / crt.sh) -> simpan ke DB."""
        req = payload or CollectRequest()
        try:
            if collector_fn is not None:
                candidates = await collector_fn(req)
            else:
                from src.cert_collector import DEFAULT_CRTSH_KEYWORDS, fetch_crtsh, tail_ct_log

                if req.mode == "crtsh":
                    kws = req.keywords or list(DEFAULT_CRTSH_KEYWORDS)
                    candidates = await fetch_crtsh(
                        keywords=kws,
                        max_age_days=req.days,
                        limit=req.limit,
                        verbose=False,
                    )
                else:
                    candidates = []
                    async for item in tail_ct_log(
                        backfill=req.backfill,
                        duration_s=req.duration,
                        limit=req.limit,
                        verbose=False,
                    ):
                        candidates.append(item)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Collector gagal: {exc}") from exc

        rows_to_insert = [
            {
                "raw_url": f"https://{c.normalized_url}" if hasattr(c, "normalized_url") else str(c["raw_url"]),
                "source": getattr(c, "source", f"ct_{req.mode}") if hasattr(c, "source") else c.get("source", f"ct_{req.mode}"),
                "ai_category": getattr(c, "category_hint", None) if hasattr(c, "category_hint") else c.get("ai_category"),
                "ai_note": f"CT match: {c.matched_rule}"[:MAX_NOTE_CHARS] if hasattr(c, "matched_rule") else c.get("ai_note"),
            }
            for c in candidates
        ]
        inserted = await asyncio.to_thread(get_db().insert_urls, rows_to_insert, f"ct_{req.mode}", "new")
        return {
            "mode": req.mode,
            "found_count": len(candidates),
            "inserted_count": len(inserted),
            "items": inserted,
        }

    @app.post("/api/pipeline/verify")
    async def pipeline_verify(payload: Optional[VerifyQueueRequest] = None) -> dict[str, Any]:
        """Ambil antrean status='new', buka di headless browser, kompres JPEG <= 150 KB & upload ke Supabase Storage."""
        from src.verify import SafeBrowserVerifier, extract_clean_text

        req = payload or VerifyQueueRequest()
        cur_db = get_db()
        queue = await asyncio.to_thread(cur_db.fetch_queue, "new", req.limit)
        if not queue:
            return {"processed": 0, "verified": 0, "dead_or_blocked": 0, "items": []}

        sem = asyncio.Semaphore(req.concurrency)
        make_verifier = verifier_factory or (
            lambda: SafeBrowserVerifier(
                timeout_ms=req.timeout_ms,
                uploader=cur_db.upload_screenshot,
            )
        )

        async def _verify_one(verifier: Any, row: dict[str, Any]) -> dict[str, Any]:
            async with sem:
                res = await verifier.verify_url(row["raw_url"], url_id=row["id"])
                clean_txt = extract_clean_text(res.raw_html or "")
                updated = await asyncio.to_thread(
                    cur_db.update_status,
                    row["id"],
                    res.status,
                    final_url=res.final_url,
                    final_normalized_url=res.final_normalized_url,
                    http_status=res.http_status,
                    page_title=res.page_title,
                    clean_text=clean_txt,
                    screenshot_path=res.screenshot_path,
                    error_code=res.error_code,
                    error_detail=res.error_detail,
                )
                return {
                    "id": row["id"],
                    "normalized_url": row["normalized_url"],
                    "status": res.status,
                    "http_status": res.http_status,
                    "screenshot_path": res.screenshot_path,
                    "error_code": res.error_code,
                    "updated": updated is not None,
                }

        try:
            async with make_verifier() as verifier:
                results = list(await asyncio.gather(*(_verify_one(verifier, row) for row in queue)))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Verifier browser gagal: {exc}") from exc

        verified_cnt = sum(1 for r in results if r["status"] == "verified")
        dead_cnt = len(results) - verified_cnt
        return {
            "processed": len(results),
            "verified": verified_cnt,
            "dead_or_blocked": dead_cnt,
            "items": results,
        }

    @app.post("/api/pipeline/triage/export-prompts")
    def pipeline_triage_export_prompts(payload: Optional[TriagePromptRequest] = None) -> dict[str, Any]:
        """Generate batch prompt (30 situs/prompt) siap copy-paste ke DeepSeek web-chat."""
        from src.ai_triage import export_batch_prompts

        req = payload or TriagePromptRequest()
        rows = get_db().fetch_queue(status="verified", limit=req.limit)
        prompts = export_batch_prompts(rows, batch_size=req.batch_size) if rows else []
        return {"site_count": len(rows), "batch_count": len(prompts), "prompts": prompts}

    @app.post("/api/pipeline/triage/import")
    def pipeline_triage_import(payload: TriageImportRequest) -> dict[str, Any]:
        """Impor jawaban JSON dari DeepSeek web-chat dan simpan ke DB (status -> triaged)."""
        from src.ai_triage import import_batch_response

        try:
            results = import_batch_response(payload.raw_text, db=get_db())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "imported_count": len(results),
            "items": [r.to_dict() for r in results],
        }

    @app.post("/api/pipeline/triage/api")
    def pipeline_triage_api(payload: Optional[TriageApiRequest] = None) -> dict[str, Any]:
        """Jalankan klasifikasi DeepSeek via openai SDK untuk antrean status='verified'."""
        from src.ai_triage import create_deepseek_client, triage_site

        req = payload or TriageApiRequest()
        cur_db = get_db()
        rows = cur_db.fetch_queue(status="verified", limit=req.limit)
        if not rows:
            return {"triaged_count": 0, "items": []}

        try:
            sdk_client = ai_client or create_deepseek_client()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        triaged: list[dict[str, Any]] = []
        for row in rows:
            res = triage_site(
                normalized_url=str(row.get("normalized_url") or ""),
                page_title=str(row.get("page_title") or ""),
                clean_text=str(row.get("clean_text") or ""),
                client=sdk_client,
                url_id=row["id"],
            )
            cur_db.update_status(
                row["id"],
                status="triaged",
                ai_category=res.category,
                ai_confidence=res.confidence,
                ai_note=res.reason_140,
            )
            triaged.append(res.to_dict())
        return {"triaged_count": len(triaged), "items": triaged}

    # --- Review Gallery & Atomic Batch Export Endpoints ---

    @app.get("/api/review/queue")
    def review_queue(
        limit: int = Query(default=30, ge=1, le=100),
    ) -> dict[str, Any]:
        """Ambil galeri item siap review lengkap dengan signed URL screenshot & ringkasan status."""
        cur_db = get_db()
        rows = cur_db.fetch_review_queue(statuses=REVIEWABLE_STATUSES, limit=limit)
        items = [_attach_signed_url(cur_db, row) for row in rows]
        counts = cur_db.get_status_counts() if hasattr(cur_db, "get_status_counts") else {}
        return {
            "items": items,
            "counts": {
                "review_queue": sum(counts.get(s, 0) for s in REVIEWABLE_STATUSES),
                "approved": counts.get("approved", 0),
                "exported": counts.get("exported", 0),
                "submitted": counts.get("submitted", 0),
                "claimed_external": counts.get("claimed_external", 0),
                "skipped": counts.get("skipped", 0),
                "new": counts.get("new", 0),
                "verified": counts.get("verified", 0),
            },
        }

    @app.post("/api/review/{url_id}/decide")
    def decide_review(url_id: int, payload: ReviewDecisionRequest) -> dict[str, Any]:
        """Proses keputusan reviewer: A (approve), N (approve + note <= 140), X (skip)."""
        reviewer = _resolve_reviewer(payload.reviewer)
        target_status = "skipped" if payload.action == "skip" else "approved"
        fields: dict[str, Any] = {
            "reviewed_by": reviewer,
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
            "locked_by": None,
            "locked_at": None,
        }
        if payload.note is not None:
            fields["ai_note"] = " ".join(payload.note.split())[:MAX_NOTE_CHARS]

        updated = get_db().update_status(url_id, status=target_status, **fields)
        if updated is None:
            raise HTTPException(status_code=404, detail=f"URL id={url_id} tidak ditemukan.")
        return {"item": updated, "action": payload.action}

    @app.post("/api/export-next-20")
    def export_next_20(payload: Optional[ExportNextRequest] = None) -> dict[str, Any]:
        """Atomically claim up to 20 approved links, create a batch record, and mark exported."""
        req = payload or ExportNextRequest()
        reviewer = _resolve_reviewer(req.reviewer)
        return get_db().export_next_batch(reviewer=reviewer, limit=req.limit)

    @app.get("/api/batches")
    def list_batches(limit: int = Query(default=20, ge=1, le=100)) -> dict[str, Any]:
        """Ambil riwayat batch terbaru beserta daftar link & status tiap link."""
        return {"batches": get_db().fetch_batches(limit=limit)}

    @app.post("/api/batches/{batch_id}/status")
    def mark_batch_status(batch_id: int, payload: SubmissionStatusRequest) -> dict[str, Any]:
        """Tandai semua link dalam 1 batch sebagai submitted atau claimed_external."""
        reviewer = _resolve_reviewer(payload.reviewer)
        updated = get_db().update_batch_urls_status(
            batch_id=batch_id,
            status=payload.status,
            reviewer=reviewer,
        )
        if not updated:
            raise HTTPException(status_code=404, detail=f"Batch #{batch_id} tidak ditemukan atau kosong.")
        return {
            "batch_id": batch_id,
            "status": payload.status,
            "updated_count": len(updated),
            "items": updated,
        }

    @app.post("/api/urls/{url_id}/status")
    def mark_url_submission_status(url_id: int, payload: SubmissionStatusRequest) -> dict[str, Any]:
        """Tandai 1 URL dalam batch sebagai submitted atau claimed_external."""
        reviewer = _resolve_reviewer(payload.reviewer)
        updated = get_db().update_status(url_id, status=payload.status, reviewed_by=reviewer)
        if updated is None:
            raise HTTPException(status_code=404, detail=f"URL id={url_id} tidak ditemukan.")
        return {"item": updated}

    @app.post("/api/review/lock")
    def lock_next_for_review(payload: Optional[ReviewLockRequest] = None) -> dict[str, Any]:
        """Atomically lock one URL for a reviewer to prevent collisions among 3 reviewers."""
        req = payload or ReviewLockRequest()
        reviewer = _resolve_reviewer(req.reviewer)
        row = get_db().lock_for_review(
            reviewer=reviewer,
            url_id=req.url_id,
            statuses=REVIEWABLE_STATUSES,
            ttl_minutes=req.ttl_minutes,
        )
        if req.url_id is not None and row is None:
            raise HTTPException(status_code=409, detail="URL tidak ditemukan atau sedang dikunci reviewer lain.")
        return {"locked": _attach_signed_url(get_db(), row) if row else None}

    return app


app = create_app()
