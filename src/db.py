"""Supabase PostgreSQL & Storage client using PostgREST + Storage REST over httpx."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Optional, Sequence, Union
from urllib.parse import quote

import httpx

from src.normalizer import MAX_BATCH_ITEMS, normalize_url


def load_dotenv(path: Path = Path(".env")) -> None:
    """Load simple KEY=VALUE pairs from .env into os.environ without overriding."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


class SupabaseDB:
    """Thin Supabase REST/RPC/Storage client backed by httpx."""

    def __init__(
        self,
        url: str,
        service_key: str,
        bucket: str = "screenshots",
        client: Optional[httpx.Client] = None,
        timeout: float = 15.0,
    ) -> None:
        self.base_url = url.rstrip("/")
        self.service_key = service_key
        self.bucket = bucket
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout)

    @classmethod
    def from_env(cls, env_path: Path = Path(".env")) -> "SupabaseDB":
        load_dotenv(env_path)
        url = os.getenv("SUPABASE_URL", "").strip()
        key = os.getenv("SUPABASE_SERVICE_KEY", "").strip()
        bucket = os.getenv("SUPABASE_STORAGE_BUCKET", "screenshots").strip() or "screenshots"
        if not url or not key or "your-supabase" in key:
            raise RuntimeError("SUPABASE_URL dan SUPABASE_SERVICE_KEY harus diisi di .env / environment.")
        return cls(url=url, service_key=key, bucket=bucket)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "SupabaseDB":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _headers(self, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
        hdrs = {
            "apikey": self.service_key,
            "Authorization": f"Bearer {self.service_key}",
        }
        if extra:
            hdrs.update(extra)
        return hdrs

    def insert_urls(
        self,
        items: Sequence[Union[str, dict[str, Any]]],
        source: str = "manual",
        status: str = "new",
    ) -> list[dict[str, Any]]:
        """Normalize & insert URLs with ON CONFLICT (normalized_url) DO NOTHING."""
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()

        for item in items:
            if isinstance(item, str):
                raw_url = item
                extra: dict[str, Any] = {}
            else:
                raw_url = str(item.get("raw_url", ""))
                extra = {k: v for k, v in item.items() if k not in ("raw_url", "normalized_url")}

            norm = normalize_url(raw_url)
            if not norm.ok or not norm.normalized or norm.normalized in seen:
                continue
            seen.add(norm.normalized)
            row = {
                "raw_url": raw_url.strip(),
                "normalized_url": norm.normalized,
                "source": extra.pop("source", source),
                "status": extra.pop("status", status),
                **extra,
            }
            rows.append(row)

        if not rows:
            return []

        resp = self._client.post(
            f"{self.base_url}/rest/v1/urls",
            params={"on_conflict": "normalized_url"},
            headers=self._headers(
                {
                    "Content-Type": "application/json",
                    "Prefer": "resolution=ignore-duplicates,return=representation",
                }
            ),
            json=rows,
        )
        resp.raise_for_status()
        return resp.json() if resp.content else []

    def insert_url(
        self,
        raw_url: str,
        source: str = "manual",
        status: str = "new",
    ) -> Optional[dict[str, Any]]:
        """Insert a single URL; returns inserted row or None if invalid/duplicate."""
        inserted = self.insert_urls([raw_url], source=source, status=status)
        return inserted[0] if inserted else None

    def fetch_queue(self, status: str = "new", limit: int = 50) -> list[dict[str, Any]]:
        """Ambil antrean URL berdasarkan status (default 'new'), urut paling lama."""
        resp = self._client.get(
            f"{self.base_url}/rest/v1/urls",
            params={
                "status": f"eq.{status}",
                "order": "id.asc",
                "limit": str(max(1, limit)),
            },
            headers=self._headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def update_status(
        self,
        url_id: int,
        status: Optional[str] = None,
        **fields: Any,
    ) -> Optional[dict[str, Any]]:
        """Update status and/or metadata columns for a single URL row."""
        payload = dict(fields)
        if "reason_140" in payload and "ai_note" not in payload:
            payload["ai_note"] = payload.pop("reason_140")
        if status is not None:
            payload["status"] = status
        payload["updated_at"] = datetime.now(timezone.utc).isoformat()

        resp = self._client.patch(
            f"{self.base_url}/rest/v1/urls",
            params={"id": f"eq.{url_id}"},
            headers=self._headers(
                {
                    "Content-Type": "application/json",
                    "Prefer": "return=representation",
                }
            ),
            json=payload,
        )
        resp.raise_for_status()
        rows = resp.json() if resp.content else []
        return rows[0] if rows else None

    def lock_for_review(
        self,
        reviewer: str,
        url_id: Optional[int] = None,
        statuses: Sequence[str] = ("verified", "triaged"),
        ttl_minutes: int = 15,
    ) -> Optional[dict[str, Any]]:
        """Atomically claim a review lock via Postgres FOR UPDATE SKIP LOCKED RPC."""
        clean_reviewer = reviewer.strip()
        if not clean_reviewer:
            raise ValueError("reviewer must not be empty")

        resp = self._client.post(
            f"{self.base_url}/rest/v1/rpc/claim_url_for_review",
            headers=self._headers({"Content-Type": "application/json"}),
            json={
                "p_reviewer": clean_reviewer,
                "p_url_id": url_id,
                "p_statuses": list(statuses),
                "p_ttl_minutes": max(1, int(ttl_minutes)),
            },
        )
        resp.raise_for_status()
        rows = resp.json() if resp.content else []
        return rows[0] if rows else None

    def unlock_review(
        self,
        url_id: int,
        reviewer: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Release a reviewer lock (optionally scoped to the owning reviewer)."""
        params: dict[str, str] = {"id": f"eq.{url_id}"}
        if reviewer:
            params["locked_by"] = f"eq.{reviewer.strip()}"
        resp = self._client.patch(
            f"{self.base_url}/rest/v1/urls",
            params=params,
            headers=self._headers(
                {
                    "Content-Type": "application/json",
                    "Prefer": "return=representation",
                }
            ),
            json={
                "locked_by": None,
                "locked_at": None,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        resp.raise_for_status()
        rows = resp.json() if resp.content else []
        return rows[0] if rows else None

    def export_next_batch(self, reviewer: str, limit: int = MAX_BATCH_ITEMS) -> dict[str, Any]:
        """Atomically create a batch and mark up to 20 approved URLs as exported."""
        clean_reviewer = reviewer.strip()
        if not clean_reviewer:
            raise ValueError("reviewer must not be empty")
        if not 1 <= limit <= MAX_BATCH_ITEMS:
            raise ValueError(f"limit must be between 1 and {MAX_BATCH_ITEMS}")

        resp = self._client.post(
            f"{self.base_url}/rest/v1/rpc/export_next_batch",
            headers=self._headers({"Content-Type": "application/json"}),
            json={"p_reviewer": clean_reviewer, "p_limit": limit},
        )
        resp.raise_for_status()
        rows = resp.json() if resp.content else []
        links = [r["normalized_url"] for r in rows]
        return {
            "batch_id": rows[0]["batch_id"] if rows else None,
            "reviewer": clean_reviewer,
            "count": len(rows),
            "links": links,
            "text": "\n".join(links),
            "items": [
                {
                    "id": r["url_id"],
                    "normalized_url": r["normalized_url"],
                    "ai_category": r.get("ai_category"),
                    "ai_note": r.get("ai_note"),
                }
                for r in rows
            ],
        }

    def upload_screenshot(
        self,
        storage_path: str,
        jpeg_bytes: bytes,
        upsert: bool = True,
    ) -> str:
        """Upload JPEG bytes to Supabase Storage bucket and return object path."""
        clean_path = storage_path.lstrip("/")
        encoded_path = quote(clean_path, safe="/")
        headers = {"Content-Type": "image/jpeg"}
        if upsert:
            headers["x-upsert"] = "true"

        resp = self._client.post(
            f"{self.base_url}/storage/v1/object/{self.bucket}/{encoded_path}",
            headers=self._headers(headers),
            content=jpeg_bytes,
        )
        resp.raise_for_status()
        return clean_path

    def create_signed_url(self, storage_path: str, expires_in: int = 3600) -> str:
        """Generate a temporary signed URL for a private screenshot object."""
        clean_path = storage_path.lstrip("/")
        encoded_path = quote(clean_path, safe="/")
        resp = self._client.post(
            f"{self.base_url}/storage/v1/object/sign/{self.bucket}/{encoded_path}",
            headers=self._headers({"Content-Type": "application/json"}),
            json={"expiresIn": expires_in},
        )
        resp.raise_for_status()
        signed = resp.json()["signedURL"]
        if signed.startswith("http"):
            return signed
        return f"{self.base_url}/storage/v1{signed}"
