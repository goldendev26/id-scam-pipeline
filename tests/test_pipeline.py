"""Unit tests for db.py, screenshot compression/upload, ai_triage.py, and app.py."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import json
from pathlib import Path
import random
import tempfile
import threading
from types import SimpleNamespace
import unittest

import httpx
from PIL import Image

from src.ai_triage import (
    DEFAULT_BATCH_SIZE,
    MAX_REASON_LEN,
    export_batch_prompts,
    import_batch_response,
    parse_batch_response,
    triage_site,
    write_batch_prompts,
)
from src.db import SupabaseDB
from src.verify import (
    DEFAULT_MAX_SCREENSHOT_BYTES,
    SafeBrowserVerifier,
    compress_jpeg_to_limit,
)
from tests.test_verify import _FakeBrowser, _FakePlaywrightCM


def _make_large_noisy_jpeg(width: int = 1280, height: int = 720) -> bytes:
    """Create a deterministic high-entropy JPEG larger than 150 KB."""
    rng = random.Random(42)
    pixels = bytes(rng.getrandbits(8) for _ in range(width * height * 3))
    img = Image.frombytes("RGB", (width, height), pixels)
    buf = BytesIO()
    img.save(buf, format="JPEG", quality=92)
    return buf.getvalue()


class TestSupabaseDB(unittest.TestCase):
    def test_insert_queue_update_lock_export_and_upload(self):
        captured: list[tuple[str, str, dict, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            qs = dict(request.url.params)
            body = json.loads(request.content.decode()) if request.headers.get("content-type", "").startswith("application/json") and request.content else request.content
            captured.append((request.method, path, qs, body))

            if request.method == "POST" and path == "/rest/v1/urls":
                self.assertEqual(qs.get("on_conflict"), "normalized_url")
                self.assertIn("resolution=ignore-duplicates", request.headers.get("Prefer", ""))
                # Simulate DB returning only newly inserted rows
                return httpx.Response(201, json=[{"id": 1, **body[0]}])

            if request.method == "GET" and path == "/rest/v1/urls":
                self.assertEqual(qs.get("status"), "eq.new")
                return httpx.Response(200, json=[{"id": 1, "normalized_url": "slot99.id", "status": "new"}])

            if request.method == "PATCH" and path == "/rest/v1/urls":
                return httpx.Response(200, json=[{"id": 1, **body}])

            if request.method == "POST" and path == "/rest/v1/rpc/claim_url_for_review":
                return httpx.Response(200, json=[{"id": 1, "locked_by": body["p_reviewer"]}])

            if request.method == "POST" and path == "/rest/v1/rpc/export_next_batch":
                return httpx.Response(
                    200,
                    json=[
                        {"batch_id": 7, "url_id": 1, "normalized_url": "slot99.id", "ai_category": "judol", "ai_note": "Promo slot"},
                        {"batch_id": 7, "url_id": 2, "normalized_url": "pinjol88.id", "ai_category": "pinjol", "ai_note": "Pinjaman ilegal"},
                    ],
                )

            if request.method == "POST" and path.startswith("/storage/v1/object/screenshots/"):
                self.assertEqual(request.headers.get("content-type"), "image/jpeg")
                self.assertEqual(request.headers.get("x-upsert"), "true")
                return httpx.Response(200, json={"Key": path})

            raise AssertionError(f"Unexpected request: {request.method} {request.url}")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        db = SupabaseDB("https://demo.supabase.co", "sb_secret_test", client=client)

        inserted = db.insert_urls(["https://www.Slot99.id/?utm=1", "slot99.id", "127.0.0.1"])
        self.assertEqual(len(inserted), 1)
        self.assertEqual(inserted[0]["normalized_url"], "slot99.id")
        self.assertEqual(inserted[0]["status"], "new")

        queue = db.fetch_queue()
        self.assertEqual(queue[0]["status"], "new")

        updated = db.update_status(1, status="triaged", ai_category="judol", reason_140="Situs slot gacor")
        self.assertEqual(updated["ai_note"], "Situs slot gacor")

        locked = db.lock_for_review("member-1")
        self.assertEqual(locked["locked_by"], "member-1")

        batch = db.export_next_batch("member-1", limit=20)
        self.assertEqual(batch["batch_id"], 7)
        self.assertEqual(batch["count"], 2)
        self.assertEqual(batch["text"], "slot99.id\npinjol88.id")

        obj_path = db.upload_screenshot("1_slot99.id.jpg", b"\xff\xd8\xffdemo")
        self.assertEqual(obj_path, "1_slot99.id.jpg")


class TestScreenshotCompressionAndUpload(unittest.IsolatedAsyncioTestCase):
    def test_compress_jpeg_to_limit_enforces_150kb_ceiling(self):
        raw = _make_large_noisy_jpeg()
        self.assertGreater(len(raw), DEFAULT_MAX_SCREENSHOT_BYTES)

        compressed = compress_jpeg_to_limit(raw, max_bytes=DEFAULT_MAX_SCREENSHOT_BYTES, initial_quality=60)
        self.assertLessEqual(len(compressed), DEFAULT_MAX_SCREENSHOT_BYTES)
        # Verify compressed bytes are still a valid JPEG image
        with Image.open(BytesIO(compressed)) as img:
            self.assertEqual(img.format, "JPEG")

    async def test_verifier_compresses_and_auto_uploads_screenshot(self):
        raw = _make_large_noisy_jpeg()
        uploaded: list[tuple[str, int]] = []

        def fake_uploader(path: str, data: bytes) -> str:
            uploaded.append((path, len(data)))
            return path

        browser = _FakeBrowser(
            lambda u: {
                "final_url": "https://slotcontoh.id/daftar",
                "status": 200,
                "title": "Slot Contoh",
                "screenshot": raw,
            }
        )
        async with SafeBrowserVerifier(
            jpeg_quality=60,
            uploader=fake_uploader,
            playwright_factory=lambda: _FakePlaywrightCM(browser),
        ) as v:
            res = await v.verify_url("slotcontoh.id", url_id=42)

        self.assertEqual(res.status, "verified")
        self.assertEqual(res.screenshot_path, "42_slotcontoh.id_daftar.jpg")
        self.assertEqual(len(uploaded), 1)
        self.assertLessEqual(uploaded[0][1], DEFAULT_MAX_SCREENSHOT_BYTES)


class TestAITriage(unittest.TestCase):
    def test_triage_site_with_openai_sdk_client_normalizes_output(self):
        long_reason = "Situs judi slot gacor online ilegal " * 10
        fake_resp = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=json.dumps(
                            {
                                "category": "JUDOL",
                                "confidence": 1.4,
                                "reason_140": long_reason,
                            }
                        )
                    )
                )
            ]
        )

        called: dict = {}

        class _FakeCompletions:
            def create(self, **kwargs):
                called.update(kwargs)
                return fake_resp

        fake_client = SimpleNamespace(chat=SimpleNamespace(completions=_FakeCompletions()))
        res = triage_site(
            "slotgacor99.id",
            page_title="Slot Gacor 99",
            clean_text="Daftar slot deposit dana 10rb",
            client=fake_client,
            model="deepseek-chat",
            url_id=10,
        )

        self.assertEqual(called["model"], "deepseek-chat")
        self.assertEqual(called["response_format"], {"type": "json_object"})
        self.assertEqual(res.category, "judol")
        self.assertEqual(res.confidence, 1.0)
        self.assertLessEqual(len(res.reason_140), MAX_REASON_LEN)
        self.assertEqual(res.url_id, 10)

    def test_batch_prompt_export_30_per_prompt_and_webchat_import(self):
        sites = [
            {"id": i, "normalized_url": f"site{i}.id", "page_title": f"Site {i}", "clean_text": "slot gacor"}
            for i in range(1, 66)
        ]
        prompts = export_batch_prompts(sites, batch_size=DEFAULT_BATCH_SIZE)
        self.assertEqual(len(prompts), 3)  # 30 + 30 + 5

        with tempfile.TemporaryDirectory() as tmp:
            paths = write_batch_prompts(sites, Path(tmp))
            self.assertEqual([p.name for p in paths], ["deepseek_batch_001.txt", "deepseek_batch_002.txt", "deepseek_batch_003.txt"])

        web_reply = """Berikut hasil klasifikasinya:
```json
[
  {"id": 1, "normalized_url": "site1.id", "category": "judol", "confidence": 0.96, "reason_140": "Menawarkan permainan slot dan deposit e-wallet."},
  {"id": 2, "normalized_url": "site2.id", "category": "invalid_cat", "confidence": -0.5, "reason_140": "x"}
]
```
Semoga membantu!"""

        saved: list[tuple[int, dict]] = []

        class _FakeDB:
            def update_status(self, url_id: int, status: str, **fields):
                saved.append((url_id, {"status": status, **fields}))

        parsed = import_batch_response(web_reply, db=_FakeDB())
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].category, "judol")
        self.assertEqual(parsed[1].category, "unsure")
        self.assertEqual(parsed[1].confidence, 0.0)
        self.assertEqual(len(saved), 2)
        self.assertEqual(saved[0][1]["status"], "triaged")
        self.assertEqual(len(parse_batch_response(web_reply)), 2)


class TestAppAtomicExport(unittest.TestCase):
    def test_concurrent_3_reviewers_export_next_20_no_overlap(self):
        from fastapi.testclient import TestClient
        from src.app import create_app

        class _AtomicMemoryDB:
            def __init__(self, total: int = 45):
                self._lock = threading.Lock()
                self._batch_seq = 0
                self.rows = [
                    {"id": i, "normalized_url": f"judol{i}.id", "status": "approved", "batch_id": None, "ai_category": "judol", "ai_note": "slot"}
                    for i in range(1, total + 1)
                ]
                self.batches: list[dict] = []

            def export_next_batch(self, reviewer: str, limit: int = 20) -> dict:
                with self._lock:
                    picked = [r for r in self.rows if r["status"] == "approved" and r["batch_id"] is None][:limit]
                    if not picked:
                        return {"batch_id": None, "reviewer": reviewer, "count": 0, "links": [], "text": "", "items": []}
                    self._batch_seq += 1
                    bid = self._batch_seq
                    self.batches.append({"id": bid, "reviewer": reviewer, "url_count": len(picked)})
                    for r in picked:
                        r["status"] = "exported"
                        r["batch_id"] = bid
                    links = [r["normalized_url"] for r in picked]
                    return {
                        "batch_id": bid,
                        "reviewer": reviewer,
                        "count": len(picked),
                        "links": links,
                        "text": "\n".join(links),
                        "items": [{"id": r["id"], "normalized_url": r["normalized_url"], "ai_category": r["ai_category"], "ai_note": r["ai_note"]} for r in picked],
                    }

        fake_db = _AtomicMemoryDB(total=45)
        client = TestClient(create_app(db=fake_db))

        def call_export(reviewer: str) -> dict:
            r = client.post("/api/export-next-20", json={"reviewer": reviewer})
            self.assertEqual(r.status_code, 200)
            return r.json()

        with ThreadPoolExecutor(max_workers=3) as pool:
            responses = list(pool.map(call_export, ["member-1", "member-2", "member-3"]))

        all_links = [link for resp in responses for link in resp["links"]]
        self.assertEqual(len(all_links), 45)
        self.assertEqual(len(set(all_links)), 45)  # Zero overlap across 3 concurrent reviewers
        self.assertEqual(sorted(resp["count"] for resp in responses), [5, 20, 20])
        self.assertEqual(len(fake_db.batches), 3)
        self.assertTrue(all(r["status"] == "exported" for r in fake_db.rows))

        # 4th call returns empty without creating an extra batch
        empty = call_export("member-1")
        self.assertIsNone(empty["batch_id"])
        self.assertEqual(empty["count"], 0)
        self.assertEqual(len(fake_db.batches), 3)


if __name__ == "__main__":
    unittest.main()
