"""Unit tests for src.worker and multi-log CT collection."""

import json
from types import SimpleNamespace
import unittest

from src.cert_collector import CertCandidate
from src.worker import run_discover_pass, run_triage_pass, run_verify_pass
from tests.test_verify import _FakeBrowser, _FakePlaywrightCM


class _MemoryWorkerDB:
    def __init__(self):
        self.rows = []
        self.next_id = 1
        self.uploads = []

    def insert_urls(self, items, source="manual", status="new"):
        inserted = []
        existing = {r["normalized_url"] for r in self.rows}
        for item in items:
            raw = item if isinstance(item, str) else item["raw_url"]
            norm = raw.replace("https://", "")
            if norm in existing:
                continue
            existing.add(norm)
            row = {
                "id": self.next_id,
                "raw_url": raw,
                "normalized_url": norm,
                "source": item.get("source", source) if isinstance(item, dict) else source,
                "status": status,
                "page_title": None,
                "clean_text": None,
            }
            self.next_id += 1
            self.rows.append(row)
            inserted.append(row)
        return inserted

    def fetch_queue(self, status="new", limit=50):
        return [r for r in self.rows if r["status"] == status][:limit]

    def update_status(self, url_id, status=None, **fields):
        for r in self.rows:
            if r["id"] == url_id:
                if status is not None:
                    r["status"] = status
                r.update(fields)
                return r
        return None

    def upload_screenshot(self, path, data):
        self.uploads.append((path, len(data)))
        return path


class TestAutomatedWorker(unittest.IsolatedAsyncioTestCase):
    async def test_discover_verify_and_triage_single_cycle(self):
        db = _MemoryWorkerDB()

        async def fake_collect(**kwargs):
            return [
                CertCandidate(
                    normalized_url="slotbaru99.xyz",
                    raw_domain="slotbaru99.xyz",
                    source="ct_log",
                    category_hint="judol",
                    matched_rule="judol:slotgacor",
                )
            ]

        disc = await run_discover_pass(db, collector_fn=fake_collect)
        self.assertEqual(disc, {"stage": "discover", "found": 1, "inserted": 1})
        self.assertEqual(len(db.rows), 1)
        self.assertEqual(db.rows[0]["status"], "new")

        browser = _FakeBrowser(
            lambda u: {
                "final_url": "https://slotbaru99.xyz/daftar",
                "status": 200,
                "title": "Slot Baru 99",
                "html": "<html><body><h1>Slot Baru 99</h1><p>Deposit QRIS</p></body></html>",
                "screenshot": b"\xff\xd8\xffdemo",
            }
        )
        from src.verify import SafeBrowserVerifier

        ver = await run_verify_pass(
            db,
            verifier_factory=lambda: SafeBrowserVerifier(
                uploader=db.upload_screenshot,
                playwright_factory=lambda: _FakePlaywrightCM(browser),
            ),
        )
        self.assertEqual(ver, {"stage": "verify", "processed": 1, "verified": 1, "dead_or_blocked": 0})
        self.assertEqual(db.rows[0]["status"], "verified")
        self.assertEqual(db.rows[0]["screenshot_path"], "1_slotbaru99.xyz_daftar.jpg")
        self.assertIn("Deposit QRIS", db.rows[0]["clean_text"])

        fake_resp = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=json.dumps(
                            {
                                "category": "judol",
                                "confidence": 0.95,
                                "reason_140": "Situs slot online aktif dengan deposit QRIS.",
                            }
                        )
                    )
                )
            ]
        )

        class _FakeCompletions:
            def create(self, **kwargs):
                return fake_resp

        fake_ai = SimpleNamespace(chat=SimpleNamespace(completions=_FakeCompletions()))
        tri = await run_triage_pass(db, ai_client=fake_ai)
        self.assertEqual(tri, {"stage": "triage", "processed": 1, "errors": 0})
        self.assertEqual(db.rows[0]["status"], "triaged")
        self.assertEqual(db.rows[0]["ai_category"], "judol")
        self.assertEqual(db.rows[0]["ai_confidence"], 0.95)


if __name__ == "__main__":
    unittest.main()
