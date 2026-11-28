"""Unit tests untuk bulk signed URL, exclude_ids, dan status_counts di src.db."""

import json
import unittest

import httpx

from src.db import SupabaseDB


def _db(handler) -> SupabaseDB:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return SupabaseDB("https://demo.supabase.co", "sb_secret_test", client=client)


class TestDbPerfHelpers(unittest.TestCase):
    def test_bulk_signed_urls_single_request(self):
        calls = []

        def handler(req: httpx.Request) -> httpx.Response:
            calls.append(req.url.path)
            self.assertEqual(req.url.path, "/storage/v1/object/sign/screenshots")
            self.assertEqual(json.loads(req.content)["paths"], ["1_a.id.jpg", "2_b.id.jpg"])
            return httpx.Response(200, json=[
                {"path": "1_a.id.jpg", "signedURL": "/object/sign/screenshots/1_a.id.jpg?token=t1", "error": None},
                {"path": "2_b.id.jpg", "signedURL": "/object/sign/screenshots/2_b.id.jpg?token=t2", "error": None},
            ])

        out = _db(handler).create_signed_urls(["1_a.id.jpg", "2_b.id.jpg"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            out["1_a.id.jpg"],
            "https://demo.supabase.co/storage/v1/object/sign/screenshots/1_a.id.jpg?token=t1",
        )
        self.assertEqual(len(out), 2)

    def test_fetch_review_queue_excludes_loaded_ids(self):
        def handler(req: httpx.Request) -> httpx.Response:
            self.assertEqual(req.url.params["id"], "not.in.(1,2,3)")
            return httpx.Response(200, json=[])

        _db(handler).fetch_review_queue(limit=15, exclude_ids=[1, 2, 3])

    def test_status_counts_uses_rpc_then_falls_back(self):
        def rpc_ok(req: httpx.Request) -> httpx.Response:
            self.assertEqual(req.url.path, "/rest/v1/rpc/status_counts")
            return httpx.Response(200, json=[{"status": "approved", "total": 5}, {"status": "new", "total": 9}])

        self.assertEqual(_db(rpc_ok).get_status_counts(), {"approved": 5, "new": 9})

        def rpc_missing(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/rpc/status_counts"):
                return httpx.Response(404, json={"message": "not found"})
            return httpx.Response(200, json=[{"status": "new"}, {"status": "new"}, {"status": "skipped"}])

        self.assertEqual(_db(rpc_missing).get_status_counts(), {"new": 2, "skipped": 1})


if __name__ == "__main__":
    unittest.main()