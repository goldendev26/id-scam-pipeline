"""Unit tests for scripts/benchmark_verifier.py"""

from pathlib import Path
import tempfile
import unittest

from scripts.benchmark_verifier import (
    MIN_THROUGHPUT_PER_MIN,
    build_benchmark_urls,
    summarize_benchmark,
)
from src.verify import VerifyResult


class TestBenchmarkHarness(unittest.TestCase):
    def test_build_benchmark_urls_default_50_and_custom_file(self):
        urls = build_benchmark_urls(count=50)
        self.assertEqual(len(urls), 50)

        urls_extra = build_benchmark_urls(count=60)
        self.assertEqual(len(urls_extra), 60)

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "urls.txt"
            p.write_text("# comment\nhttps://example.com\n\nhttps://example.org\n", encoding="utf-8")
            loaded = build_benchmark_urls(count=10, urls_file=p)
            self.assertEqual(loaded, ["https://example.com", "https://example.org"])

    def test_summarize_benchmark_computes_throughput_and_gates(self):
        results = [
            VerifyResult(
                input_url=f"https://s{i}.id",
                normalized_url=f"s{i}.id",
                status="verified" if i < 30 else "dead_or_blocked",
                screenshot_bytes=(b"\xff\xd8" + b"x" * 1000) if i < 30 else None,
                error_code=None if i < 30 else "ERR_DNS_OR_CONN",
                elapsed_ms=500 + i * 10,
            )
            for i in range(50)
        ]

        summary_fast = summarize_benchmark(results, wall_seconds=60.0)
        self.assertEqual(summary_fast["total_urls"], 50)
        self.assertEqual(summary_fast["throughput_urls_per_min"], 50.0)
        self.assertTrue(summary_fast["throughput_ok"])
        self.assertTrue(summary_fast["screenshots"]["size_ok"])
        self.assertEqual(summary_fast["status_counts"], {"verified": 30, "dead_or_blocked": 20})

        summary_slow = summarize_benchmark(
            results,
            wall_seconds=300.0,
            min_throughput=MIN_THROUGHPUT_PER_MIN,
        )
        self.assertEqual(summary_slow["throughput_urls_per_min"], 10.0)
        self.assertFalse(summary_slow["throughput_ok"])


if __name__ == "__main__":
    unittest.main()
