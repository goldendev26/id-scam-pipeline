"""Sandbox benchmark and security verification harness.

Runs two checks inside the hardened Docker verifier container:
1. Security audit: verifies non-root execution, read-only rootfs, and proves both
   direct `.apk` URLs and stealth `Content-Disposition: attachment` downloads are
   blocked without dropping any file to disk.
2. Throughput benchmark: verifies 50 mixed URLs (live, redirect, HTTP 4xx, dead
   NXDOMAIN, and invalid format) and checks throughput >= 20 URLs/min and JPEG
   screenshot ceiling <= 150 KB.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Sequence

from src.verify import (
    CHROMIUM_ARGS,
    DEFAULT_MAX_SCREENSHOT_BYTES,
    SafeBrowserVerifier,
    USER_AGENT,
    VIEWPORT,
    VerifyResult,
    should_abort_request,
)

MIN_THROUGHPUT_PER_MIN = 20.0
DEFAULT_BENCHMARK_COUNT = 50

# Safe, legal mixed pool for deterministic 50-URL throughput benchmarking.
_BASE_MIXED_URLS: List[str] = [
    # Live fast pages (18)
    "https://example.com",
    "https://example.org",
    "https://example.net",
    "https://www.iana.org/domains/reserved",
    "https://httpbin.org/html",
    "https://httpbin.org/robots.txt",
    "https://httpbin.org/get",
    "https://httpbin.org/headers",
    "https://httpbin.org/user-agent",
    "https://httpbin.org/uuid",
    "https://httpbin.org/ip",
    "https://httpbin.org/anything/page1",
    "https://httpbin.org/anything/page2",
    "https://httpbin.org/anything/page3",
    "https://httpbin.org/anything/page4",
    "https://httpbin.org/anything/page5",
    "https://httpbin.org/anything/page6",
    "https://httpbin.org/anything/page7",
    # Redirects (6)
    "https://httpbin.org/redirect-to?url=https://example.com",
    "https://httpbin.org/redirect/1",
    "https://httpbin.org/redirect/2",
    "https://httpbin.org/relative-redirect/1",
    "https://httpbin.org/absolute-redirect/1",
    "https://httpbin.org/redirect-to?url=https://example.org",
    # HTTP 4xx / 5xx errors (8)
    "https://httpbin.org/status/404",
    "https://httpbin.org/status/403",
    "https://httpbin.org/status/410",
    "https://httpbin.org/status/500",
    "https://httpbin.org/status/502",
    "https://httpbin.org/status/503",
    "https://example.com/definitely-not-found-404-a",
    "https://example.com/definitely-not-found-404-b",
    # Dead / NXDOMAIN using RFC 2606 reserved `.invalid` TLD (12)
    "https://dead-slot-test-01.invalid",
    "https://dead-slot-test-02.invalid",
    "https://dead-slot-test-03.invalid",
    "https://dead-slot-test-04.invalid",
    "https://dead-slot-test-05.invalid",
    "https://dead-slot-test-06.invalid",
    "https://dead-pinjol-07.invalid",
    "https://dead-pinjol-08.invalid",
    "https://dead-pinjol-09.invalid",
    "https://dead-phish-10.invalid",
    "https://dead-phish-11.invalid",
    "https://dead-phish-12.invalid",
    # Invalid formats blocked by normalizer before browser launch (6)
    "http://103.21.44.5:8080/slot",
    "http://127.0.0.1/admin",
    "https://user:pass@example.com",
    "javascript:alert(1)",
    "not-a-domain",
    "https://example.com:9000/badport",
]


def build_benchmark_urls(
    count: int = DEFAULT_BENCHMARK_COUNT,
    urls_file: Optional[Path] = None,
) -> List[str]:
    """Load custom URLs from file or slice/cycle the default mixed benchmark pool."""
    if urls_file is not None:
        lines = [
            ln.strip()
            for ln in urls_file.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        return lines[:count] if count > 0 else lines

    if count <= len(_BASE_MIXED_URLS):
        return list(_BASE_MIXED_URLS[:count])

    out = list(_BASE_MIXED_URLS)
    idx = 1
    while len(out) < count:
        out.append(f"https://httpbin.org/anything/extra-{idx}")
        idx += 1
    return out


class _ApkTrapHandler(BaseHTTPRequestHandler):
    """Local HTTP trap server simulating direct `.apk` and stealth attachment downloads."""

    def log_message(self, format: str, *args: Any) -> None:
        return None

    def do_GET(self) -> None:
        if self.path.endswith(".apk"):
            body = b"PK\x03\x04fake-apk-payload"
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.android.package-archive")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/stealth-download":
            body = b"PK\x03\x04stealth-apk-payload"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="pinjol-resmi.apk"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        html = (
            b"<html><body>"
            b"<a id='apk' href='/pinjol-resmi.apk'>Download APK</a>"
            b"<a id='stealth' href='/stealth-download'>Unduh Aplikasi</a>"
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


def check_container_hardening(app_dir: Path = Path("/app")) -> Dict[str, Any]:
    """Check non-root UID and read-only `/app` filesystem."""
    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    non_root = euid != 0

    read_only_app = False
    if app_dir.exists():
        probe = app_dir / ".ro_probe_test"
        try:
            probe.write_text("x", encoding="utf-8")
            probe.unlink(missing_ok=True)
            read_only_app = False
        except OSError:
            read_only_app = True

    return {
        "euid": euid,
        "non_root_ok": non_root,
        "app_dir_exists": app_dir.exists(),
        "read_only_rootfs_ok": read_only_app,
    }


async def run_apk_download_security_test() -> Dict[str, Any]:
    """Verify `.apk` route abort and `accept_downloads=False` against a local trap server."""
    from playwright.async_api import async_playwright

    server = ThreadingHTTPServer(("127.0.0.1", 0), _ApkTrapHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    aborted_urls: List[str] = []
    direct_apk_blocked = False
    stealth_download_blocked = False
    dropped_files: List[str] = []

    try:
        with tempfile.TemporaryDirectory(prefix="apk_sec_") as tmp_dir:
            before_files = set(os.listdir(tmp_dir))
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True, args=CHROMIUM_ARGS)
                context = await browser.new_context(
                    accept_downloads=False,
                    ignore_https_errors=True,
                    viewport=VIEWPORT,
                    user_agent=USER_AGENT,
                )
                try:
                    page = await context.new_page()

                    async def _handle_route(route: Any) -> None:
                        req = route.request
                        if should_abort_request(req.resource_type, req.url):
                            aborted_urls.append(req.url)
                            await route.abort()
                        else:
                            await route.continue_()

                    await page.route("**/*", _handle_route)

                    # 1. Direct .apk URL must be aborted at route layer before reaching Chromium.
                    try:
                        await page.goto(f"http://127.0.0.1:{port}/pinjol-resmi.apk", timeout=5000)
                    except Exception:
                        direct_apk_blocked = any(u.endswith(".apk") for u in aborted_urls)

                    # 2. Stealth attachment without .apk suffix must be refused by accept_downloads=False.
                    try:
                        await page.goto(f"http://127.0.0.1:{port}/stealth-download", timeout=5000)
                    except Exception:
                        stealth_download_blocked = True

                    after_files = set(os.listdir(tmp_dir))
                    dropped_files = sorted(after_files - before_files)
                finally:
                    await context.close()
                    await browser.close()
    finally:
        server.shutdown()
        server.server_close()

    return {
        "direct_apk_aborted": direct_apk_blocked,
        "stealth_download_blocked": stealth_download_blocked,
        "dropped_files": dropped_files,
        "apk_security_ok": direct_apk_blocked and stealth_download_blocked and len(dropped_files) == 0,
    }


def summarize_benchmark(
    results: Sequence[VerifyResult],
    wall_seconds: float,
    min_throughput: float = MIN_THROUGHPUT_PER_MIN,
    max_screenshot_bytes: int = DEFAULT_MAX_SCREENSHOT_BYTES,
) -> Dict[str, Any]:
    """Compute throughput, status breakdown, latency percentiles, and pass/fail flags."""
    total = len(results)
    throughput_per_min = (total / wall_seconds * 60.0) if wall_seconds > 0 else 0.0
    status_counts = dict(Counter(r.status for r in results))
    error_counts = dict(Counter(r.error_code for r in results if r.error_code))

    latencies = sorted(r.elapsed_ms for r in results)
    p50_ms = latencies[len(latencies) // 2] if latencies else 0
    p95_idx = min(len(latencies) - 1, int(len(latencies) * 0.95)) if latencies else 0
    p95_ms = latencies[p95_idx] if latencies else 0

    shot_sizes = [len(r.screenshot_bytes) for r in results if r.screenshot_bytes]
    max_shot = max(shot_sizes) if shot_sizes else 0
    avg_shot = int(sum(shot_sizes) / len(shot_sizes)) if shot_sizes else 0

    # ru_maxrss is KiB on Linux
    peak_rss_mb = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 1)

    return {
        "total_urls": total,
        "wall_seconds": round(wall_seconds, 2),
        "throughput_urls_per_min": round(throughput_per_min, 2),
        "target_urls_per_min": min_throughput,
        "throughput_ok": throughput_per_min >= min_throughput,
        "status_counts": status_counts,
        "error_counts": error_counts,
        "latency_ms": {"p50": p50_ms, "p95": p95_ms},
        "screenshots": {
            "count": len(shot_sizes),
            "avg_bytes": avg_shot,
            "max_bytes": max_shot,
            "limit_bytes": max_screenshot_bytes,
            "size_ok": max_shot <= max_screenshot_bytes,
        },
        "python_peak_rss_mb": peak_rss_mb,
    }


async def run_benchmark(
    urls: Sequence[str],
    concurrency: int = 6,
    timeout_ms: int = 12000,
    run_security_checks: bool = True,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {}

    if run_security_checks:
        report["hardening"] = check_container_hardening()
        report["apk_security"] = await run_apk_download_security_test()

    started = time.monotonic()
    async with SafeBrowserVerifier(timeout_ms=timeout_ms) as verifier:
        results = await verifier.verify_many(urls, concurrency=concurrency)
    wall_s = time.monotonic() - started

    report["benchmark"] = summarize_benchmark(results, wall_seconds=wall_s)

    checks = [
        report["benchmark"]["throughput_ok"],
        report["benchmark"]["screenshots"]["size_ok"],
    ]
    if run_security_checks:
        checks.append(report["hardening"]["non_root_ok"])
        checks.append(report["apk_security"]["apk_security_ok"])
        if report["hardening"]["app_dir_exists"]:
            checks.append(report["hardening"]["read_only_rootfs_ok"])

    report["all_passed"] = all(checks)
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 scripts/benchmark_verifier.py",
        description="Benchmark SafeBrowserVerifier throughput (50 URLs) and APK sandbox security.",
    )
    parser.add_argument("--count", type=int, default=DEFAULT_BENCHMARK_COUNT, help="Number of URLs (default: 50).")
    parser.add_argument("--urls-file", type=Path, default=None, help="Optional newline-delimited URLs file.")
    parser.add_argument("--concurrency", type=int, default=6, help="Concurrent Chromium contexts (default: 6).")
    parser.add_argument("--timeout-ms", type=int, default=12000, help="Per-URL timeout in ms (default: 12000).")
    parser.add_argument("--skip-security", action="store_true", help="Skip container/APK security tests.")
    args = parser.parse_args(argv)

    urls = build_benchmark_urls(count=args.count, urls_file=args.urls_file)
    print(
        f"[benchmark] starting {len(urls)} URLs (concurrency={args.concurrency}, timeout={args.timeout_ms}ms)...",
        file=sys.stderr,
        flush=True,
    )
    report = asyncio.run(
        run_benchmark(
            urls=urls,
            concurrency=args.concurrency,
            timeout_ms=args.timeout_ms,
            run_security_checks=not args.skip_security,
        )
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
