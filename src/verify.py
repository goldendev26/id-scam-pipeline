"""Sandboxed Playwright browser verifier (FR-VERIF-001, Task #12).

Opens candidate URLs inside an isolated headless Chromium context with downloads
disabled, follows HTTP/JS redirects, normalizes the final landing URL using
`src.normalizer`, and returns HTML + JPEG screenshot bytes for downstream text
parsing (Task #13) and Supabase Storage upload (Task #14).
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from io import BytesIO
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Iterable, List, Optional, Sequence
from urllib.parse import urlsplit

from src.normalizer import normalize_url

DEFAULT_TIMEOUT_MS = int(os.getenv("VERIFY_TIMEOUT_MS", "15000"))
DEFAULT_JPEG_QUALITY = int(os.getenv("SCREENSHOT_JPEG_QUALITY", "60"))
DEFAULT_MAX_SCREENSHOT_BYTES = int(os.getenv("MAX_SCREENSHOT_BYTES", str(150 * 1024)))
DEFAULT_NETWORK_IDLE_MS = 3000
DEFAULT_CONCURRENCY = 4

VIEWPORT = {"width": 1280, "height": 720}
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36"
)

CHROMIUM_ARGS = [
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--no-first-run",
    "--mute-audio",
]

BLOCKED_RESOURCE_TYPES = frozenset({"media", "font"})
BLOCKED_EXTENSIONS = (
    ".apk",
    ".exe",
    ".msi",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".iso",
    ".bat",
    ".sh",
    ".ps1",
    ".scr",
)


@dataclass(frozen=True)
class VerifyResult:
    input_url: str
    normalized_url: Optional[str]
    final_url: Optional[str] = None
    final_normalized_url: Optional[str] = None
    status: str = "dead_or_blocked"
    http_status: Optional[int] = None
    page_title: Optional[str] = None
    raw_html: Optional[str] = None
    screenshot_bytes: Optional[bytes] = None
    screenshot_path: Optional[str] = None
    error_code: Optional[str] = None
    error_detail: Optional[str] = None
    elapsed_ms: int = 0

    def to_summary_dict(self) -> dict:
        return {
            "input_url": self.input_url,
            "normalized_url": self.normalized_url,
            "final_url": self.final_url,
            "final_normalized_url": self.final_normalized_url,
            "status": self.status,
            "http_status": self.http_status,
            "page_title": self.page_title,
            "html_bytes": len(self.raw_html.encode("utf-8")) if self.raw_html else 0,
            "screenshot_bytes": len(self.screenshot_bytes) if self.screenshot_bytes else 0,
            "screenshot_path": self.screenshot_path,
            "error_code": self.error_code,
            "error_detail": self.error_detail,
            "elapsed_ms": self.elapsed_ms,
        }


def compress_jpeg_to_limit(
    jpeg_bytes: bytes,
    max_bytes: int = DEFAULT_MAX_SCREENSHOT_BYTES,
    initial_quality: int = DEFAULT_JPEG_QUALITY,
) -> bytes:
    """Ensure JPEG bytes fit within max_bytes (default 150 KB) via Pillow quality/scale steps."""
    if not jpeg_bytes or len(jpeg_bytes) <= max_bytes:
        return jpeg_bytes

    from PIL import Image

    with Image.open(BytesIO(jpeg_bytes)) as img:
        rgb = img.convert("RGB")
        qualities = [q for q in (initial_quality, 50, 40, 30, 22, 15) if q <= initial_quality]
        if not qualities:
            qualities = [initial_quality]

        best = jpeg_bytes
        for quality in qualities:
            buf = BytesIO()
            rgb.save(buf, format="JPEG", quality=quality, optimize=True)
            candidate = buf.getvalue()
            if len(candidate) < len(best):
                best = candidate
            if len(candidate) <= max_bytes:
                return candidate

        cur = rgb
        while cur.width > 320 and len(best) > max_bytes:
            new_size = (max(320, int(cur.width * 0.8)), max(180, int(cur.height * 0.8)))
            cur = cur.resize(new_size, Image.Resampling.LANCZOS)
            for quality in (35, 25, 18):
                buf = BytesIO()
                cur.save(buf, format="JPEG", quality=quality, optimize=True)
                candidate = buf.getvalue()
                if len(candidate) < len(best):
                    best = candidate
                if len(candidate) <= max_bytes:
                    return candidate

        return best


def should_abort_request(resource_type: str, url: str) -> bool:
    """Return True for heavy media/fonts or risky executable/APK download URLs."""
    if resource_type in BLOCKED_RESOURCE_TYPES:
        return True
    path = urlsplit(url).path.lower()
    return path.endswith(BLOCKED_EXTENSIONS)


def _build_candidate_schemes(raw_url: str, normalized_url: str) -> List[str]:
    lowered = raw_url.strip().lower()
    if lowered.startswith("http://"):
        return [f"http://{normalized_url}"]
    if lowered.startswith("https://"):
        return [f"https://{normalized_url}", f"http://{normalized_url}"]
    return [f"https://{normalized_url}", f"http://{normalized_url}"]


def _is_timeout_error(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    return "timeout" in name or "timed out" in msg or "err_timed_out" in msg


class SafeBrowserVerifier:
    """Async headless Chromium verifier using one clean BrowserContext per URL."""

    def __init__(
        self,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        jpeg_quality: int = DEFAULT_JPEG_QUALITY,
        max_screenshot_bytes: int = DEFAULT_MAX_SCREENSHOT_BYTES,
        network_idle_ms: int = DEFAULT_NETWORK_IDLE_MS,
        capture_screenshot: bool = True,
        uploader: Optional[Callable[[str, bytes], str]] = None,
        playwright_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        self.timeout_ms = timeout_ms
        self.jpeg_quality = jpeg_quality
        self.max_screenshot_bytes = max_screenshot_bytes
        self.network_idle_ms = network_idle_ms
        self.capture_screenshot = capture_screenshot
        self.uploader = uploader
        self._playwright_factory = playwright_factory
        self._playwright_cm: Any = None
        self._playwright: Any = None
        self._browser: Any = None

    async def __aenter__(self) -> "SafeBrowserVerifier":
        if self._playwright_factory is None:
            from playwright.async_api import async_playwright

            self._playwright_factory = async_playwright

        self._playwright_cm = self._playwright_factory()
        self._playwright = await self._playwright_cm.__aenter__()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=CHROMIUM_ARGS,
        )
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright_cm is not None:
            await self._playwright_cm.__aexit__(exc_type, exc, tb)
            self._playwright_cm = None
            self._playwright = None

    async def verify_url(self, raw_url: str, url_id: Optional[int] = None) -> VerifyResult:
        """Open a single URL in a disposable context and collect redirect + page artifacts."""
        started = time.monotonic()

        norm = normalize_url(raw_url)
        if not norm.ok or not norm.normalized:
            return VerifyResult(
                input_url=raw_url,
                normalized_url=None,
                status="invalid",
                error_code=norm.error_code,
                error_detail=norm.error_message,
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )

        if self._browser is None:
            raise RuntimeError("SafeBrowserVerifier must be entered with `async with`.")

        candidates = _build_candidate_schemes(raw_url, norm.normalized)
        last_error_code = "ERR_DNS_OR_CONN"
        last_error_detail = "Navigation failed."

        for target_url in candidates:
            context = await self._browser.new_context(
                accept_downloads=False,
                ignore_https_errors=True,
                java_script_enabled=True,
                viewport=VIEWPORT,
                locale="id-ID",
                timezone_id="Asia/Jakarta",
                user_agent=USER_AGENT,
            )
            try:
                page = await context.new_page()
                page.set_default_navigation_timeout(self.timeout_ms)
                page.set_default_timeout(self.timeout_ms)

                async def _handle_route(route: Any) -> None:
                    req = route.request
                    if should_abort_request(req.resource_type, req.url):
                        await route.abort()
                    else:
                        await route.continue_()

                await page.route("**/*", _handle_route)
                page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))

                response = await page.goto(
                    target_url,
                    wait_until="domcontentloaded",
                    timeout=self.timeout_ms,
                )

                # Allow short JS redirects to settle without failing on slow trackers.
                if self.network_idle_ms > 0:
                    try:
                        await page.wait_for_load_state(
                            "networkidle",
                            timeout=self.network_idle_ms,
                        )
                    except Exception:
                        pass

                http_status = response.status if response is not None else None
                final_url = page.url or target_url
                final_norm = normalize_url(final_url)

                if http_status is not None and http_status >= 400:
                    return VerifyResult(
                        input_url=raw_url,
                        normalized_url=norm.normalized,
                        final_url=final_url,
                        final_normalized_url=final_norm.normalized if final_norm.ok else None,
                        status="dead_or_blocked",
                        http_status=http_status,
                        error_code="ERR_HTTP_ERROR",
                        error_detail=f"HTTP {http_status}",
                        elapsed_ms=int((time.monotonic() - started) * 1000),
                    )

                if not final_norm.ok:
                    return VerifyResult(
                        input_url=raw_url,
                        normalized_url=norm.normalized,
                        final_url=final_url,
                        final_normalized_url=None,
                        status="dead_or_blocked",
                        http_status=http_status,
                        error_code="ERR_INVALID_FINAL_URL",
                        error_detail=final_norm.error_code,
                        elapsed_ms=int((time.monotonic() - started) * 1000),
                    )

                title = (await page.title()).strip() or None
                raw_html = await page.content()
                screenshot: Optional[bytes] = None
                screenshot_path: Optional[str] = None
                if self.capture_screenshot:
                    raw_shot = await page.screenshot(
                        type="jpeg",
                        quality=self.jpeg_quality,
                        full_page=False,
                    )
                    screenshot = compress_jpeg_to_limit(
                        raw_shot,
                        max_bytes=self.max_screenshot_bytes,
                        initial_quality=self.jpeg_quality,
                    )
                    if self.uploader is not None and screenshot:
                        target_key = build_screenshot_path(
                            final_norm.normalized or norm.normalized,
                            url_id=url_id,
                        )
                        screenshot_path = await asyncio.to_thread(
                            self.uploader,
                            target_key,
                            screenshot,
                        )

                return VerifyResult(
                    input_url=raw_url,
                    normalized_url=norm.normalized,
                    final_url=final_url,
                    final_normalized_url=final_norm.normalized,
                    status="verified",
                    http_status=http_status,
                    page_title=title,
                    raw_html=raw_html,
                    screenshot_bytes=screenshot,
                    screenshot_path=screenshot_path,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                )
            except Exception as exc:
                if _is_timeout_error(exc):
                    last_error_code = "ERR_TARGET_TIMEOUT"
                    last_error_detail = f"Timed out after {self.timeout_ms}ms"
                    # Do not retry http after a full timeout on https.
                    break
                last_error_code = "ERR_DNS_OR_CONN"
                last_error_detail = str(exc)[:200]
            finally:
                await context.close()

        return VerifyResult(
            input_url=raw_url,
            normalized_url=norm.normalized,
            status="dead_or_blocked",
            error_code=last_error_code,
            error_detail=last_error_detail,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )

    async def verify_many(
        self,
        urls: Iterable[str],
        concurrency: int = DEFAULT_CONCURRENCY,
    ) -> List[VerifyResult]:
        """Verify multiple URLs concurrently while bounding active browser contexts."""
        sem = asyncio.Semaphore(max(1, concurrency))

        async def _worker(url: str) -> VerifyResult:
            async with sem:
                return await self.verify_url(url)

        tasks = [asyncio.create_task(_worker(u)) for u in urls]
        return list(await asyncio.gather(*tasks))


def _safe_filename(normalized_url: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", normalized_url).strip("._")
    return (cleaned[:120] or "page") + ".jpg"


def build_screenshot_path(normalized_url: str, url_id: Optional[int] = None) -> str:
    """Build a sanitized Supabase Storage object path for a screenshot JPEG."""
    name = _safe_filename(normalized_url)
    return f"{url_id}_{name}" if url_id is not None else name


def upload_verify_screenshot(
    res: VerifyResult,
    db: Any,
    url_id: Optional[int] = None,
    max_bytes: int = DEFAULT_MAX_SCREENSHOT_BYTES,
) -> Optional[str]:
    """Compress (<= 150 KB) and upload a VerifyResult screenshot to Supabase Storage."""
    if not res.screenshot_bytes:
        return None
    jpeg = compress_jpeg_to_limit(res.screenshot_bytes, max_bytes=max_bytes)
    storage_path = build_screenshot_path(
        res.final_normalized_url or res.normalized_url or "page",
        url_id=url_id,
    )
    return db.upload_screenshot(storage_path, jpeg)


def save_debug_screenshot(res: VerifyResult, out_dir: Path) -> Optional[Path]:
    """Write JPEG bytes to disk for local debug inspection only."""
    if not res.screenshot_bytes:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    name = _safe_filename(res.final_normalized_url or res.normalized_url or "page")
    target = out_dir / name
    target.write_bytes(res.screenshot_bytes)
    return target


async def _run_cli(
    urls: Sequence[str],
    concurrency: int,
    out_dir: Optional[Path] = None,
    upload: bool = False,
) -> int:
    db = None
    uploader = None
    if upload:
        from src.db import SupabaseDB

        db = SupabaseDB.from_env()
        uploader = db.upload_screenshot
    try:
        async with SafeBrowserVerifier(uploader=uploader) as verifier:
            results = await verifier.verify_many(urls, concurrency=concurrency)
    finally:
        if db is not None:
            db.close()

    for res in results:
        summary = res.to_summary_dict()
        if out_dir is not None:
            saved = save_debug_screenshot(res, out_dir)
            if saved is not None:
                summary["saved_screenshot"] = str(saved)
        print(json.dumps(summary, ensure_ascii=False))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m src.verify",
        description="Verify URLs inside a sandboxed headless Chromium context.",
    )
    parser.add_argument("urls", nargs="+", help="One or more candidate URLs to verify.")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Optional debug directory to save captured JPEG screenshots.",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload compressed JPEG screenshots (<= 150 KB) to Supabase Storage.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Max concurrent browser contexts (default: {DEFAULT_CONCURRENCY}).",
    )
    args = parser.parse_args(argv)
    return asyncio.run(
        _run_cli(
            args.urls,
            concurrency=args.concurrency,
            out_dir=args.out_dir,
            upload=args.upload,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
