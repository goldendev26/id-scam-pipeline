"""Unit tests for src.verify (FR-VERIF-001, Task #12)."""

from pathlib import Path
import tempfile
import unittest

from src.verify import (
    SafeBrowserVerifier,
    VerifyResult,
    save_debug_screenshot,
    should_abort_request,
)


class _FakeResponse:
    def __init__(self, status: int):
        self.status = status


class _FakePage:
    def __init__(self, handler):
        self._handler = handler
        self.url = ""
        self._title = ""
        self._html = ""
        self._screenshot = b""
        self.route_registered = False
        self.dialog_registered = False

    def set_default_navigation_timeout(self, ms: int):
        self.nav_timeout = ms

    def set_default_timeout(self, ms: int):
        self.default_timeout = ms

    async def route(self, pattern: str, fn):
        self.route_registered = True

    def on(self, event: str, fn):
        if event == "dialog":
            self.dialog_registered = True

    async def goto(self, target_url: str, wait_until: str, timeout: int):
        outcome = self._handler(target_url)
        if isinstance(outcome, Exception):
            raise outcome
        self.url = outcome["final_url"]
        self._title = outcome.get("title", "")
        self._html = outcome.get("html", "<html></html>")
        self._screenshot = outcome.get("screenshot", b"\xff\xd8fakejpeg")
        return _FakeResponse(outcome.get("status", 200))

    async def wait_for_load_state(self, state: str, timeout: int):
        return None

    async def title(self) -> str:
        return self._title

    async def content(self) -> str:
        return self._html

    async def screenshot(self, type: str, quality: int, full_page: bool) -> bytes:
        return self._screenshot


class _FakeContext:
    def __init__(self, kwargs: dict, handler):
        self.kwargs = kwargs
        self.handler = handler
        self.closed = False

    async def new_page(self):
        return _FakePage(self.handler)

    async def close(self):
        self.closed = True


class _FakeBrowser:
    def __init__(self, handler):
        self.handler = handler
        self.contexts = []
        self.closed = False

    async def new_context(self, **kwargs):
        ctx = _FakeContext(kwargs, self.handler)
        self.contexts.append(ctx)
        return ctx

    async def close(self):
        self.closed = True


class _FakePlaywrightCM:
    def __init__(self, browser: _FakeBrowser):
        self._browser = browser

    async def __aenter__(self):
        class _Chromium:
            def __init__(self, b):
                self._b = b

            async def launch(self, headless: bool, args: list):
                return self._b

        class _PW:
            def __init__(self, b):
                self.chromium = _Chromium(b)

        return _PW(self._browser)

    async def __aexit__(self, exc_type, exc, tb):
        return None


class TestVerifyHelpers(unittest.TestCase):
    def test_should_abort_request_blocks_apks_and_media(self):
        self.assertTrue(should_abort_request("media", "https://slot.id/video.mp4"))
        self.assertTrue(should_abort_request("font", "https://slot.id/font.woff2"))
        self.assertTrue(should_abort_request("document", "https://pinjol.id/app-resmi.APK"))
        self.assertTrue(should_abort_request("other", "https://scam.id/drop.exe?v=1"))

        self.assertFalse(should_abort_request("document", "https://slot.id/daftar"))
        self.assertFalse(should_abort_request("script", "https://slot.id/app.js"))
        self.assertFalse(should_abort_request("image", "https://slot.id/banner.webp"))

    def test_save_debug_screenshot_writes_sanitized_jpeg(self):
        res = VerifyResult(
            input_url="https://example.com/a/b",
            normalized_url="example.com/a/b",
            final_normalized_url="example.com/a/b",
            status="verified",
            screenshot_bytes=b"\xff\xd8\xfftest",
        )
        with tempfile.TemporaryDirectory() as tmp:
            saved = save_debug_screenshot(res, Path(tmp))
            self.assertIsNotNone(saved)
            self.assertEqual(saved.name, "example.com_a_b.jpg")
            self.assertEqual(saved.read_bytes(), b"\xff\xd8\xfftest")


class TestSafeBrowserVerifier(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_invalid_url_before_opening_browser(self):
        browser = _FakeBrowser(lambda u: {"final_url": u})
        async with SafeBrowserVerifier(playwright_factory=lambda: _FakePlaywrightCM(browser)) as v:
            res = await v.verify_url("http://103.21.44.5:8080/slot")
        self.assertEqual(res.status, "invalid")
        self.assertEqual(res.error_code, "ERR_FORBIDDEN")
        self.assertEqual(len(browser.contexts), 0)

    async def test_follows_redirect_normalizes_final_url_and_blocks_downloads(self):
        def handler(url):
            return {
                "final_url": "https://www.SlotContoh.id/Daftar/?utm=wa#top",
                "status": 200,
                "title": "Slot Contoh Gacor",
                "html": "<html><body>Daftar Slot</body></html>",
                "screenshot": b"\xff\xd8\xffdemo",
            }

        browser = _FakeBrowser(handler)
        async with SafeBrowserVerifier(playwright_factory=lambda: _FakePlaywrightCM(browser)) as v:
            res = await v.verify_url("bit.ly/promo99")

        self.assertEqual(res.status, "verified")
        self.assertEqual(res.normalized_url, "bit.ly/promo99")
        self.assertEqual(res.final_normalized_url, "slotcontoh.id/Daftar")
        self.assertEqual(res.http_status, 200)
        self.assertEqual(res.page_title, "Slot Contoh Gacor")
        self.assertEqual(res.screenshot_bytes, b"\xff\xd8\xffdemo")
        self.assertEqual(len(browser.contexts), 1)
        self.assertFalse(browser.contexts[0].kwargs["accept_downloads"])
        self.assertTrue(browser.contexts[0].closed)

    async def test_http_fallback_after_https_connection_error(self):
        seen = []

        def handler(url):
            seen.append(url)
            if url.startswith("https://"):
                raise RuntimeError("net::ERR_CONNECTION_REFUSED")
            return {"final_url": "http://mirror99.id/", "status": 200, "title": "Mirror"}

        browser = _FakeBrowser(handler)
        async with SafeBrowserVerifier(playwright_factory=lambda: _FakePlaywrightCM(browser)) as v:
            res = await v.verify_url("mirror99.id")

        self.assertEqual(seen, ["https://mirror99.id", "http://mirror99.id"])
        self.assertEqual(res.status, "verified")
        self.assertEqual(res.final_normalized_url, "mirror99.id")
        self.assertTrue(all(ctx.closed for ctx in browser.contexts))

    async def test_timeout_marks_dead_or_blocked_and_closes_context(self):
        class TimeoutErrorFake(Exception):
            pass

        def handler(url):
            raise TimeoutErrorFake("Page.goto: Timeout 15000ms exceeded")

        browser = _FakeBrowser(handler)
        async with SafeBrowserVerifier(
            timeout_ms=15000,
            playwright_factory=lambda: _FakePlaywrightCM(browser),
        ) as v:
            res = await v.verify_url("slowsite.id")

        self.assertEqual(res.status, "dead_or_blocked")
        self.assertEqual(res.error_code, "ERR_TARGET_TIMEOUT")
        self.assertEqual(len(browser.contexts), 1)
        self.assertTrue(browser.contexts[0].closed)

    async def test_http_404_marks_dead_or_blocked(self):
        browser = _FakeBrowser(lambda u: {"final_url": u, "status": 404})
        async with SafeBrowserVerifier(playwright_factory=lambda: _FakePlaywrightCM(browser)) as v:
            res = await v.verify_url("gone.id/slot")

        self.assertEqual(res.status, "dead_or_blocked")
        self.assertEqual(res.http_status, 404)
        self.assertEqual(res.error_code, "ERR_HTTP_ERROR")

    async def test_verify_many_runs_concurrently(self):
        browser = _FakeBrowser(lambda u: {"final_url": u, "status": 200, "title": "OK"})
        urls = ["a.id", "b.id", "c.id", "127.0.0.1"]
        async with SafeBrowserVerifier(playwright_factory=lambda: _FakePlaywrightCM(browser)) as v:
            results = await v.verify_many(urls, concurrency=2)

        self.assertEqual([r.status for r in results], ["verified", "verified", "verified", "invalid"])
        self.assertTrue(browser.closed)


if __name__ == "__main__":
    unittest.main()
