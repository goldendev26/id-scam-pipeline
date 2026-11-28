"""Configurable Playwright batch form submitter.

Defaults to the local mock portal (`http://127.0.0.1:8001` or `http://mock-target:8001`).
Enforces the 20-link batch cap, a >= 3-second cooldown between submissions,
SSRF target-host validation, and never bypasses CAPTCHAs or login gates.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
import os
import re
import time
from typing import Any, Callable, Optional, Sequence
from urllib.parse import urlsplit

from src.db import load_dotenv
from src.normalizer import MAX_BATCH_ITEMS
from src.verify import CHROMIUM_ARGS

DEFAULT_SUBMIT_TARGET_URL = "http://127.0.0.1:8001"
DEFAULT_LINKS_SELECTOR = 'textarea[name="links"]'
DEFAULT_REPORTER_SELECTOR = 'input[name="reporter"]'
DEFAULT_BUTTON_SELECTOR = 'button[type="submit"]'
DEFAULT_SUCCESS_SELECTOR = '[data-submit-status="ok"]'
DEFAULT_SUBMIT_TIMEOUT_MS = 15000
DEFAULT_SUBMIT_COOLDOWN_S = 3.0

ALLOWED_SUBMIT_HOSTS = frozenset({"127.0.0.1", "localhost", "mock-target", "imphnen.dev"})

_CAPTCHA_MARKERS = (
    "challenges.cloudflare.com/turnstile",
    "cf-turnstile",
    "g-recaptcha",
    "google.com/recaptcha",
    "h-captcha",
    "hcaptcha.com",
    "verify you are human",
)

_last_submit_ts: float = 0.0
_cooldown_lock: Optional[asyncio.Lock] = None


def _get_cooldown_lock() -> asyncio.Lock:
    global _cooldown_lock
    if _cooldown_lock is None:
        _cooldown_lock = asyncio.Lock()
    return _cooldown_lock


async def _enforce_cooldown(cooldown_s: float) -> None:
    """Wait if needed so consecutive submissions respect the >= 3s cooldown."""
    global _last_submit_ts
    if cooldown_s <= 0:
        return
    async with _get_cooldown_lock():
        now = time.monotonic()
        elapsed = now - _last_submit_ts
        if _last_submit_ts > 0 and elapsed < cooldown_s:
            await asyncio.sleep(cooldown_s - elapsed)
        _last_submit_ts = time.monotonic()


def validate_submit_target_url(target_url: str) -> str:
    """Validate target URL against allowed submission hosts to prevent SSRF."""
    cleaned = (target_url or "").strip()
    parsed = urlsplit(cleaned)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target portal URL tidak valid (wajib http/https).")

    host = parsed.hostname.lower()
    env_target = os.getenv("SUBMIT_TARGET_URL", "").strip()
    env_host = urlsplit(env_target).hostname.lower() if env_target and urlsplit(env_target).hostname else ""

    allowed = set(ALLOWED_SUBMIT_HOSTS)
    if env_host:
        allowed.add(env_host)

    if host not in allowed:
        raise ValueError(
            f"Host target '{host}' tidak diizinkan. Atur SUBMIT_TARGET_URL di .env atau gunakan portal mock."
        )
    return cleaned


@dataclass(frozen=True)
class SubmitConfig:
    target_url: str
    links_selector: str = DEFAULT_LINKS_SELECTOR
    reporter_selector: str = DEFAULT_REPORTER_SELECTOR
    button_selector: str = DEFAULT_BUTTON_SELECTOR
    success_selector: str = DEFAULT_SUCCESS_SELECTOR
    timeout_ms: int = DEFAULT_SUBMIT_TIMEOUT_MS
    cooldown_s: float = DEFAULT_SUBMIT_COOLDOWN_S

    @classmethod
    def from_env(cls, target_url_override: Optional[str] = None) -> "SubmitConfig":
        load_dotenv()
        raw_target = (target_url_override or os.getenv("SUBMIT_TARGET_URL", "")).strip() or DEFAULT_SUBMIT_TARGET_URL
        validated_target = validate_submit_target_url(raw_target)
        return cls(
            target_url=validated_target,
            links_selector=os.getenv("SUBMIT_LINKS_SELECTOR", DEFAULT_LINKS_SELECTOR).strip() or DEFAULT_LINKS_SELECTOR,
            reporter_selector=os.getenv("SUBMIT_REPORTER_SELECTOR", DEFAULT_REPORTER_SELECTOR).strip(),
            button_selector=os.getenv("SUBMIT_BUTTON_SELECTOR", DEFAULT_BUTTON_SELECTOR).strip() or DEFAULT_BUTTON_SELECTOR,
            success_selector=os.getenv("SUBMIT_SUCCESS_SELECTOR", DEFAULT_SUCCESS_SELECTOR).strip(),
            timeout_ms=int(os.getenv("SUBMIT_TIMEOUT_MS", str(DEFAULT_SUBMIT_TIMEOUT_MS))),
            cooldown_s=float(os.getenv("SUBMIT_COOLDOWN_S", str(DEFAULT_SUBMIT_COOLDOWN_S))),
        )


@dataclass(frozen=True)
class SubmitResult:
    ok: bool
    status: str  # "submitted" | "needs_manual" | "failed"
    target_url: str
    submitted_links: list[str] = field(default_factory=list)
    duplicate_links: list[str] = field(default_factory=list)
    detail: str = ""
    http_status: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "target_url": self.target_url,
            "submitted_links": self.submitted_links,
            "duplicate_links": self.duplicate_links,
            "detail": self.detail,
            "http_status": self.http_status,
        }


def detect_gate_or_captcha(html_text: str, current_url: str = "") -> Optional[str]:
    """Return a reason string if the page has a CAPTCHA/anti-bot/login gate (never bypass)."""
    lowered_html = (html_text or "").lower()
    lowered_url = (current_url or "").lower()
    for marker in _CAPTCHA_MARKERS:
        if marker in lowered_html:
            return f"Terdeteksi CAPTCHA/anti-bot ({marker}); lanjutkan submit manual."
    if any(seg in lowered_url for seg in ("/login", "/signin", "/masuk", "/auth/")) and "<input" in lowered_html and 'type="password"' in lowered_html:
        return "Halaman membutuhkan login; silakan login & submit manual."
    return None


async def _launch_browser(playwright: Any) -> Any:
    try:
        return await playwright.chromium.launch(headless=True, args=CHROMIUM_ARGS)
    except Exception as exc:
        if "executable doesn't exist" not in str(exc).lower():
            raise
        for channel in ("chrome", "msedge"):
            try:
                return await playwright.chromium.launch(headless=True, channel=channel, args=CHROMIUM_ARGS)
            except Exception:
                continue
        raise


def _parse_json_attr(raw: Optional[str]) -> Optional[list[str]]:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(x) for x in parsed]
    except json.JSONDecodeError:
        pass
    return None


async def submit_batch_playwright(
    links: Sequence[str],
    *,
    reporter: str = "member-1",
    config: Optional[SubmitConfig] = None,
    target_url: Optional[str] = None,
    playwright_factory: Optional[Callable[[], Any]] = None,
) -> SubmitResult:
    """Fill and submit up to 20 normalized links to the configured submission portal."""
    clean_links = [str(u).strip() for u in links if str(u).strip()][:MAX_BATCH_ITEMS]
    cfg = config or SubmitConfig.from_env(target_url_override=target_url)
    validate_submit_target_url(cfg.target_url)

    if not clean_links:
        return SubmitResult(ok=False, status="failed", target_url=cfg.target_url, detail="Tidak ada link untuk dikirim.")

    await _enforce_cooldown(cfg.cooldown_s)

    if playwright_factory is None:
        from playwright.async_api import async_playwright

        playwright_factory = async_playwright

    async with playwright_factory() as pw:
        browser = await _launch_browser(pw)
        try:
            context = await browser.new_context(accept_downloads=False)
            try:
                page = await context.new_page()
                page.set_default_timeout(cfg.timeout_ms)
                resp = await page.goto(cfg.target_url, wait_until="domcontentloaded", timeout=cfg.timeout_ms)
                http_status = resp.status if resp is not None else None
                if http_status is not None and http_status >= 400:
                    return SubmitResult(
                        ok=False,
                        status="failed",
                        target_url=cfg.target_url,
                        http_status=http_status,
                        detail=f"Target portal mengembalikan HTTP {http_status}.",
                    )

                gate_reason = detect_gate_or_captcha(await page.content(), page.url or cfg.target_url)
                if gate_reason:
                    return SubmitResult(
                        ok=False,
                        status="needs_manual",
                        target_url=cfg.target_url,
                        http_status=http_status,
                        detail=gate_reason,
                    )

                if cfg.reporter_selector:
                    rep_loc = page.locator(cfg.reporter_selector).first
                    if await rep_loc.count() > 0:
                        await rep_loc.fill(reporter)

                await page.locator(cfg.links_selector).first.fill("\n".join(clean_links))
                await page.locator(cfg.button_selector).first.click()

                if cfg.success_selector:
                    success_el = page.locator(cfg.success_selector).first
                    await success_el.wait_for(state="visible", timeout=cfg.timeout_ms)
                    accepted = _parse_json_attr(await success_el.get_attribute("data-accepted-json"))
                    duplicates = _parse_json_attr(await success_el.get_attribute("data-duplicates-json"))
                    text_summary = re.sub(r"\s+", " ", (await success_el.inner_text()) or "").strip()
                    return SubmitResult(
                        ok=True,
                        status="submitted",
                        target_url=cfg.target_url,
                        submitted_links=accepted if accepted is not None else clean_links,
                        duplicate_links=duplicates or [],
                        detail=text_summary[:200] or "Berhasil terkirim ke portal target.",
                        http_status=http_status,
                    )

                await page.wait_for_load_state("networkidle", timeout=min(5000, cfg.timeout_ms))
                post_gate = detect_gate_or_captcha(await page.content(), page.url or cfg.target_url)
                if post_gate:
                    return SubmitResult(
                        ok=False,
                        status="needs_manual",
                        target_url=cfg.target_url,
                        http_status=http_status,
                        detail=post_gate,
                    )
                return SubmitResult(
                    ok=True,
                    status="submitted",
                    target_url=cfg.target_url,
                    submitted_links=clean_links,
                    detail="Form berhasil disubmit.",
                    http_status=http_status,
                )
            finally:
                await context.close()
        finally:
            await browser.close()
