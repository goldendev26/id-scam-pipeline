"""Environment settings, URL status state machine, limits, and error codes from the SRS."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
import os
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None  # type: ignore[assignment]

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if load_dotenv is not None:
    # override=False so variables already set (e.g. by Docker) win over .env.
    load_dotenv(PROJECT_ROOT / ".env", override=False)


STATUS_NEW = "new"
STATUS_VERIFYING = "verifying"
STATUS_VERIFIED = "verified"
STATUS_DEAD_OR_BLOCKED = "dead_or_blocked"
STATUS_AI_SCORED = "ai_scored"
STATUS_APPROVED = "approved"
STATUS_SKIPPED = "skipped"
STATUS_EXPORTED = "exported"
STATUS_SUBMITTED = "submitted"
STATUS_VALID = "valid"
STATUS_CLAIMED_EXTERNAL = "claimed_external"
STATUS_REJECTED = "rejected"

ALL_STATUSES: FrozenSet[str] = frozenset(
    {
        STATUS_NEW,
        STATUS_VERIFYING,
        STATUS_VERIFIED,
        STATUS_DEAD_OR_BLOCKED,
        STATUS_AI_SCORED,
        STATUS_APPROVED,
        STATUS_SKIPPED,
        STATUS_EXPORTED,
        STATUS_SUBMITTED,
        STATUS_VALID,
        STATUS_CLAIMED_EXTERNAL,
        STATUS_REJECTED,
    }
)

# SRS 5.2 diagram. `verified` may go straight to review when AI is off.
# `rejected` is read as a judge rejection after `submitted`.
ALLOWED_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    STATUS_NEW: frozenset({STATUS_VERIFYING}),
    STATUS_VERIFYING: frozenset({STATUS_VERIFIED, STATUS_DEAD_OR_BLOCKED}),
    STATUS_VERIFIED: frozenset({STATUS_AI_SCORED, STATUS_APPROVED, STATUS_SKIPPED}),
    STATUS_AI_SCORED: frozenset({STATUS_APPROVED, STATUS_SKIPPED}),
    STATUS_APPROVED: frozenset({STATUS_EXPORTED}),
    STATUS_EXPORTED: frozenset({STATUS_SUBMITTED}),
    STATUS_SUBMITTED: frozenset({STATUS_VALID, STATUS_CLAIMED_EXTERNAL, STATUS_REJECTED}),
    STATUS_DEAD_OR_BLOCKED: frozenset(),
    STATUS_SKIPPED: frozenset(),
    STATUS_VALID: frozenset(),
    STATUS_CLAIMED_EXTERNAL: frozenset(),
    STATUS_REJECTED: frozenset(),
}

# SRS 5.2: rejected hard (HTTP 409) when re-entering approved/exported.
HARD_BLOCKED_STATUSES: FrozenSet[str] = frozenset(
    {
        STATUS_DEAD_OR_BLOCKED,
        STATUS_SKIPPED,
        STATUS_EXPORTED,
        STATUS_SUBMITTED,
        STATUS_CLAIMED_EXTERNAL,
        STATUS_VALID,
    }
)

AI_CATEGORIES: Tuple[str, ...] = (
    "judol",
    "pinjol",
    "phishing",
    "scam",
    "legit",
    "parked",
    "unclear",
)

KEY_APPROVE_BATCH = "a"
KEY_APPROVE_SINGLE_NOTE = "n"
KEY_SKIP = "x"

# Duplicated from src.normalizer to keep this module import-free.
MAX_URL_LENGTH = 300
MAX_BATCH_ITEMS = 20

PAGE_TEXT_MAX_CHARS = 2000
AI_NOTE_MAX_CHARS = 140
SCREENSHOT_MAX_BYTES = 150 * 1024
AI_FALLBACK_BATCH_SIZE = 30
LOCK_TTL_SECONDS = 5 * 60

ERR_EMPTY = "ERR_EMPTY"
ERR_TOO_LONG = "ERR_TOO_LONG"
ERR_FORMAT = "ERR_FORMAT"
ERR_FORBIDDEN = "ERR_FORBIDDEN"
ERR_DUP_LOCAL = "ERR_DUP_LOCAL"
ERR_TARGET_TIMEOUT = "ERR_TARGET_TIMEOUT"
ERR_AI_UNAVAILABLE = "ERR_AI_UNAVAILABLE"
ERR_STORAGE_QUOTA = "ERR_STORAGE_QUOTA"
ERR_INVALID_STATE = "ERR_INVALID_STATE"

# Already used by src/verify.py.
ERR_HTTP_ERROR = "ERR_HTTP_ERROR"
ERR_DNS_OR_CONN = "ERR_DNS_OR_CONN"
ERR_INVALID_FINAL_URL = "ERR_INVALID_FINAL_URL"

HTTP_CONFLICT = 409


class InvalidStateError(Exception):
    error_code = ERR_INVALID_STATE
    http_status = HTTP_CONFLICT

    def __init__(self, current: str, target: str) -> None:
        self.current = current
        self.target = target
        super().__init__(f"[{ERR_INVALID_STATE}] Illegal transition: {current} -> {target}")


class ConfigError(Exception):
    pass


def is_valid_transition(current: str, target: str) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def assert_transition(current: str, target: str) -> None:
    if not is_valid_transition(current, target):
        raise InvalidStateError(current, target)


def _env_str(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env_str(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    supabase_url: str
    supabase_service_key: str = field(repr=False)
    supabase_storage_bucket: str
    deepseek_api_key: str = field(repr=False)
    deepseek_base_url: str
    deepseek_model: str
    reviewer_name: str
    verify_timeout_ms: int
    screenshot_jpeg_quality: int

    @property
    def ai_enabled(self) -> bool:
        return bool(self.deepseek_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    # The SRS names the key SUPABASE_KEY; .env.example uses SUPABASE_SERVICE_KEY.
    service_key = _env_str("SUPABASE_SERVICE_KEY") or _env_str("SUPABASE_KEY")
    return Settings(
        supabase_url=_env_str("SUPABASE_URL").rstrip("/"),
        supabase_service_key=service_key,
        supabase_storage_bucket=_env_str("SUPABASE_STORAGE_BUCKET", "screenshots"),
        deepseek_api_key=_env_str("DEEPSEEK_API_KEY"),
        deepseek_base_url=_env_str("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        deepseek_model=_env_str("DEEPSEEK_MODEL", "deepseek-chat"),
        reviewer_name=_env_str("REVIEWER_NAME", "member-1"),
        verify_timeout_ms=_env_int("VERIFY_TIMEOUT_MS", 15000),
        screenshot_jpeg_quality=_env_int("SCREENSHOT_JPEG_QUALITY", 60),
    )


def validate_settings(settings: Optional[Settings] = None, *, require_ai: bool = False) -> Settings:
    """Raise ConfigError listing missing variables. AI is optional (pipeline fails open)."""
    s = settings or get_settings()
    missing: List[str] = []
    if not s.supabase_url:
        missing.append("SUPABASE_URL")
    if not s.supabase_service_key:
        missing.append("SUPABASE_SERVICE_KEY")
    if require_ai and not s.deepseek_api_key:
        missing.append("DEEPSEEK_API_KEY")
    if missing:
        raise ConfigError("Missing environment variables: " + ", ".join(missing))
    return s