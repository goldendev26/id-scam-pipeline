"""URL normalizer and validator matching imphnen.dev.

Direct Python port of `url.Bw-SVL99.js` from https://imphnen.dev/hackaton-anti-judol/info:
- Trim whitespace; reject empty strings and inputs longer than 300 chars.
- Allow only http/https (bare domains default to https://).
- Reject credentials, `@` in authority, non-default ports, IP literals, and localhost.
- Lowercase hostname, strip at most one leading `www.`, convert IDN to punycode.
- Strip `?query`, `#fragment`, and trailing `/` while keeping path case-sensitive.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import sys
from typing import List, Optional
from urllib.parse import quote, urlsplit

MAX_URL_LENGTH = 300
MAX_BATCH_ITEMS = 20

_FORBIDDEN_SCHEMES_RE = re.compile(
    r"^(javascript|mailto|data|tel|sms|vbscript|blob|about|file|geo|urn):",
    re.IGNORECASE,
)
_SCHEME_AUTH_RE = re.compile(r"^[a-z][a-z0-9+.-]*://([^/?#]*)", re.IGNORECASE)
_HTTP_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_VALID_DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+(?:[a-z]{2,}|xn--[a-z0-9-]+)$")

ERROR_MESSAGES = {
    "ERR_EMPTY": "Isi link dulu.",
    "ERR_FORMAT": "Ini belum berbentuk domain atau link.",
    "ERR_FORBIDDEN": "Link ini tidak boleh dipakai (alamat internal, IP, port, atau memuat kata sandi).",
    "ERR_TOO_LONG": "Linknya terlalu panjang (maksimal 300 karakter).",
}

SITE_CODE_MAP = {
    "ERR_EMPTY": "kosong",
    "ERR_FORMAT": "format",
    "ERR_FORBIDDEN": "terlarang",
    "ERR_TOO_LONG": "kepanjangan",
}


@dataclass(frozen=True)
class NormalizeResult:
    ok: bool
    normalized: Optional[str] = None
    display: Optional[str] = None
    error_code: Optional[str] = None
    site_code: Optional[str] = None
    error_message: Optional[str] = None


@dataclass(frozen=True)
class BatchItem:
    line: int
    raw: str
    result: NormalizeResult


def _fail(error_code: str) -> NormalizeResult:
    return NormalizeResult(
        ok=False,
        error_code=error_code,
        site_code=SITE_CODE_MAP[error_code],
        error_message=ERROR_MESSAGES[error_code],
    )


def _is_ipv4_shorthand(host: str) -> bool:
    """Catch numeric IPv4 forms (127.1, 2130706433, 0x7f.1) that WHATWG URL expands."""
    parts = host.rstrip(".").split(".")
    if not parts or len(parts) > 4:
        return False
    for part in parts:
        if not part:
            return False
        try:
            if part.lower().startswith("0x"):
                int(part, 16)
            elif part.startswith("0") and len(part) > 1:
                int(part, 8)
            else:
                int(part, 10)
        except ValueError:
            return False
    return True


def _remove_dot_segments(path: str) -> str:
    if not path:
        return ""
    out: List[str] = []
    for seg in path.split("/"):
        if seg == ".":
            continue
        if seg == "..":
            if len(out) > 1:
                out.pop()
        else:
            out.append(seg)
    normalized = "/".join(out)
    if path.startswith("/") and not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def _normalize_path(raw_path: str) -> str:
    if not raw_path:
        return ""
    path = _remove_dot_segments(raw_path.replace("\\", "/"))
    path = quote(path, safe="/:@!$&'()*+,;=-._~%")
    return path.rstrip("/")


def normalize_url(raw_url: str) -> NormalizeResult:
    """Normalize and validate a single URL to match imphnen.dev."""
    if raw_url is None:
        return _fail("ERR_EMPTY")

    trimmed = raw_url.strip()
    if trimmed == "":
        return _fail("ERR_EMPTY")
    if len(trimmed) > MAX_URL_LENGTH:
        return _fail("ERR_TOO_LONG")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in trimmed):
        return _fail("ERR_FORMAT")

    has_scheme = bool(
        _SCHEME_AUTH_RE.match(trimmed) or _FORBIDDEN_SCHEMES_RE.match(trimmed)
    )
    candidate = trimmed if has_scheme else f"https://{trimmed}"

    if has_scheme and not _HTTP_SCHEME_RE.match(candidate):
        return _fail("ERR_FORMAT")

    # WHATWG special schemes treat backslashes before ?/# as forward slashes.
    scheme_prefix_end = candidate.find("://") + 3
    head = candidate[:scheme_prefix_end]
    tail = candidate[scheme_prefix_end:]
    qf_idx = len(tail)
    for sep in ("?", "#"):
        pos = tail.find(sep)
        if pos != -1 and pos < qf_idx:
            qf_idx = pos
    candidate_fixed = head + tail[:qf_idx].replace("\\", "/") + tail[qf_idx:]

    try:
        parsed = urlsplit(candidate_fixed)
    except ValueError:
        return _fail("ERR_FORMAT")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return _fail("ERR_FORMAT")

    auth_match = _SCHEME_AUTH_RE.match(candidate_fixed)
    raw_authority = auth_match.group(1) if auth_match else ""
    if parsed.username is not None or parsed.password is not None or "@" in raw_authority:
        return _fail("ERR_FORBIDDEN")

    try:
        port = parsed.port
    except ValueError:
        return _fail("ERR_FORMAT")

    raw_host = parsed.hostname
    if not raw_host:
        return _fail("ERR_FORMAT")

    if raw_authority.startswith("[") or ":" in raw_host:
        return _fail("ERR_FORBIDDEN")

    host_lower = raw_host.lower()
    if (
        _IPV4_RE.match(host_lower)
        or _is_ipv4_shorthand(host_lower)
        or host_lower == "localhost"
        or host_lower.endswith(".localhost")
    ):
        return _fail("ERR_FORBIDDEN")

    try:
        ipaddress.ip_address(host_lower)
        return _fail("ERR_FORBIDDEN")
    except ValueError:
        pass

    try:
        ascii_host = host_lower.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return _fail("ERR_FORMAT")

    if ascii_host.startswith("www."):
        ascii_host = ascii_host[4:]

    if not _VALID_DOMAIN_RE.match(ascii_host):
        return _fail("ERR_FORMAT")

    # Browser new URL() clears default ports (80/443) and keeps all others.
    default_port = 80 if scheme == "http" else 443
    if port is not None and port != default_port:
        return _fail("ERR_FORBIDDEN")

    path = _normalize_path(parsed.path)
    normalized = f"{ascii_host}{path}"
    return NormalizeResult(ok=True, normalized=normalized, display=normalized)


def normalize_batch(text: str, max_items: int = MAX_BATCH_ITEMS) -> List[BatchItem]:
    """Parse up to 20 non-empty lines, matching imphnen.dev batch submit mode."""
    items: List[BatchItem] = []
    for line_no, raw_line in enumerate(text.split("\n"), start=1):
        if len(items) >= max_items:
            break
        cleaned_line = raw_line.rstrip("\r")
        if cleaned_line.strip() == "":
            continue
        items.append(
            BatchItem(
                line=line_no,
                raw=cleaned_line,
                result=normalize_url(cleaned_line),
            )
        )
    return items


def _cli(argv: List[str]) -> int:
    if not argv:
        print("Usage: python3 -m src.normalizer <url1> [url2 ...]")
        return 1
    exit_code = 0
    for raw in argv:
        res = normalize_url(raw)
        if res.ok:
            print(f"OK   | {raw} -> {res.normalized}")
        else:
            exit_code = 1
            print(f"FAIL | {raw} -> [{res.error_code}/{res.site_code}] {res.error_message}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
