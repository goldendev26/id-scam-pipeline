"""Passive public threat feed collector & CSV/TXT dork importer.

Sources (100% passive and public):
- OpenPhish live phishing feed
- Phishing.Database active-today feed
- Manual CSV or plain-text dork exports (e.g., hacked .ac.id/.sch.id/.go.id pages)

All URLs are normalized via `src.normalizer` before entering Supabase.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
from dataclasses import asdict, dataclass
import io
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from src.cert_collector import (
    JUDOL_KEYWORDS,
    PINJOL_KEYWORDS,
    classify_domain,
    is_official_domain,
)
from src.normalizer import normalize_url

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
PHISHING_DB_TODAY_URL = (
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
    "master/phishing-links-ACTIVE-today.txt"
)

INDONESIAN_TLDS: Tuple[str, ...] = (
    ".id",
    ".co.id",
    ".my.id",
    ".biz.id",
    ".web.id",
    ".or.id",
    ".ac.id",
    ".sch.id",
    ".go.id",
    ".desa.id",
)

HACKED_TARGET_TLDS: Tuple[str, ...] = (
    ".ac.id",
    ".sch.id",
    ".go.id",
    ".desa.id",
    ".or.id",
)

PATH_JUDOL_MARKERS: Tuple[str, ...] = (
    "slot",
    "gacor",
    "judol",
    "togel",
    "maxwin",
    "sbobet",
    "mahjong",
    "olympus",
    "zeus",
    "pragmatic",
    "rtp-slot",
    "rtp_slot",
    "bandar",
    "sabung",
    "scatter",
    "deposit",
)

PATH_PINJOL_MARKERS: Tuple[str, ...] = (
    "pinjol",
    "pinjaman",
    "danacepat",
    "kreditcepat",
    "caircepat",
)

PATH_PHISH_MARKERS: Tuple[str, ...] = (
    "brimo",
    "klikbca",
    "mybca",
    "livin",
    "dana-kaget",
    "danakaget",
    "bansos",
    "kemensos",
    "verifikasi-bri",
    "verifikasi-bca",
    "tarif-bri",
    "kurir-paket",
    "unduh-apk",
)

_URL_EXTRACT_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


@dataclass(frozen=True)
class DiscoveredCandidate:
    normalized_url: str
    raw_url: str
    source: str
    category_hint: Optional[str] = None
    matched_rule: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _has_indonesian_tld(host: str) -> bool:
    lowered = host.lower()
    return any(lowered.endswith(tld) for tld in INDONESIAN_TLDS)


def _is_hacked_institution_tld(host: str) -> bool:
    lowered = host.lower()
    return any(lowered.endswith(tld) for tld in HACKED_TARGET_TLDS)


def classify_feed_url(
    raw_url: str,
    *,
    source: str,
    indonesia_only: bool = True,
) -> Optional[DiscoveredCandidate]:
    """Normalize a candidate URL and check Indonesian illegal-site relevance."""
    norm = normalize_url(raw_url)
    if not norm.ok or not norm.normalized:
        return None

    normalized = norm.normalized
    parts = normalized.split("/", 1)
    host = parts[0]
    path = ("/" + parts[1]).lower() if len(parts) > 1 else ""
    compact_path = path.replace("-", "").replace("_", "")

    if is_official_domain(host) and not path:
        return None

    dom_hit = classify_domain(host)
    if dom_hit is not None:
        _, cat, rule = dom_hit
        return DiscoveredCandidate(
            normalized_url=normalized,
            raw_url=raw_url.strip(),
            source=source,
            category_hint=cat,
            matched_rule=rule,
        )

    for kw in PATH_JUDOL_MARKERS + JUDOL_KEYWORDS:
        if kw in path or kw in compact_path:
            if not indonesia_only or _has_indonesian_tld(host) or kw in JUDOL_KEYWORDS:
                return DiscoveredCandidate(
                    normalized_url=normalized,
                    raw_url=raw_url.strip(),
                    source=source,
                    category_hint="judol",
                    matched_rule=f"path:{kw}",
                )

    for kw in PATH_PINJOL_MARKERS + PINJOL_KEYWORDS:
        if kw in path or kw in compact_path:
            return DiscoveredCandidate(
                normalized_url=normalized,
                raw_url=raw_url.strip(),
                source=source,
                category_hint="pinjol",
                matched_rule=f"path:{kw}",
            )

    for kw in PATH_PHISH_MARKERS:
        if kw in path or kw in compact_path:
            return DiscoveredCandidate(
                normalized_url=normalized,
                raw_url=raw_url.strip(),
                source=source,
                category_hint="phishing",
                matched_rule=f"path:{kw}",
            )

    if source in ("openphish", "phishing_db", "urlhaus"):
        if _has_indonesian_tld(host) and (not is_official_domain(host) or bool(path)):
            cat = "phishing" if source in ("openphish", "phishing_db") else "scam"
            return DiscoveredCandidate(
                normalized_url=normalized,
                raw_url=raw_url.strip(),
                source=source,
                category_hint=cat,
                matched_rule=f"{source}:id_tld",
            )
        if not indonesia_only:
            cat = "phishing" if source in ("openphish", "phishing_db") else "scam"
            return DiscoveredCandidate(
                normalized_url=normalized,
                raw_url=raw_url.strip(),
                source=source,
                category_hint=cat,
                matched_rule=f"{source}:global",
            )

    if source == "dork_import":
        cat_hint = "judol" if _is_hacked_institution_tld(host) and path else None
        return DiscoveredCandidate(
            normalized_url=normalized,
            raw_url=raw_url.strip(),
            source=source,
            category_hint=cat_hint,
            matched_rule="dork:manual",
        )

    return None


def parse_feed_lines(
    lines: Iterable[str],
    *,
    source: str,
    indonesia_only: bool = True,
    limit: Optional[int] = 100,
    seen: Optional[Set[str]] = None,
) -> List[DiscoveredCandidate]:
    """Parse newline-delimited public feed text into deduped DiscoveredCandidate items."""
    dedupe = seen if seen is not None else set()
    results: List[DiscoveredCandidate] = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        cand = classify_feed_url(line, source=source, indonesia_only=indonesia_only)
        if cand is None or cand.normalized_url in dedupe:
            continue
        dedupe.add(cand.normalized_url)
        results.append(cand)
        if limit is not None and len(results) >= limit:
            break
    return results


def parse_dork_text(
    text: str,
    *,
    source: str = "dork_import",
    seen: Optional[Set[str]] = None,
) -> List[DiscoveredCandidate]:
    """Extract, normalize, and dedupe URLs from plain text or CSV dork exports."""
    dedupe = seen if seen is not None else set()
    raw_candidates: List[str] = []

    stripped = text.strip()
    if not stripped:
        return []

    first_line = stripped.splitlines()[0].lower()
    is_csv_like = ("," in first_line or "\t" in first_line) and any(
        col in first_line for col in ("url", "link", "domain", "href")
    )

    if is_csv_like:
        dialect = csv.excel_tab if "\t" in first_line and "," not in first_line else csv.excel
        reader = csv.DictReader(io.StringIO(stripped), dialect=dialect)
        for row in reader:
            for key, val in row.items():
                if not val:
                    continue
                k = (key or "").strip().lower()
                if k in ("url", "link", "domain", "href", "raw_url", "normalized_url"):
                    raw_candidates.append(val.strip())
                else:
                    raw_candidates.extend(_URL_EXTRACT_RE.findall(val))
    else:
        for line in stripped.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            found = _URL_EXTRACT_RE.findall(clean)
            if found:
                raw_candidates.extend(found)
            elif " " not in clean and "." in clean:
                raw_candidates.append(clean)

    results: List[DiscoveredCandidate] = []
    for raw in raw_candidates:
        cand = classify_feed_url(raw, source=source, indonesia_only=False)
        if cand is None or cand.normalized_url in dedupe:
            continue
        dedupe.add(cand.normalized_url)
        results.append(cand)
    return results


def load_dork_file(path: Path, *, source: str = "dork_import") -> List[DiscoveredCandidate]:
    return parse_dork_text(path.read_text(encoding="utf-8", errors="ignore"), source=source)


async def fetch_phishing_db(
    limit: Optional[int] = 100,
    indonesia_only: bool = True,
    timeout_s: float = 20.0,
    seen: Optional[Set[str]] = None,
) -> List[DiscoveredCandidate]:
    """Fetch active today phishing URLs from Phishing.Database public GitHub feed."""
    import httpx

    headers = {"User-Agent": "id-scam-pipeline/0.1 (passive threat feed)"}
    async with httpx.AsyncClient(timeout=timeout_s, headers=headers, follow_redirects=True) as client:
        resp = await client.get(PHISHING_DB_TODAY_URL)
        resp.raise_for_status()
        return parse_feed_lines(
            resp.text.splitlines(),
            source="phishing_db",
            indonesia_only=indonesia_only,
            limit=limit,
            seen=seen,
        )


async def fetch_openphish(
    limit: Optional[int] = 100,
    indonesia_only: bool = True,
    timeout_s: float = 20.0,
    seen: Optional[Set[str]] = None,
) -> List[DiscoveredCandidate]:
    """Fetch live phishing URLs from public OpenPhish text feed."""
    import httpx

    headers = {"User-Agent": "id-scam-pipeline/0.1 (passive threat feed)"}
    async with httpx.AsyncClient(timeout=timeout_s, headers=headers, follow_redirects=True) as client:
        resp = await client.get(OPENPHISH_FEED_URL)
        resp.raise_for_status()
        return parse_feed_lines(
            resp.text.splitlines(),
            source="openphish",
            indonesia_only=indonesia_only,
            limit=limit,
            seen=seen,
        )


async def fetch_all_feeds(
    limit_per_feed: Optional[int] = 100,
    indonesia_only: bool = True,
    timeout_s: float = 20.0,
    verbose: bool = False,
) -> List[DiscoveredCandidate]:
    """Fetch OpenPhish and Phishing.Database concurrently with per-feed fault isolation."""
    seen: Set[str] = set()
    merged: List[DiscoveredCandidate] = []

    async def _safe_fetch(name: str, coro: Any) -> List[DiscoveredCandidate]:
        try:
            items = await coro
            if verbose:
                print(f"[discover:{name}] matched={len(items)}", file=sys.stderr, flush=True)
            return items
        except Exception as exc:
            if verbose:
                print(f"[discover:{name}] error: {exc}", file=sys.stderr, flush=True)
            return []

    batches = await asyncio.gather(
        _safe_fetch("openphish", fetch_openphish(limit=limit_per_feed, indonesia_only=indonesia_only, timeout_s=timeout_s)),
        _safe_fetch("phishing_db", fetch_phishing_db(limit=limit_per_feed, indonesia_only=indonesia_only, timeout_s=timeout_s)),
    )
    for batch in batches:
        for item in batch:
            if item.normalized_url in seen:
                continue
            seen.add(item.normalized_url)
            merged.append(item)
    return merged


def _save_to_db(candidates: Sequence[DiscoveredCandidate]) -> int:
    from src.db import SupabaseDB

    rows = [
        {
            "raw_url": c.raw_url if c.raw_url.startswith(("http://", "https://")) else f"https://{c.normalized_url}",
            "source": c.source,
            "ai_category": c.category_hint,
            "ai_note": f"Feed match: {c.matched_rule}"[:140] if c.matched_rule else None,
        }
        for c in candidates
    ]
    if not rows:
        return 0
    with SupabaseDB.from_env() as db:
        inserted = db.insert_urls(rows, source="feed", status="new")
    return len(inserted)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m src.discover",
        description="Passive threat feed collector (OpenPhish, PhishingDB) and CSV/TXT dork importer.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_feeds = sub.add_parser("feeds", help="Fetch Indonesian threats from OpenPhish and PhishingDB.")
    p_feeds.add_argument("--limit", type=int, default=100, help="Max items per feed (default: 100).")
    p_feeds.add_argument("--include-global", action="store_true", help="Include non-Indonesian feed entries.")
    p_feeds.add_argument("--save-db", action="store_true", help="Insert matched URLs into Supabase.")

    p_dork = sub.add_parser("import-dorks", help="Import URLs from a manual CSV or TXT dork export.")
    p_dork.add_argument("file", type=Path, help="Path to CSV or TXT file.")
    p_dork.add_argument("--source", default="dork_import", help="Source tag stored in DB.")
    p_dork.add_argument("--save-db", action="store_true", help="Insert matched URLs into Supabase.")

    args = parser.parse_args(argv)
    if args.command == "feeds":
        items = asyncio.run(
            fetch_all_feeds(
                limit_per_feed=args.limit,
                indonesia_only=not args.include_global,
                verbose=True,
            )
        )
    else:
        items = load_dork_file(args.file, source=args.source)

    for item in items:
        print(json.dumps(item.to_dict(), ensure_ascii=False))

    if args.save_db:
        inserted = _save_to_db(items)
        print(f"[discover] inserted={inserted} new rows into Supabase", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
