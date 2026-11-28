"""DeepSeek AI triage via openai SDK + fallback 30-site web-chat batch prompt mode."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Any, Optional, Sequence

from src.db import SupabaseDB, load_dotenv

VALID_CATEGORIES = ("judol", "pinjol", "phishing", "scam", "benign", "unsure")
MAX_REASON_LEN = 140
DEFAULT_BATCH_SIZE = 30
DEFAULT_DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"

_SYSTEM_PROMPT = (
    "Kamu adalah analis keamanan siber Indonesia untuk hackathon pemberantasan situs ilegal. "
    "Klasifikasikan situs ke salah satu kategori: judol, pinjol, phishing, scam, benign, atau unsure. "
    "Balas HANYA JSON valid dengan field: "
    '{"category": "...", "confidence": 0.0-1.0, "reason_140": "alasan singkat maks 140 karakter"}.'
)

_BATCH_HEADER = (
    "Kamu adalah analis keamanan siber Indonesia. Klasifikasikan setiap situs pada daftar JSON di bawah "
    "ke kategori: judol | pinjol | phishing | scam | benign | unsure.\n"
    "Aturan wajib:\n"
    "- Balas HANYA JSON array valid tanpa teks tambahan.\n"
    '- Format tiap elemen: {"id": <id>, "normalized_url": "<url>", "category": "<kat>", '
    '"confidence": <0.0-1.0>, "reason_140": "<maks 140 karakter>"}\n'
    "- Pastikan urutan & jumlah elemen sama dengan input.\n\n"
    "Daftar situs:\n"
)

_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


@dataclass(frozen=True)
class TriageResult:
    category: str
    confidence: float
    reason_140: str
    url_id: Optional[int] = None
    normalized_url: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "category": self.category,
            "confidence": self.confidence,
            "reason_140": self.reason_140,
        }
        if self.url_id is not None:
            out["id"] = self.url_id
        if self.normalized_url is not None:
            out["normalized_url"] = self.normalized_url
        return out


def truncate_reason(text: str, max_len: int = MAX_REASON_LEN) -> str:
    """Collapse whitespace and enforce <= 140 character limit."""
    cleaned = " ".join(str(text or "").split())
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3].rstrip() + "..."


def normalize_triage_item(
    raw: dict[str, Any],
    *,
    default_url_id: Optional[int] = None,
    default_normalized_url: Optional[str] = None,
) -> TriageResult:
    """Validate and coerce raw LLM JSON into a strict TriageResult."""
    cat = str(raw.get("category", "unsure")).strip().lower()
    if cat not in VALID_CATEGORIES:
        cat = "unsure"

    try:
        conf = float(raw.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    conf = round(max(0.0, min(1.0, conf)), 3)

    reason_raw = raw.get("reason_140")
    if reason_raw is None:
        reason_raw = raw.get("reason") or raw.get("ai_note") or ""
    reason = truncate_reason(str(reason_raw), MAX_REASON_LEN)

    raw_id = raw.get("id", raw.get("url_id", default_url_id))
    url_id: Optional[int] = None
    if raw_id is not None and str(raw_id).strip() != "":
        try:
            url_id = int(raw_id)
        except (TypeError, ValueError):
            url_id = default_url_id

    norm_url = raw.get("normalized_url") or default_normalized_url
    return TriageResult(
        category=cat,
        confidence=conf,
        reason_140=reason,
        url_id=url_id,
        normalized_url=str(norm_url) if norm_url is not None else None,
    )


def _extract_json_payload(raw_text: str) -> Any:
    """Parse JSON from raw LLM output, stripping markdown fences or chatter."""
    text = raw_text.strip()
    if not text:
        raise ValueError("Respons LLM kosong.")

    fence = _CODE_FENCE_RE.search(text)
    if fence:
        text = fence.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    for open_ch, close_ch in (("[", "]"), ("{", "}")):
        start = text.find(open_ch)
        end = text.rfind(close_ch)
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue

    raise ValueError("Tidak ditemukan JSON valid pada respons LLM.")


def create_deepseek_client(
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Any:
    """Create an openai.OpenAI client pointed at DeepSeek's OpenAI-compatible API."""
    load_dotenv()
    resolved_key = (api_key or os.getenv("DEEPSEEK_API_KEY", "")).strip()
    resolved_url = (base_url or os.getenv("DEEPSEEK_BASE_URL", DEFAULT_DEEPSEEK_BASE_URL)).strip()
    if not resolved_key or "your-deepseek" in resolved_key:
        raise RuntimeError(
            "DEEPSEEK_API_KEY belum diset. Isi .env atau gunakan mode fallback: "
            "python -m src.ai_triage export-prompts"
        )
    from openai import OpenAI

    return OpenAI(api_key=resolved_key, base_url=resolved_url)


def triage_site(
    normalized_url: str,
    page_title: str = "",
    clean_text: str = "",
    *,
    client: Optional[Any] = None,
    model: Optional[str] = None,
    url_id: Optional[int] = None,
) -> TriageResult:
    """Classify one site via DeepSeek openai SDK and return strict TriageResult."""
    load_dotenv()
    sdk_client = client or create_deepseek_client()
    chosen_model = model or os.getenv("DEEPSEEK_MODEL", DEFAULT_DEEPSEEK_MODEL)

    user_payload = {
        "normalized_url": normalized_url,
        "page_title": (page_title or "")[:200],
        "clean_text": (clean_text or "")[:2000],
    }
    resp = sdk_client.chat.completions.create(
        model=chosen_model,
        temperature=0.0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
    )
    content = resp.choices[0].message.content or ""
    parsed = _extract_json_payload(content)
    if not isinstance(parsed, dict):
        raise ValueError("Output DeepSeek untuk triage tunggal harus berupa JSON object.")
    return normalize_triage_item(
        parsed,
        default_url_id=url_id,
        default_normalized_url=normalized_url,
    )


def export_batch_prompts(
    sites: Sequence[dict[str, Any]],
    batch_size: int = DEFAULT_BATCH_SIZE,
    snippet_chars: int = 350,
) -> list[str]:
    """Split sites into chunks of 30 and build ready-to-paste DeepSeek web-chat prompts."""
    if batch_size < 1:
        raise ValueError("batch_size harus >= 1")

    prompts: list[str] = []
    for offset in range(0, len(sites), batch_size):
        chunk = sites[offset : offset + batch_size]
        compact = [
            {
                "id": s.get("id"),
                "normalized_url": s.get("normalized_url") or s.get("final_normalized_url") or "",
                "page_title": " ".join(str(s.get("page_title") or "").split())[:140],
                "snippet": " ".join(str(s.get("clean_text") or "").split())[:snippet_chars],
            }
            for s in chunk
        ]
        prompts.append(_BATCH_HEADER + json.dumps(compact, ensure_ascii=False, indent=2))
    return prompts


def write_batch_prompts(
    sites: Sequence[dict[str, Any]],
    out_dir: Path,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> list[Path]:
    """Write 30-site web-chat prompts to numbered .txt files."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for idx, prompt in enumerate(export_batch_prompts(sites, batch_size=batch_size), start=1):
        target = out_dir / f"deepseek_batch_{idx:03d}.txt"
        target.write_text(prompt, encoding="utf-8")
        paths.append(target)
    return paths


def parse_batch_response(raw_text: str) -> list[TriageResult]:
    """Parse copy-pasted DeepSeek web-chat batch JSON into validated TriageResults."""
    parsed = _extract_json_payload(raw_text)
    if isinstance(parsed, dict):
        items = parsed.get("results") or parsed.get("items") or [parsed]
    elif isinstance(parsed, list):
        items = parsed
    else:
        raise ValueError("Format batch JSON harus berupa array atau object.")

    return [normalize_triage_item(item) for item in items if isinstance(item, dict)]


def import_batch_response(
    raw_text: str,
    db: Optional[Any] = None,
) -> list[TriageResult]:
    """Parse DeepSeek web-chat output and optionally persist results to Supabase."""
    results = parse_batch_response(raw_text)
    if db is not None:
        for res in results:
            if res.url_id is None:
                continue
            db.update_status(
                res.url_id,
                status="triaged",
                ai_category=res.category,
                ai_confidence=res.confidence,
                ai_note=res.reason_140,
            )
    return results


def _load_sites_source(input_path: Optional[Path], limit: int) -> list[dict[str, Any]]:
    if input_path is not None:
        data = json.loads(input_path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("File input JSON harus berupa list situs.")
        return data[:limit] if limit > 0 else data
    with SupabaseDB.from_env() as db:
        return db.fetch_queue(status="verified", limit=limit)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.ai_triage",
        description="DeepSeek AI triage (API SDK & fallback 30-site web-chat batch mode).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_api = sub.add_parser("api", help="Klasifikasi via DeepSeek openai SDK.")
    p_api.add_argument("--input", type=Path, default=None, help="JSON list situs (opsional; default ambil queue verified dari DB).")
    p_api.add_argument("--limit", type=int, default=30)
    p_api.add_argument("--save-db", action="store_true", help="Simpan hasil triage ke Supabase.")

    p_exp = sub.add_parser("export-prompts", help="Ekspor prompt batch (30 situs/file) untuk DeepSeek web-chat.")
    p_exp.add_argument("--input", type=Path, default=None, help="JSON list situs (opsional; default queue verified dari DB).")
    p_exp.add_argument("--out-dir", type=Path, default=Path("data/deepseek_prompts"))
    p_exp.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    p_exp.add_argument("--limit", type=int, default=300)

    p_imp = sub.add_parser("import-response", help="Impor jawaban JSON dari DeepSeek web-chat.")
    p_imp.add_argument("response_file", type=Path, help="File teks/JSON hasil copy-paste dari web-chat.")
    p_imp.add_argument("--save-db", action="store_true", help="Update baris urls di Supabase.")

    args = parser.parse_args(argv)

    if args.command == "api":
        sites = _load_sites_source(args.input, args.limit)
        client = create_deepseek_client()
        db = SupabaseDB.from_env() if args.save_db else None
        try:
            for site in sites:
                res = triage_site(
                    normalized_url=str(site.get("normalized_url") or site.get("final_normalized_url") or ""),
                    page_title=str(site.get("page_title") or ""),
                    clean_text=str(site.get("clean_text") or ""),
                    client=client,
                    url_id=site.get("id"),
                )
                if db is not None and res.url_id is not None:
                    db.update_status(
                        res.url_id,
                        status="triaged",
                        ai_category=res.category,
                        ai_confidence=res.confidence,
                        ai_note=res.reason_140,
                    )
                print(json.dumps(res.to_dict(), ensure_ascii=False))
        finally:
            if db is not None:
                db.close()
        return 0

    if args.command == "export-prompts":
        sites = _load_sites_source(args.input, args.limit)
        paths = write_batch_prompts(sites, args.out_dir, batch_size=args.batch_size)
        print(json.dumps({"sites": len(sites), "files": [str(p) for p in paths]}, ensure_ascii=False))
        return 0

    if args.command == "import-response":
        raw_text = args.response_file.read_text(encoding="utf-8")
        if args.save_db:
            with SupabaseDB.from_env() as db:
                results = import_batch_response(raw_text, db=db)
        else:
            results = import_batch_response(raw_text, db=None)
        print(json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
