"""Minimal smoke test: DB (urls + UNIQUE dedupe) & Storage bucket 'screenshots'."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request


def _load_dotenv(path: Path = Path(".env")) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _req(method: str, url: str, key: str, data: bytes | None = None, headers: dict | None = None) -> tuple[int, bytes]:
    hdrs = {"apikey": key, "Authorization": f"Bearer {key}", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main() -> int:
    _load_dotenv()
    base = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_SERVICE_KEY", "")
    bucket = os.getenv("SUPABASE_STORAGE_BUCKET", "screenshots")
    if not base or not key or "your-supabase" in key:
        print("Set SUPABASE_URL dan SUPABASE_SERVICE_KEY di .env terlebih dahulu.", file=sys.stderr)
        return 1

    # 1. Uji koneksi DB + UNIQUE(normalized_url)
    url_row = json.dumps({"raw_url": "https://example.id/?smoke=1", "normalized_url": "smoke-test.example.id", "status": "pending"}).encode()
    st1, body1 = _req("POST", f"{base}/rest/v1/urls", key, url_row, {"Content-Type": "application/json", "Prefer": "return=representation"})
    assert st1 == 201, f"Insert gagal ({st1}): {body1.decode()}"

    st2, _ = _req("POST", f"{base}/rest/v1/urls", key, url_row, {"Content-Type": "application/json"})
    assert st2 == 409, f"Expected 409 duplicate UNIQUE(normalized_url), got {st2}"

    st3, _ = _req("DELETE", f"{base}/rest/v1/urls?normalized_url=eq.smoke-test.example.id", key)
    assert st3 in (200, 204), f"Cleanup DB gagal ({st3})"
    print("DB OK: insert, UNIQUE(normalized_url) conflict (409), & cleanup berhasil.")

    # 2. Uji upload file dummy ke Storage bucket 'screenshots'
    obj_url = f"{base}/storage/v1/object/{bucket}/_smoke_test_dummy.txt"
    st4, body4 = _req("POST", obj_url, key, b"dummy screenshot test", {"Content-Type": "text/plain", "x-upsert": "true"})
    assert st4 == 200, f"Upload dummy gagal ({st4}): {body4.decode()}"

    st5, body5 = _req("GET", obj_url, key)
    assert st5 == 200 and body5 == b"dummy screenshot test", f"Download dummy gagal ({st5})"

    st6, _ = _req("DELETE", obj_url, key)
    assert st6 in (200, 204), f"Cleanup storage gagal ({st6})"
    print(f"STORAGE OK: upload, read-back, & cleanup dummy di bucket '{bucket}' berhasil.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
