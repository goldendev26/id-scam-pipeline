"""Simple mock submission portal simulating the hackathon organizer web form.

Run directly with:
    uvicorn src.mock_target:app --host 0.0.0.0 --port 8001
Or automatically alongside the dashboard via:
    docker compose build && docker compose up dashboard
"""

from __future__ import annotations

from datetime import datetime, timezone
import html
import json
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from src.normalizer import MAX_BATCH_ITEMS, normalize_url


def _render_page(
    submissions: list[dict[str, Any]],
    last_result: dict[str, Any] | None = None,
) -> str:
    banner = ""
    if last_result is not None:
        acc_json = html.escape(json.dumps(last_result["accepted"], ensure_ascii=False), quote=True)
        dup_json = html.escape(json.dumps(last_result["duplicates"], ensure_ascii=False), quote=True)
        banner = (
            f'<div class="notice" data-submit-status="ok" '
            f'data-accepted-json="{acc_json}" data-duplicates-json="{dup_json}">'
            f'<strong>Submission #{last_result["id"]} diterima</strong> — '
            f'Valid baru: <b>{len(last_result["accepted"])}</b>, '
            f'Sudah pernah dilaporkan: <b>{len(last_result["duplicates"])}</b>, '
            f'Tidak valid: <b>{len(last_result["invalid"])}</b>.'
            f"</div>"
        )

    rows_html = "".join(
        f"<tr>"
        f"<td class='mono'>#{s['id']}</td>"
        f"<td>{html.escape(s['reporter'])}</td>"
        f"<td class='mono'>{len(s['accepted'])} baru / {len(s['duplicates'])} dup</td>"
        f"<td class='mono'>{html.escape(', '.join(s['accepted'] or s['duplicates']))}</td>"
        f"<td class='muted'>{html.escape(s['created_at'])}</td>"
        f"</tr>"
        for s in reversed(submissions[-50:])
    ) or "<tr><td colspan='5' class='muted' style='text-align:center;'>Belum ada laporan masuk.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Mock Portal Pelaporan Panitia</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #fafafa; color: #09090b; margin: 0; padding: 24px; }}
    .wrap {{ max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 18px; }}
    .card {{ background: #fff; border: 1px solid rgba(9,9,11,0.1); border-radius: 10px; padding: 18px; }}
    h1 {{ margin: 0 0 4px; font-size: 18px; }}
    p.sub {{ margin: 0 0 14px; font-size: 13px; color: #52525b; }}
    label {{ display: block; font-size: 12px; font-weight: 600; margin-bottom: 4px; color: #3f3f46; }}
    input, textarea {{ width: 100%; box-sizing: border-box; border: 1px solid rgba(9,9,11,0.18); border-radius: 6px; padding: 8px 10px; font-size: 13px; margin-bottom: 12px; }}
    textarea {{ font-family: ui-monospace, Menlo, monospace; }}
    button {{ background: #09090b; color: #fafafa; border: 0; border-radius: 6px; padding: 9px 16px; font-size: 13px; font-weight: 600; cursor: pointer; }}
    button:hover {{ background: #27272a; }}
    .notice {{ padding: 12px 14px; border-radius: 8px; background: rgba(5,150,105,0.1); border: 1px solid rgba(5,150,105,0.3); color: #047857; font-size: 13px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
    th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid rgba(9,9,11,0.08); vertical-align: top; }}
    th {{ color: #71717a; font-weight: 600; font-size: 11px; text-transform: uppercase; }}
    .mono {{ font-family: ui-monospace, Menlo, monospace; word-break: break-all; }}
    .muted {{ color: #71717a; font-size: 11.5px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Mock Portal Pelaporan Web Ilegal (Simulasi Hari-H)</h1>
      <p class="sub">Form simulasi batch (maks {MAX_BATCH_ITEMS} link per kirim). Saat hari perlombaan, ganti <code>SUBMIT_TARGET_URL</code> di <code>.env</code>.</p>
      {banner}
      <form method="post" action="/submit" style="margin-top:12px;">
        <label for="reporter">Nama Tim / Pelapor</label>
        <input id="reporter" name="reporter" type="text" placeholder="tim-hackathon" value="member-1" />
        <label for="links">Daftar Link (1 URL per baris, maks {MAX_BATCH_ITEMS})</label>
        <textarea id="links" name="links" rows="8" required placeholder="slotcontoh88.id&#10;pinjol-ilegal.com/daftar"></textarea>
        <button type="submit">Kirim Laporan</button>
      </form>
    </div>

    <div class="card">
      <h2 style="margin:0 0 10px;font-size:14px;">Riwayat Laporan Masuk ({len(submissions)})</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Pelapor</th><th>Hasil</th><th>Link</th><th>Waktu (UTC)</th></tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </div>
</body>
</html>"""


def create_mock_app() -> FastAPI:
    mock = FastAPI(title="Mock Hackathon Submission Portal")
    # ponytail: in-memory state only; resets on container restart (staging mock, not production DB).
    seen_urls: set[str] = set()
    submissions: list[dict[str, Any]] = []

    @mock.get("/", response_class=HTMLResponse)
    def form_page() -> HTMLResponse:
        return HTMLResponse(_render_page(submissions))

    @mock.post("/submit", response_class=HTMLResponse)
    async def submit_form(request: Request) -> HTMLResponse:
        raw_body = (await request.body()).decode("utf-8", errors="ignore")
        parsed = parse_qs(raw_body, keep_blank_values=True)
        links_text = (parsed.get("links") or [""])[0]
        reporter = ((parsed.get("reporter") or ["anonymous"])[0]).strip() or "anonymous"

        raw_lines = [ln.strip() for ln in links_text.splitlines() if ln.strip()][:MAX_BATCH_ITEMS]
        accepted: list[str] = []
        duplicates: list[str] = []
        invalid: list[str] = []

        for raw in raw_lines:
            norm = normalize_url(raw)
            if not norm.ok or not norm.normalized:
                invalid.append(raw)
                continue
            if norm.normalized in seen_urls:
                duplicates.append(norm.normalized)
            else:
                seen_urls.add(norm.normalized)
                accepted.append(norm.normalized)

        record = {
            "id": len(submissions) + 1,
            "reporter": reporter,
            "accepted": accepted,
            "duplicates": duplicates,
            "invalid": invalid,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        }
        submissions.append(record)
        return HTMLResponse(_render_page(submissions, last_result=record))

    @mock.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @mock.get("/api/submissions")
    def api_submissions() -> dict[str, Any]:
        return {"total_submissions": len(submissions), "unique_links": len(seen_urls), "submissions": submissions}

    @mock.post("/api/reset")
    def api_reset() -> dict[str, str]:
        seen_urls.clear()
        submissions.clear()
        return {"status": "reset"}

    return mock


app = create_mock_app()
