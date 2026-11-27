# id-scam-pipeline

Passive discovery, sandboxed verification, deduplication, and human-in-the-loop triage pipeline for **Hackathon Berantas Web Ilegal di Indo** (IMPHNEN, 5-10 Dec 2026 WIB).

Built to report live Indonesian illegal websites (online gambling, unlicensed loans, phishing, and digital scams) safely, legally, and at high precision.

## Architecture

```text
[1. Discovery]      Passive public feeds (CertStream/crt.sh, URLhaus, OpenPhish, CSV dorks)
        |
        v
[2. Normalizer]     Exact 1:1 port of imphnen.dev URL rules -> Supabase PostgreSQL (UNIQUE dedupe)
        |
        v
[3. Verifier]       Docker + Playwright Chromium (non-root, downloads off, 15s timeout)
        |           Saves clean text (<= 2000 chars) and JPEG screenshots to Supabase Storage
        v
[4. AI Triage]      DeepSeek classifier (category, confidence, 140-char note) with manual fallback
        |
        v
[5. Review UI]      FastAPI gallery for 3 reviewers (keyboard A/N/X + atomic Copy Next 20 Links)
```

## Tech Stack

| Layer | Tools |
| :--- | :--- |
| Language | Python 3.10+ |
| Discovery (passive) | `httpx`, `websockets`, `dnspython` |
| Sandboxed verification | Docker, Playwright (Chromium), `beautifulsoup4` |
| Database & storage | Supabase (PostgreSQL + Storage bucket) |
| AI classification | DeepSeek via `openai` Python SDK |
| Review dashboard | FastAPI, Jinja2, plain HTML/JS |
| Testing | `unittest` / `pytest` |

## Project Structure

```text
id-scam-pipeline/
├── src/            # Pipeline modules (normalizer, discovery, verifier, AI triage, dashboard)
├── tests/          # Unit and integration tests
├── .env.example    # Environment variable template
├── requirements.txt
└── LICENSE
```

## Quickstart

```bash
# 1. Clone and enter the repository
git clone https://github.com/goldendev26/id-scam-pipeline.git
cd id-scam-pipeline

# 2. Create a local environment file
cp .env.example .env

# 3. Run normalizer unit tests (no external packages required)
python3 -m unittest discover -s tests -v

# 4. Test URLs directly from the CLI
python3 -m src.normalizer "https://www.TokoBudi.id/?utm=ig#promo" "tokobudi.id/Produk"
```

To install the full pipeline dependencies inside a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Legal and Safety Scope

This repository is strictly **passive and read-only**:
- No vulnerability scanning, port scanning, exploitation, brute-forcing, or DDoS.
- No logging in, registering accounts, submitting personal data, or depositing money on target sites.
- No automated form-posting to `imphnen.dev` without written organizer permission; batches of 20 verified links are copied and submitted manually through the official web form.
- Suspicious pages are opened only inside an isolated Docker container with downloads disabled.

## License

MIT License. See [LICENSE](LICENSE).
