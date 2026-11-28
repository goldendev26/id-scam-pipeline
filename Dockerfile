FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY scripts/ ./scripts/
COPY templates/ ./templates/
COPY tests/ ./tests/

RUN chown -R pwuser:pwuser /app

# Run browser verification as non-root (NFR-SEC-001)
USER pwuser

ENTRYPOINT ["python3", "-m", "src.verify"]
