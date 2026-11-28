-- Schema untuk id-scam-pipeline (Supabase PostgreSQL)

CREATE TABLE IF NOT EXISTS batches (
    id BIGSERIAL PRIMARY KEY,
    reviewer TEXT NOT NULL,
    url_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS urls (
    id BIGSERIAL PRIMARY KEY,
    raw_url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    final_url TEXT,
    final_normalized_url TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    status TEXT NOT NULL DEFAULT 'new',
    http_status INTEGER,
    page_title TEXT,
    clean_text TEXT,
    screenshot_path TEXT,
    ai_category TEXT,
    ai_confidence REAL,
    ai_note TEXT,
    submit_mode TEXT NOT NULL DEFAULT 'batch',
    judge_reason TEXT,
    locked_by TEXT,
    locked_at TIMESTAMPTZ,
    reviewed_by TEXT,
    reviewed_at TIMESTAMPTZ,
    batch_id BIGINT REFERENCES batches(id) ON DELETE SET NULL,
    error_code TEXT,
    error_detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (normalized_url)
);

-- Safe idempotent migration for existing Supabase instances.
ALTER TABLE public.urls ADD COLUMN IF NOT EXISTS submit_mode TEXT NOT NULL DEFAULT 'batch';
ALTER TABLE public.urls ADD COLUMN IF NOT EXISTS judge_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_urls_status ON urls (status);
CREATE INDEX IF NOT EXISTS idx_urls_batch_id ON urls (batch_id);
CREATE INDEX IF NOT EXISTS idx_urls_export_ready
    ON urls (reviewed_at, id)
    WHERE status = 'approved' AND batch_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_urls_locked_by
    ON urls (locked_by)
    WHERE locked_by IS NOT NULL;

-- Aktifkan RLS agar tabel di schema public tidak terbuka ke anon/authenticated secara default
-- (backend pipeline mengakses lewat service_role yang otomatis bypass RLS).
ALTER TABLE batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE urls ENABLE ROW LEVEL SECURITY;

-- Atomic reviewer lock: klaim 1 URL spesifik atau antrean berikutnya (urut ai_confidence tertinggi).
CREATE OR REPLACE FUNCTION public.claim_url_for_review(
    p_reviewer TEXT,
    p_url_id BIGINT DEFAULT NULL,
    p_statuses TEXT[] DEFAULT ARRAY['ai_scored', 'triaged', 'verified'],
    p_ttl_minutes INTEGER DEFAULT 5
)
RETURNS SETOF public.urls
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
DECLARE
    v_id BIGINT;
    v_ttl INTERVAL := make_interval(mins => GREATEST(1, COALESCE(p_ttl_minutes, 5)));
BEGIN
    IF p_reviewer IS NULL OR btrim(p_reviewer) = '' THEN
        RAISE EXCEPTION 'p_reviewer is required';
    END IF;

    IF p_url_id IS NOT NULL THEN
        SELECT u.id INTO v_id
        FROM public.urls u
        WHERE u.id = p_url_id
          AND (
              u.locked_by IS NULL
              OR u.locked_by = p_reviewer
              OR u.locked_at < NOW() - v_ttl
          )
        FOR UPDATE SKIP LOCKED;
    ELSE
        SELECT u.id INTO v_id
        FROM public.urls u
        WHERE u.status = ANY(p_statuses)
          AND (
              u.locked_by IS NULL
              OR u.locked_by = p_reviewer
              OR u.locked_at < NOW() - v_ttl
          )
        ORDER BY u.ai_confidence DESC NULLS LAST, u.id ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED;
    END IF;

    IF v_id IS NULL THEN
        RETURN;
    END IF;

    RETURN QUERY
    UPDATE public.urls u
    SET locked_by = p_reviewer,
        locked_at = NOW(),
        updated_at = NOW()
    WHERE u.id = v_id
    RETURNING u.*;
END;
$$;

-- Atomic Export Next 20 Links: kembalikan final_normalized_url (jika redirect) dalam 1 transaksi.
CREATE OR REPLACE FUNCTION public.export_next_batch(
    p_reviewer TEXT,
    p_limit INTEGER DEFAULT 20
)
RETURNS TABLE (
    batch_id BIGINT,
    url_id BIGINT,
    normalized_url TEXT,
    ai_category TEXT,
    ai_note TEXT
)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
DECLARE
    v_batch_id BIGINT;
    v_ids BIGINT[];
    v_limit INTEGER := GREATEST(1, LEAST(COALESCE(p_limit, 20), 20));
BEGIN
    IF p_reviewer IS NULL OR btrim(p_reviewer) = '' THEN
        RAISE EXCEPTION 'p_reviewer is required';
    END IF;

    SELECT ARRAY(
        SELECT u.id
        FROM public.urls u
        WHERE u.status = 'approved'
          AND u.batch_id IS NULL
        ORDER BY u.reviewed_at ASC NULLS LAST, u.id ASC
        LIMIT v_limit
        FOR UPDATE SKIP LOCKED
    ) INTO v_ids;

    IF v_ids IS NULL OR array_length(v_ids, 1) IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO public.batches (reviewer, url_count)
    VALUES (btrim(p_reviewer), array_length(v_ids, 1))
    RETURNING id INTO v_batch_id;

    RETURN QUERY
    UPDATE public.urls u
    SET status = 'exported',
        batch_id = v_batch_id,
        locked_by = NULL,
        locked_at = NULL,
        updated_at = NOW()
    WHERE u.id = ANY(v_ids)
    RETURNING
        v_batch_id,
        u.id,
        COALESCE(u.final_normalized_url, u.normalized_url),
        u.ai_category,
        u.ai_note;
END;
$$;

REVOKE ALL ON FUNCTION public.claim_url_for_review(TEXT, BIGINT, TEXT[], INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_url_for_review(TEXT, BIGINT, TEXT[], INTEGER) TO service_role;

REVOKE ALL ON FUNCTION public.export_next_batch(TEXT, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.export_next_batch(TEXT, INTEGER) TO service_role;
