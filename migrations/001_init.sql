-- ============================================================================
-- 001_init.sql — initial schema for rag-api
--
-- Auto-runs ONCE on first boot of the postgres container, because the
-- migrations/ folder is mounted to /docker-entrypoint-initdb.d (see compose).
-- If you change this file, you must wipe the postgres volume to re-trigger:
--     docker compose down -v
--
-- Why one table instead of documents + chunks?
--   For Phase 1 each row IS a chunk. source + chunk_index are denormalized
--   onto every row. Cheap; avoids a JOIN on every retrieval. Revisit if
--   we add multi-tenancy or large per-doc metadata in Phase 2.
-- ============================================================================

-- pgvector ships with the pgvector/pgvector:pg16 image but the extension is
-- not enabled by default in the database. CREATE EXTENSION wires it in so
-- the `vector` type and `<=>`, `<->`, `<#>` operators become available.
CREATE EXTENSION IF NOT EXISTS vector;

-- ----------------------------------------------------------------------------
-- documents
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS documents (
    id           BIGSERIAL PRIMARY KEY,                  -- auto-increment, room to grow
    source       TEXT        NOT NULL,                   -- filename, URL, or upload id
    chunk_index  INT         NOT NULL,                   -- 0-based order within source
    content      TEXT        NOT NULL,                   -- the chunk text, fed to LLM at query time
    embedding    vector(384) NOT NULL,                   -- MiniLM-L6-v2 output dim. Must match EMBEDDING_DIM env.
    metadata     JSONB       NOT NULL DEFAULT '{}'::jsonb, -- escape hatch: page_num, tenant_id, mime, etc.
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- A given (source, chunk_index) pair must be unique. Re-ingesting a doc
    -- without first deleting old rows would otherwise duplicate chunks.
    CONSTRAINT documents_source_chunk_uq UNIQUE (source, chunk_index)
);

-- ----------------------------------------------------------------------------
-- HNSW vector index (cosine distance)
--
-- Why HNSW: graph-based ANN, no training step, works on empty tables, best
-- recall/speed tradeoff for <10M vectors. Cosine because we're using sentence
-- embeddings — magnitude doesn't carry meaning, only direction does.
--
-- Why a separate index instead of relying on the seq scan: at >a few hundred
-- vectors a seq scan dominates query latency. HNSW gets us O(log n) lookups.
--
-- m / ef_construction are HNSW tuning knobs. Defaults (m=16, ef_construction=64)
-- are fine for portfolio scale. Bump ef_construction for higher recall at
-- index-build time; bump ef_search at query time for higher recall per query.
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS documents_embedding_hnsw_cos_idx
    ON documents
    USING hnsw (embedding vector_cosine_ops);

-- ----------------------------------------------------------------------------
-- Lookup index on source — for delete-by-source and re-ingest workflows.
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS documents_source_idx ON documents (source);
