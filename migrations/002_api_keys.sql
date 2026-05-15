-- ============================================================================
-- 002_api_keys.sql — per-tenant API keys (Phase 2 Step 1)
--
-- Replaces the single shared API_KEY env-var model from Phase 1 with a
-- table-backed multi-tenant key store. Each request's bearer token is
-- hashed (SHA-256) and looked up against `key_hash`.
--
-- Re-run note: migrations/ is mounted into /docker-entrypoint-initdb.d
-- and Postgres only executes those files on the FIRST boot of a volume.
-- To re-apply a changed migration locally:
--     docker compose down -v        # wipes the postgres volume
--     docker compose up -d --build  # re-initializes from migrations/
--
-- Why these columns:
--   tenant_id   caller-facing identity. Logged on every request once Step 6
--               (audit logging) lands. NOT used for auth — only key_hash is.
--   key_hash    SHA-256 hex digest of the bearer token. UNIQUE so a stolen
--               digest cannot be re-registered as a "second key" and so
--               lookup is O(log n) via the auto-created btree.
--   key_prefix  first 8 chars of the cleartext token, e.g. "rk_a3b9c4d2".
--               Safe to log (it identifies WHICH key, not WHAT the key is).
--               Pattern lifted from AWS access-key IDs.
--   revoked_at  NULL = active. Soft-delete instead of DROP so audit-log rows
--               tied to a revoked key still resolve. Set to now() to revoke.
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    TEXT        NOT NULL,
    key_hash     TEXT        NOT NULL UNIQUE,
    key_prefix   TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ DEFAULT NULL
);

-- ----------------------------------------------------------------------------
-- Secondary index on tenant_id — supports future "list all keys for tenant"
-- and per-tenant audit queries (Step 6). Cheap to add now, painful to add
-- later on a large table.
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys (tenant_id);
