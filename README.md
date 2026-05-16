# rag-api

A Retrieval-Augmented Generation (RAG) API built with FastAPI, Postgres + pgvector, sentence-transformers, and Anthropic's Claude.

**Status:** Phase 2 Step 2 shipped — per-key rate limiting on top of per-tenant API keys.

## What it does

Ingests documents (text or PDF), chunks and embeds them into a Postgres vector database via pgvector, then answers questions by retrieving the most semantically similar chunks and either returning them raw or feeding them to Claude for a synthesized answer.

## Stack

| Layer | Choice |
|---|---|
| API | FastAPI (Python 3.11) |
| Embeddings | sentence-transformers/all-MiniLM-L6-v2 (local, 384-dim) |
| Vector DB | Postgres 16 + pgvector with HNSW cosine index |
| LLM | Anthropic Claude (claude-sonnet-4-5 by default) |
| Container | Docker Compose, native ARM64 on Apple Silicon |
| Auth | Per-tenant bearer keys: SHA-256 hashed in `api_keys` table, indexed lookup, soft-delete revocation |
| Rate limit | In-memory fixed-window counter, per `key_id`, env-tunable (default 60 req / 60 s) |

## Quick start

```bash
cp .env.example .env
# Add your Anthropic key (only needed for /query/answer):
# ANTHROPIC_API_KEY=sk-ant-api03-...

docker compose up --build -d
curl http://localhost:8000/health

# Mint a per-tenant key (Phase 2):
docker compose exec api python -m scripts.issue_key --tenant my-tenant
# Copy the printed `token: rk_...` value — it cannot be recovered.
```

## Endpoints

All routes except `/health` require `Authorization: Bearer <API_KEY>`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness probe (public) |
| POST | `/ingest` | JSON body: `{source, text, metadata?}` |
| POST | `/ingest/file` | Multipart upload (PDF or text/plain, 10MB cap) |
| POST | `/query/retrieve` | Top-K chunks by cosine similarity, no LLM tokens spent |
| POST | `/query/answer` | Top-K retrieval + Claude synthesis with grounding |
| GET | `/docs` | Auto-generated OpenAPI |

### Example: ingest then ask

```bash
API_KEY=$(grep ^API_KEY= .env | cut -d= -f2)

curl -s -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"source":"my-doc","text":"The quick brown fox jumps over the lazy dog."}'

curl -s -X POST http://localhost:8000/query/retrieve \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"question":"What animal jumped?","top_k":3}'
```

## Smoke test

End-to-end test that exercises auth, ingestion, retrieval, and (optionally) synthesis.

```bash
chmod +x tests/smoke.sh
./tests/smoke.sh
```

Skips the Anthropic call by default (so it costs zero tokens). To exercise the full synthesis path:

```bash
SMOKE_TEST_ANTHROPIC=1 ./tests/smoke.sh
```

The script is idempotent. It uses a fixed source name (`smoke-test-fixture`) and the API's DELETE-by-source re-ingest semantics, so re-running does not pollute the documents table.

## Security posture

### Phase 2 Step 2 — Per-key rate limiting (Sec+ domain: Availability / DoS, IAM abuse containment)

- Fixed-window counter, in-memory, keyed by `api_keys.id`. Default: `RATE_LIMIT_REQUESTS=60` requests per `RATE_LIMIT_WINDOW_SECONDS=60` seconds, both env-tunable.
- Lives in `app/security/ratelimit.py` as a FastAPI dependency (`enforce_rate_limit`) that wraps `verify_api_key`. The dep chain is auth → rate check → handler; an unauthenticated request never consumes a slot.
- 429 responses include `Retry-After: <seconds-until-window-end>` per RFC 9110 §10.2.3.
- Thread-safety: dict mutation is serialized with `threading.Lock`. FastAPI sync handlers run in a worker thread pool, so this is the correct primitive for our concurrency model. The lock prevents a TOCTOU race where two simultaneous requests both read `count=59` and both increment to 60 — i.e. the limit becomes meaningless under load.
- Clock source is `time.monotonic()`, not wall clock. Window math survives NTP correction and DST shifts.

**Known limitations (intentional, documented for Phase 3 swap):**

1. **In-memory state** — counters reset on container restart and are not shared across replicas. Single-container portfolio deploy is fine; horizontal scale is not. Phase 3 swaps to Redis.
2. **Boundary burst** — a fixed-window limiter can let a client fire up to 2x the stated limit across a window edge (e.g. burst at `:59.5` + burst at `:00.5`). Sliding window or token bucket fixes this; deferred to Phase 3.
3. **Unbounded bucket dict** — one entry per unique `key_id` seen, never reaped. For portfolio scope this is bounded by the number of issued keys. Phase 3 adds LRU eviction.

### Phase 2 Step 1 — Per-tenant API keys (Sec+ domain: IAM, least privilege)

- Bearer tokens are 256-bit URL-safe random (`secrets.token_urlsafe(32)`) with an `rk_` brand prefix for secret-scanner matching (GitHub, TruffleHog, gitleaks pattern).
- Tokens are stored as SHA-256 hex digests in the `api_keys` table. A DB breach yields unusable digests, not live tokens.
- Lookup is `WHERE key_hash = $1` against a UNIQUE btree index — O(log n) and side-channel free.
- Revocation is soft-delete via `revoked_at` timestamp. Audit-log entries that reference a revoked key still resolve.
- Both "unknown key" and "revoked key" return the same generic `401 "Invalid API key."` message — defeats key-enumeration probing.
- `key_prefix` (first 11 chars of the cleartext) is the only log-safe identifier. Never log the cleartext token or the digest.
- Admin CLI: `docker compose exec api python -m scripts.issue_key --tenant <id> [--revoke <prefix>] [--list-tenant]`.

### Phase 1 baseline

- `Authorization: Bearer <key>` per RFC 6750. Never accept the key in URL params (URL params leak via access logs, browser history, Referer headers).
- `Authorization: Bearer <key>` per RFC 6750. Never accept the key in URL params (URL params leak via access logs, browser history, Referer headers).
- Server fails closed if `API_KEY` env is unset (returns 500, never bypasses auth).
- `/health` is intentionally unauthenticated so the Docker `HEALTHCHECK` works without baking the secret into the container.
- `WWW-Authenticate: Bearer` header on all 401 responses per RFC 6750.
- Postgres has no published port: only reachable inside the Docker bridge network.
- Container runs as non-root user `app`. Multi-stage Docker build keeps the runtime image free of build tools.
- Bounded payloads: 10MB hard cap on file uploads, 2000 char cap on questions, 512 char cap on source IDs.
- MIME allowlist on file ingest (text/plain, application/pdf only). Never trusts file extension.

## Phase 2 roadmap

- [x] **Step 1**: Per-tenant API keys.
- [x] **Step 2**: Per-key rate limiting (this release).
- [ ] Step 3: PII redaction on `/ingest`.
- [ ] Step 4: Prompt injection defense.
- [ ] Step 5: Relevance threshold for "I don't know" responses.
- [ ] Step 6: Structured audit logging.
- [ ] Step 7: CI/CD via GitHub Actions.

## License

MIT (will be added before publish).
