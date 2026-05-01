# rag-api

A Retrieval-Augmented Generation (RAG) API built with FastAPI, Postgres + pgvector, sentence-transformers, and Anthropic's Claude.

**Status:** Phase 1 (MVP) — in progress.

## What it does

Ingests documents, chunks and embeds them into a vector database, then answers questions by retrieving relevant chunks and feeding them to an LLM.

## Stack

| Layer | Choice |
|---|---|
| API | FastAPI (Python 3.11) |
| Embeddings | sentence-transformers/all-MiniLM-L6-v2 (local, 384-dim) |
| Vector DB | Postgres 16 + pgvector |
| LLM | Anthropic Claude |
| Container | Docker Compose |
| Auth | Bearer token (env-loaded) |

## Quick start (coming after Step 2)

```bash
cp .env.example .env       # then edit values
docker compose up --build
curl -H "Authorization: Bearer $API_KEY" http://localhost:8000/health
```

## Endpoints

- `POST /ingest` — chunk + embed + store a document
- `POST /query` — ask a question, get answer + sources
- `GET  /health` — DB + model readiness
- `GET  /docs` — auto-generated OpenAPI

## Security notes

(Phase 2 will add: rate limiting, prompt injection defense, PII redaction, audit logging.)

## License

MIT (will be added before publish).
