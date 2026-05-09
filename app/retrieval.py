"""
Vector retrieval — the "R" in RAG.

Given a natural-language question, find the top-K chunks from `documents`
whose embeddings are closest to the question's embedding under cosine
distance.

Why cosine (not Euclidean L2):
- Sentence-transformer embeddings are length-normalized. With normalized
  vectors, cosine distance and L2 distance are monotonically related, but
  cosine is the convention for sentence embeddings and gives intuitive
  scores in [0, 2]: 0 = identical direction, 1 = orthogonal, 2 = opposite.
- pgvector exposes cosine via the `<=>` operator. The HNSW index built in
  Step 3 was created with `vector_cosine_ops`, so this operator hits the
  index path; using `<#>` (negative inner product) or `<->` (L2) would
  fall back to a Seq Scan.

Why a separate module (not in main.py):
- Same separation rationale as db.py / embeddings.py: routing layer
  (FastAPI handlers) calls into a clean library layer. Lets us unit-test
  retrieval without standing up the HTTP stack, and keeps main.py thin.

Step 5 design choices (locked 2026-05-06):
- Top-K: env default `TOP_K=5`, optional per-request override.
- No distance threshold filtering in Phase 1 — return raw scores so we
  can calibrate a threshold in Phase 2.
"""

import os
from dataclasses import dataclass

from app.db import get_conn
from app.embeddings import encode


@dataclass
class RetrievedChunk:
    """One row from the top-K result set."""
    source: str            # canonical doc id (e.g. "kickoff.pdf")
    chunk_text: str        # the chunk content shown to the user / LLM
    distance: float        # cosine distance, lower = more similar


def _resolve_top_k(top_k_override: int | None) -> int:
    """
    Pick the effective K.

    Per-request override wins when provided. Otherwise fall back to
    `TOP_K` from the environment (set in .env, defaulted to 5 in
    .env.example). KeyError on missing env var is intentional —
    fail loudly at retrieval time rather than ship a silent default.
    """
    if top_k_override is not None:
        if top_k_override < 1 or top_k_override > 50:
            raise ValueError(
                f"top_k must be between 1 and 50, got {top_k_override}"
            )
        return top_k_override
    return int(os.environ["TOP_K"])


def retrieve(
    question: str,
    top_k: int | None = None,
) -> list[RetrievedChunk]:
    """
    Retrieve the top-K chunks most similar to `question`.

    Pipeline:
        1. Embed the question via the same model used for ingestion.
           Same-model encoding is non-negotiable: query-side and doc-side
           vectors must live in the same space or cosine distance is
           meaningless.
        2. Run a single SQL with pgvector's cosine `<=>` operator and
           ORDER BY ... LIMIT. The HNSW index handles the heavy lifting.
        3. Return distance scores alongside the chunks so the caller
           (or Phase 2 threshold logic) can reason about confidence.

    Empty DB returns []. No semantic match still returns top_k rows
    (with high distance values) — by design; HTTP 200 with low-score
    results is more informative than 404.
    """
    if not question or not question.strip():
        raise ValueError("question must be non-empty")

    k = _resolve_top_k(top_k)

    # Embed the question. encode() takes a batch and returns a list of
    # vectors; we pass [question] and unwrap the single result.
    query_vec = encode([question])[0]

    # Single SQL: KNN with cosine distance.
    # Note we send query_vec twice — once for ORDER BY (drives index
    # usage) and once for the SELECT distance column (so we can return
    # the score). Postgres evaluates each occurrence; the planner is
    # smart enough to compute it once per row.
    # Schema note: the `documents` table column is `content` (set in
    # migrations/001_init.sql + ingest._persist_chunks). We alias it to
    # `chunk_text` so the row order matches the RetrievedChunk dataclass
    # field names below — internal vocabulary stays "chunk_text" while
    # the DB column stays "content".
    sql = """
        SELECT
            source,
            content AS chunk_text,
            (embedding <=> %s::vector) AS distance
        FROM documents
        ORDER BY embedding <=> %s::vector
        LIMIT %s
    """

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (query_vec, query_vec, k))
            rows = cur.fetchall()

    return [
        RetrievedChunk(source=row[0], chunk_text=row[1], distance=float(row[2]))
        for row in rows
    ]
