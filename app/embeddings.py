"""
Sentence-transformer singleton.

Why singleton (same logic as app/db.py):
- Loading the model = ~100MB RAM allocation + 1-3s deserialization. Per-request
  loading would tax every /ingest call before any real work begins.
- The model is deterministic and stateless: same input -> same vector. Sharing
  one instance across threads/requests is safe.

Why lazy:
- Module import stays fast and side-effect-free. Tests can import this module
  without paying the model load cost.
- /health stays responsive — model only loads when /ingest or /query is hit.

Model: sentence-transformers/all-MiniLM-L6-v2 (384-dim, ~90MB on disk).
Locked to the EMBEDDING_DIM=384 in .env which matches the vector(384) schema.
"""

import os
from typing import Sequence

from sentence_transformers import SentenceTransformer


# Module-level singleton. None until first get_model() call.
_model: SentenceTransformer | None = None


def get_model() -> SentenceTransformer:
    """
    Return the singleton SentenceTransformer, lazy-loading on first call.

    First call is slow (1-3s + first-time HuggingFace download if model not
    cached). Every subsequent call returns the same warm instance instantly.
    """
    global _model
    if _model is None:
        model_name = os.environ["EMBEDDING_MODEL"]
        _model = SentenceTransformer(model_name)
    return _model


def encode(texts: Sequence[str]) -> list[list[float]]:
    """
    Embed a batch of strings into 384-dim vectors.

    Why batch (not one-at-a-time):
    - SentenceTransformer encodes batches via vectorized matrix ops on the GPU
      or optimized CPU SIMD. A batch of 32 chunks is ~30x faster than 32 calls
      of size 1.

    Returns: list[list[float]] — outer length == len(texts), each inner list
    is exactly EMBEDDING_DIM long (384). Format is plain Python lists so the
    caller can pass them straight to psycopg without numpy hassles.
    """
    model = get_model()
    # convert_to_numpy=True returns a 2D numpy array; .tolist() makes it
    # JSON-serializable and pgvector-friendly.
    vectors = model.encode(
        list(texts),
        convert_to_numpy=True,
        show_progress_bar=False,
    )
    return vectors.tolist()
