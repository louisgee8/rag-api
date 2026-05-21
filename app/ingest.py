"""
Ingest orchestrator.

Pipeline: payload -> extract text -> chunk -> embed -> persist.

Two entry points (one per route branch):
- ingest_text(source, text, metadata)            # JSON body
- ingest_file(source, file_bytes, mime, meta)    # multipart upload

Both end at _persist_chunks, which atomically:
  1. DELETE FROM documents WHERE source = %s   (clean re-ingest semantics)
  2. cur.executemany INSERT for the batch       (one round-trip)

Returns IngestResult: (source, chunks_created, chunks_replaced).
"""

import io
from dataclasses import dataclass
from typing import Any

from psycopg.types.json import Json
from pypdf import PdfReader

from app.chunker import recursive_split
from app.db import get_conn
from app.embeddings import encode
from app.security.injection import scan_or_raise as injection_scan_or_raise
from app.security.pii import scan_or_raise as pii_scan_or_raise

# Sec+: allowlist by MIME type, never trust extensions. .pdf.exe would slip a
# blocklist. In production, sniff magic bytes via libmagic for true defense.
ALLOWED_MIMES = {"text/plain", "application/pdf"}

# Sec+: bounded payloads. A 10GB upload would OOM the embedder + DB. 10MB is
# generous for typical docs; raise if you have legitimate large-PDF use cases.
MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB


@dataclass
class IngestResult:
    """Stats returned to the API caller after a successful ingest."""
    source: str
    chunks_created: int
    chunks_replaced: int  # rows wiped by the DELETE-by-source step


def _extract_text_from_pdf(file_bytes: bytes) -> str:
    """
    Extract concatenated text from every page of a PDF.

    pypdf's text extraction is heuristic — scanned PDFs (image-only) return
    empty strings. Phase 2 candidate: OCR fallback via pytesseract for
    image-only PDFs.
    """
    reader = PdfReader(io.BytesIO(file_bytes))
    return "\n\n".join(page.extract_text() or "" for page in reader.pages)


def _persist_chunks(
    source: str,
    chunks: list[str],
    embeddings: list[list[float]],
    metadata: dict[str, Any] | None,
) -> IngestResult:
    """
    Atomic transaction: DELETE prior rows for `source`, then bulk INSERT.

    Why atomic: if INSERT fails halfway, we don't leave an empty source.
    psycopg3's connection context manager wraps the block in BEGIN/COMMIT;
    any exception triggers ROLLBACK and the prior rows stay intact.
    """
    metadata_json = Json(metadata or {})
    rows = [
        (source, idx, chunk, embedding, metadata_json)
        for idx, (chunk, embedding) in enumerate(zip(chunks, embeddings))
    ]

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Step 1: wipe prior rows for this source. .rowcount tells us
            # how many we replaced — useful info for the API response.
            cur.execute("DELETE FROM documents WHERE source = %s", (source,))
            chunks_replaced = cur.rowcount

            # Step 2: batch INSERT in a single round-trip.
            cur.executemany(
                """
                INSERT INTO documents
                    (source, chunk_index, content, embedding, metadata)
                VALUES (%s, %s, %s, %s, %s)
                """,
                rows,
            )
        # COMMIT happens implicitly here on clean exit. ROLLBACK on exception.

    return IngestResult(
        source=source,
        chunks_created=len(chunks),
        chunks_replaced=chunks_replaced,
    )


def ingest_text(
    source: str,
    text: str,
    metadata: dict[str, Any] | None = None,
) -> IngestResult:
    """
    JSON-body entry point. Used by POST /ingest with {source, text} body.

    Phase 2 Step 3: scans for PII before any persistence work. Raises
    `PIIDetectedError` on hit (caught at the route layer -> HTTP 400).
    Scan runs on the full text — cheaper than scanning every chunk, and
    catches patterns that span chunk boundaries (a chunker that splits an
    SSN across two chunks would otherwise pass both halves through).

    Phase 2 Step 4 (indirect prompt injection): scans for jailbreak
    phrases BEFORE the PII scan. Cheaper to reject an injection attempt
    up-front than to scan it for PII first. Raises `InjectionDetectedError`
    on hit (caught at the route layer -> HTTP 400). Closes the indirect
    injection vector: an attacker who plants "ignore previous instructions"
    inside a doc never lands the doc in the chunks table or vector index,
    so it never gets retrieved into a later victim's prompt.
    """
    injection_scan_or_raise(text)
    pii_scan_or_raise(text)
    chunks = recursive_split(text)
    if not chunks:
        # Empty/whitespace-only text. Don't even hit the DB — return zeros.
        return IngestResult(source=source, chunks_created=0, chunks_replaced=0)
    embeddings = encode(chunks)
    return _persist_chunks(source, chunks, embeddings, metadata)


def ingest_file(
    source: str,
    file_bytes: bytes,
    content_type: str,
    metadata: dict[str, Any] | None = None,
) -> IngestResult:
    """
    Multipart-upload entry point. Used by POST /ingest with file= field.

    Raises ValueError on disallowed MIME or oversize payload — the route
    handler in main.py converts these to 400 / 413 responses.
    """
    if len(file_bytes) > MAX_FILE_BYTES:
        raise ValueError(
            f"File too large: {len(file_bytes)} bytes (max {MAX_FILE_BYTES})"
        )
    if content_type not in ALLOWED_MIMES:
        raise ValueError(f"Unsupported content type: {content_type}")

    if content_type == "application/pdf":
        text = _extract_text_from_pdf(file_bytes)
    else:  # text/plain
        text = file_bytes.decode("utf-8", errors="replace")

    return ingest_text(source, text, metadata)
