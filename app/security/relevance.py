"""
Relevance gate — Phase 2 Step 5.

Purpose
-------
Decide whether the chunks pgvector returned for a question are *meaningfully*
better than the next-best alternatives. When the top hit is no better than a
random chunk, the LLM has nothing to ground on and tends to hallucinate.
Cheaper to refuse with a 422 than to spend an Anthropic call and ship a
confident-sounding wrong answer.

The metric: gap-to-#2
---------------------
We compare the cosine *distance* of the top-1 hit to the cosine distance of
the top-2 hit. pgvector cosine distance lives in [0, 2]; lower = more similar.
So the "gap" is::

    gap = chunks[1].distance - chunks[0].distance

A positive gap means hit #1 is genuinely closer to the question than hit #2.
A near-zero gap means everything in the corpus is roughly the same distance
from the question — i.e. the question isn't grounded by any specific chunk.

Why gap-to-#2 instead of an absolute distance threshold:
- Absolute distance varies by domain. A technical corpus might cluster around
  0.6, a chatty one around 0.8. A fixed "anything above 0.7 is bad" cutoff
  would need re-tuning per corpus.
- Gap-to-#2 is scale-invariant: it measures *separation* between candidates,
  not their absolute closeness. Stays informative across corpora.

Calibration (Phase 1, locked 2026-05-08)
----------------------------------------
- Absent-from-corpus content:          gap ~0.01
- Smoke fixture (related question):    gap  0.2039
- Strong real matches:                 gap  0.55+

Default threshold `RELEVANCE_MIN_GAP=0.05` blocks the absent case and lets
the smoke fixture + real matches through. Configurable via env so we can
tune per deployment.

Edge cases
----------
- Zero chunks (empty DB or table wiped): low_confidence by definition.
- One chunk only (corpus has < 2 documents): no second candidate to
  measure against — also low_confidence. This is intentional: the gate is
  a *separation* test, and you can't separate one thing.

Where this fires
----------------
Only on `/query/answer` (the expensive LLM path). `/query/retrieve` stays
raw so clients can use it to debug their corpus without being gated.

Stdlib only — no new dependencies.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# --------------------------------------------------------------------------
# Exception
# --------------------------------------------------------------------------

@dataclass
class LowConfidenceError(Exception):
    """
    Raised when retrieved chunks fail the gap-to-#2 separation test.

    Carries enough numbers for the route to build a structured 422 envelope
    that's actually useful to API consumers — they can see how close the
    call was to passing and tune their corpus / threshold accordingly.

    Fields:
        chunks_returned: how many chunks pgvector returned (0, 1, or top_k).
        top_distance:    cosine distance of hit #1, or None if no chunks.
        gap:             distance gap between hit #2 and hit #1, or None if
                         fewer than 2 chunks were returned.
        threshold:       the configured RELEVANCE_MIN_GAP at the time of
                         evaluation. Echoed back so the caller knows what
                         bar they failed to clear.
        reason:          short machine-readable reason code.
    """
    chunks_returned: int
    top_distance: float | None
    gap: float | None
    threshold: float
    reason: str

    def __post_init__(self):
        # Exception requires args to be set for repr / str. Compose a useful
        # message that does NOT leak chunk contents (matches the no-echo
        # discipline we used in PII / injection).
        super().__init__(
            f"low_confidence: {self.reason} "
            f"(gap={self.gap}, threshold={self.threshold}, "
            f"chunks_returned={self.chunks_returned})"
        )

    @property
    def envelope(self) -> dict:
        """Shape for the FastAPI 422 detail body."""
        return {
            "error": "low_confidence",
            "reason": self.reason,
            "chunks_returned": self.chunks_returned,
            "top_distance": self.top_distance,
            "gap": self.gap,
            "threshold": self.threshold,
        }


# --------------------------------------------------------------------------
# Threshold resolver
# --------------------------------------------------------------------------

def _resolve_threshold(override: float | None) -> float:
    """
    Pick the effective threshold.

    Per-call override wins (useful for tests). Otherwise read
    `RELEVANCE_MIN_GAP` from the environment. We fail loudly on a missing
    or non-numeric env var rather than ship a silent default — same
    discipline as `_resolve_top_k` in retrieval.py.
    """
    if override is not None:
        return float(override)
    raw = os.environ["RELEVANCE_MIN_GAP"]  # KeyError if unset
    return float(raw)


# --------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------

def evaluate_or_raise(
    chunks: list,
    *,
    threshold: float | None = None,
) -> None:
    """
    Inspect the retrieved chunk list and raise LowConfidenceError if the
    gap-to-#2 is below the configured threshold.

    `chunks` is duck-typed: any iterable of objects with a `.distance`
    attribute (i.e. `RetrievedChunk` from `app.retrieval`) works. We don't
    import the dataclass here to avoid a circular dep between
    `app.security.*` and `app.retrieval`.

    Side-effect-free on the pass path: returns None. Raises on failure.

    Raises:
        LowConfidenceError on:
          - zero chunks (reason="empty_result")
          - one chunk   (reason="single_candidate")
          - gap < threshold (reason="insufficient_gap")
    """
    t = _resolve_threshold(threshold)

    # Edge case 1: empty result.
    if len(chunks) == 0:
        raise LowConfidenceError(
            chunks_returned=0,
            top_distance=None,
            gap=None,
            threshold=t,
            reason="empty_result",
        )

    # Edge case 2: single candidate. No way to compute a separation.
    if len(chunks) == 1:
        raise LowConfidenceError(
            chunks_returned=1,
            top_distance=float(chunks[0].distance),
            gap=None,
            threshold=t,
            reason="single_candidate",
        )

    # Normal path: at least two candidates.
    top = float(chunks[0].distance)
    second = float(chunks[1].distance)
    gap = second - top  # positive when hit #1 is closer (lower distance)

    if gap < t:
        raise LowConfidenceError(
            chunks_returned=len(chunks),
            top_distance=top,
            gap=gap,
            threshold=t,
            reason="insufficient_gap",
        )
    # Pass.
