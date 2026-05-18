"""
PII detection on /ingest (Phase 2 Step 3).

Policy: hard-reject. Any matched pattern raises HTTP 400 at the route layer;
nothing sensitive is ever written to the chunks table or vector index.

Why hard-reject (not scrub-and-store):
    Cleanest control. The rejection IS the audit evidence. Scrub-and-store
    would require a permanent `pii_redacted` metadata column, version-track
    which patterns were applied to which chunk, and accept that the original
    text exists somewhere (in request logs, in upstream caller buffers).
    Hard-reject keeps the DLP boundary at the API edge where it is easiest
    to reason about.

Why stdlib `re` (not Microsoft Presidio or similar):
    Portfolio scope. Presidio is the right answer in production: it adds
    contextual NER for names, addresses, MRNs, IBANs, and ~50 other entities
    that pure regex cannot detect (e.g. unformatted SSNs, names like
    "John Smith"). It also ships with confidence scoring and locale packs.
    For a single-container portfolio API the install cost (spaCy model
    download, GBs of memory) is not justified. README documents this
    explicitly.

Pattern set (Phase 2 lock):
    - SSN (dashed NANP format only)
    - Email (RFC 5322 practical subset)
    - US phone (NANP, four common formattings)
    - Credit card (13-19 digits with Luhn validation)

Threat model:
    - DB compromise: PII in the chunks table is queryable, exfiltratable,
      and (worst case) embedded into vector space where it cannot be
      reliably deleted without a full rebuild. The cheapest defense is
      to never let it land. This module is that defense.
    - LLM exposure: anything ingested can be retrieved by /query and
      surfaced verbatim in an LLM answer. Sec+ Domain 5 (Governance /
      Risk / Compliance) calls this out as a category of data leakage
      independent of the storage threat.
    - Insider lookup: an analyst with /query access could retrieve a
      stored SSN by guessing a fragment. Rejection at ingest is the
      only control that defeats this without a separate access layer.

Sec+ domain framing:
    - DLP (Data Loss Prevention) — blocking control at the data egress
      point (here, the API ingress that becomes the persistence egress).
    - CIA triad — Confidentiality. We accept some Availability cost
      (legitimate documents may be rejected) in exchange for stronger
      Confidentiality guarantees.

What this module deliberately does NOT do:
    - Detect unformatted SSNs (`123456789`). Adding `\\b\\d{9}\\b` would flag
      every 9-digit order ID, tracking number, and pasted hash. The false-
      positive cost outweighs the additional recall for portfolio scope.
    - Detect international PII (IBAN, EU phone, non-Latin scripts). NANP /
      US-only by design. A multi-locale build is a deliberate scope expansion,
      not a fix.
    - Detect personal names, addresses, dates of birth, MRNs. These require
      NER (named-entity recognition) which pure regex cannot do. Documented
      as a Presidio swap point if/when warranted.
    - Echo the matched value back in the rejection message. The 400 body
      names the KIND and COUNT only — never the value. Echoing would itself
      be a PII leak (e.g. log scraping the 400 responses).
    - Detect base64-encoded PII. Detection would require trying to b64decode
      every numeric-looking chunk (expensive + false positives) or entropy
      heuristics (noisy). Documented as a hard limit.

Step 3.5 hardening (2026-05-17):
    NFKC normalization + zero-width strip + digit-separator collapse
    pre-pass. Closes 6 of 7 known bypass classes (full-width chars,
    zero-width splits, spaced digits, underscore CCs, spaced emails,
    spaced phones). Base64 remains a documented bypass.

    Spans in returned PIIHit objects reference the normalized view, not
    the original text. Acceptable because we never echo matched values
    back to clients — only kind+count. Audit logs use the normalized
    spans as best-effort offsets.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable


# ---------------------------------------------------------------------------
# Pattern set. Compiled at module load (one-time cost, zero per-request cost).
# Word boundaries (`\b`) guard against mid-token matches.
# ---------------------------------------------------------------------------

# SSN: XXX-XX-XXXX. NANP dashed format only.
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Email: RFC 5322 practical subset.
# Allows: alnum, dot, underscore, percent, plus, hyphen in local part.
# Domain: alnum + dot + hyphen. TLD: 2+ Latin letters.
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# US phone: NANP. Covers (xxx) xxx-xxxx, xxx-xxx-xxxx, xxx.xxx.xxxx,
# +1 xxx xxx xxxx. Verbose mode for readability.
PHONE_RE = re.compile(
    r"""(?x)
    (?<!\d)                             # left guard: not preceded by a digit
    (?:\+?1[\s\-\.]?)?                  # optional country code (1 / +1)
    \(?\d{3}\)?[\s\-\.]?                # area code, optionally in parens
    \d{3}[\s\-\.]?                      # exchange
    \d{4}                               # subscriber number
    (?!\d)                              # right guard: not followed by a digit
    """
)

# Credit card candidate: 13-19 contiguous digits, optionally with internal
# spaces or hyphens (which we strip before Luhn).
CC_CANDIDATE_RE = re.compile(
    r"\b(?:\d[\s\-]?){13,19}\b"
)


# ---------------------------------------------------------------------------
# Hit record. `value` is intentionally NOT included — see module docstring.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PIIHit:
    kind: str           # one of: "ssn" | "email" | "phone" | "credit_card"
    span: tuple[int, int]   # (start, end) byte offsets in original text

    def to_audit_dict(self) -> dict:
        """Returns a dict safe to write to audit logs. Never includes the value."""
        return {"kind": self.kind, "start": self.span[0], "end": self.span[1]}


# ---------------------------------------------------------------------------
# Luhn checksum (ISO/IEC 7812-1) for credit-card filtering.
# Cuts random-digit-run false positives by ~90%.
# ---------------------------------------------------------------------------

def _luhn_valid(digits: str) -> bool:
    """
    True iff `digits` (already stripped to characters [0-9]) passes Luhn.

    Algorithm: starting from the rightmost digit and moving left, double
    every second digit. If the doubled value exceeds 9, subtract 9 (which
    equals summing the two digits). Sum everything. Valid iff total % 10 == 0.
    """
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _strip_to_digits(raw: str) -> str:
    """Remove spaces, hyphens, underscores. Normalizes a CC candidate before Luhn."""
    return raw.replace(" ", "").replace("-", "").replace("_", "")


# ---------------------------------------------------------------------------
# Step 3.5: Normalization pre-pass.
# Production DLP (Presidio, AWS Macie, Microsoft Purview) all do this. The
# detector reads a normalized view of the input — pure regex on raw bytes
# loses to any attacker who knows the alphabet is bigger than ASCII.
# ---------------------------------------------------------------------------

# Zero-width characters used for obfuscation. ZWSP, ZWNJ, ZWJ, BOM.
_ZERO_WIDTH_RE = re.compile("[​‌‍﻿]")

# Inside a numeric run, drop spaces/underscores adjacent to digits OR to
# format separators (`-`, `.`). Broader char class catches the case where
# the obfuscator pads BOTH the digits AND the dashes: `1 2 3 - 4 5 - 6 7 8 9`.
# Still leaves prose alone — `2 - 1 = 1` collapses to `2-1=1` which is benign
# and doesn't match any PII pattern.
_INTERDIGIT_SEP_RE = re.compile(r"(?<=[\d\-\.])[ _]+(?=[\d\-\.])")

# Collapse whitespace padding around the @ sign for email scanning.
# Catches `user @ example.com`. Tight by design — only collapses on @.
_EMAIL_PADDING_RE = re.compile(r"\s*@\s*")


def _normalize_for_scan(text: str) -> str:
    """
    NFKC + strip zero-width. Used as the base view for every pattern.
    NFKC ('Normalization Form Compatibility Composition') folds full-width
    digits, full-width @, full-width period, etc. down to their ASCII
    equivalents — defeating the cheapest obfuscation tier in one call.
    """
    return _ZERO_WIDTH_RE.sub("", unicodedata.normalize("NFKC", text))


def _collapse_digit_separators(text: str) -> str:
    """Drop spaces/underscores between adjacent digits. Numeric-pattern view."""
    return _INTERDIGIT_SEP_RE.sub("", text)


def _collapse_email_padding(text: str) -> str:
    """Collapse whitespace around @. Email-pattern view."""
    return _EMAIL_PADDING_RE.sub("@", text)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_for_pii(text: str) -> list[PIIHit]:
    """
    Scan `text` for PII patterns. Returns a list of hits in source order.
    Empty list means clean. Caller decides what to do with non-empty result
    (this module's job is detection, not response).

    Scanning runs against THREE normalized views built from the input:
      - base: NFKC + zero-width strip. Defeats #1 (Unicode forms) and #4
        (zero-width splits) without touching whitespace semantics.
      - numeric: base + interdigit space/underscore collapse. Defeats #2
        (spaced SSN/phone) and #7 (underscore-separated CC).
      - email: base + @-padding collapse. Defeats #6 (spaced email).

    Performance note: compiled patterns + four single-pass scans + three
    cheap rewrites. Low single-digit ms per MB. Cheap enough to apply
    unconditionally on every /ingest call.

    Span fidelity: spans reference the normalized view, not the original.
    Acceptable here because we never echo matched values — only kind+count.
    """
    hits: list[PIIHit] = []

    base = _normalize_for_scan(text)
    numeric_view = _collapse_digit_separators(base)
    email_view = _collapse_email_padding(base)

    # Numeric patterns run on the digit-collapsed view.
    for match in SSN_RE.finditer(numeric_view):
        hits.append(PIIHit(kind="ssn", span=match.span()))

    for match in PHONE_RE.finditer(numeric_view):
        hits.append(PIIHit(kind="phone", span=match.span()))

    for match in CC_CANDIDATE_RE.finditer(numeric_view):
        raw = match.group(0)
        digits = _strip_to_digits(raw)
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            hits.append(PIIHit(kind="credit_card", span=match.span()))

    # Email runs on the @-padding-collapsed view.
    for match in EMAIL_RE.finditer(email_view):
        hits.append(PIIHit(kind="email", span=match.span()))

    hits.sort(key=lambda h: h.span[0])
    return hits


def summarize_hits(hits: Iterable[PIIHit]) -> list[dict]:
    """
    Aggregate hits by kind for the rejection response body.
    Returns [{"kind": "ssn", "count": 2}, {"kind": "email", "count": 1}, ...]
    Sorted by kind for stable test output.
    """
    counts: dict[str, int] = {}
    for h in hits:
        counts[h.kind] = counts.get(h.kind, 0) + 1
    return sorted(
        ({"kind": k, "count": v} for k, v in counts.items()),
        key=lambda d: d["kind"],
    )


# ---------------------------------------------------------------------------
# Exception raised by `scan_or_raise`. Caught at the route layer and converted
# to an HTTP 400 with a structured body. Carries `.summary` (a list of
# {kind,count} dicts) — never the matched values themselves.
# ---------------------------------------------------------------------------

class PIIDetectedError(Exception):
    """Raised when PII patterns are present in ingest text. Hard-reject."""

    def __init__(self, summary: list[dict]) -> None:
        self.summary = summary
        super().__init__(f"PII detected: {summary}")


def scan_or_raise(text: str) -> None:
    """
    Convenience for orchestrator use. Scans `text`; raises `PIIDetectedError`
    iff any pattern matched. Returns None on clean input.
    """
    hits = scan_for_pii(text)
    if hits:
        raise PIIDetectedError(summary=summarize_hits(hits))
