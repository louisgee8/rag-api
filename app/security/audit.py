"""
Structured audit logging — Phase 2 Step 6.

Purpose
-------
Emit one JSON line per security-relevant or workflow event to stdout.
Docker's json-file log driver rotates the stream; a downstream SIEM /
log shipper (Vector, Fluentbit, etc.) picks it up in Phase 3.

Why JSONL on stdout, not a DB audit_events table
------------------------------------------------
- Append-only by construction. An attacker who lands a SQL injection on
  one path cannot UPDATE history written via print() to stdout.
- Zero writes inside the request path. No migration to own. No
  retention / archival code to write.
- Every cloud platform's logging stack consumes stdout JSONL natively,
  so Phase 3 wiring is a log-shipper config, not application code.

Trade-off accepted: search becomes a log-tool query, not SQL. Fine for
the portfolio scope we set for the rate limiter.

Envelope schema
---------------
Every event uses the same outer shape so a downstream parser can pivot
on `event_type` without parser-specific hacks:

    {
      "ts":         "<ISO 8601 UTC, Z-suffixed, millisecond precision>",
      "event_type": "<dotted.name>",
      "key_prefix": "ak_xxxxxxxx" | null,
      "tenant":     "<tenant-id>"  | null,
      "request_id": "<uuid4-hex>"  | null,
      "payload":    { ...per-event fields, redacted by caller... }
    }

Redaction discipline (contract)
-------------------------------
emit() does NOT introspect `payload`. Callers MUST pass only:
  - identifiers     (key_prefix, tenant, request_id),
  - counts / kinds  (match_count, kinds=["ssn", ...]),
  - structured outcomes (reason, status_code, gap, threshold).

Callers MUST NOT pass:
  - raw API tokens or other bearer secrets,
  - PII values themselves (log "kinds": ["ssn"], not the SSN string),
  - full request or response bodies.

The audit log itself is a downstream-consumed artifact — a leaked log
should not by itself constitute a breach.

Stdlib only — no new dependencies.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

# --------------------------------------------------------------------------
# Event-type constants
# --------------------------------------------------------------------------
# Define every event_type the codebase emits as a module-level constant.
# Typos in a string literal become silent SIEM blind spots; typos in a
# symbol crash at import time.

EVT_AUTH_SUCCESS = "auth.success"
EVT_AUTH_FAILURE = "auth.failure"
EVT_RATELIMIT_EXCEEDED = "ratelimit.exceeded"
EVT_PII_DETECTED = "pii.detected"
EVT_INJECTION_DETECTED = "injection.detected"
EVT_RELEVANCE_LOW_CONFIDENCE = "relevance.low_confidence"
EVT_INGEST_SUCCESS = "ingest.success"
EVT_QUERY_ANSWER_SUCCESS = "query.answer.success"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _now_iso() -> str:
    """
    ISO 8601 UTC, Z-suffixed, millisecond precision.

    Lexicographically sortable so `sort` on a JSONL file orders events
    chronologically without parsing the timestamp.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_request_id() -> str:
    """
    Generate a correlation id for one request's full event trail.

    Routes call this once at request entry and thread the id through
    every emit() in the request handler. Lets an investigator stitch
    `auth.success` + `injection.detected` + `query.answer.success`
    back to one logical request.
    """
    return uuid.uuid4().hex


# --------------------------------------------------------------------------
# Emitter
# --------------------------------------------------------------------------

def emit(
    event_type: str,
    *,
    key_prefix: str | None = None,
    tenant: str | None = None,
    request_id: str | None = None,
    **payload: Any,
) -> None:
    """
    Write one structured audit event to stdout as a single JSON line.

    Args:
        event_type: Dotted name from the EVT_* constants above. Free-form
            strings are accepted (we don't validate) so we don't break
            forward-compat for future event types — but you should add a
            constant for any new event type to keep typos catchable.
        key_prefix: Safe-to-display prefix of the actor's API key
            (the part we already store in cleartext). None when the
            event fired before auth resolved or in a system-side context.
        tenant: tenant_id of the actor, or None pre-auth.
        request_id: Correlation id linking events from the same request.
            Pass None if no upstream id is available.
        **payload: Per-event fields. Caller is responsible for redaction.
            Do not pass raw secrets, PII values, or full request bodies.

    Side effects:
        Writes one line to stdout, flushed. On serialization failure,
        writes a brief diagnostic to stderr so the failure is visible
        during dev/test without poisoning the stdout JSONL stream.

    Never raises. An audit emission failure must not take down a request.
    """
    event = {
        "ts": _now_iso(),
        "event_type": event_type,
        "key_prefix": key_prefix,
        "tenant": tenant,
        "request_id": request_id,
        "payload": payload,
    }
    try:
        # `separators` removes the default ", " / ": " whitespace so each
        # line is compact — log shippers ship fewer bytes, log readers see
        # tighter output.
        # `default=str` is a safety net for non-JSON-native values (e.g. a
        # caller passing a Decimal or datetime through **payload). It
        # coerces rather than crashing.
        line = json.dumps(event, separators=(",", ":"), default=str)
        print(line, file=sys.stdout, flush=True)
    except Exception as exc:
        # Best-effort visibility. stderr is the right channel because the
        # stdout stream is a contract with downstream JSONL parsers —
        # writing a non-JSON line there would corrupt it.
        print(
            f"[audit-emit-error] event_type={event_type} err={exc!r}",
            file=sys.stderr,
            flush=True,
        )
