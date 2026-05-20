"""
Per-tenant Bearer-token authentication (Phase 2 Step 1).

Replaces the Phase 1 single-shared-key model. Each tenant has one or
more rows in the `api_keys` table; the bearer token presented in the
`Authorization` header is hashed and looked up against `key_hash`.

Request flow:
    1. Extract `Authorization: Bearer <token>` from request headers.
    2. SHA-256 the token -> digest.
    3. SELECT tenant_id, key_prefix, revoked_at FROM api_keys
       WHERE key_hash = <digest> LIMIT 1.
    4. No row     -> 401 (invalid key)
       revoked    -> 401 (revoked key)
       active row -> return TenantIdentity for downstream consumers.

Failure modes:
    - DB unreachable        -> 500 (fail closed; we cannot authenticate
                                    anyone if the auth store is down)
    - Missing/malformed hdr -> 401 (same as Phase 1)
    - Wrong/revoked token   -> 401 (generic message; no leak about WHICH
                                    failure mode triggered)

What this module deliberately does NOT do:
    - Cache the lookup. Phase 2 throughput is small; a DB hit per request
      is fine. Caching would have to handle revocation invalidation, which
      is a Step 6+ concern. KISS.
    - Update a `last_used_at` column. Same Step 6 deferral — audit
      logging will land per-request timestamps in a structured log,
      not by mutating the auth row on every read.

Wire-format compatibility:
    - The HTTP layer is unchanged. Clients still send
      `Authorization: Bearer <token>`. Only the server-side validation
      changed. This means existing curl scripts / API clients keep
      working as long as they swap their token value.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, HTTPException, status
from psycopg import OperationalError

from app.db import get_conn
from app.security import audit
from app.security.keys import extract_prefix, hash_token


@dataclass(frozen=True)
class TenantIdentity:
    """Resolved identity of the caller for the current request.

    Returned by `verify_api_key` for handlers that need to know WHO is
    calling. Feeds Step 2 (per-key rate limiting) and Step 6 (audit log
    key/tenant/request-id tagging).
    """
    key_id: int        # api_keys.id — stable PK for joins to audit_log
    tenant_id: str     # caller-facing identity, e.g. "acme-corp"
    key_prefix: str    # rk_<8 chars> — log-safe identifier of the key
    request_id: str    # uuid4 hex — correlates every audit event from this request


def _parse_bearer(authorization: str | None) -> str:
    """
    Pull the token bytes out of an `Authorization: Bearer <token>` header.

    Raises 401 (with WWW-Authenticate: Bearer) on:
    - Missing header
    - Header that doesn't split into [scheme, value]
    - Scheme != "bearer" (case-insensitive)
    - Empty token after the scheme

    Same parser as Phase 1 — wire format is unchanged, only the
    validation logic past this point is different.
    """
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed Authorization header. Expected: Bearer <key>.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scheme, token = parts[0], parts[1].strip()
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid auth scheme. Expected: Bearer <key>.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token


def verify_api_key(
    authorization: str | None = Header(default=None),
) -> TenantIdentity:
    """
    FastAPI dependency: enforce a valid, active per-tenant bearer token.

    Wire onto a route either way:
        # Side-effect only (most current handlers):
        @app.post("/ingest", dependencies=[Depends(verify_api_key)])
        def ingest(...): ...

        # Need tenant identity downstream (Step 2+ handlers):
        @app.post("/ingest")
        def ingest(..., tenant: TenantIdentity = Depends(verify_api_key)):
            log.info("ingest from", tenant_id=tenant.tenant_id)

    Returns:
        TenantIdentity if the token resolves to an active key row.

    Raises:
        HTTPException 401: missing/malformed header, unknown token,
            or token belongs to a revoked key. Generic message — we
            deliberately do not distinguish "no such key" from
            "revoked" so an attacker cannot probe which prefix bytes
            were ever issued.
        HTTPException 500: Postgres unreachable. Fail closed — we
            cannot authenticate anyone if the auth store is down.
    """
    # Phase 2 Step 6: mint the per-request correlation id at auth entry.
    # Every audit event emitted while serving this request will carry it.
    rid = audit.new_request_id()

    # Header parsing can raise HTTPException (missing / malformed / bad scheme).
    # Bucket those under one reason code — the SIEM can split on payload.detail
    # if it cares about which sub-failure fired.
    try:
        token = _parse_bearer(authorization)
    except HTTPException as exc:
        audit.emit(
            audit.EVT_AUTH_FAILURE,
            request_id=rid,
            reason="header_parse_failure",
            detail=str(exc.detail),
        )
        raise

    digest = hash_token(token)

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, tenant_id, key_prefix, revoked_at
                      FROM api_keys
                     WHERE key_hash = %s
                     LIMIT 1
                    """,
                    (digest,),
                )
                row = cur.fetchone()
    except OperationalError as e:
        # Database is down or unreachable. We cannot prove or disprove
        # the caller's identity, so we MUST refuse rather than guess.
        audit.emit(
            audit.EVT_AUTH_FAILURE,
            request_id=rid,
            reason="auth_store_down",
            exc=e.__class__.__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Auth store unavailable: {e.__class__.__name__}",
        )

    if row is None:
        # No row matched the digest. Either the token is bogus or
        # was hashed differently. We log the EXTRACTED PREFIX (rk_xxxx)
        # of the attempted token — never the full token — so a log leak
        # doesn't compound the breach we're already investigating.
        attempted_prefix = extract_prefix(token)
        audit.emit(
            audit.EVT_AUTH_FAILURE,
            key_prefix=attempted_prefix,
            request_id=rid,
            reason="unknown_key",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    key_id, tenant_id, key_prefix, revoked_at = row

    if revoked_at is not None:
        # Key was active at some point but has since been revoked.
        # Same generic 401 message as "unknown key" — see docstring.
        # Audit log DOES distinguish the two (revoked_key vs unknown_key)
        # because the threat models differ: revoked = credential rotation
        # didn't propagate; unknown = brute-force or stale client.
        audit.emit(
            audit.EVT_AUTH_FAILURE,
            key_prefix=key_prefix,
            tenant=tenant_id,
            request_id=rid,
            reason="revoked_key",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Happy path: emit auth.success and return the identity carrying rid.
    audit.emit(
        audit.EVT_AUTH_SUCCESS,
        key_prefix=key_prefix,
        tenant=tenant_id,
        request_id=rid,
    )
    return TenantIdentity(
        key_id=key_id,
        tenant_id=tenant_id,
        key_prefix=key_prefix,
        request_id=rid,
    )
