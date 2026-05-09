"""
Bearer-token authentication for protected routes.

Single shared API key model (Phase 1). The key is read from the API_KEY
environment variable at request time and compared to the value provided by
the client in the `Authorization: Bearer <key>` header.

Why this design:
- Single shared key is appropriate for a single-tenant Phase 1 deployment.
  Phase 2 (multi-tenant) would swap this for per-tenant keys in a table.
- Reading from env at request time (not import time) means the server can
  be reconfigured without a code-path change. It also means a missing key
  fails CLOSED (server returns 500), not OPEN.
- `Authorization: Bearer <token>` is RFC 6750 standard, plays nicely with
  API gateways, reverse proxies, and tooling that already understands the
  Bearer scheme (JWT, OAuth2, etc).
- `secrets.compare_digest()` is a constant-time byte comparison. Plain `==`
  short-circuits on the first mismatched byte, so total comparison time
  leaks how many leading bytes of the candidate key were correct. With
  enough samples and low network jitter, an attacker can recover the key
  one byte at a time. compare_digest closes that side channel.

Failure modes (all return 401 to the client, generic message):
- Missing `Authorization` header
- Malformed header (no scheme, scheme without value, wrong scheme)
- Wrong key (correct shape, wrong bytes)

Server misconfiguration (API_KEY env unset or empty) returns 500. Never
trust a server that can't tell you what its own key is supposed to be.
"""

from __future__ import annotations

import os
import secrets

from fastapi import Header, HTTPException, status


def require_api_key(
    authorization: str | None = Header(default=None),
) -> str:
    """
    FastAPI dependency that enforces a valid Bearer token.

    Wire it onto a route with `Depends(require_api_key)`. On success the
    validated key string is returned (handy if a future route wants to log
    or rate-limit per-key). On any failure path, an HTTPException is
    raised and FastAPI converts it into a JSON error response.

    Returns:
        The validated bearer token (same value as the env API_KEY).

    Raises:
        HTTPException 500: API_KEY env var is missing or empty (server
            misconfiguration — fail closed).
        HTTPException 401: Authorization header missing, malformed,
            wrong scheme, or wrong key.
    """
    expected_key = os.getenv("API_KEY")
    if not expected_key:
        # Fail closed. Server has no configured key, so it cannot
        # authenticate anyone. Refuse rather than accept blindly.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfigured: API_KEY not set.",
        )

    if authorization is None:
        # No header at all.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Parse "Bearer <token>" — split on first whitespace only so tokens
    # containing spaces (unusual but legal) are not mangled.
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

    # Constant-time compare. encode() to bytes so equal-length unicode
    # surrogate edge cases don't matter; compare_digest accepts both
    # str and bytes, but bytes is the unambiguous form.
    if not secrets.compare_digest(token.encode("utf-8"), expected_key.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token
