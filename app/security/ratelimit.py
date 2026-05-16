"""
Per-API-key rate limiting (Phase 2 Step 2).

Algorithm: fixed-window counter, in-memory, per `key_id`.

Why fixed window:
    Simplest data structure that solves the threat. One int (count) + one
    float (window_start_epoch) per key. The known weakness — boundary-burst
    of up to 2x the stated limit across a window edge — is acceptable for
    portfolio scope and documented in README. Phase 3 (cloud deploy) can
    swap to sliding window or token bucket without changing route wiring,
    because the limiter is a FastAPI dependency.

Why in-memory:
    Single-container portfolio deploy. Zero new infra. The cost is documented:
    counters reset on container restart, and the state is not shared if the
    app ever scales to >1 replica. Phase 3 swaps to Redis when those costs
    actually bite.

Why threading.Lock (not asyncio.Lock):
    All current /ingest /query routes are sync handlers. FastAPI runs sync
    handlers in a worker thread pool. Multiple threads can hit the limiter
    simultaneously, so the dict mutation must be protected with a primitive
    that serializes across THREADS, not coroutines. `asyncio.Lock` only
    serializes coroutines on a single event-loop thread, which is the wrong
    scope for our concurrency model.

Why time.monotonic():
    Wall-clock (`time.time()`) can jump backwards on NTP sync or DST. A
    backwards jump would re-open windows that should be closed. monotonic()
    is guaranteed non-decreasing, so window math stays correct. Same rule
    applies to any timeout / TTL / deadline math.

Threat addressed: credential abuse against a single compromised key
(brute-force lookup attempts, scraping, runaway client loops). Sec+ domains:
- Availability (CIA triad — DoS protection)
- Identification & Authorization (Domain 3) — abuse of a valid key is
  still abuse; rate limiting bounds the blast radius of a leaked credential.

What this module deliberately does NOT do:
- Bucket cleanup for inactive keys. Dict grows monotonically with unique
  key ids seen. For Phase 2 scope (handful of test keys) this is fine.
  TODO Phase 3: LRU eviction or time-based reaping.
- Distributed coordination. Single-process state only. See Why in-memory.
- Per-route quotas. One global limit per key applies across all protected
  routes. Differentiating /ingest from /query is a Phase 3 refinement.
"""

from __future__ import annotations

import math
import os
import threading
import time
from dataclasses import dataclass

from fastapi import Depends, HTTPException, status

from app.auth import TenantIdentity, verify_api_key


# --------------------------------------------------------------------------
# Config (env-driven, 12-factor — same pattern as RAG_API_KEY in Phase 1)
# --------------------------------------------------------------------------

# Default: 60 requests per 60-second window per key.
# Overridable in docker-compose env without a code change.
DEFAULT_LIMIT = 60
DEFAULT_WINDOW_SECONDS = 60


def _env_int(name: str, default: int) -> int:
    """
    Read an int from env, fall back to default. Fail loudly on garbage.

    We intentionally raise on malformed env (e.g. RATE_LIMIT_REQUESTS=abc)
    rather than silently using the default — a typo in compose config
    should crash the container at startup, not silently disable the limiter.
    """
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(
            f"Env var {name}={raw!r} is not a valid integer."
        ) from None
    if value <= 0:
        raise RuntimeError(
            f"Env var {name}={value} must be a positive integer."
        )
    return value


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

@dataclass
class BucketState:
    """
    Per-key counter state.

    Mutable on purpose: we increment `count` in place under the lock to
    avoid allocating a fresh dataclass on every request.

    Fields:
        count: requests served in the current window.
        window_start_monotonic: monotonic clock reading when this window
            opened. The window ends at window_start_monotonic + window_seconds.
    """
    count: int
    window_start_monotonic: float


class RateLimiter:
    """
    Fixed-window rate limiter, keyed by a caller-supplied string (key_id).

    Thread-safety: every dict read AND write of `_buckets` happens under
    `_lock`. The check-and-mutate sequence is one critical section so two
    concurrent threads can't both see `count=59` and both increment to 60.

    Usage:
        limiter = RateLimiter(limit=60, window_seconds=60)
        limiter.check("123")   # str(key_id) — raises HTTPException 429 on limit
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._buckets: dict[str, BucketState] = {}
        self._lock = threading.Lock()

    def check(self, key_id: str) -> None:
        """
        Record a request from `key_id`. Raise 429 if the window is full.

        Algorithm (fixed window):
            now = monotonic clock reading
            if no bucket for this key OR current window has expired:
                open a fresh window starting at `now`; count = 1; allow.
            else if count < limit:
                increment count; allow.
            else:
                deny with Retry-After = seconds until window end.

        429 response includes a `Retry-After` header per RFC 9110 §10.2.3,
        rounded UP so a client honoring the header doesn't fire its retry
        in the same window that just rejected it.
        """
        now = time.monotonic()

        with self._lock:
            bucket = self._buckets.get(key_id)

            # Case 1: brand-new key, or its previous window has elapsed.
            # Open a fresh window. This is also why a key that goes silent
            # for >window_seconds gets a "free" first request afterwards.
            if bucket is None or (now - bucket.window_start_monotonic) >= self.window_seconds:
                self._buckets[key_id] = BucketState(
                    count=1,
                    window_start_monotonic=now,
                )
                return

            # Case 2: inside an active window with room left.
            if bucket.count < self.limit:
                bucket.count += 1
                return

            # Case 3: inside an active window, limit hit. Compute Retry-After
            # and refuse. We compute the remainder while still holding the
            # lock so the value is consistent with the bucket state we read.
            elapsed = now - bucket.window_start_monotonic
            retry_after = max(1, math.ceil(self.window_seconds - elapsed))

        # Released the lock before raising — exceptions out of a `with` block
        # release it automatically, but doing the raise outside the block
        # makes the contract obvious to readers.
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded: "
                f"{self.limit} requests per {self.window_seconds}s. "
                f"Retry after {retry_after}s."
            ),
            headers={"Retry-After": str(retry_after)},
        )


# --------------------------------------------------------------------------
# Module-level singleton + FastAPI dependency
# --------------------------------------------------------------------------

# Built once at import time. FastAPI workers share this object across all
# requests in the same process. State is intentionally not shared across
# processes — see "Why in-memory" in the module docstring.
_limiter = RateLimiter(
    limit=_env_int("RATE_LIMIT_REQUESTS", DEFAULT_LIMIT),
    window_seconds=_env_int("RATE_LIMIT_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS),
)


def enforce_rate_limit(
    identity: TenantIdentity = Depends(verify_api_key),
) -> TenantIdentity:
    """
    FastAPI dependency: enforce per-key rate limit, then pass identity through.

    Chain: bearer-token parse -> hash lookup -> identity resolved
           -> THIS function -> per-key counter check -> handler runs.

    Returns the same `TenantIdentity` that `verify_api_key` returned, so
    handlers wired to this dep still have access to tenant_id / key_prefix
    for downstream logging (Step 6).

    Wire onto a route either way:
        # Side-effect only:
        @app.post("/query/retrieve", dependencies=[Depends(enforce_rate_limit)])
        def retrieve(...): ...

        # Need identity downstream:
        @app.post("/query/retrieve")
        def retrieve(..., tenant = Depends(enforce_rate_limit)):
            log.info("retrieve from", tenant_id=tenant.tenant_id)
    """
    # str() the key_id — dict keys are stringly typed so we never get
    # int/str collisions if the id type ever changes (e.g. UUIDs in Phase 3).
    _limiter.check(str(identity.key_id))
    return identity
