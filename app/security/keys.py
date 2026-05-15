"""
API-key primitives: generation, hashing, prefix slicing.

This module is intentionally pure (no DB, no FastAPI). It is consumed by:
- `app.auth.verify_api_key` at request time (hash-then-lookup)
- `scripts/issue_key.py` at admin time (generate + insert hashed row)

Threat model (Phase 2 Step 1):
- DB compromise: attacker pulls every `api_keys` row. Because we store
  SHA-256(token), not the token itself, the leaked digests are
  unusable as bearer tokens. The token is 256-bit random, so brute
  force against the hash is computationally infeasible.
- Stolen log file: logs only ever contain `key_prefix` (first 11 chars
  of the cleartext token). The prefix identifies WHICH key was used
  for forensic correlation; it does NOT reveal the secret bytes.
- Side-channel on auth: SHA-256 is fast and deterministic. We look up
  by exact-match on the hash via Postgres btree (UNIQUE index). No
  per-byte comparison path that could leak via timing.

What this module does NOT do:
- Argon2/bcrypt/scrypt key stretching. These are KDFs designed to
  defend low-entropy human passwords against offline guessing. Our
  tokens are 256-bit OS-CSPRNG output; stretching adds latency without
  meaningful security gain. See NIST SP 800-63B §5.1.1.2 ("verifier
  shall use approved cryptographic functions ... memorized secrets
  SHALL be hashed with a salt and an approved one-way function" —
  the "memorized secret" qualifier is what excludes our tokens).
- Constant-time compare. The lookup is `SELECT ... WHERE key_hash = $1`
  with a UNIQUE-index btree — Postgres returns a row or doesn't.
  There's no byte-by-byte compare in our auth path to be timed.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


# Brand prefix. Visible in cleartext tokens. Lets secret scanners
# (GitHub, TruffleHog, gitleaks) match on a known shape, the same way
# `ghp_` flags a GitHub PAT and `AKIA` flags an AWS access key.
TOKEN_BRAND = "rk_"

# 32 bytes -> ~43 URL-safe base64 chars after stripping padding.
# Combined with the 3-char brand prefix, full tokens are ~46 chars.
# 256 bits of entropy is comfortably above any brute-force horizon.
TOKEN_ENTROPY_BYTES = 32

# How many chars of the cleartext token to store as `key_prefix`.
# 3 brand chars + 8 random chars = 11. 8 random base64 chars is ~48 bits
# of identifying entropy — plenty to distinguish keys in logs without
# being a meaningful guess advantage on the secret.
PREFIX_LEN = len(TOKEN_BRAND) + 8


@dataclass(frozen=True)
class IssuedKey:
    """Bundle returned by `generate_token`.

    Why a dataclass instead of a tuple: clarity at call sites. The
    issue_key CLI prints `token` to the operator and inserts `prefix`
    + `key_hash` into the DB. Naming the fields prevents the classic
    "I swapped these two strings by accident" bug.
    """
    token: str       # cleartext, return to operator ONCE, then discard
    prefix: str      # first PREFIX_LEN chars of token; safe to log + persist
    key_hash: str    # SHA-256 hex digest of token; what the DB stores


def generate_token() -> IssuedKey:
    """Mint a new API key.

    Returns:
        IssuedKey containing:
        - token:    `rk_<43 random chars>` — show to operator ONCE
        - prefix:   `rk_<8 random chars>`  — store + log
        - key_hash: SHA-256 hex digest      — store in api_keys.key_hash

    The cleartext `token` is never persisted by this module. Callers
    MUST display it to the operator immediately and discard it.
    """
    random_part = secrets.token_urlsafe(TOKEN_ENTROPY_BYTES)
    token = f"{TOKEN_BRAND}{random_part}"
    return IssuedKey(
        token=token,
        prefix=token[:PREFIX_LEN],
        key_hash=hash_token(token),
    )


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a bearer token.

    Used at two call sites:
    1. `generate_token` populates `key_hash` for insert.
    2. `app.auth.verify_api_key` hashes the incoming bearer token and
       looks up `api_keys` by that digest.

    Returning hex (not raw bytes) means the value is JSON-safe and
    pastes cleanly into psql for ad-hoc debugging.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def extract_prefix(token: str) -> str:
    """Return the log-safe prefix slice of an already-issued token.

    Useful in `app.auth` for stamping `key_prefix` onto log lines when
    an inbound token doesn't match any row (so we can still tell, e.g.,
    "someone tried `rk_abcd1234...` 50 times in a minute" without
    storing the full guess attempt).
    """
    return token[:PREFIX_LEN]
