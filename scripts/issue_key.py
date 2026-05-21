"""
issue_key — admin CLI for the api_keys table.

Subcommands (mutually exclusive flags):
    --tenant TENANT                       Mint a new key for TENANT.
    --revoke PREFIX --tenant TENANT       Revoke key by prefix (scoped by tenant).
    --list-tenant TENANT                  List all keys for TENANT (no secrets).

Run from inside the api container so the DB env vars resolve:
    docker compose exec api python -m scripts.issue_key --tenant acme-corp
    docker compose exec api python -m scripts.issue_key --revoke rk_a3b9c4d2 --tenant acme-corp
    docker compose exec api python -m scripts.issue_key --list-tenant acme-corp

Security notes:
    - The cleartext token is printed ONCE to stdout on issue. There is no
      retrieval path. Lose it = re-issue.
    - Revoke is constrained to `WHERE key_prefix = ? AND tenant_id = ?` so a
      typo cannot bleed across tenants. (Least-privilege scoping.)
    - `--list-tenant` shows only prefixes + timestamps — never key_hash,
      never the cleartext token (which we don't have anyway).
"""

from __future__ import annotations

import argparse
import sys
from typing import NoReturn

from app.db import get_conn
from app.security.keys import generate_token


def _exit(msg: str, code: int = 1) -> NoReturn:
    """Print to stderr and exit with the given code."""
    print(msg, file=sys.stderr)
    sys.exit(code)


def issue(tenant_id: str) -> None:
    """Mint a key for `tenant_id` and print the cleartext to stdout once."""
    issued = generate_token()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO api_keys (tenant_id, key_hash, key_prefix)
                VALUES (%s, %s, %s)
                RETURNING id, created_at
                """,
                (tenant_id, issued.key_hash, issued.prefix),
            )
            row = cur.fetchone()
        conn.commit()

    key_id, created_at = row
    # Loud, copy-friendly output. Cleartext appears ONCE — capture it now.
    print("=" * 60)
    print("  NEW API KEY ISSUED — copy this token NOW, it cannot be recovered.")
    print("=" * 60)
    print(f"  tenant_id  : {tenant_id}")
    print(f"  key_id     : {key_id}")
    print(f"  key_prefix : {issued.prefix}")
    print(f"  created_at : {created_at.isoformat()}")
    print(f"  token      : {issued.token}")
    print("=" * 60)


def revoke(tenant_id: str, key_prefix: str) -> None:
    """Mark a key revoked. Scoped by (prefix, tenant_id) — typo-safe."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE api_keys
                   SET revoked_at = NOW()
                 WHERE key_prefix = %s
                   AND tenant_id  = %s
                   AND revoked_at IS NULL
                RETURNING id, revoked_at
                """,
                (key_prefix, tenant_id),
            )
            row = cur.fetchone()
        conn.commit()

    if row is None:
        _exit(
            f"No active key found for tenant={tenant_id!r} prefix={key_prefix!r}. "
            f"(Maybe already revoked, wrong tenant, or wrong prefix.)"
        )

    key_id, revoked_at = row
    print(f"Revoked key_id={key_id} tenant={tenant_id} "
          f"prefix={key_prefix} at {revoked_at.isoformat()}")


def list_tenant(tenant_id: str) -> None:
    """Show all keys for a tenant. Prefixes + timestamps only — no secrets."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, key_prefix, created_at, revoked_at
                  FROM api_keys
                 WHERE tenant_id = %s
                 ORDER BY created_at DESC
                """,
                (tenant_id,),
            )
            rows = cur.fetchall()

    if not rows:
        print(f"No keys found for tenant={tenant_id!r}.")
        return

    print(f"{'id':<6} {'prefix':<14} {'created_at':<28} {'revoked_at'}")
    print("-" * 80)
    for key_id, key_prefix, created_at, revoked_at in rows:
        revoked = revoked_at.isoformat() if revoked_at else "(active)"
        print(f"{key_id:<6} {key_prefix:<14} {created_at.isoformat():<28} {revoked}")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="issue_key",
        description="Admin CLI for per-tenant API keys.",
    )
    p.add_argument("--tenant", required=True, metavar="TENANT",
                   help="Tenant identifier (required for all subcommands).")
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--revoke", metavar="PREFIX",
                     help="Revoke the key with this prefix (scoped by --tenant).")
    grp.add_argument("--list-tenant", action="store_true",
                     help="List all keys for the given tenant. No default: issue.")
    return p


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    if args.revoke:
        revoke(tenant_id=args.tenant, key_prefix=args.revoke)
    elif args.list_tenant:
        list_tenant(tenant_id=args.tenant)
    else:
        issue(tenant_id=args.tenant)


if __name__ == "__main__":
    main()
