"""
Postgres connection pool singleton.

Why a pool (not connect-per-request):
- TCP + auth handshake costs ~5ms per new connection. Pooling reuses warm ones.
- Postgres has a hard `max_connections` cap (default 100). Pool bounds our usage
  so a runaway endpoint can't starve other tenants.
- One pool per process = one shared resource, easy to reason about.

Why register_vector in `configure`:
- pgvector ships a `vector` Postgres type. psycopg3 needs to learn the codec
  (so embeddings come back as numpy-friendly objects, not raw strings).
- `configure=` runs once per connection when it joins the pool. Cheap, correct.

Used by app/ingest.py (Step 4) and app/query.py (Step 5).
"""

import os
from contextlib import contextmanager
from typing import Iterator

from psycopg import Connection
from psycopg_pool import ConnectionPool
from pgvector.psycopg import register_vector


# Module-level singleton. None until first get_pool() call.
_pool: ConnectionPool | None = None


def _build_dsn() -> str:
    """Assemble Postgres DSN from env vars set in .env / docker-compose."""
    return (
        f"host={os.environ['POSTGRES_HOST']} "
        f"port={os.environ['POSTGRES_PORT']} "
        f"dbname={os.environ['POSTGRES_DB']} "
        f"user={os.environ['POSTGRES_USER']} "
        f"password={os.environ['POSTGRES_PASSWORD']}"
    )


def _configure(conn: Connection) -> None:
    """
    Per-connection setup callback.

    Runs once when each connection enters the pool. Teaches psycopg how to
    encode/decode the pgvector `vector` type so we can pass Python lists/numpy
    arrays directly as query parameters.
    """
    register_vector(conn)


def get_pool() -> ConnectionPool:
    """
    Return the singleton ConnectionPool, lazy-creating it on first call.

    Lazy init means the pool isn't built at import time — important for tests
    and for `/health` to return 200 even if Postgres is briefly unreachable.
    """
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            conninfo=_build_dsn(),
            min_size=1,
            max_size=5,
            configure=_configure,
            open=True,
        )
    return _pool


@contextmanager
def get_conn() -> Iterator[Connection]:
    """
    Borrow a pooled connection for the duration of the `with` block.

    Usage:
        from app.db import get_conn

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                row = cur.fetchone()

    The connection auto-returns to the pool on block exit, even on exception.
    """
    pool = get_pool()
    with pool.connection() as conn:
        yield conn
