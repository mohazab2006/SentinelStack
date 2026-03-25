import json
import os
from typing import Any, Optional

import asyncpg

_pool: Optional[asyncpg.Pool] = None


def _encode_jsonb(value: Any) -> str:
    """Encode Python values for pg jsonb (asyncpg often treats dict args as TEXT otherwise)."""
    return json.dumps(value)


def _decode_jsonb(value: str) -> Any:
    return json.loads(value)


async def _init_connection(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec(
        "jsonb",
        schema="pg_catalog",
        encoder=_encode_jsonb,
        decoder=_decode_jsonb,
        format="text",
    )


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        database_url = os.environ["DATABASE_URL"]
        _pool = await asyncpg.create_pool(
            dsn=database_url,
            min_size=1,
            max_size=5,
            init=_init_connection,
        )
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
