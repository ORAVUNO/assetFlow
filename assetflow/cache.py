"""On-disk cache for the most recent result of each query.

The web UI runs queries live against Elasticsearch, but also caches the latest
result per query so you can reopen the page and review the last fetch (and
download it) without re-querying. Cache files are plain JSON under a local
``.assetflow_cache/`` directory (gitignored).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import Query
from .runner import QueryResult

CACHE_DIRNAME = ".assetflow_cache"


def cache_dir() -> Path:
    path = Path.cwd() / CACHE_DIRNAME
    path.mkdir(exist_ok=True)
    return path


def _cache_path(query_id: str) -> Path:
    safe = "".join(c for c in query_id if c.isalnum() or c in "-_")
    return cache_dir() / f"{safe}.json"


def save_result(
    query: Query,
    result: QueryResult,
    limit: Optional[int],
    time_range: Optional[str] = None,
) -> dict:
    """Persist a query result and return the stored record."""
    record = {
        "query_id": query.id,
        "name": query.name,
        "status": query.status.value,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "limit": limit,
        "time_range": time_range,
        "row_count": result.row_count,
        "columns": result.columns,
        "rows": result.rows,
    }
    _cache_path(query.id).write_text(json.dumps(record, default=str), encoding="utf-8")
    return record


def load_result(query_id: str) -> Optional[dict]:
    """Return the cached record for a query, or None if there is none."""
    path = _cache_path(query_id)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def cached_at(query_id: str) -> Optional[str]:
    record = load_result(query_id)
    return record.get("ran_at") if record else None
