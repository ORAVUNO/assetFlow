"""Build adapter-wide and platform-wide export bundles.

Two formats, because a bundle spans many queries with different columns:

- **JSON**: one structured file — scope, timestamp, and per-adapter query
  results (columns + rows).
- **ZIP**: a ``manifest.json`` plus one ``<adapter>/<query>.csv`` per saved
  query, for opening in Excel/Sheets.

Each element of ``blocks`` is ``(adapter_info, records)`` where ``adapter_info``
is ``{"id","name","category"}`` and ``records`` are db fetch records that
include ``columns`` and ``rows``.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from typing import List, Tuple

from .runner import QueryResult

Block = Tuple[dict, List[dict]]

_META_KEYS = ("query_id", "name", "status", "ran_at", "limit", "time_range", "row_count")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _adapter_block(info: dict, records: List[dict], include_data: bool) -> dict:
    queries = []
    for rec in records:
        q = {k: rec.get(k) for k in _META_KEYS}
        if include_data:
            q["columns"] = rec.get("columns", [])
            q["rows"] = rec.get("rows", [])
        queries.append(q)
    return {
        "id": info["id"],
        "name": info["name"],
        "category": info["category"],
        "query_count": len(queries),
        "queries": queries,
    }


def build_json(scope: str, blocks: List[Block]) -> str:
    bundle = {
        "exported_at": _now(),
        "scope": scope,
        "adapters": [_adapter_block(info, recs, include_data=True) for info, recs in blocks],
    }
    return json.dumps(bundle, indent=2, default=str)


def build_zip(scope: str, blocks: List[Block]) -> bytes:
    buf = io.BytesIO()
    manifest = {"exported_at": _now(), "scope": scope, "adapters": []}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for info, records in blocks:
            for rec in records:
                result = QueryResult(columns=rec.get("columns", []), rows=rec.get("rows", []))
                z.writestr(f"{info['id']}/{rec['query_id']}.csv", result.to_csv())
            manifest["adapters"].append(_adapter_block(info, records, include_data=False))
        z.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
    return buf.getvalue()
