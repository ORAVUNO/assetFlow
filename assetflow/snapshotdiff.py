"""Detect inventory drift by diffing two saved snapshots of a query.

Elasticsearch's raw-event feeds (anything with an ``@timestamp`` column) already
*are* change events — each row is a change. The **aggregation / inventory**
feeds (users per host, applications per host, database engines, …) instead
describe *current state*, so "what changed" is computed by comparing the two
most recent saved snapshots of that query in ``fetch_runs``. This is the
Elasticsearch analogue of the Tufin revision diff.

The diff is expressed as **facts** per host: ``(attribute, value)`` pairs drawn
from the identifying columns — ``*.name``/``*Name`` fields and list-valued
(``VALUES()``) columns — while volatile metrics (counts, last-seen timestamps)
are ignored so they don't read as changes. A fact present in the new snapshot
but not the old is ``added``; the reverse is ``removed``.
"""

from __future__ import annotations

from typing import List, Optional, Set, Tuple

HOST_KEY = "host.name"
EVENT_MARKER = "@timestamp"  # its presence marks a raw-event feed (not inventory)

# Columns never treated as identifying (volatile / non-entity).
_SKIP_SUFFIXES = ("Count",)
_SKIP_PREFIXES = ("Last",)
_SKIP_EXACT = {"host.ip", "@timestamp"}


def is_inventory(columns: List[dict]) -> bool:
    """True when a result is a host-keyed inventory snapshot worth diffing."""
    names = [c.get("name") for c in columns]
    return HOST_KEY in names and EVENT_MARKER not in names


def _col_index(columns: List[dict], name: str) -> Optional[int]:
    for i, c in enumerate(columns):
        if c.get("name") == name:
            return i
    return None


def _diffable_indices(columns: List[dict], rows: List[list], host_idx: int) -> List[int]:
    out: List[int] = []
    for i, c in enumerate(columns):
        if i == host_idx:
            continue
        name = str(c.get("name", ""))
        if name in _SKIP_EXACT or name.startswith(_SKIP_PREFIXES) or name.endswith(_SKIP_SUFFIXES):
            continue
        is_list = any(i < len(r) and isinstance(r[i], list) for r in rows)
        name_like = name.endswith(".name") or "Name" in name or name in (
            "Applications", "Hosts", "DatabaseProcesses",
        )
        if is_list or name_like:
            out.append(i)
    # Fallback: if nothing looked identifying, diff every non-skipped column.
    if not out:
        for i, c in enumerate(columns):
            if i == host_idx:
                continue
            name = str(c.get("name", ""))
            if name in _SKIP_EXACT or name.startswith(_SKIP_PREFIXES) or name.endswith(_SKIP_SUFFIXES):
                continue
            out.append(i)
    return out


def _facts(rec: dict) -> dict:
    """Build ``host -> {(attribute, value)}`` from a fetch record."""
    columns = rec.get("columns", [])
    rows = rec.get("rows", [])
    host_idx = _col_index(columns, HOST_KEY)
    facts: dict = {}
    if host_idx is None:
        return facts
    diffable = _diffable_indices(columns, rows, host_idx)
    for row in rows:
        if host_idx >= len(row) or row[host_idx] in (None, ""):
            continue
        host = str(row[host_idx])
        bucket: Set[Tuple[str, str]] = facts.setdefault(host, set())
        for i in diffable:
            if i >= len(row):
                continue
            cell = row[i]
            attr = str(columns[i].get("name", ""))
            values = cell if isinstance(cell, list) else [cell]
            for v in values:
                if v not in (None, ""):
                    bucket.add((attr, str(v)))
    return facts


def diff_snapshots(old_rec: dict, new_rec: dict) -> dict:
    """Diff two fetch records into per-host added/removed facts.

    Returns ``{columns, rows, added, removed}`` where each row is
    ``[host.name, attribute, change_type, value]``. Non-inventory results (no
    ``host.name``, or an event feed) yield no rows.
    """
    columns = [{"name": n} for n in ("host.name", "attribute", "change_type", "value")]
    if not is_inventory(new_rec.get("columns", [])):
        return {"columns": columns, "rows": [], "added": 0, "removed": 0}

    old = _facts(old_rec)
    new = _facts(new_rec)
    rows: List[list] = []
    added = removed = 0
    for host in sorted(set(old) | set(new)):
        o = old.get(host, set())
        n = new.get(host, set())
        for attr, value in sorted(n - o):
            rows.append([host, attr, "added", value])
            added += 1
        for attr, value in sorted(o - n):
            rows.append([host, attr, "removed", value])
            removed += 1
    return {"columns": columns, "rows": rows, "added": added, "removed": removed}
