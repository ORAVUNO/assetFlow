"""Run-and-persist helpers shared by the web API, Fetch-all, and the scheduler.

Keeping the "execute a query, save the fetch, feed the change log" step in one
place means the interactive Run button, the Fetch-all action, and the background
scheduler all behave identically.
"""

from __future__ import annotations

from typing import Optional

from . import db
from . import snapshotdiff
from .adapters import Adapter


def save_result(
    adapter: Adapter,
    query,
    result,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
) -> dict:
    """Persist an already-computed result, feeding the change log for
    change_detail. Use this when the caller has already run the query."""
    rec = db.save_fetch(adapter.info.id, query, result, limit, time_range)
    if getattr(query, "resource", "") == "change_detail":
        rec["new_changes"] = db.record_changes(adapter.info.id, result)
    else:
        drift = _record_drift(adapter, query, result)
        if drift is not None:
            rec["drift"] = drift
    return rec


def _record_drift(adapter: Adapter, query, result) -> Optional[int]:
    """For host-keyed inventory queries, diff this fetch against the previous
    snapshot and record the drift into the deduplicated snapshot-change log.
    Event feeds (with ``@timestamp``) are skipped — their rows are already
    changes. Returns the number of newly recorded drift rows, or None if the
    query isn't an inventory snapshot / has no prior fetch to compare."""
    if not snapshotdiff.is_inventory(result.columns):
        return None
    runs = db.last_two_fetches(adapter.info.id, query.id)
    if len(runs) < 2:
        return None
    new_run, old_run = runs[0], runs[1]
    diff = snapshotdiff.diff_snapshots(old_run, new_run)
    return db.record_snapshot_changes(
        adapter.info.id, query.id, diff["rows"],
        old_run.get("run_id"), new_run.get("run_id"), new_run.get("ran_at"),
    )


def run_and_save(
    adapter: Adapter,
    query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
) -> dict:
    """Run one query, persist the fetch, and (for change_detail) dedupe it into
    the change log. Returns the saved fetch record."""
    result = adapter.run(query, limit=limit, time_range=time_range)
    return save_result(adapter, query, result, limit, time_range)


def run_all(
    adapter: Adapter,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
) -> dict:
    """Run every runnable query for an adapter, saving each. Per-query errors are
    captured so one failure does not abort the rest."""
    results = []
    for q in adapter.registry.queries:
        if not q.is_runnable:
            results.append({"query_id": q.id, "ok": None, "skipped": "placeholder"})
            continue
        try:
            rec = run_and_save(adapter, q, limit=limit, time_range=time_range)
            results.append({
                "query_id": q.id,
                "ok": True,
                "row_count": rec["row_count"],
                "new_changes": rec.get("new_changes"),
            })
        except Exception as exc:
            results.append({"query_id": q.id, "ok": False, "error": str(exc)})
    ok = sum(1 for r in results if r["ok"] is True)
    failed = sum(1 for r in results if r["ok"] is False)
    return {"adapter": adapter.info.id, "ran": ok, "failed": failed, "results": results}
