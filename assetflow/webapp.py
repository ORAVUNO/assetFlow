"""Local web UI: pick an adapter (grouped by category), open its panel, fetch.

Run with ``assetflow serve``. Binds to 127.0.0.1 by default, so the app, your
credentials, and your data stay on your machine. Fetched results are persisted
to a local SQLite database (see db.py); the newest run per (adapter, query) is
the panel's cached view, older runs are history.
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException, Query as QueryParam
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from datetime import datetime, timezone

from . import adapters as adapters_mod
from . import db
from . import export as export_mod
from . import merge as merge_mod
from . import scheduler as scheduler_mod
from . import service as service_mod
from . import snapshotdiff as snapshotdiff_mod
from . import tufin_profile as tufin_profile_mod
from . import tufin_runner as tufin_runner_mod
from .runner import QueryResult

_state: dict = {"manager": None}


class ConnectRequest(BaseModel):
    host: str = ""
    port: str = ""
    url: str = ""
    cloud_id: str = ""
    username: str = ""
    password: str = ""
    api_key: str = ""
    base_path: str = ""  # Tufin SecureTrack API base path
    verify_certs: bool = True
    request_timeout: int = 60
    remember: bool = False  # opt-in: save this connection to .env on success


class ConnectionCreateRequest(BaseModel):
    kind: str
    label: str = ""


class ConnectionRenameRequest(BaseModel):
    label: str


class ScheduleRequest(BaseModel):
    adapter: str
    query_id: str = "*"       # "*" = every runnable query for the adapter
    interval_seconds: int = 600
    time_range: str = ""
    limit: Optional[int] = None
    enabled: bool = True


def _manager() -> adapters_mod.AdapterManager:
    return _state["manager"]


def _get_adapter(adapter_id: str) -> adapters_mod.Adapter:
    try:
        return _manager().get(adapter_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown adapter {adapter_id}")


def _query_public(adapter: adapters_mod.Adapter, query) -> dict:
    last = db.latest_fetch(adapter.info.id, query.id, include_data=False)
    return {
        "id": query.id,
        "name": query.name,
        "category": query.category,
        "status": query.status.value,
        "validated": query.validated,
        "purpose": query.purpose,
        "notes": query.notes,
        "esql_query": query.esql_query,
        "resource": query.resource,
        "expected_output_fields": query.expected_output_fields,
        "recommended_refresh_frequency": query.recommended_refresh_frequency,
        "is_runnable": query.is_runnable,
        "last_fetch": last,  # None or {ran_at, row_count, ...}
    }


def create_app(
    registry_path: Optional[str] = None,
    db_url: Optional[str] = None,
    start_scheduler: bool = False,
) -> FastAPI:
    db.init_engine(db_url)

    # Adapter kinds are templates; connections (instances) are persisted in the
    # database so multiple instances of a kind — e.g. two Tufin servers — survive
    # restarts. On a fresh database, seed one default connection per kind.
    kinds = adapters_mod.available_kinds(registry_path)
    manager = adapters_mod.AdapterManager(kinds)
    conns = db.list_connections()
    if not conns:
        for kind in kinds.values():
            db.add_connection(kind.kind, kind.kind, kind.name)
        conns = db.list_connections()
    for c in conns:
        if c["kind"] in kinds:
            manager.add_instance(c["kind"], c["label"], instance_id=c["id"])
    _state["manager"] = manager

    # Best-effort auto-connect: remembered credentials first, else (for the
    # default per-kind instance) environment variables.
    for adapter in manager.list():
        secrets = db.get_connection_secrets(adapter.info.id)
        if secrets:
            try:
                adapter.connect_form(secrets)
                continue
            except Exception:
                pass
        if adapter.info.id == adapter.info.kind:
            adapter.try_auto_connect()

    if start_scheduler:
        _state["scheduler"] = scheduler_mod.Scheduler(manager).start()

    app = FastAPI(title="assetFlow", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return INDEX_HTML

    @app.get("/api/adapters")
    def api_adapters() -> dict:
        cats = manager.by_category()
        return {
            "categories": [
                {
                    "name": cat,
                    "adapters": [
                        {
                            "id": a.info.id,
                            "name": a.info.name,
                            "kind": a.info.kind,
                            "description": a.info.description,
                            "connected": a.connected,
                            "query_count": len(a.registry.queries),
                            "feed_count": len(a.registry.feeds),
                        }
                        for a in adapters
                    ],
                }
                for cat, adapters in cats.items()
            ]
        }

    @app.get("/api/kinds")
    def api_kinds() -> dict:
        """Adapter kinds that can be instantiated as new connections."""
        return {
            "kinds": [
                {
                    "kind": k.kind,
                    "name": k.name,
                    "category": k.category,
                    "description": k.description,
                }
                for k in manager.kinds()
            ]
        }

    @app.post("/api/connections")
    def api_connection_create(req: "ConnectionCreateRequest") -> dict:
        try:
            kind = manager.get_kind(req.kind)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown adapter kind {req.kind}")
        adapter = manager.add_instance(kind.kind, req.label or kind.name)
        db.add_connection(adapter.info.id, adapter.info.kind, adapter.info.name)
        return {"id": adapter.info.id, "name": adapter.info.name, "kind": adapter.info.kind}

    @app.patch("/api/connections/{adapter_id}")
    def api_connection_rename(adapter_id: str, req: "ConnectionRenameRequest") -> dict:
        a = _get_adapter(adapter_id)
        manager.rename(adapter_id, req.label)
        db.update_connection_label(adapter_id, a.info.name)
        return {"id": a.info.id, "name": a.info.name}

    @app.delete("/api/connections/{adapter_id}")
    def api_connection_delete(adapter_id: str) -> dict:
        _get_adapter(adapter_id)
        manager.remove(adapter_id)
        db.delete_connection(adapter_id)
        return {"ok": True}

    @app.get("/api/adapters/{adapter_id}")
    def api_adapter(adapter_id: str) -> dict:
        a = _get_adapter(adapter_id)
        reg = a.registry
        return {
            "id": a.info.id,
            "name": a.info.name,
            "category": a.info.category,
            "description": a.info.description,
            "kind": a.info.kind,
            "connected": a.connected,
            "conn_info": a.conn_info,
            "has_saved": db.get_connection_secrets(a.info.id) is not None,
            "feeds": [
                {
                    "id": f.id,
                    "name": f.name,
                    "category": f.category,
                    "description": f.description,
                    "recommended_refresh_frequency": f.recommended_refresh_frequency,
                    "query_ids": f.query_ids,
                }
                for f in reg.feeds
            ],
            "queries": [_query_public(a, q) for q in reg.queries],
        }

    @app.post("/api/adapters/{adapter_id}/connect")
    def api_connect(adapter_id: str, req: ConnectRequest) -> JSONResponse:
        a = _get_adapter(adapter_id)
        form = req.model_dump()
        try:
            info = a.connect_form(form)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=200)
        saved = False
        if req.remember:
            try:
                # Persist this instance's connection form (minus the flag) so it
                # reconnects on restart. Local plaintext, same posture as .env.
                secrets = {k: v for k, v in form.items() if k != "remember"}
                db.set_connection_secrets(a.info.id, secrets)
                saved = True
            except Exception:
                saved = False  # persistence is best-effort; the connection stands
        return JSONResponse({"ok": True, "saved": saved, **info})

    @app.delete("/api/adapters/{adapter_id}/saved-connection")
    def api_forget_connection(adapter_id: str) -> dict:
        a = _get_adapter(adapter_id)
        db.set_connection_secrets(a.info.id, None)
        return {"ok": True}

    @app.post("/api/adapters/{adapter_id}/run/{query_id}")
    def api_run(
        adapter_id: str,
        query_id: str,
        limit: Optional[int] = QueryParam(default=None, ge=1),
        range: Optional[str] = QueryParam(default=None),
    ) -> dict:
        a = _get_adapter(adapter_id)
        try:
            query = a.registry.get_query(query_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown query {query_id}")
        if not query.is_runnable:
            raise HTTPException(
                status_code=422,
                detail=f"{query.id} has no query defined (status {query.status.value})",
            )
        if not a.connected:
            raise HTTPException(status_code=400, detail="adapter is not connected")
        try:
            result = a.run(query, limit=limit, time_range=range)
        except Exception as exc:
            detail = f"query failed: {exc}"
            if "timeout" in str(exc).lower():
                detail += (
                    " — this query is heavy; raise the Timeout in the Connection "
                    "panel (e.g. 180s) and reconnect, or pick a smaller time range."
                )
            raise HTTPException(status_code=502, detail=detail)
        # Persist the fetch (and, for change_detail, dedupe into the change log).
        return service_mod.save_result(a, query, result, limit, range)

    @app.post("/api/adapters/{adapter_id}/run-all")
    def api_run_all(
        adapter_id: str,
        limit: Optional[int] = QueryParam(default=None, ge=1),
        range: Optional[str] = QueryParam(default=None),
    ) -> dict:
        a = _get_adapter(adapter_id)
        if not a.connected:
            raise HTTPException(status_code=400, detail="adapter is not connected")
        return service_mod.run_all(a, limit=limit, time_range=range)

    @app.get("/api/scheduler")
    def api_scheduler() -> dict:
        sch = _state.get("scheduler")
        if sch is None:
            return {"running": False}
        return sch.status()

    @app.get("/api/schedules")
    def api_schedules() -> dict:
        return {"schedules": db.list_schedules()}

    @app.post("/api/schedules")
    def api_schedule_create(req: ScheduleRequest) -> dict:
        _get_adapter(req.adapter)  # 404 if the adapter is unknown
        return db.add_schedule(
            adapter=req.adapter,
            query_id=(req.query_id or "*"),
            interval_seconds=max(1, int(req.interval_seconds)),
            time_range=(req.time_range or None),
            limit=req.limit,
            enabled=req.enabled,
        )

    @app.post("/api/schedules/{schedule_id}/toggle")
    def api_schedule_toggle(schedule_id: int, enabled: bool = QueryParam(...)) -> dict:
        rec = db.set_schedule_enabled(schedule_id, enabled)
        if rec is None:
            raise HTTPException(status_code=404, detail="unknown schedule")
        return rec

    @app.delete("/api/schedules/{schedule_id}")
    def api_schedule_delete(schedule_id: int) -> dict:
        if not db.delete_schedule(schedule_id):
            raise HTTPException(status_code=404, detail="unknown schedule")
        return {"ok": True}

    @app.get("/api/adapters/{adapter_id}/latest/{query_id}")
    def api_latest(adapter_id: str, query_id: str) -> dict:
        _get_adapter(adapter_id)
        rec = db.latest_fetch(adapter_id, query_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="no saved result; run the query first")
        return rec

    @app.get("/api/adapters/{adapter_id}/history/{query_id}")
    def api_history(adapter_id: str, query_id: str) -> dict:
        _get_adapter(adapter_id)
        return {"runs": db.history(adapter_id, query_id)}

    @app.get("/api/adapters/{adapter_id}/changelog")
    def api_changelog(adapter_id: str) -> dict:
        _get_adapter(adapter_id)
        return db.change_log(adapter_id)

    @app.get("/api/adapters/{adapter_id}/change-dashboard")
    def api_change_dashboard(adapter_id: str) -> dict:
        _get_adapter(adapter_id)
        dash = db.change_dashboard(adapter_id)
        # Inventory context from the latest saved fetches (best-effort per id).
        def _count(*qids):
            for qid in qids:
                rec = db.latest_fetch(adapter_id, qid, include_data=False)
                if rec is not None:
                    return {"value": rec["row_count"], "query_id": qid, "ran_at": rec["ran_at"]}
            return None
        dash["inventory"] = {
            "devices": _count("TUF001"),
            "rules": _count("TUF003"),
            "cleanup": _count("TUF007"),
        }
        return dash

    # The revision Compare/Policy views read the SAVED "Revision Rulebases"
    # (TUF009) snapshot from the DB — no live SecureTrack call — so they work
    # offline and stay consistent with the rest of the fetch-then-view model.
    _REVISION_RULES_QID = "TUF009"

    def _saved_revision_rules(adapter_id: str) -> dict:
        _get_adapter(adapter_id)  # 404 on unknown adapter
        rec = db.latest_fetch(adapter_id, _REVISION_RULES_QID)
        if rec is None:
            raise HTTPException(
                status_code=404,
                detail="No saved rulebase snapshot — run TUF009 (Revision Rulebases) first.",
            )
        return rec

    @app.get("/api/adapters/{adapter_id}/tufin/revision-index")
    def api_tufin_revision_index(adapter_id: str) -> dict:
        rec = _saved_revision_rules(adapter_id)
        return {
            "ran_at": rec.get("ran_at"),
            "devices": tufin_runner_mod.index_revision_rules(rec["columns"], rec["rows"]),
        }

    @app.get("/api/adapters/{adapter_id}/tufin/revision-compare")
    def api_tufin_revision_compare(
        adapter_id: str,
        device_id: str = QueryParam(...),
        old_rev: Optional[str] = QueryParam(default=None),
        new_rev: Optional[str] = QueryParam(default=None),
    ) -> dict:
        rec = _saved_revision_rules(adapter_id)
        obj = db.latest_fetch(adapter_id, "TUF010")  # optional network-object snapshot
        out = tufin_runner_mod.compare_from_saved(
            rec["columns"], rec["rows"], device_id, old_rev=old_rev, new_rev=new_rev,
            object_columns=(obj["columns"] if obj else None),
            object_rows=(obj["rows"] if obj else None),
        )
        out["ran_at"] = rec.get("ran_at")
        out["objects_ran_at"] = obj.get("ran_at") if obj else None
        return out

    @app.get("/api/adapters/{adapter_id}/tufin/revision-policy")
    def api_tufin_revision_policy(
        adapter_id: str,
        device_id: str = QueryParam(...),
        revision_id: Optional[str] = QueryParam(default=None),
    ) -> dict:
        rec = _saved_revision_rules(adapter_id)
        out = tufin_runner_mod.policy_from_saved(
            rec["columns"], rec["rows"], device_id, revision_id=revision_id
        )
        out["ran_at"] = rec.get("ran_at")
        return out

    def _build_tufin_profile(a: adapters_mod.Adapter) -> dict:
        """Fold every latest saved Tufin fetch + the change log into one profile."""
        recs = db.latest_all(a.info.id, include_data=True)
        sections: dict = {}
        for rec in recs:
            try:
                q = a.registry.get_query(rec["query_id"])
            except KeyError:
                continue
            res = (q.resource or "").strip()
            # One saved table per resource; if two query ids share a resource,
            # keep the richer (more rows) one.
            if res and (res not in sections or rec["row_count"] > sections[res]["row_count"]):
                sections[res] = rec
        changes = db.change_log(a.info.id)
        return tufin_profile_mod.build_profile(
            sections, changes, datetime.now(timezone.utc).isoformat()
        )

    @app.get("/api/adapters/{adapter_id}/tufin/profile")
    def api_tufin_profile(adapter_id: str) -> dict:
        a = _get_adapter(adapter_id)
        if a.info.kind != "tufin":
            raise HTTPException(status_code=400, detail="not a Tufin adapter")
        return _build_tufin_profile(a)

    @app.post("/api/adapters/{adapter_id}/tufin/discover")
    def api_tufin_discover(adapter_id: str) -> dict:
        a = _get_adapter(adapter_id)
        if a.info.kind != "tufin":
            raise HTTPException(status_code=400, detail="not a Tufin adapter")
        if not a.connected:
            raise HTTPException(status_code=400, detail="adapter is not connected")
        run = service_mod.run_all(a)  # fetch + save + dedupe every runnable feed
        profile = _build_tufin_profile(a)
        profile["discover"] = run
        return profile

    @app.get("/api/adapters/{adapter_id}/drift")
    def api_drift(adapter_id: str) -> dict:
        _get_adapter(adapter_id)
        return db.snapshot_change_log(adapter_id)

    @app.get("/api/adapters/{adapter_id}/change-detail/{query_id}")
    def api_change_detail(adapter_id: str, query_id: str) -> dict:
        _get_adapter(adapter_id)
        runs = db.last_two_fetches(adapter_id, query_id)
        if len(runs) < 2:
            raise HTTPException(
                status_code=404,
                detail="need at least two saved fetches of this query to diff",
            )
        diff = snapshotdiff_mod.diff_snapshots(runs[1], runs[0])  # (old, new)
        diff["ran_at"] = runs[0].get("ran_at")
        diff["prev_ran_at"] = runs[1].get("ran_at")
        return diff

    @app.get("/api/adapters/{adapter_id}/merged")
    def api_merged(adapter_id: str) -> dict:
        a = _get_adapter(adapter_id)
        recs = db.latest_all(adapter_id, include_data=True)
        by_qid = {r["query_id"]: r for r in recs}
        main = merge_mod.build_host_view(recs)
        sheets = []
        for feed in a.registry.feeds:
            queries = []
            for qid in feed.query_ids:
                q = a.registry.get_query(qid)
                rec = by_qid.get(qid)
                queries.append(
                    {
                        "query_id": qid,
                        "name": q.name,
                        "status": q.status.value,
                        "has_data": rec is not None,
                        "row_count": rec["row_count"] if rec else 0,
                        "ran_at": rec["ran_at"] if rec else None,
                        "columns": rec["columns"] if rec else [],
                        "rows": rec["rows"] if rec else [],
                    }
                )
            sheets.append({"feed_id": feed.id, "feed_name": feed.name, "queries": queries})
        return {"main": main, "sheets": sheets}

    @app.get("/api/adapters/{adapter_id}/merged.{fmt}")
    def api_merged_export(adapter_id: str, fmt: str) -> Response:
        _get_adapter(adapter_id)
        recs = db.latest_all(adapter_id, include_data=True)
        main = merge_mod.build_host_view(recs)
        result = QueryResult(columns=main["columns"], rows=main["rows"])
        if fmt == "csv":
            return Response(
                content=result.to_csv(),
                media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="{adapter_id}-unified.csv"'},
            )
        if fmt == "json":
            return Response(
                content=result.to_json(),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{adapter_id}-unified.json"'},
            )
        raise HTTPException(status_code=400, detail="format must be csv or json")

    def _blocks(adapter_id: Optional[str]) -> list:
        adapters = [_get_adapter(adapter_id)] if adapter_id else manager.list()
        blocks = []
        for a in adapters:
            info = {"id": a.info.id, "name": a.info.name,
                    "category": a.info.category, "kind": a.info.kind}
            blocks.append((info, db.latest_all(a.info.id, include_data=True)))
        return blocks

    def _bundle_response(scope: str, blocks: list, fmt: str, stem: str) -> Response:
        date = datetime.now(timezone.utc).strftime("%Y%m%d")
        if fmt == "json":
            return Response(
                content=export_mod.build_json(scope, blocks),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{stem}-{date}.json"'},
            )
        if fmt == "zip":
            return Response(
                content=export_mod.build_zip(scope, blocks),
                media_type="application/zip",
                headers={"Content-Disposition": f'attachment; filename="{stem}-{date}.zip"'},
            )
        raise HTTPException(status_code=400, detail="format must be json or zip")

    def _check_type(asset_type: str) -> str:
        if asset_type not in merge_mod.ASSET_TYPES:
            raise HTTPException(status_code=404, detail=f"unknown asset type {asset_type}")
        return asset_type

    @app.get("/api/inventory/types")
    def api_inventory_types() -> dict:
        """Asset types and how many correlated assets of each the data yields."""
        return {"types": merge_mod.inventory_types(_blocks(None))}

    @app.get("/api/inventory")
    def api_inventory(type: str = QueryParam(default=merge_mod.DEFAULT_TYPE)) -> dict:
        """Cross-adapter unified inventory for one asset type (device / user /
        application): one asset per correlated entity, with the adapters that saw
        it. Assets seen by multiple adapters surface first."""
        return merge_mod.build_unified_inventory(_blocks(None), _check_type(type))

    @app.get("/api/inventory.{fmt}")
    def api_inventory_export(
        fmt: str, type: str = QueryParam(default=merge_mod.DEFAULT_TYPE)
    ) -> Response:
        inv = merge_mod.build_unified_inventory(_blocks(None), _check_type(type))
        result = QueryResult(columns=inv["columns"], rows=inv["rows"])
        stem = f"assetflow-inventory-{type}"
        if fmt == "csv":
            return Response(
                content=result.to_csv(),
                media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="{stem}.csv"'},
            )
        if fmt == "json":
            return Response(
                content=result.to_json(),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{stem}.json"'},
            )
        raise HTTPException(status_code=400, detail="format must be csv or json")

    @app.get("/api/inventory/asset")
    def api_inventory_asset(
        host: str = QueryParam(..., min_length=1),
        type: str = QueryParam(default=merge_mod.DEFAULT_TYPE),
    ) -> dict:
        """Full cross-adapter detail for one asset: aggregated/preferred fields
        (tagged common vs adapter-specific) and per-query mini tables."""
        detail = merge_mod.build_asset_detail(_blocks(None), host, _check_type(type))
        if not detail["found"]:
            raise HTTPException(status_code=404, detail=f"no saved {type} data for {host!r}")
        return detail

    @app.get("/api/export-all.{fmt}")
    def api_export_platform(fmt: str) -> Response:
        return _bundle_response("platform", _blocks(None), fmt, "assetflow-export")

    @app.get("/api/adapters/{adapter_id}/export-all.{fmt}")
    def api_export_adapter(adapter_id: str, fmt: str) -> Response:
        _get_adapter(adapter_id)
        return _bundle_response(f"adapter:{adapter_id}", _blocks(adapter_id), fmt, f"{adapter_id}-export")

    @app.get("/api/adapters/{adapter_id}/export/{query_id}.{fmt}")
    def api_export(adapter_id: str, query_id: str, fmt: str) -> Response:
        _get_adapter(adapter_id)
        rec = db.latest_fetch(adapter_id, query_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="no saved result; run the query first")
        result = QueryResult(columns=rec["columns"], rows=rec["rows"])
        if fmt == "csv":
            return Response(
                content=result.to_csv(),
                media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="{query_id}.csv"'},
            )
        if fmt == "json":
            return Response(
                content=result.to_json(),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{query_id}.json"'},
            )
        raise HTTPException(status_code=400, detail="format must be csv or json")

    return app


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>assetFlow</title>
<style>
  :root{
    --bg:#f6f7f9; --panel:#fff; --border:#e3e6ea; --text:#1c2128; --muted:#66707a;
    --accent:#2f6feb; --accent-fg:#fff; --row:#fafbfc; --code:#f0f2f5;
    --ok:#1a7f37; --warn:#9a6700; --info:#4b5563; --bad:#b42318;
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#0d1117; --panel:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e;
      --accent:#4f8cf7; --accent-fg:#fff; --row:#12171e; --code:#0b0f14;
      --ok:#3fb950; --warn:#d29922; --info:#9aa4af; --bad:#f85149;
    }
  }
  *{box-sizing:border-box}
  body{margin:0;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       background:var(--bg);color:var(--text)}
  header{display:flex;align-items:center;gap:10px;padding:12px 18px;background:var(--panel);
         border-bottom:1px solid var(--border);position:sticky;top:0;z-index:5}
  header h1{font-size:16px;margin:0;font-weight:650;cursor:pointer}
  #crumb{color:var(--muted);font-size:14px}
  #conn{margin-left:auto;font-size:12px;color:var(--muted)}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;background:var(--muted)}
  .dot.ok{background:var(--ok)} .dot.bad{background:var(--bad)}
  #conntoggle,#fetchall,#schedbtn{background:transparent;color:var(--accent);border:1px solid var(--border);
              padding:5px 12px;font-size:12px;font-weight:600;border-radius:7px;cursor:pointer}
  #fetchall{color:var(--accent-fg);background:var(--accent);border-color:var(--accent)}
  .schedrow{display:flex;align-items:center;gap:10px;padding:6px 0;font-size:12.5px;border-top:1px solid var(--border)}
  .schedrow .sdel{color:var(--bad);cursor:pointer;font-weight:600}
  .schedrow .stog{cursor:pointer;color:var(--accent);font-weight:600}
  .hidden{display:none !important}
  /* connection panel */
  .connpanel{background:var(--panel);border-bottom:1px solid var(--border);padding:14px 18px}
  .connrow{display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end}
  .connrow label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--muted)}
  .connrow input[type=text],.connrow input[type=password]{min-width:200px}
  .connrow .chk{flex-direction:row;align-items:center;gap:6px;color:var(--text)}
  .cstat{margin-top:10px;font-size:12.5px;min-height:18px}
  .chint{margin-top:6px;font-size:11.5px;color:var(--muted)}
  input,select{padding:7px 9px;border:1px solid var(--border);border-radius:7px;
               background:var(--panel);color:var(--text)}
  button{background:var(--accent);color:var(--accent-fg);border:0;border-radius:7px;
         padding:8px 16px;font-size:13px;font-weight:600;cursor:pointer}
  button:disabled{opacity:.5;cursor:not-allowed}
  /* export links */
  .exp{font-size:12px;color:var(--muted)} .exp a{color:var(--accent);font-weight:600;text-decoration:none}
  .exp a:hover{text-decoration:underline}
  .gbar{display:flex;align-items:center;gap:8px;padding:2px 2px 6px;font-size:13px;color:var(--muted)}
  /* gallery */
  #gallery{padding:22px}
  .gcat{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
        margin:18px 0 10px}
  .cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:11px;padding:16px;
        cursor:pointer;transition:border-color .12s,transform .12s}
  .card:hover{border-color:var(--accent);transform:translateY(-1px)}
  .card h3{margin:0 0 4px;font-size:15px;display:flex;align-items:center;gap:8px}
  .card p{margin:6px 0 12px;color:var(--muted);font-size:12.5px;min-height:34px}
  .card .foot{display:flex;justify-content:space-between;align-items:center;font-size:11.5px;color:var(--muted)}
  .cardactions{display:flex;gap:14px;margin-top:10px;padding-top:9px;border-top:1px solid var(--border);font-size:11.5px}
  .cardactions span{color:var(--accent);cursor:pointer;font-weight:600}
  .cardactions span.danger{color:var(--bad)}
  .kind{font-size:10px;padding:1px 7px;border-radius:20px;background:var(--code);color:var(--muted);font-weight:600}
  /* workspace */
  .wrap{display:flex;min-height:calc(100vh - 49px)}
  aside{width:300px;flex:none;border-right:1px solid var(--border);background:var(--panel);
        overflow:auto;max-height:calc(100vh - 49px);position:sticky;top:49px}
  .feed{padding:8px 14px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;
        color:var(--muted);border-top:1px solid var(--border)}
  .q{padding:8px 14px;cursor:pointer;border-left:3px solid transparent;display:flex;
     justify-content:space-between;gap:8px;align-items:center}
  .q:hover{background:var(--row)} .q.active{background:var(--row);border-left-color:var(--accent)}
  .q .qid{font-weight:600;font-size:12px} .q .qname{color:var(--muted);font-size:12px}
  main{flex:1;padding:20px;overflow:auto;max-height:calc(100vh - 49px)}
  .badge{font-size:10.5px;padding:1px 7px;border-radius:20px;font-weight:600;white-space:nowrap}
  .b-validated{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
  .b-partially_validated{background:color-mix(in srgb,var(--warn) 20%,transparent);color:var(--warn)}
  .b-investigation_required{background:color-mix(in srgb,var(--info) 20%,transparent);color:var(--info)}
  .b-not_validated{background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)}
  h2{margin:0 0 2px;font-size:20px} .sub{color:var(--muted);margin-bottom:14px}
  pre{background:var(--code);border:1px solid var(--border);border-radius:8px;padding:12px;
      overflow:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
  .controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:14px 0}
  input[type=number]{width:90px}
  .meta{font-size:12px;color:var(--muted);margin:6px 0}
  .tablewrap{overflow:auto;border:1px solid var(--border);border-radius:8px;margin-top:10px}
  table{border-collapse:collapse;width:100%;font-size:12.5px}
  th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);white-space:nowrap}
  th{background:var(--panel);position:sticky;top:0;cursor:pointer;user-select:none}
  th:hover{color:var(--accent)} tr:nth-child(even) td{background:var(--row)}
  .err{color:var(--bad);background:color-mix(in srgb,var(--bad) 10%,transparent);
       border:1px solid color-mix(in srgb,var(--bad) 30%,transparent);border-radius:8px;padding:10px 12px}
  .hint{color:var(--muted)} .fields{font-size:12px;color:var(--muted)}
  a.dl{font-size:12px} .savedtag{color:var(--ok);font-size:11px;margin-left:6px}
  .ov .qid{color:var(--accent)}
  .tfilter{margin:4px 0 6px;min-width:220px}
  .minihdr{margin:14px 0 4px;font-size:13px;font-weight:600}
  .minihdr.dim{color:var(--muted);font-weight:500}
  .sheethdr{margin:18px 0 2px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  .mini table{font-size:12px}
  /* revision comparison */
  .rcbar{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin:8px 0 4px}
  .rcbar label{display:flex;flex-direction:column;gap:3px;font-size:11px;color:var(--muted)}
  .rcbar select{min-width:150px}
  .rctag{display:inline-block;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;
         padding:1px 7px;border-radius:5px;white-space:nowrap}
  .rc-added{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
  .rc-removed{background:color-mix(in srgb,var(--bad) 14%,transparent);color:var(--bad)}
  .rc-modified{background:color-mix(in srgb,var(--warn) 20%,transparent);color:var(--warn)}
  .rc-moved{background:color-mix(in srgb,var(--accent) 16%,transparent);color:var(--accent)}
  tr.row-added td{background:color-mix(in srgb,var(--ok) 7%,transparent)}
  tr.row-removed td{background:color-mix(in srgb,var(--bad) 7%,transparent)}
  tr.row-modified td{background:color-mix(in srgb,var(--warn) 8%,transparent)}
  tr.row-moved td{background:color-mix(in srgb,var(--accent) 7%,transparent)}
  .rcfld{white-space:normal;max-width:340px}
  .rcfld .chg{background:color-mix(in srgb,var(--warn) 22%,transparent);border-radius:3px;padding:0 2px}
  .rcfld .b4{color:var(--muted);text-decoration:line-through}
  .rcfld .af{color:var(--text);font-weight:600}
  .rcfld .arw{color:var(--muted);padding:0 4px}
  /* discover / unified profile */
  .advtoggle{cursor:pointer;user-select:none;color:var(--accent)}
  .advtoggle:hover{color:var(--text)}
  .ghostbtn{background:transparent;color:var(--accent);border:1px solid var(--border)}
  .atchip{display:inline-block;font-size:12px;padding:3px 10px;margin:0 6px 6px 0;border-radius:20px;
          background:var(--code);border:1px solid var(--border)}
  .atchip b{color:var(--accent)}
  tr.devrow{cursor:pointer}
  tr.devrow:hover td{background:color-mix(in srgb,var(--accent) 8%,transparent)}
  tr.devrow.open td{background:color-mix(in srgb,var(--accent) 12%,transparent);font-weight:600}
  td.exptoggle{width:22px;color:var(--muted);text-align:center}
  .devdetinner{padding:10px 6px 14px}
  .dtabs{display:flex;gap:6px;flex-wrap:wrap;margin:2px 0 8px}
  .dtab{background:var(--code);color:var(--text);border:1px solid var(--border);border-radius:7px;
        padding:5px 12px;font-size:12px;font-weight:600;cursor:pointer}
  .dtab.active{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}
  /* unified inventory */
  tr.multi td{background:color-mix(in srgb,var(--accent) 12%,transparent) !important;font-weight:600}
  .invbtn{background:var(--accent);color:var(--accent-fg);border:0;border-radius:7px;
          padding:6px 14px;font-size:12.5px;font-weight:600;cursor:pointer}
  .backlink{color:var(--accent);cursor:pointer;font-weight:600}
  .typeswitch{display:flex;gap:8px;margin:12px 0 4px;flex-wrap:wrap}
  .typepill{background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:20px;
            padding:6px 14px;font-size:12.5px;font-weight:600;cursor:pointer}
  .typepill.active{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}
  .typepill .pilln{opacity:.7;font-weight:500;margin-left:4px}
  .typepill.active .pilln{opacity:.85}
  .scopetag{font-size:10px;padding:1px 7px;border-radius:20px;font-weight:600;white-space:nowrap}
  .scopetag.common{background:color-mix(in srgb,var(--accent) 18%,transparent);color:var(--accent)}
  .scopetag.specific{background:color-mix(in srgb,var(--info) 20%,transparent);color:var(--info)}
  .scopetag.conflict{background:color-mix(in srgb,var(--warn) 22%,transparent);color:var(--warn)}
  details.asset-det{border:1px solid var(--border);border-radius:8px;margin:8px 0;background:var(--panel)}
  details.asset-det>summary{cursor:pointer;padding:9px 12px;font-size:12.5px;font-weight:600;user-select:none}
  details.asset-det[open]>summary{border-bottom:1px solid var(--border)}
  details.asset-det .mini{padding:10px 12px}
  /* adapter source logos, pinned Source column, trimmed/expandable cells */
  .srclogo{border-radius:5px;display:inline-block;vertical-align:middle;flex:none}
  .card h3 .srclogo{margin-right:2px}
  th{z-index:5}
  th.pin,td.pin{position:sticky;left:0;background:var(--panel);box-shadow:1px 0 0 var(--border)}
  td.pin{z-index:3} th.pin{top:0;z-index:8}
  tr:nth-child(even) td.pin{background:var(--row)}
  tr.multi td.pin{background:color-mix(in srgb,var(--accent) 12%,transparent) !important}
  .srcwrap{display:inline-flex;align-items:center;gap:6px;max-width:190px}
  .srcwrap .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--muted)}
  td .cell{display:inline-block;max-width:340px;overflow:hidden;text-overflow:ellipsis;
           white-space:nowrap;vertical-align:bottom}
  td .cell.list,td .cell.long{cursor:pointer}
  td .cell.list::after{content:'▸';color:var(--accent);font-size:10px;margin-left:3px}
  td .cell.open{max-width:560px;white-space:normal;overflow:visible;word-break:break-word}
  td .cell.open.list::after{content:'▾'}
  /* unified-inventory breakdown chips + collapsible groups */
  .chiprow{display:flex;flex-wrap:wrap;gap:7px;margin:8px 0;align-items:center}
  .chiplabel{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-right:2px}
  .chip{display:inline-flex;align-items:center;gap:6px;background:var(--panel);border:1px solid var(--border);
        border-radius:20px;padding:4px 11px;font-size:12px;cursor:pointer;color:var(--text)}
  .chip:hover{border-color:var(--accent)}
  .chip.active{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}
  .chip .cnt{opacity:.65;font-weight:600} .chip.active .cnt{opacity:.9}
  details.invgroup>summary .srclogo{vertical-align:middle}
  /* inline row expansion (per-connection breakdown) */
  .exptog{display:inline-block;color:var(--accent);font-size:10px;width:11px;text-align:center}
  tr.exprow>td{background:var(--code);padding:0;border-bottom:1px solid var(--border)}
  .expbody{padding:12px 16px}
  .expsrc{margin:0 0 12px} .expsrc:last-child{margin-bottom:2px}
  .expsrc .hd{display:flex;align-items:center;gap:7px;font-weight:600;font-size:13px;margin-bottom:5px}
  .expsrc table{width:auto;min-width:340px;font-size:12px}
</style>
</head>
<body>
<header>
  <h1 onclick="showGallery()">assetFlow</h1>
  <span id="crumb"></span>
  <span id="adapterexport" class="exp hidden"></span>
  <span id="conn" class="hidden"><span class="dot"></span></span>
  <button id="fetchall" class="hidden" onclick="runAll()">Fetch all</button>
  <button id="schedbtn" class="hidden" onclick="toggleSched()">Schedules</button>
  <button id="conntoggle" class="hidden" onclick="togglePanel()">Connection</button>
</header>

<div id="connpanel" class="connpanel hidden">
  <div class="connrow">
    <label>Hostname or IP / URL
      <input type="text" id="c_host" placeholder="10.0.0.5  ·  host:9200  ·  https://host:9200"/>
    </label>
    <label id="f_port">Port <input type="text" id="c_port" placeholder="9200" style="min-width:90px"/></label>
    <label id="f_basepath" class="hidden">API base path <input type="text" id="c_basepath" value="/securetrack/api" style="min-width:160px"/></label>
    <label>Username <input type="text" id="c_user" autocomplete="off" placeholder="elastic"/></label>
    <label>Password <input type="password" id="c_pass" autocomplete="off"/></label>
    <label>Timeout (s) <input type="text" id="c_timeout" value="60" style="min-width:80px"/></label>
    <label class="chk"><input type="checkbox" id="c_verify" checked/> Verify TLS certificate</label>
    <label class="chk"><input type="checkbox" id="c_remember"/> Remember on this machine</label>
    <button id="c_btn" onclick="connect()">Test &amp; connect</button>
  </div>
  <div class="cstat" id="c_status"></div>
  <div class="chint" id="c_hint">Credentials are held in this local server's memory only — never written to disk.
    Fetched results are saved to a local SQLite database. Bare hostnames default to <code>https://host:9200</code>.</div>
  <div class="chint" id="c_forget"></div>
</div>

<div id="schedpanel" class="connpanel hidden">
  <div class="connrow">
    <label>Query <select id="s_query"></select></label>
    <label>Every <input type="text" id="s_interval" value="10" style="min-width:70px"/> min</label>
    <label>Mode <select id="s_range">
      <option value="">All time</option>
      <option value="incremental">Since last check</option>
      <option value="24h">Last 24h</option>
      <option value="7d">Last 7 days</option>
      <option value="30d">Last 30 days</option>
      <option value="90d">Last 90 days</option>
    </select></label>
    <label>Limit <input type="text" id="s_limit" placeholder="(none)" style="min-width:80px"/></label>
    <button onclick="addSchedule()">Add schedule</button>
  </div>
  <div id="s_status" class="cstat"></div>
  <div id="s_list"></div>
  <div class="chint">Schedules run in the background while the app is running, and only while the adapter is connected.
    Pick <b>All endpoints</b> + <b>Since last check</b> for continuous change monitoring.</div>
</div>

<section id="gallery"></section>

<div id="workspace" class="wrap hidden">
  <aside id="sidebar"></aside>
  <main id="main"></main>
</div>

<script>
let ADAPTER=null, DETAIL=null, CURRENT=null, LASTROWS=null, SORT={col:null,dir:1};
let RCDEVS=[], RPDEVS=[];   // devices (+embedded revisions) from the saved TUF009 snapshot
let PROFILE=null;           // unified Tufin device-profile (Discover view)

async function j(url,opts){const r=await fetch(url,opts);const d=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(d.detail||('HTTP '+r.status)); return d;}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function val(id){return (document.getElementById(id).value||'').trim();}

/* ---------- adapter logos (demo marks) ---------- */
const KIND_LOGO={
  elasticsearch:{bg:'#FEC514',fg:'#1c1e24',txt:'es'},
  tufin:{bg:'#12b886',fg:'#ffffff',txt:'T'},
  vmware:{bg:'#607d8b',fg:'#ffffff',txt:'vm'},
  solarwinds:{bg:'#f7941e',fg:'#1c1e24',txt:'SW'}
};
function kindMeta(kind){return KIND_LOGO[kind]||{bg:'#8a8f98',fg:'#ffffff',txt:String(kind||'?').slice(0,2)};}
function kindName(kind){const k=(KINDS||[]).find(x=>x.kind===kind);return k?k.name:(kind||'');}
function kindLogo(kind,size){size=size||18;const m=kindMeta(kind);const fs=m.txt.length>1?9:11;
  return '<svg class="srclogo" width="'+size+'" height="'+size+'" viewBox="0 0 24 24" '+
    'role="img" aria-label="'+esc(kindName(kind)||kind||'source')+'">'+
    '<rect x="1" y="1" width="22" height="22" rx="5" fill="'+m.bg+'"/>'+
    '<text x="12" y="16.5" text-anchor="middle" font-family="ui-sans-serif,system-ui,sans-serif" '+
    'font-size="'+fs+'" font-weight="700" fill="'+m.fg+'">'+esc(m.txt)+'</text></svg>';}
/* pin descriptor for the currently-open connection (the pinned Source column) */
function srcPin(){return DETAIL?{kind:DETAIL.kind,label:DETAIL.name}:null;}

/* ---------- gallery ---------- */
let KINDS=[];
async function loadGallery(){
  const g=document.getElementById('gallery'); g.innerHTML='<p class="hint">Loading connections…</p>';
  const d=await j('/api/adapters');
  try{ KINDS=(await j('/api/kinds')).kinds; }catch(e){ KINDS=[]; }
  let kopts=KINDS.map(k=>'<option value="'+esc(k.kind)+'">'+esc(k.name)+'</option>').join('');
  let h='<div class="gbar"><button class="invbtn" onclick="openInventory()">★ Unified inventory</button>'+
        '<button class="invbtn" style="background:transparent;color:var(--accent);border:1px solid var(--border)" '+
          'onclick="toggleAddConn()">＋ Add connection</button>'+
        '<span style="margin-left:auto">Export all saved data (every connection): '+
        '<span class="exp"><a href="/api/export-all.json">JSON</a> · '+
        '<a href="/api/export-all.zip">ZIP</a></span></span></div>'+
    '<div id="addconn" class="connpanel hidden" style="border:1px solid var(--border);border-radius:10px;margin-bottom:14px">'+
      '<div class="connrow">'+
        '<label>Adapter type <select id="ac_kind">'+kopts+'</select></label>'+
        '<label>Connection label <input type="text" id="ac_label" placeholder="e.g. Tufin HQ, Elastic – EU"/></label>'+
        '<button onclick="addConnection()">Create connection</button>'+
      '</div>'+
      '<div class="chint">Add another instance of an adapter — e.g. a second Tufin server or a '+
      'separate Elasticsearch cluster. Each connection keeps its own data and appears '+
      'separately in the unified inventory.</div></div>';
  d.categories.forEach(cat=>{
    h+='<div class="gcat">'+esc(cat.name)+'</div><div class="cards">';
    cat.adapters.forEach(a=>{
      h+='<div class="card" onclick="openAdapter(\''+esc(a.id)+'\')">'+
         '<h3>'+kindLogo(a.kind,20)+'<span>'+esc(a.name)+'</span> <span class="kind">'+esc(a.kind)+'</span></h3>'+
         '<p>'+esc(a.description)+'</p>'+
         '<div class="foot"><span>'+a.query_count+' queries · '+a.feed_count+' feeds</span>'+
         '<span>'+(a.connected?'<span class="dot ok"></span>connected':'<span class="dot"></span>not connected')+'</span></div>'+
         '<div class="cardactions">'+
           '<span onclick="event.stopPropagation();renameConnection(\''+esc(a.id)+'\',\''+esc(a.name).replace(/'/g,"\\'")+'\')">Rename</span>'+
           '<span class="danger" onclick="event.stopPropagation();removeConnection(\''+esc(a.id)+'\',\''+esc(a.name).replace(/'/g,"\\'")+'\')">Remove</span>'+
         '</div>'+
         '</div>';
    });
    h+='</div>';
  });
  g.innerHTML=h;
}
function toggleAddConn(){ const p=document.getElementById('addconn'); if(p) p.classList.toggle('hidden'); }
async function addConnection(){
  const kind=val('ac_kind')||(KINDS[0]&&KINDS[0].kind);
  const label=val('ac_label');
  if(!kind){ alert('No adapter types available.'); return; }
  try{
    const r=await j('/api/connections',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({kind:kind,label:label})});
    await loadGallery(); openAdapter(r.id);
  }catch(e){ alert('Could not add connection: '+e.message); }
}
async function renameConnection(id,current){
  const label=prompt('New label for this connection:',current||'');
  if(label==null) return;
  try{ await j('/api/connections/'+encodeURIComponent(id),{method:'PATCH',
        headers:{'Content-Type':'application/json'},body:JSON.stringify({label:label})});
       loadGallery(); }
  catch(e){ alert('Could not rename: '+e.message); }
}
async function removeConnection(id,label){
  if(!confirm('Remove connection "'+(label||id)+'"? Its saved data stays in the database but it '+
              'will no longer appear until re-added.')) return;
  try{ await j('/api/connections/'+encodeURIComponent(id),{method:'DELETE'}); loadGallery(); }
  catch(e){ alert('Could not remove: '+e.message); }
}
function showGallery(){
  document.getElementById('workspace').classList.add('hidden');
  document.getElementById('connpanel').classList.add('hidden');
  document.getElementById('schedpanel').classList.add('hidden');
  stopSchedPoll();
  document.getElementById('conn').classList.add('hidden');
  document.getElementById('conntoggle').classList.add('hidden');
  document.getElementById('fetchall').classList.add('hidden');
  document.getElementById('schedbtn').classList.add('hidden');
  document.getElementById('adapterexport').classList.add('hidden');
  document.getElementById('crumb').textContent='';
  document.getElementById('gallery').classList.remove('hidden');
  ADAPTER=null; loadGallery();
}

/* ---------- unified inventory (cross-adapter, layer 3) ---------- */
let INV_TYPE='device', INV_TYPES=[];
async function openInventory(type){
  if(type) INV_TYPE=type;
  const g=document.getElementById('gallery');
  g.innerHTML='<p class="hint">Correlating assets across adapters…</p>';
  try{ INV_TYPES=(await j('/api/inventory/types')).types; }catch(e){ INV_TYPES=[]; }
  if(!INV_TYPES.some(t=>t.type===INV_TYPE) && INV_TYPES[0]) INV_TYPE=INV_TYPES[0].type;
  let d; try{ d=await j('/api/inventory?type='+encodeURIComponent(INV_TYPE)); }
  catch(e){ g.innerHTML='<div class="err">'+esc(e.message)+'</div>'+
    '<p><span class="backlink" onclick="showGallery()">← Back to adapters</span></p>'; return; }
  const names=d.adapters.map(a=>a.name);
  const pills=INV_TYPES.map(t=>'<button class="typepill'+(t.type===INV_TYPE?' active':'')+'" '+
    'onclick="openInventory(\''+esc(t.type)+'\')">'+esc(t.label)+' <span class="pilln">'+t.count+'</span></button>').join('');
  let h='<div class="gbar"><span class="backlink" onclick="showGallery()">← Back to adapters</span></div>'+
    '<h2 style="margin:6px 0 2px">Unified Inventory</h2>'+
    '<div class="sub">One row per asset, correlated across every adapter by shared '+
    'identifiers of its type. Each type (devices, users, applications) is correlated '+
    'separately. Rows highlighted in blue are seen by more than one adapter. '+
    '<b>Click a row</b> to open the asset.</div>'+
    '<div class="typeswitch">'+pills+'</div>'+
    '<div class="meta">'+d.asset_count+' asset(s) · '+d.multi_adapter_count+
    ' seen by multiple adapters · '+(d.correlated_count||0)+' merged via shared identifiers'+
    ' · adapters: '+esc(names.join(', ')||'none')+
    ' · <a class="dl" href="/api/inventory.csv?type='+esc(INV_TYPE)+'">Download CSV</a>'+
    ' · <a class="dl" href="/api/inventory.json?type='+esc(INV_TYPE)+'">Download JSON</a></div>'+
    '<div id="invtable"></div>';
  g.innerHTML=h;
  const t=document.getElementById('invtable');
  if(!d.rows.length){
    t.innerHTML='<p class="hint">No '+esc(INV_TYPE)+' assets saved yet. Open a connection, connect, '+
      'and fetch a query that returns this asset type — assets appear here as adapters report them.</p>';
    return;
  }
  const cols=d.columns.map(c=>c.name);
  const ci=cols.indexOf('adapter_count');
  const cat=cols.indexOf('category');
  const sb=cols.indexOf('seen_by');
  const akind={}; (d.adapters||[]).forEach(a=>{akind[a.name]=a.kind;});
  const namesOf=r=>(sb>=0?String(r[sb]||''):'').split(/,\s*/).filter(Boolean);
  const catOf=r=>(cat>=0?(r[cat]||'unknown'):'unknown');
  const invPin=r=>{const nm=namesOf(r);
    return {kinds:[...new Set(nm.map(n=>akind[n]).filter(Boolean))], label:nm.join(', ')||'—'};};
  const state={cat:'',conn:'',multi:false,group:'none'};
  const pass=r=>{
    if(state.multi && !(ci>=0 && (+r[ci])>1)) return false;
    if(state.cat && catOf(r)!==state.cat) return false;
    if(state.conn && !namesOf(r).includes(state.conn)) return false;
    return true;
  };
  async function invExpand(r, body){
    body.innerHTML='<p class="hint">Loading per-connection detail…</p>';
    try{ const a=await j('/api/inventory/asset?host='+encodeURIComponent(r[0])+
      '&type='+encodeURIComponent(INV_TYPE));
      body.innerHTML=renderInlineAsset(a);
    }catch(e){ body.innerHTML='<div class="hint">'+esc(e.message)+'</div>'; }
  }
  const mkTable=(el,rows,showFilter)=>mountTable(el, cols, rows, {
    rowClass:r=>((ci>=0 && (+r[ci])>1)?'multi':''),
    expand:invExpand, pin:invPin, filter: showFilter?undefined:false});

  // controls: chip rows + group-by + multi-source toggle, inserted above the table
  const ctrl=document.createElement('div');
  ctrl.innerHTML='<div id="invchips"></div>'+
    '<div class="typeswitch" style="align-items:center">'+
      '<label class="hint" style="display:flex;align-items:center;gap:6px">Group by '+
        '<select id="invgroupby"><option value="none">None (flat)</option>'+
        '<option value="category">Category</option><option value="connection">Connection</option></select></label>'+
      '<label class="hint" style="display:flex;align-items:center;gap:6px">'+
        '<input type="checkbox" id="invmulti"/> Multi-source only</label>'+
      '<span class="hint" id="invcount"></span></div>';
  t.parentNode.insertBefore(ctrl, t);
  document.getElementById('invgroupby').onchange=e=>{state.group=e.target.value; renderInv();};
  document.getElementById('invmulti').onchange=e=>{state.multi=e.target.checked; renderInv();};

  function renderInv(){
    // breakdown chips: by source connection, and (devices) by category
    let ch='<div class="chiprow"><span class="chiplabel">Sources</span>';
    (d.adapters||[]).forEach(a=>{const n=d.rows.filter(r=>namesOf(r).includes(a.name)).length;
      ch+='<span class="chip'+(state.conn===a.name?' active':'')+'" data-conn="'+esc(a.name)+'">'+
        kindLogo(a.kind,16)+esc(a.name)+' <span class="cnt">'+n+'</span></span>';});
    ch+='</div>';
    if(cat>=0){
      ch+='<div class="chiprow"><span class="chiplabel">Type</span>'+
        '<span class="chip'+(state.cat===''?' active':'')+'" data-cat="">All <span class="cnt">'+d.rows.length+'</span></span>';
      Array.from(new Set(d.rows.map(catOf))).sort().forEach(c=>{const n=d.rows.filter(r=>catOf(r)===c).length;
        ch+='<span class="chip'+(state.cat===c?' active':'')+'" data-cat="'+esc(c)+'">'+esc(c)+' <span class="cnt">'+n+'</span></span>';});
      ch+='</div>';
    }
    document.getElementById('invchips').innerHTML=ch;
    document.querySelectorAll('#invchips .chip[data-conn]').forEach(el=>el.onclick=()=>{
      state.conn=(state.conn===el.dataset.conn?'':el.dataset.conn); renderInv();});
    document.querySelectorAll('#invchips .chip[data-cat]').forEach(el=>el.onclick=()=>{
      state.cat=el.dataset.cat; renderInv();});

    const rows=d.rows.filter(pass);
    document.getElementById('invcount').textContent=rows.length+' shown'+
      (rows.length!==d.rows.length?(' of '+d.rows.length):'');
    if(state.group==='none'){
      t.innerHTML=''; if(rows.length) mkTable(t, rows, true);
      else t.innerHTML='<p class="hint">No assets match the current filters.</p>';
      return;
    }
    let groups=[];
    if(state.group==='category'){
      groups=Array.from(new Set(rows.map(catOf))).sort()
        .map(k=>({label:k, rows:rows.filter(r=>catOf(r)===k)}));
    }else{
      groups=(d.adapters||[]).map(a=>({label:a.name, kind:a.kind,
        rows:rows.filter(r=>namesOf(r).includes(a.name))})).filter(gp=>gp.rows.length);
    }
    t.innerHTML=groups.length?groups.map((gp,i)=>'<details class="asset-det invgroup" open><summary>'+
      (gp.kind?kindLogo(gp.kind,16)+' ':'')+esc(gp.label)+' <span class="hint">('+gp.rows.length+')</span></summary>'+
      '<div class="mini" id="invg'+i+'"></div></details>').join(''):
      '<p class="hint">No assets match the current filters.</p>';
    groups.forEach((gp,i)=>mkTable(document.getElementById('invg'+i), gp.rows, false));
  }
  renderInv();
}

/* Inline per-connection breakdown shown when a Unified Inventory row is expanded:
   for each connection that saw the asset, the field/value(s) it contributed. */
function renderInlineAsset(a){
  if(!a || !a.found) return '<p class="hint">No detail available.</p>';
  const cb=a.correlated_by||{};
  const IDLBL={ip:'host.ip',mac:'host.mac',serial:'serial',uid:'id'};
  const cbtxt=['mac','serial','uid','ip'].filter(k=>cb[k]&&cb[k].length)
    .map(k=>esc(IDLBL[k])+' '+esc(cb[k].join(', '))).join(' · ');
  let h=cbtxt?('<div class="meta" style="margin:0 0 8px">🔗 Correlated by '+cbtxt+'</div>'):'';
  (a.adapters||[]).forEach(ad=>{
    const fs=(a.fields||[]).filter(f=>(f.values_by_adapter[ad.name]||[]).length);
    h+='<div class="expsrc"><div class="hd">'+kindLogo(ad.kind,16)+esc(ad.name)+
       ' <span class="hint" style="font-weight:400">('+fs.length+' field'+(fs.length===1?'':'s')+')</span></div>';
    if(fs.length){
      h+='<div class="tablewrap"><table><thead><tr><th>Field</th><th>Value</th><th>Scope</th></tr></thead><tbody>'+
        fs.map(f=>{const v=esc((f.values_by_adapter[ad.name]||[]).join(', '));
          const tag='<span class="scopetag '+f.scope+'">'+f.scope+'</span>'+
            (f.scope==='common'&&!f.agree?' <span class="scopetag conflict">differs</span>':'');
          return '<tr><td><b>'+esc(f.name)+'</b></td><td>'+v+'</td><td>'+tag+'</td></tr>';}).join('')+
        '</tbody></table></div>';
    }else h+='<p class="hint">No scalar fields from this connection.</p>';
    h+='</div>';
  });
  h+='<div style="margin-top:6px"><span class="backlink" onclick="event.stopPropagation();openAsset(\''+
     esc(String(a.host).replace(/'/g,"\\'"))+'\',\''+esc(a.type||INV_TYPE)+'\')">Open full asset page →</span></div>';
  return h;
}

/* ---------- asset drill-down (open one host) ---------- */
let ASSET=null, ASSET_VIEW='__all__';
async function openAsset(host, type){
  const g=document.getElementById('gallery');
  g.innerHTML='<p class="hint">Loading asset '+esc(host)+'…</p>';
  const q='host='+encodeURIComponent(host)+'&type='+encodeURIComponent(type||INV_TYPE);
  try{ ASSET=await j('/api/inventory/asset?'+q); }
  catch(e){ g.innerHTML='<div class="err">'+esc(e.message)+'</div>'+
    '<p><span class="backlink" onclick="openInventory()">← Back to inventory</span></p>'; return; }
  ASSET_VIEW='__all__';
  renderAsset();
}
function renderAsset(){
  const g=document.getElementById('gallery'), a=ASSET; if(!a) return;
  const adapters=a.adapters;
  let opts='<option value="__all__">All adapters (aggregated)</option>';
  adapters.forEach(ad=>{ opts+='<option value="'+esc(ad.id)+'"'+
    (ASSET_VIEW===ad.id?' selected':'')+'>'+esc(ad.name)+'</option>'; });
  const IDLBL={ip:'host.ip',mac:'host.mac',serial:'serial',uid:'id',name:'host.name'};
  const cb=a.correlated_by||{};
  const cbtxt=['mac','serial','uid','ip'].filter(k=>cb[k]&&cb[k].length)
    .map(k=>esc(IDLBL[k])+' '+esc(cb[k].join(', '))).join(' · ');
  const ident=a.identities||{};
  const identtxt=['ip','mac','serial','uid'].filter(k=>ident[k]&&ident[k].length)
    .map(k=>esc(IDLBL[k])+': '+esc(ident[k].join(', '))).join(' · ');
  let h='<div class="gbar"><span class="backlink" onclick="openInventory()">← Back to inventory</span></div>'+
    '<h2 style="margin:6px 0 2px">'+esc(a.host)+'</h2>'+
    '<div class="sub">'+(a.category?('<span class="scopetag common">'+esc(a.category)+'</span> · '):'')+
    'Seen by '+adapters.length+' adapter(s): '+esc(adapters.map(x=>x.name).join(', '))+
    ((a.aliases&&a.aliases.length)?(' · also known as: '+esc(a.aliases.join(', '))):'')+'</div>'+
    (identtxt?'<div class="meta">Identifiers: '+identtxt+'</div>':'')+
    (cbtxt?'<div class="meta">🔗 Correlated across adapters by '+cbtxt+'</div>':'')+
    '<div class="controls"><label class="hint">View by adapter '+
      '<select id="assetview" onchange="setAssetView(this.value)">'+opts+'</select></label>'+
      '<span class="hint">'+
        '<span class="scopetag common">common</span> = seen by 2+ adapters · '+
        '<span class="scopetag specific">specific</span> = only this source</span>'+
    '</div>';

  const view=ASSET_VIEW;
  const perAdapter=(view!=='__all__');
  // ----- fields (aggregated / preferred, or one adapter's fields) -----
  const fields=a.fields.filter(f=>!perAdapter || f.adapter_ids.indexOf(view)>=0);
  h+='<div class="minihdr">'+(perAdapter?'Fields from this adapter':'All fields — aggregated &amp; preferred')+
     ' <span class="hint">('+fields.length+')</span></div>';
  if(fields.length){
    h+='<div class="tablewrap"><table><thead><tr><th>Field</th><th>Preferred</th><th>Scope</th>'+
       (perAdapter?'<th>This adapter</th><th>Other adapters</th>':'<th>Reported by</th><th>Values by adapter</th>')+
       '</tr></thead><tbody>';
    fields.forEach(f=>{
      const tag='<span class="scopetag '+f.scope+'">'+f.scope+'</span>'+
        (f.scope==='common'&&!f.agree?' <span class="scopetag conflict">differs</span>':'');
      let c3,c4;
      if(perAdapter){
        const selName=(adapters.find(x=>x.id===view)||{}).name;
        c3=esc((f.values_by_adapter[selName]||[]).join(', '));
        const others=f.adapters.filter(n=>n!==selName)
          .map(n=>esc(n)+': '+esc((f.values_by_adapter[n]||[]).join(', ')));
        c4=others.length?others.join('<br>'):'<span class="hint">—</span>';
      }else{
        c3=esc(f.adapters.join(', '));
        c4=f.adapters.map(n=>esc(n)+': '+esc((f.values_by_adapter[n]||[]).join(', '))).join('<br>');
      }
      h+='<tr><td><b>'+esc(f.name)+'</b></td><td>'+esc(f.preferred==null?'':f.preferred)+'</td>'+
         '<td>'+tag+'</td><td>'+c3+'</td><td>'+c4+'</td></tr>';
    });
    h+='</tbody></table></div>';
  }else{ h+='<p class="hint">No scalar fields for this selection.</p>'; }

  // ----- mini tables (users, revisions, applications, …) -----
  const tbls=a.tables.filter(t=>!perAdapter || t.adapter_id===view);
  h+='<div class="sheethdr">Detail tables — click to expand</div>';
  if(tbls.length){
    tbls.forEach((t,idx)=>{
      const single=(a.adapters.length<2);
      const src=perAdapter?'':(esc(t.adapter)+' · ');
      h+='<details class="asset-det"'+(tbls.length===1?' open':'')+'>'+
         '<summary>'+src+esc(t.query_id)+' — '+esc(t.query_name)+
         ' <span class="hint">('+t.row_count+' row'+(t.row_count===1?'':'s')+')</span></summary>'+
         '<div class="mini" data-t="'+idx+'"></div></details>';
    });
  }else{ h+='<p class="hint">No detail tables for this selection.</p>'; }
  g.innerHTML=h;

  tbls.forEach((t,idx)=>{
    const el=g.querySelector('.mini[data-t="'+idx+'"]');
    if(el && t.rows.length) mountTable(el, t.columns, t.rows, {filter:false});
    else if(el) el.innerHTML='<p class="hint">(no rows)</p>';
  });
}
function setAssetView(v){ ASSET_VIEW=v; renderAsset(); }

/* ---------- workspace ---------- */
async function openAdapter(id){
  ADAPTER=id;
  stopSchedPoll();
  document.getElementById('schedpanel').classList.add('hidden');
  DETAIL=await j('/api/adapters/'+id);
  document.getElementById('gallery').classList.add('hidden');
  document.getElementById('workspace').classList.remove('hidden');
  document.getElementById('conn').classList.remove('hidden');
  document.getElementById('conntoggle').classList.remove('hidden');
  document.getElementById('fetchall').classList.remove('hidden');
  document.getElementById('schedbtn').classList.remove('hidden');
  const ax=document.getElementById('adapterexport');
  ax.innerHTML='export this adapter: <a href="/api/adapters/'+id+'/export-all.json">JSON</a> · '+
               '<a href="/api/adapters/'+id+'/export-all.zip">ZIP</a>';
  ax.classList.remove('hidden');
  document.getElementById('crumb').innerHTML='› '+kindLogo(DETAIL.kind,18)+
    ' <span style="vertical-align:middle">'+esc(DETAIL.name)+'</span>';
  applyKind(DETAIL.kind);
  updateForget();
  setConn(DETAIL.connected, DETAIL.conn_info||{});
  togglePanel(!DETAIL.connected);
  renderSidebar();
  document.getElementById('main').innerHTML='<p class="hint">Select a query on the left.</p>';
  CURRENT=null;
}

/* remember/forget saved credentials */
function updateForget(){
  const el=document.getElementById('c_forget');
  const rem=document.getElementById('c_remember');
  if(DETAIL && DETAIL.has_saved){
    el.innerHTML='✓ Saved on this machine (local database) — this connection auto-connects on startup. '+
      '<a href="#" onclick="forgetConn();return false;" style="color:var(--accent)">Forget saved credentials</a>';
    if(rem) rem.checked=true;
  }else{
    el.innerHTML='';
    if(rem) rem.checked=false;
  }
}
async function forgetConn(){
  if(!ADAPTER) return;
  try{ await j('/api/adapters/'+ADAPTER+'/saved-connection',{method:'DELETE'});
       DETAIL.has_saved=false; updateForget(); }
  catch(e){ alert('Could not forget: '+e.message); }
}

/* show the connection fields that fit the adapter kind */
function applyKind(kind){
  const tufin = (kind==='tufin');
  const vmware = (kind==='vmware');
  const solarwinds = (kind==='solarwinds');
  // Tufin uses an API base path; Elasticsearch, VMware, and SolarWinds use a port.
  document.getElementById('f_port').classList.toggle('hidden', tufin);
  document.getElementById('f_basepath').classList.toggle('hidden', !tufin);
  const remember='Credentials stay in this local server\'s memory unless you tick Remember (then stored in the local database). ';
  if(solarwinds){
    document.getElementById('c_host').placeholder = 'solarwinds.example.com  ·  10.0.0.20';
    document.getElementById('c_user').placeholder = 'orion-read-user';
    document.getElementById('c_port').placeholder = '17774';
    document.getElementById('c_timeout').value = '120';
    document.getElementById('c_hint').innerHTML = remember+
      'Connects to the SolarWinds Information Service (SWIS) at '+
      '<code>https://host:17774/SolarWinds/InformationService/v3/Json/Query</code> and runs SWQL. '+
      'Fetches typed device inventory with custom properties (columns prefixed <code>custom.</code>); '+
      'NCM config posture, config-change, and compliance resources need NCM licensed.';
    return;
  }
  if(vmware){
    document.getElementById('c_host').placeholder = 'vcenter.example.com  ·  10.0.0.10';
    document.getElementById('c_user').placeholder = 'administrator@vsphere.local';
    document.getElementById('c_port').placeholder = '443';
    document.getElementById('c_timeout').value = '60';
    document.getElementById('c_hint').innerHTML = remember+
      'Connects to the vCenter REST API at <code>https://host/api</code> for the VM / host / '+
      'cluster inventory. vCenter Custom Attributes (columns prefixed <code>custom.</code>) are '+
      'read via pyVmomi when it is installed; without it, standard inventory still works.';
    return;
  }
  document.getElementById('c_host').placeholder = tufin
    ? 'securetrack.example.com  ·  10.0.0.5'
    : '10.0.0.5  ·  host:9200  ·  https://host:9200';
  document.getElementById('c_user').placeholder = tufin ? 'securetrack-api-user' : 'elastic';
  document.getElementById('c_port').placeholder = '9200';
  document.getElementById('c_timeout').value = tufin ? '30' : '60';
  document.getElementById('c_hint').innerHTML = tufin
    ? remember+'Connects to the SecureTrack REST API at <code>https://host/securetrack/api</code>.'
    : remember+'Fetched results are saved to a local SQLite database. Bare hostnames default to <code>https://host:9200</code>.';
}

/* generic sortable/filterable table mounted into any container */
/* one table cell: trim long text (hover shows full), make comma-lists expandable */
function cellHTML(v){
  const s=String(v==null?'':v);
  const parts=s.split(/,\s+/).filter(x=>x.length);
  const isList=parts.length>=2 && s.length>26;
  const isLong=!isList && s.length>64;
  const cls='cell'+(isList?' list':(isLong?' long':''));
  const attr=(isList||isLong)?(' title="'+esc(s)+'"'):'';
  return '<span class="'+cls+'"'+attr+'>'+esc(s)+'</span>';
}
function mountTable(container, cols, rows, opts){
  opts=opts||{}; let sort={col:null,dir:1};
  // opts.pin: a constant {kind,label} / {kinds:[...],label} or a function(row)->same.
  const pinFn = (typeof opts.pin==='function') ? opts.pin : (opts.pin?()=>opts.pin:null);
  function pinInfo(row){ if(!pinFn) return null; const p=pinFn(row)||{};
    const kinds=p.kinds||(p.kind?[p.kind]:[]); const label=p.label||kinds.map(kindName).join(', ');
    return {kinds:kinds,label:label}; }
  container.innerHTML=(opts.filter===false?'':'<input type="text" class="tfilter" placeholder="filter…"/>')+
    '<div class="tablewrap"></div>';
  const tw=container.querySelector('.tablewrap'), fin=container.querySelector('.tfilter');
  function draw(){
    let rs=rows.slice();
    const f=fin?fin.value.toLowerCase():'';
    if(f) rs=rs.filter(r=>{const pi=pinInfo(r);const extra=pi?pi.label:'';
      return r.some(v=>String(v==null?'':v).toLowerCase().includes(f))||extra.toLowerCase().includes(f);});
    if(sort.col!==null){const i=sort.col; rs.sort((a,b)=>{
      const x=a[i],y=b[i]; if(x==null)return 1; if(y==null)return -1;
      const nx=parseFloat(x),ny=parseFloat(y);
      if(!isNaN(nx)&&!isNaN(ny))return (nx-ny)*sort.dir;
      return String(x).localeCompare(String(y))*sort.dir;});}
    const pinHead=pinFn?'<th class="pin">Connection</th>':'';
    const span=cols.length+(pinFn?1:0);
    tw.innerHTML='<table><thead><tr>'+pinHead+cols.map((c,i)=>'<th data-i="'+i+'">'+esc(c)+
      (sort.col===i?(sort.dir>0?' ▲':' ▼'):'')+'</th>').join('')+'</tr></thead><tbody>'+
      rs.map(r=>{ let pc='';
        if(pinFn){const pi=pinInfo(r);
          pc='<td class="pin"><span class="srcwrap" title="'+esc(pi.label)+'">'+
             (opts.expand?'<span class="exptog">▸</span>':'')+
             (pi.kinds.length?pi.kinds.map(k=>kindLogo(k,18)).join(''):kindLogo('',18))+
             '<span class="nm">'+esc(pi.label)+'</span></span></td>';}
        const tr='<tr class="datarow'+(opts.rowClass?(' '+esc(opts.rowClass(r))):'')+'">'+pc+
          r.map(v=>'<td>'+cellHTML(v)+'</td>').join('')+'</tr>';
        return tr+(opts.expand?('<tr class="exprow" style="display:none"><td colspan="'+span+
          '"><div class="expbody"></div></td></tr>'):'');}).join('')+'</tbody></table>';
    tw.querySelectorAll('th[data-i]').forEach(th=>th.onclick=()=>{
      const i=+th.dataset.i; if(sort.col===i)sort.dir*=-1; else{sort.col=i;sort.dir=1;} draw();});
    tw.querySelectorAll('td .cell.list, td .cell.long').forEach(el=>{
      el.onclick=e=>{e.stopPropagation(); el.classList.toggle('open');};});
    if(opts.expand){
      tw.querySelectorAll('tbody tr.datarow').forEach((tr,idx)=>{
        tr.style.cursor='pointer';
        tr.onclick=()=>{ const det=tr.nextElementSibling; if(!det) return;
          const wasOpen=det.style.display!=='none';
          det.style.display=wasOpen?'none':''; const tog=tr.querySelector('.exptog');
          if(tog) tog.textContent=wasOpen?'▸':'▾';
          if(!wasOpen && !det.dataset.filled){det.dataset.filled='1';
            opts.expand(rs[idx], det.querySelector('.expbody'));}};
      });
    }else if(opts.onRow){
      tw.querySelectorAll('tbody tr.datarow').forEach((tr,idx)=>{
        tr.style.cursor='pointer'; tr.onclick=()=>opts.onRow(rs[idx]);});
    }
  }
  if(fin) fin.oninput=draw;
  draw();
}

async function openMerged(){
  CURRENT=null;
  document.querySelectorAll('.q').forEach(e=>e.classList.remove('active'));
  const el=document.getElementById('ovAll'); if(el) el.classList.add('active');
  const m=document.getElementById('main'); m.innerHTML='<p class="hint">Building unified view…</p>';
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/merged'); }
  catch(e){ m.innerHTML='<div class="err">'+esc(e.message)+'</div>'; return; }
  const main=d.main;
  let h='<h2>All Fetched Results — '+esc(DETAIL.name)+'</h2>'+
    '<div class="sub">Unified host view: one row per host, correlated across host-keyed queries. Detail sheets follow.</div>'+
    '<div class="meta">'+main.host_count+' host(s) · contributing: '+esc(main.contributing.join(', ')||'none')+
    (main.excluded.length?(' · not host-keyed (sheets only): '+esc(main.excluded.join(', '))):'')+
    ' · <a class="dl" href="/api/adapters/'+ADAPTER+'/merged.csv">Download CSV</a>'+
    ' · <a class="dl" href="/api/adapters/'+ADAPTER+'/merged.json">Download JSON</a></div>'+
    '<div id="maintable"></div>'+
    '<div class="sheethdr">Sheets (mini tables)</div>';
  d.sheets.forEach(sh=>{
    h+='<div class="minihdr" style="text-transform:uppercase;color:var(--muted);font-size:11px;margin-top:14px">'+esc(sh.feed_name)+'</div>';
    sh.queries.forEach(q=>{
      if(q.has_data){
        h+='<div class="minihdr">'+esc(q.query_id)+' — '+esc(q.name)+' <span class="hint">('+q.row_count+' rows)</span></div>'+
           '<div class="mini" data-q="'+q.query_id+'"></div>';
      }else{
        h+='<div class="minihdr dim">'+esc(q.query_id)+' — '+esc(q.name)+' <span class="hint">(not fetched)</span></div>';
      }
    });
  });
  m.innerHTML=h;
  const mt=document.getElementById('maintable');
  if(main.rows.length) mountTable(mt, main.columns.map(c=>c.name), main.rows, {pin:srcPin()});
  else mt.innerHTML='<p class="hint">No host-keyed results saved yet. Run a host query (e.g. AI001) first.</p>';
  d.sheets.forEach(sh=>sh.queries.forEach(q=>{ if(q.has_data){
    const el=document.querySelector('.mini[data-q="'+q.query_id+'"]');
    if(el) mountTable(el, q.columns.map(c=>c.name), q.rows, {filter:false, pin:srcPin()});
  }}));
}

async function openChangeLog(){
  CURRENT=null;
  document.querySelectorAll('.q').forEach(e=>e.classList.remove('active'));
  const el=document.getElementById('ovChangeLog'); if(el) el.classList.add('active');
  const m=document.getElementById('main'); m.innerHTML='<p class="hint">Loading change log…</p>';
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/changelog'); }
  catch(e){ m.innerHTML='<div class="err">'+esc(e.message)+'</div>'; return; }
  let h='<h2>Change Log — '+esc(DETAIL.name)+'</h2>'+
    '<div class="sub">Deduplicated changes across every Change Detail fetch (any mode). '+
    'One row per unique revision change, keyed by the globally-unique revision id.</div>'+
    '<div class="meta">'+d.rows.length+' change(s)</div><div id="cltable"></div>';
  m.innerHTML=h;
  const t=document.getElementById('cltable');
  if(d.rows.length) mountTable(t, d.columns.map(c=>c.name), d.rows, {pin:srcPin()});
  else t.innerHTML='<p class="hint">No changes recorded yet. Run a Change Detail query (Tufin TUF008, SolarWinds SW006) — its rows accumulate here.</p>';
}

async function openChangeDashboard(){
  CURRENT=null;
  document.querySelectorAll('.q').forEach(e=>e.classList.remove('active'));
  const el=document.getElementById('ovChangeDash'); if(el) el.classList.add('active');
  const m=document.getElementById('main'); m.innerHTML='<p class="hint">Loading changes dashboard…</p>';
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/change-dashboard'); }
  catch(e){ m.innerHTML='<div class="err">'+esc(e.message)+'</div>'; return; }
  const t=d.by_type||{}, au=d.by_authorization||{}, inv=d.inventory||{};
  const tile=(label,val,sub)=>'<div style="flex:1;min-width:130px;border:1px solid var(--border);border-radius:10px;padding:14px;background:var(--panel)">'+
    '<div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">'+esc(label)+'</div>'+
    '<div style="font-size:26px;font-weight:700;margin-top:4px">'+esc(val==null?'—':val)+'</div>'+
    (sub?'<div style="font-size:11px;color:var(--muted)">'+esc(sub)+'</div>':'')+'</div>';
  const act=d.by_action||{};
  let automatic=0, manual=0;
  Object.keys(act).forEach(k=>{ if(/automat/i.test(k)) automatic+=act[k]; else if(k) manual+=act[k]; });
  let h='<h2>Changes Dashboard — '+esc(DETAIL.name)+'</h2>'+
    '<div class="sub">Aggregated from the deduplicated Change Log. Run Change Detail (TUF008) to populate; TUF001/TUF003/TUF007 add inventory context.</div>'+
    '<div style="display:flex;gap:12px;flex-wrap:wrap;margin:12px 0">'+
      tile('Total changes', d.total_changes)+ tile('Added', t.added||0)+
      tile('Modified', t.modified||0)+ tile('Removed', t.removed||0)+
      tile('Moved', t.moved||0)+ tile('Unauthorized', au.unauthorized||0)+
    '</div>'+
    '<div style="display:flex;gap:12px;flex-wrap:wrap;margin:0 0 8px">'+
      tile('Automatic', automatic, 'system / auto-install')+
      tile('Manual', manual, 'named admin action')+
    '</div>'+
    '<div style="display:flex;gap:12px;flex-wrap:wrap;margin:0 0 8px">'+
      tile('Devices', inv.devices?inv.devices.value:null,'TUF001')+
      tile('Rules', inv.rules?inv.rules.value:null,'TUF003')+
      tile('Cleanup (shadowed)', inv.cleanup?inv.cleanup.value:null,'TUF007')+
    '</div>'+
    '<div style="display:flex;gap:18px;flex-wrap:wrap;margin-top:8px">'+
      '<div style="flex:1;min-width:280px"><div class="sheethdr">Devices with most changes</div><div id="cdDevices"></div></div>'+
      '<div style="flex:1;min-width:280px"><div class="sheethdr">Top administrators</div><div id="cdAdmins"></div></div>'+
    '</div>'+
    '<div class="sheethdr">Recent changes</div><div id="cdRecent"></div>';
  m.innerHTML=h;
  const dev=(d.top_devices||[]).map(r=>[r.key||'(unknown)', r.count]);
  const adm=(d.top_admins||[]).map(r=>[r.key||'(unknown)', r.count]);
  if(dev.length) mountTable(document.getElementById('cdDevices'), ['device','changes'], dev, {filter:false});
  else document.getElementById('cdDevices').innerHTML='<p class="hint">—</p>';
  if(adm.length) mountTable(document.getElementById('cdAdmins'), ['administrator','changes'], adm, {filter:false});
  else document.getElementById('cdAdmins').innerHTML='<p class="hint">—</p>';
  const rec=d.recent||{columns:[],rows:[]};
  if(rec.rows.length) mountTable(document.getElementById('cdRecent'), rec.columns.map(c=>c.name), rec.rows, {pin:srcPin()});
  else document.getElementById('cdRecent').innerHTML='<p class="hint">No changes recorded yet. Run TUF008 (Change Detail).</p>';
}

// ----- Tufin revision comparison (SecureTrack-style compare report) -----
// Reads the saved "Revision Rulebases" (TUF009) snapshot — fetch once, then
// compare the fetched data offline.
function rcNeedsFetch(m){
  m.innerHTML='<h2>Compare Revisions — '+esc(DETAIL.name)+'</h2>'+
    '<div class="sub">Compares the saved <b>Revision Rulebases</b> snapshot.</div>'+
    '<div class="err">No saved rulebase snapshot yet. Run <b>TUF009 — Revision Rulebases</b> '+
    '(or use <b>Fetch all</b>) to snapshot recent revisions, then come back here to compare them.</div>';
}

async function openRevisionCompare(){
  CURRENT=null;
  document.querySelectorAll('.q').forEach(e=>e.classList.remove('active'));
  const el=document.getElementById('ovRevCompare'); if(el) el.classList.add('active');
  const m=document.getElementById('main'); m.innerHTML='<p class="hint">Loading saved revisions…</p>';
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/tufin/revision-index'); }
  catch(e){ if(/no saved/i.test(e.message)){ rcNeedsFetch(m); return; }
    m.innerHTML='<h2>Compare Revisions</h2><div class="err">'+esc(e.message)+'</div>'; return; }
  RCDEVS=d.devices||[];
  const when=d.ran_at?(' · snapshot '+new Date(d.ran_at).toLocaleString()):'';
  m.innerHTML='<h2>Compare Revisions — '+esc(DETAIL.name)+'</h2>'+
    '<div class="sub">Pick a device and two revisions to see exactly what changed between them — '+
    'new, deleted, modified and moved security rules. From the saved Revision Rulebases snapshot'+when+'.</div>'+
    '<div class="rcbar">'+
      '<label>Device<select id="rcDev"><option value="">Select a device…</option>'+
        RCDEVS.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+' ('+(x.revisions||[]).length+' rev)</option>').join('')+
      '</select></label>'+
      '<label>From (before)<select id="rcOld"></select></label>'+
      '<label>To (after)<select id="rcNew"></select></label>'+
      '<button id="rcGo" disabled>Compare</button>'+
    '</div><div id="rcout"></div>';
  document.getElementById('rcGo').onclick=rcRun;
  document.getElementById('rcDev').onchange=rcLoadRevisions;
  if(!RCDEVS.length) document.getElementById('rcout').innerHTML='<p class="hint">The snapshot has no devices.</p>';
}

function rcLoadRevisions(){
  const dev=document.getElementById('rcDev').value;
  const os=document.getElementById('rcOld'), ns=document.getElementById('rcNew'), go=document.getElementById('rcGo');
  const out=document.getElementById('rcout'); out.innerHTML=''; go.disabled=true; os.innerHTML=ns.innerHTML='';
  if(!dev) return;
  const d=RCDEVS.find(x=>String(x.id)===String(dev)); const revs=(d&&d.revisions)||[];
  if(revs.length<2){ os.innerHTML=ns.innerHTML='<option value="">(need 2+)</option>';
    out.innerHTML='<p class="hint">This device has fewer than two revisions in the snapshot. '+
      'Re-run TUF009 with a wider range to capture more.</p>'; return; }
  const opt=r=>'<option value="'+esc(r.id)+'">#'+esc(r.number||r.id)+' · '+esc(r.date||'')+(r.admin?(' · '+esc(r.admin)):'')+'</option>';
  os.innerHTML=revs.map(opt).join(''); ns.innerHTML=revs.map(opt).join('');
  ns.selectedIndex=0; os.selectedIndex=1;   // newest-first list → To=newest, From=second-newest
  go.disabled=false; rcRun();
}

async function rcRun(){
  const dev=document.getElementById('rcDev').value;
  const oldR=document.getElementById('rcOld').value, newR=document.getElementById('rcNew').value;
  const out=document.getElementById('rcout');
  if(!dev){ out.innerHTML='<p class="hint">Pick a device.</p>'; return; }
  out.innerHTML='<p class="hint">Comparing revisions…</p>';
  const p=new URLSearchParams({device_id:dev});
  if(oldR) p.set('old_rev',oldR); if(newR) p.set('new_rev',newR);
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/tufin/revision-compare?'+p.toString()); }
  catch(e){ out.innerHTML='<div class="err">'+esc(e.message)+'</div>'; return; }
  out.innerHTML=renderRevCompare(d);
}

function rcTag(ct){return '<span class="rctag rc-'+ct+'">'+esc(ct)+'</span>';}

function rcCell(entry, label){
  const b=(entry.before||{})[label]||'', a=(entry.after||{})[label]||'';
  if(entry.change_type==='removed') return esc(b);
  if(entry.change_type==='added') return esc(a);
  if((entry.changed_fields||[]).indexOf(label)>=0)
    return '<span class="b4">'+esc(b||'∅')+'</span><span class="arw">→</span><span class="af">'+esc(a||'∅')+'</span>';
  return esc(a);
}

function renderRevCompare(d){
  if(d.error) return '<div class="err">'+esc(d.error)+'</div>';
  const f=d.from||{}, t=d.to||{};
  let h='<div class="meta">'+esc((d.device&&d.device.name)||'')+
    ' · from <b>#'+esc(f.number||f.id||'?')+'</b> ('+esc(f.date||'')+')'+
    ' → to <b>#'+esc(t.number||t.id||'?')+'</b> ('+esc(t.date||'')+')'+
    (t.admin?(' · by '+esc(t.admin)):'')+'</div>';
  h+='<div class="sheethdr">Summary</div><div class="tablewrap"><table><thead><tr>'+
    '<th>Category</th><th>New</th><th>Deleted</th><th>Modified</th><th>Moved</th></tr></thead><tbody>';
  (d.summary||[]).forEach(s=>{ h+='<tr><td>'+esc(s.category)+'</td><td>'+(s.added||0)+'</td><td>'+
    (s.deleted||0)+'</td><td>'+(s.modified||0)+'</td><td>'+(s.moved||0)+'</td></tr>'; });
  h+='</tbody></table></div>';
  const flds=d.rule_fields||['name','src_zone','source','dst_zone','destination','service','action'];
  const rules=d.rules||[];
  h+='<div class="sheethdr">Security rule changes ('+rules.length+')</div>';
  if(!rules.length) h+='<p class="hint">No security-rule changes between these revisions.</p>';
  else{
    h+='<div class="tablewrap"><table><thead><tr><th>Change</th><th>rule.uid</th>'+
      flds.map(x=>'<th>'+esc(x)+'</th>').join('')+'</tr></thead><tbody>';
    rules.forEach(r=>{ h+='<tr class="row-'+r.change_type+'"><td>'+rcTag(r.change_type)+'</td><td>'+esc(r.rule_uid)+'</td>'+
      flds.map(lbl=>'<td class="rcfld">'+rcCell(r,lbl)+'</td>').join('')+'</tr>'; });
    h+='</tbody></table></div>';
  }
  // Network objects — only when a TUF010 snapshot was fetched.
  if(!d.has_objects){
    h+='<div class="sheethdr">Network object changes</div>'+
      '<p class="hint">Run <b>TUF010 — Revision Objects</b> (or <b>Fetch all</b>) to also detect '+
      'network-object edits — changes to a host/subnet/group that alter what a rule permits '+
      'without the rule text changing.</p>';
  }else{
    const ofl=d.object_fields||['name','type','value','comment'];
    const objs=d.objects||[];
    h+='<div class="sheethdr">Network object changes ('+objs.length+')</div>';
    if(!objs.length) h+='<p class="hint">No network-object changes between these revisions.</p>';
    else{
      h+='<div class="tablewrap"><table><thead><tr><th>Change</th><th>object.uid</th>'+
        ofl.map(x=>'<th>'+esc(x)+'</th>').join('')+'</tr></thead><tbody>';
      objs.forEach(o=>{ h+='<tr class="row-'+o.change_type+'"><td>'+rcTag(o.change_type)+'</td><td>'+esc(o.object_uid)+'</td>'+
        ofl.map(lbl=>'<td class="rcfld">'+rcCell(o,lbl)+'</td>').join('')+'</tr>'; });
      h+='</tbody></table></div>';
    }
  }
  return h;
}

// ----- Tufin revision policy viewer (full rulebase of any one saved revision) -----
async function openRevisionPolicy(){
  CURRENT=null;
  document.querySelectorAll('.q').forEach(e=>e.classList.remove('active'));
  const el=document.getElementById('ovRevPolicy'); if(el) el.classList.add('active');
  const m=document.getElementById('main'); m.innerHTML='<p class="hint">Loading saved revisions…</p>';
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/tufin/revision-index'); }
  catch(e){ if(/no saved/i.test(e.message)){
      m.innerHTML='<h2>Revision Policy — '+esc(DETAIL.name)+'</h2>'+
        '<div class="sub">Views the saved <b>Revision Rulebases</b> snapshot.</div>'+
        '<div class="err">No saved rulebase snapshot yet. Run <b>TUF009 — Revision Rulebases</b> '+
        '(or <b>Fetch all</b>) to snapshot revisions, then come back here.</div>'; return; }
    m.innerHTML='<h2>Revision Policy</h2><div class="err">'+esc(e.message)+'</div>'; return; }
  RPDEVS=d.devices||[];
  const when=d.ran_at?(' · snapshot '+new Date(d.ran_at).toLocaleString()):'';
  m.innerHTML='<h2>Revision Policy — '+esc(DETAIL.name)+'</h2>'+
    '<div class="sub">View the full firewall rulebase exactly as it stood at any one revision — '+
    'pick a device and a point in its history. From the saved Revision Rulebases snapshot'+when+'.</div>'+
    '<div class="rcbar">'+
      '<label>Device<select id="rpDev"><option value="">Select a device…</option>'+
        RPDEVS.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+' ('+(x.revisions||[]).length+' rev)</option>').join('')+
      '</select></label>'+
      '<label>Revision<select id="rpRev"></select></label>'+
      '<button id="rpGo" disabled>View</button>'+
    '</div><div id="rpmeta" class="meta"></div><div id="rpout"></div>';
  document.getElementById('rpGo').onclick=rpRun;
  document.getElementById('rpDev').onchange=rpLoadRevisions;
  if(!RPDEVS.length) document.getElementById('rpout').innerHTML='<p class="hint">The snapshot has no devices.</p>';
}

function rpLoadRevisions(){
  const dev=document.getElementById('rpDev').value;
  const rs=document.getElementById('rpRev'), go=document.getElementById('rpGo');
  const out=document.getElementById('rpout'); out.innerHTML=''; document.getElementById('rpmeta').innerHTML='';
  rs.innerHTML=''; go.disabled=true;
  if(!dev) return;
  const d=RPDEVS.find(x=>String(x.id)===String(dev)); const revs=(d&&d.revisions)||[];
  if(!revs.length){ rs.innerHTML='<option value="">(none)</option>';
    out.innerHTML='<p class="hint">This device has no revisions in the snapshot.</p>'; return; }
  rs.innerHTML=revs.map(r=>'<option value="'+esc(r.id)+'">#'+esc(r.number||r.id)+' · '+esc(r.date||'')+
    (r.admin?(' · '+esc(r.admin)):'')+'</option>').join('');
  rs.selectedIndex=0;   // newest-first
  go.disabled=false; rpRun();
}

async function rpRun(){
  const dev=document.getElementById('rpDev').value, rev=document.getElementById('rpRev').value;
  const out=document.getElementById('rpout'), meta=document.getElementById('rpmeta');
  if(!dev){ out.innerHTML='<p class="hint">Pick a device.</p>'; return; }
  out.innerHTML='<p class="hint">Loading rulebase…</p>'; meta.innerHTML='';
  const p=new URLSearchParams({device_id:dev}); if(rev) p.set('revision_id',rev);
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/tufin/revision-policy?'+p.toString()); }
  catch(e){ out.innerHTML='<div class="err">'+esc(e.message)+'</div>'; return; }
  if(d.error){ out.innerHTML='<div class="err">'+esc(d.error)+'</div>'; return; }
  const r=d.revision||{};
  meta.innerHTML=esc((d.device&&d.device.name)||'')+' · revision <b>#'+esc(r.number||r.id||'?')+'</b>'+
    (r.date?(' · '+esc(r.date)):'')+(r.admin?(' · by '+esc(r.admin)):'')+
    (r.action?(' · '+esc(r.action)):'')+
    (r.authorization_status?(' · '+esc(r.authorization_status)):'')+
    ' · '+(d.rows||[]).length+' rules';
  if((d.rows||[]).length) mountTable(out, d.columns.map(c=>c.name), d.rows, {});
  else out.innerHTML='<p class="hint">This revision has no rules.</p>';
}

// ----- Discover: unified device-centric Tufin view (dashboard + nested tables) -----
async function openDiscover(){
  CURRENT=null;
  document.querySelectorAll('.q').forEach(e=>e.classList.remove('active'));
  const el=document.getElementById('ovDiscover'); if(el) el.classList.add('active');
  const m=document.getElementById('main'); m.innerHTML='<p class="hint">Building unified view…</p>';
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/tufin/profile'); }
  catch(e){ m.innerHTML='<h2>Discover</h2><div class="err">'+esc(e.message)+'</div>'; return; }
  PROFILE=d; renderDiscover(d, false);
}

async function runDiscover(){
  if(!DETAIL.connected){ alert('Connect the Tufin adapter first (Connection panel) — Discover fetches every feed live.'); return; }
  const btn=document.getElementById('discBtn');
  if(btn){ btn.disabled=true; btn.textContent='Discovering… fetching all feeds'; }
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/tufin/discover',{method:'POST'}); }
  catch(e){ const m=document.getElementById('main');
    if(m) m.innerHTML='<h2>Discover</h2><div class="err">'+esc(e.message)+'</div>'; return; }
  PROFILE=d; renderDiscover(d, true);
}

function downloadProfile(){
  if(!PROFILE) return;
  const blob=new Blob([JSON.stringify(PROFILE,null,2)],{type:'application/json'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=(DETAIL.name||'tufin').replace(/[^a-z0-9_-]+/gi,'_')+'-profile.json';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href), 2000);
}

function dtile(label,val,sub){
  return '<div style="flex:1;min-width:120px;border:1px solid var(--border);border-radius:10px;padding:12px 14px;background:var(--panel)">'+
    '<div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">'+esc(label)+'</div>'+
    '<div style="font-size:24px;font-weight:700;margin-top:3px">'+esc(val==null?'—':val)+'</div>'+
    (sub?'<div style="font-size:11px;color:var(--muted)">'+esc(sub)+'</div>':'')+'</div>';
}

function renderDiscover(d, justRan){
  const m=document.getElementById('main');
  const t=d.totals||{}, ch=t.changes||{}, at=t.by_asset_type||{};
  const gen=d.generated_at?new Date(d.generated_at).toLocaleString():'';
  const devs=d.devices||[];
  const ran=(justRan&&d.discover)?('<span class="meta">fetched '+d.discover.ran+' feed(s)'+
    (d.discover.failed?(', '+d.discover.failed+' failed'):'')+'</span>'):'';
  let h='<h2>Discover — '+esc(DETAIL.name)+'</h2>'+
    '<div class="sub">Every Tufin feed folded into one device-centric view. '+
    (gen?('Built '+esc(gen)+'.'):'Not built yet.')+'</div>'+
    '<div class="controls">'+
      '<button id="discBtn" onclick="runDiscover()">🔄 Discover (fetch all)</button>'+
      '<button class="ghostbtn" onclick="downloadProfile()">⬇ Download JSON</button>'+ran+
    '</div>';
  if(!devs.length){
    h+='<div class="err">No Tufin data yet. Click <b>Discover (fetch all)</b> to fetch every feed and '+
       'build the unified view (needs the adapter connected).</div>';
    m.innerHTML=h; return;
  }
  // Estate tiles
  h+='<div style="display:flex;gap:12px;flex-wrap:wrap;margin:12px 0">'+
      dtile('Devices', t.devices)+ dtile('Rules', t.rules)+ dtile('Objects', t.objects)+
      dtile('Services', t.services)+ dtile('Zones', t.zones)+ dtile('Revisions', t.revisions)+
      dtile('Cleanups', t.cleanups)+
    '</div>'+
    '<div style="display:flex;gap:12px;flex-wrap:wrap;margin:0 0 10px">'+
      dtile('Changes', ch.total||0)+ dtile('Added', ch.added||0)+ dtile('Modified', ch.modified||0)+
      dtile('Removed', ch.removed||0)+ dtile('Unauthorized', ch.unauthorized||0)+
    '</div>';
  // Asset-type breakdown
  const chips=Object.keys(at).sort().map(k=>'<span class="atchip">'+esc(k)+' <b>'+at[k]+'</b></span>').join('');
  if(chips) h+='<div class="sheethdr">Devices by asset type</div><div style="margin:4px 0 10px">'+chips+'</div>';
  // Device table (expandable)
  h+='<div class="sheethdr">Devices ('+devs.length+') — click a row to expand</div>'+
     '<div class="tablewrap"><table><thead><tr>'+
     '<th></th><th>Device</th><th>Asset type</th><th>Vendor / model</th><th>IP</th>'+
     '<th>Rules</th><th>Objects</th><th>Revisions</th><th>Changes</th></tr></thead><tbody>';
  devs.forEach((dev,idx)=>{
    const c=dev.counts||{}, dch=dev.changes||{};
    const chg=dch.total||0;
    const badge=chg?('<span class="rctag rc-modified">'+chg+'</span>'):'<span class="hint">0</span>';
    const unauth=dch.unauthorized?(' <span class="rctag rc-removed">'+dch.unauthorized+' unauth</span>'):'';
    h+='<tr class="devrow" id="devrow-'+idx+'" onclick="discToggle('+idx+')">'+
       '<td class="exptoggle">▸</td>'+
       '<td><b>'+esc(dev.name)+'</b></td>'+
       '<td>'+esc(dev.asset_type||'')+'</td>'+
       '<td>'+esc([dev.vendor,dev.model].filter(Boolean).join(' / '))+'</td>'+
       '<td>'+esc(dev.ip||'')+'</td>'+
       '<td>'+(c.rules||0)+'</td><td>'+(c.objects||0)+'</td><td>'+(c.revisions||0)+'</td>'+
       '<td>'+badge+unauth+'</td></tr>'+
       '<tr class="devdet hidden" id="devdet-'+idx+'"><td colspan="9"><div class="devdetinner"></div></td></tr>';
  });
  h+='</tbody></table></div>';
  m.innerHTML=h;
}

function discToggle(idx){
  const det=document.getElementById('devdet-'+idx), row=document.getElementById('devrow-'+idx);
  if(!det) return;
  const show=det.classList.contains('hidden');
  det.classList.toggle('hidden'); row.classList.toggle('open', show);
  const arr=row.querySelector('.exptoggle'); if(arr) arr.textContent=show?'▾':'▸';
  if(show && !det.dataset.built){ buildDeviceDetail(idx); det.dataset.built='1'; }
}

function mountObjs(container, rows, preferredCols){
  if(!rows || !rows.length){ container.innerHTML='<p class="hint">None.</p>'; return; }
  const cols=(preferredCols&&preferredCols.length)?preferredCols.slice():Object.keys(rows[0]);
  const seen=new Set(cols);
  rows.forEach(r=>Object.keys(r).forEach(k=>{ if(!seen.has(k)){ seen.add(k); cols.push(k); } }));
  const data=rows.map(r=>cols.map(k=>r[k]==null?'':r[k]));
  mountTable(container, cols, data, {});
}

function buildDeviceDetail(idx){
  const dev=PROFILE.devices[idx];
  const body=document.getElementById('devdet-'+idx).querySelector('.devdetinner');
  const secs=[['rules','Rules'],['objects','Objects'],['services','Services'],
              ['zones','Zones'],['revisions','Revisions'],['cleanups','Cleanups']];
  const tabs=[]; let first=null;
  secs.forEach(([k,label])=>{ const n=(dev[k]||[]).length; if(n){ tabs.push([k,label+' ('+n+')']); if(!first)first=k; } });
  const recent=(dev.changes&&dev.changes.recent)||[];
  if(recent.length){ tabs.push(['changes','Changes ('+recent.length+')']); if(!first)first='changes'; }
  if(!tabs.length){ body.innerHTML='<p class="hint">No detail fetched for this device. Run Discover (fetch all).</p>'; return; }
  body.innerHTML='<div class="dtabs">'+
    tabs.map(([k,l])=>'<button class="dtab" data-k="'+k+'" onclick="discShow('+idx+',&quot;'+k+'&quot;)">'+esc(l)+'</button>').join('')+
    '</div><div class="dsecbody" id="dsec-'+idx+'"></div>';
  discShow(idx, first);
}

function discShow(idx, k){
  const dev=PROFILE.devices[idx];
  const body=document.getElementById('dsec-'+idx);
  document.querySelectorAll('#devdet-'+idx+' .dtab').forEach(b=>b.classList.toggle('active', b.dataset.k===k));
  if(k==='changes')
    mountObjs(body, (dev.changes&&dev.changes.recent)||[],
      ['revision.id','@timestamp','changed_by','change_type','rule.uid','before','after','authorized','requester']);
  else
    mountObjs(body, dev[k]||[]);
}

async function openDrift(){
  CURRENT=null;
  document.querySelectorAll('.q').forEach(e=>e.classList.remove('active'));
  const el=document.getElementById('ovDrift'); if(el) el.classList.add('active');
  const m=document.getElementById('main'); m.innerHTML='<p class="hint">Loading drift log…</p>';
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/drift'); }
  catch(e){ m.innerHTML='<div class="err">'+esc(e.message)+'</div>'; return; }
  let h='<h2>Drift Log — '+esc(DETAIL.name)+'</h2>'+
    '<div class="sub">Inventory drift detected by diffing consecutive snapshots of host-keyed queries. '+
    'One row per unique (host · attribute · value) that appeared or disappeared. Deduplicated.</div>'+
    '<div class="meta">'+d.rows.length+' change(s)</div><div id="drifttable"></div>';
  m.innerHTML=h;
  const t=document.getElementById('drifttable');
  if(d.rows.length) mountTable(t, d.columns.map(c=>c.name), d.rows, {pin:srcPin()});
  else t.innerHTML='<p class="hint">No drift recorded yet. Fetch an inventory query (e.g. AI011) at least twice — added/removed items land here.</p>';
}

async function openChangeDetail(qid){
  const out=document.getElementById('diffout'); if(!out) return;
  out.innerHTML='<p class="hint">Diffing the last two fetches…</p>';
  let d; try{ d=await j('/api/adapters/'+ADAPTER+'/change-detail/'+qid); }
  catch(e){ out.innerHTML='<div class="hint">'+esc(e.message)+'</div>'; return; }
  let h='<div class="sheethdr">Change since previous fetch</div>'+
    '<div class="meta">'+d.added+' added · '+d.removed+' removed'+
    (d.prev_ran_at?(' · vs '+new Date(d.prev_ran_at).toLocaleString()):'')+'</div><div id="ddtable"></div>';
  out.innerHTML=h;
  const t=document.getElementById('ddtable');
  if(d.rows.length) mountTable(t, d.columns.map(c=>c.name), d.rows, {pin:srcPin()});
  else t.innerHTML='<p class="hint">No differences between the last two fetches.</p>';
}

function renderSidebar(){
  const qById={}; DETAIL.queries.forEach(q=>qById[q.id]=q);
  const side=document.getElementById('sidebar'); side.innerHTML='';
  const ovh=document.createElement('div'); ovh.className='feed'; ovh.textContent='OVERVIEW'; side.appendChild(ovh);
  // Discover is the headline unified view for Tufin — one click fetches every
  // feed and folds it into a device-centric dashboard + nested tables.
  if(DETAIL.kind==='tufin'){
    const dc=document.createElement('div'); dc.className='q ov'; dc.id='ovDiscover';
    dc.innerHTML='<span class="qid">🔎 Discover</span>';
    dc.onclick=openDiscover; side.appendChild(dc);
  }
  const all=document.createElement('div'); all.className='q ov'; all.id='ovAll';
  all.innerHTML='<span class="qid">★ All Fetched Results</span>';
  all.onclick=openMerged; side.appendChild(all);
  // Any adapter with a change_detail resource (Tufin revisions, SolarWinds NCM
  // config changes) accumulates a deduplicated Change Log.
  if((DETAIL.queries||[]).some(q=>q.resource==='change_detail')){
    const cl=document.createElement('div'); cl.className='q ov'; cl.id='ovChangeLog';
    cl.innerHTML='<span class="qid">⟳ Change Log</span>';
    cl.onclick=openChangeLog; side.appendChild(cl);
    const cd=document.createElement('div'); cd.className='q ov'; cd.id='ovChangeDash';
    cd.innerHTML='<span class="qid">📊 Changes Dashboard</span>';
    cd.onclick=openChangeDashboard; side.appendChild(cd);
  }
  // Revision comparison is Tufin-specific (needs live per-revision rulebases).
  if(DETAIL.kind==='tufin'){
    const rc=document.createElement('div'); rc.className='q ov'; rc.id='ovRevCompare';
    rc.innerHTML='<span class="qid">🔀 Compare Revisions</span>';
    rc.onclick=openRevisionCompare; side.appendChild(rc);
    const rp=document.createElement('div'); rp.className='q ov'; rp.id='ovRevPolicy';
    rp.innerHTML='<span class="qid">📜 Revision Policy</span>';
    rp.onclick=openRevisionPolicy; side.appendChild(rp);
  }
  const dl=document.createElement('div'); dl.className='q ov'; dl.id='ovDrift';
  dl.innerHTML='<span class="qid">⇄ Drift Log</span>';
  dl.onclick=openDrift; side.appendChild(dl);
  // Raw per-resource feeds. For Tufin these are a power-user drill-down behind
  // an Advanced toggle (Discover is the primary view); other adapters show them
  // directly.
  const advanced=(DETAIL.kind!=='tufin');
  const feedWrap=document.createElement('div'); feedWrap.id='feedWrap';
  if(!advanced) feedWrap.classList.add('hidden');
  if(DETAIL.kind==='tufin'){
    const tog=document.createElement('div'); tog.className='feed advtoggle'; tog.id='advToggle';
    tog.innerHTML='▸ Advanced — raw feeds';
    tog.onclick=()=>{ feedWrap.classList.toggle('hidden');
      tog.innerHTML=(feedWrap.classList.contains('hidden')?'▸':'▾')+' Advanced — raw feeds'; };
    side.appendChild(tog);
  }
  DETAIL.feeds.forEach(f=>{
    const h=document.createElement('div'); h.className='feed'; h.textContent=f.name; feedWrap.appendChild(h);
    f.query_ids.forEach(qid=>{
      const q=qById[qid]; if(!q) return;
      const row=document.createElement('div'); row.className='q'; row.dataset.id=q.id;
      row.innerHTML='<span><span class="qid">'+esc(q.id)+'</span> <span class="qname">'+esc(q.name)+'</span></span>'+
        '<span class="badge b-'+q.status+'">'+q.status.replace(/_/g,' ')+'</span>';
      row.onclick=()=>select(q.id); feedWrap.appendChild(row);
    });
  });
  side.appendChild(feedWrap);
}

function select(id){
  CURRENT=DETAIL.queries.find(q=>q.id===id); LASTROWS=null; SORT={col:null,dir:1};
  document.querySelectorAll('.q').forEach(e=>e.classList.toggle('active',e.dataset.id===id));
  const q=CURRENT, m=document.getElementById('main');
  const last=q.last_fetch?('saved '+new Date(q.last_fetch.ran_at).toLocaleString()+' · '+q.last_fetch.row_count+' rows'):'not fetched yet';
  m.innerHTML=
    '<h2>'+esc(q.id)+' — '+esc(q.name)+' <span class="badge b-'+q.status+'">'+q.status.replace(/_/g,' ')+'</span></h2>'+
    '<div class="sub">'+esc(q.purpose)+'</div>'+
    (q.expected_output_fields.length?'<div class="fields">Fields: '+q.expected_output_fields.map(esc).join(', ')+'</div>':'')+
    '<pre>'+esc(q.esql_query.trim()||(q.resource?(DETAIL.name+' resource: '+q.resource):'(no query — placeholder)'))+'</pre>'+
    '<div class="controls">'+
      (q.is_runnable
        ? '<button id="runbtn">Run</button>'+
          '<label class="hint">limit <input type="number" id="limit" min="1" value="100"></label>'+
          '<label class="hint">range <select id="range">'+
            (q.resource==='change_detail'?'<option value="incremental">Since last check</option>':'')+
            '<option value="all">All time</option><option value="24h">Last 24h</option>'+
            '<option value="7d">Last 7 days</option><option value="30d">Last 30 days</option>'+
            '<option value="90d">Last 90 days</option></select></label>'
        : '<span class="hint">Placeholder — no query defined yet.</span>')+
      '<span class="meta" id="runmeta">'+esc(last)+'</span>'+
    '</div>'+
    '<div id="results"></div>';
  if(q.is_runnable){
    document.getElementById('runbtn').onclick=run;
    if(q.last_fetch) loadSaved(q.id);
  }
}

async function loadSaved(id){
  try{const rec=await j('/api/adapters/'+ADAPTER+'/latest/'+id); render(rec);}catch(e){}
}

async function run(){
  const btn=document.getElementById('runbtn'), res=document.getElementById('results');
  const limit=document.getElementById('limit').value, range=document.getElementById('range').value;
  const params=new URLSearchParams();
  if(limit) params.set('limit',limit);
  if(range && range!=='all') params.set('range',range);
  const qs=params.toString();
  btn.disabled=true; btn.textContent='Running…'; res.innerHTML='';
  try{
    const rec=await j('/api/adapters/'+ADAPTER+'/run/'+CURRENT.id+(qs?('?'+qs):''),{method:'POST'});
    document.getElementById('runmeta').innerHTML='fetched '+new Date(rec.ran_at).toLocaleString()+
      '<span class="savedtag">✓ saved to database</span>';
    render(rec);
  }catch(e){res.innerHTML='<div class="err">'+esc(e.message)+'</div>';}
  finally{btn.disabled=false; btn.textContent='Run';}
}

function render(rec){
  LASTROWS={cols:rec.columns.map(c=>c.name),rows:rec.rows.slice()};
  const cols=rec.columns.map(c=>c.name);
  const inventory=cols.includes('host.name') && !cols.includes('@timestamp');
  const res=document.getElementById('results');
  res.innerHTML=
    '<div class="meta">'+rec.row_count+' row(s)'+(rec.limit?(' · limit '+rec.limit):'')+
      (rec.time_range?(' · range '+esc(rec.time_range)):'')+
      ' · <a class="dl" href="/api/adapters/'+ADAPTER+'/export/'+rec.query_id+'.csv">Download CSV</a>'+
      ' · <a class="dl" href="/api/adapters/'+ADAPTER+'/export/'+rec.query_id+'.json">Download JSON</a>'+
      (inventory?(' · <a class="dl" href="#" onclick="openChangeDetail(\''+rec.query_id+'\');return false;">⇄ Diff vs previous fetch</a>'):'')+
      '</div>'+
    '<div id="tw"></div>'+
    '<div id="diffout"></div>';
  mountTable(document.getElementById('tw'), LASTROWS.cols, LASTROWS.rows, {pin:srcPin()});
}

/* ---------- fetch all ---------- */
async function runAll(){
  if(!ADAPTER) return;
  const btn=document.getElementById('fetchall'); const label=btn.textContent;
  btn.disabled=true; btn.textContent='Fetching all…';
  try{
    const d=await j('/api/adapters/'+ADAPTER+'/run-all?limit=200',{method:'POST'});
    const nc=d.results.reduce((s,r)=>s+(r.new_changes||0),0);
    alert('Fetched all endpoints for '+DETAIL.name+':\n'+d.ran+' ran, '+d.failed+' failed'+
          (nc?('\n'+nc+' new change(s) recorded'):''));
    DETAIL=await j('/api/adapters/'+ADAPTER); renderSidebar();  // refresh saved badges
  }catch(e){ alert('Fetch all failed: '+e.message); }
  finally{ btn.disabled=false; btn.textContent=label; }
}

/* ---------- schedules ---------- */
let SCHED_TIMER=null;
function toggleSched(){
  const p=document.getElementById('schedpanel');
  const open=p.classList.contains('hidden');
  p.classList.toggle('hidden',!open);
  if(open){ fillSchedQuery(); refreshSched(); SCHED_TIMER=setInterval(refreshSched,5000); }
  else stopSchedPoll();
}
function stopSchedPoll(){ if(SCHED_TIMER){ clearInterval(SCHED_TIMER); SCHED_TIMER=null; } }
async function refreshSched(){ await loadSchedStatus(); await loadSchedules(); }
async function loadSchedStatus(){
  const el=document.getElementById('s_status');
  let s; try{ s=await j('/api/scheduler'); }catch(e){ el.textContent=''; return; }
  if(s.running){
    const tick=s.last_tick_at?new Date(s.last_tick_at).toLocaleTimeString():'—';
    el.innerHTML='<span style="color:var(--ok)">● scheduler running</span> · every '+Math.round(s.tick_seconds)+'s'+
      ' · last tick '+esc(tick)+(s.last_ran_count?(' · '+s.last_ran_count+' ran'):'');
  }else{
    el.innerHTML='<span style="color:var(--warn)">○ scheduler not running</span> — start the app with <code>assetflow serve</code>';
  }
}
function fillSchedQuery(){
  const sel=document.getElementById('s_query');
  let h='<option value="*">All endpoints</option>';
  (DETAIL.queries||[]).forEach(q=>{ if(q.is_runnable) h+='<option value="'+q.id+'">'+esc(q.id+' — '+q.name)+'</option>'; });
  sel.innerHTML=h;
}
async function loadSchedules(){
  const list=document.getElementById('s_list');
  let d; try{ d=await j('/api/schedules'); }catch(e){ list.innerHTML='<div class="err">'+esc(e.message)+'</div>'; return; }
  const mine=d.schedules.filter(s=>s.adapter===ADAPTER);
  if(!mine.length){ list.innerHTML='<div class="chint">No schedules yet.</div>'; return; }
  list.innerHTML=mine.map(s=>{
    const mins=Math.round(s.interval_seconds/60);
    const q=(s.query_id==='*'?'All endpoints':s.query_id);
    const mode=s.time_range?s.time_range:'all time';
    const nxt=s.next_run_at?new Date(s.next_run_at).toLocaleTimeString():'due now';
    const last=s.last_run_at?('last '+new Date(s.last_run_at).toLocaleTimeString()):'not run yet';
    return '<div class="schedrow"><span>'+esc(q)+' · every '+mins+'m · '+esc(mode)+
      (s.limit?(' · limit '+s.limit):'')+' · '+esc(last)+' · '+(s.enabled?('next '+esc(nxt)):'<i>disabled</i>')+'</span>'+
      '<span class="stog" onclick="toggleSchedule('+s.id+','+(!s.enabled)+')">'+(s.enabled?'disable':'enable')+'</span>'+
      '<span class="sdel" onclick="deleteSchedule('+s.id+')">delete</span></div>';
  }).join('');
}
async function addSchedule(){
  const mins=parseFloat(val('s_interval'))||10;
  const body={adapter:ADAPTER, query_id:val('s_query')||'*',
              interval_seconds:Math.max(60,Math.round(mins*60)),
              time_range:val('s_range'), limit:(parseInt(val('s_limit'))||null)};
  try{ await j('/api/schedules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
       loadSchedules(); }
  catch(e){ alert('Could not add schedule: '+e.message); }
}
async function toggleSchedule(id,enabled){
  try{ await j('/api/schedules/'+id+'/toggle?enabled='+enabled,{method:'POST'}); loadSchedules(); }catch(e){ alert(e.message); }
}
async function deleteSchedule(id){
  try{ await j('/api/schedules/'+id,{method:'DELETE'}); loadSchedules(); }catch(e){ alert(e.message); }
}

/* ---------- connection ---------- */
function connSummary(d){
  if(!d) return '';
  if(d.summary) return d.summary;
  const parts=[]; if(d.cluster_name) parts.push(d.cluster_name); if(d.version) parts.push('v'+d.version);
  return parts.join(' · ');
}
function setConn(ok,d){
  const el=document.getElementById('conn');
  if(ok){el.innerHTML='<span class="dot ok"></span>connected · '+esc(connSummary(d));}
  else{el.innerHTML='<span class="dot bad"></span>'+esc((d&&d.error)||'not connected');}
}
function togglePanel(force){
  const p=document.getElementById('connpanel');
  const open=(force===undefined)?p.classList.contains('hidden'):force;
  p.classList.toggle('hidden',!open);
}
async function connect(){
  if(!ADAPTER) return;
  const btn=document.getElementById('c_btn'), st=document.getElementById('c_status');
  btn.disabled=true; const label=btn.textContent; btn.textContent='Connecting…'; st.textContent='';
  const body={host:val('c_host'),port:val('c_port'),username:val('c_user'),
              password:document.getElementById('c_pass').value||'',
              base_path:val('c_basepath'),
              verify_certs:document.getElementById('c_verify').checked,
              remember:document.getElementById('c_remember').checked,
              request_timeout:parseInt(val('c_timeout'))||60};
  try{
    const d=await j('/api/adapters/'+ADAPTER+'/connect',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(d.ok){
      st.innerHTML='<span style="color:var(--ok)">✓ Connected · '+esc(connSummary(d))+
        (d.saved?' · saved on this machine':'')+'</span>';
      if(DETAIL){ DETAIL.has_saved=DETAIL.has_saved||d.saved; updateForget(); }
      setConn(true,d); setTimeout(()=>togglePanel(false),900);
    }else{ st.innerHTML='<span style="color:var(--bad)">✗ '+esc(d.error)+'</span>'; setConn(false,d);}
  }catch(e){st.innerHTML='<span style="color:var(--bad)">✗ '+esc(e.message)+'</span>';}
  finally{btn.disabled=false; btn.textContent=label;}
}

showGallery();
</script>
</body>
</html>
"""
