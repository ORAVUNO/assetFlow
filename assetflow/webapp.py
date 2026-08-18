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


def create_app(registry_path: Optional[str] = None, db_url: Optional[str] = None) -> FastAPI:
    db.init_engine(db_url)
    manager = adapters_mod.default_manager(registry_path)
    _state["manager"] = manager

    # Best-effort auto-connect each adapter from environment variables.
    for adapter in manager.list():
        adapter.try_auto_connect()

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
        try:
            info = a.connect_form(req.model_dump())
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=200)
        return JSONResponse({"ok": True, **info})

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
        return db.save_fetch(a.info.id, query, result, limit, range)

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
            info = {"id": a.info.id, "name": a.info.name, "category": a.info.category}
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
  #conntoggle{background:transparent;color:var(--accent);border:1px solid var(--border);
              padding:5px 12px;font-size:12px;font-weight:600;border-radius:7px;cursor:pointer}
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
</style>
</head>
<body>
<header>
  <h1 onclick="showGallery()">assetFlow</h1>
  <span id="crumb"></span>
  <span id="adapterexport" class="exp hidden"></span>
  <span id="conn" class="hidden"><span class="dot"></span></span>
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
    <button id="c_btn" onclick="connect()">Test &amp; connect</button>
  </div>
  <div class="cstat" id="c_status"></div>
  <div class="chint" id="c_hint">Credentials are held in this local server's memory only — never written to disk.
    Fetched results are saved to a local SQLite database. Bare hostnames default to <code>https://host:9200</code>.</div>
</div>

<section id="gallery"></section>

<div id="workspace" class="wrap hidden">
  <aside id="sidebar"></aside>
  <main id="main"></main>
</div>

<script>
let ADAPTER=null, DETAIL=null, CURRENT=null, LASTROWS=null, SORT={col:null,dir:1};

async function j(url,opts){const r=await fetch(url,opts);const d=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(d.detail||('HTTP '+r.status)); return d;}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function val(id){return (document.getElementById(id).value||'').trim();}

/* ---------- gallery ---------- */
async function loadGallery(){
  const g=document.getElementById('gallery'); g.innerHTML='<p class="hint">Loading adapters…</p>';
  const d=await j('/api/adapters');
  let h='<div class="gbar">Export all saved data (every adapter): '+
        '<span class="exp"><a href="/api/export-all.json">JSON</a> · '+
        '<a href="/api/export-all.zip">ZIP</a></span></div>';
  d.categories.forEach(cat=>{
    h+='<div class="gcat">'+esc(cat.name)+'</div><div class="cards">';
    cat.adapters.forEach(a=>{
      h+='<div class="card" onclick="openAdapter(\''+a.id+'\')">'+
         '<h3>'+esc(a.name)+' <span class="kind">'+esc(a.kind)+'</span></h3>'+
         '<p>'+esc(a.description)+'</p>'+
         '<div class="foot"><span>'+a.query_count+' queries · '+a.feed_count+' feeds</span>'+
         '<span>'+(a.connected?'<span class="dot ok"></span>connected':'<span class="dot"></span>not connected')+'</span></div>'+
         '</div>';
    });
    h+='</div>';
  });
  g.innerHTML=h;
}
function showGallery(){
  document.getElementById('workspace').classList.add('hidden');
  document.getElementById('connpanel').classList.add('hidden');
  document.getElementById('conn').classList.add('hidden');
  document.getElementById('conntoggle').classList.add('hidden');
  document.getElementById('adapterexport').classList.add('hidden');
  document.getElementById('crumb').textContent='';
  document.getElementById('gallery').classList.remove('hidden');
  ADAPTER=null; loadGallery();
}

/* ---------- workspace ---------- */
async function openAdapter(id){
  ADAPTER=id;
  DETAIL=await j('/api/adapters/'+id);
  document.getElementById('gallery').classList.add('hidden');
  document.getElementById('workspace').classList.remove('hidden');
  document.getElementById('conn').classList.remove('hidden');
  document.getElementById('conntoggle').classList.remove('hidden');
  const ax=document.getElementById('adapterexport');
  ax.innerHTML='export this adapter: <a href="/api/adapters/'+id+'/export-all.json">JSON</a> · '+
               '<a href="/api/adapters/'+id+'/export-all.zip">ZIP</a>';
  ax.classList.remove('hidden');
  document.getElementById('crumb').textContent='› '+DETAIL.name;
  applyKind(DETAIL.kind);
  setConn(DETAIL.connected, DETAIL.conn_info||{});
  togglePanel(!DETAIL.connected);
  renderSidebar();
  document.getElementById('main').innerHTML='<p class="hint">Select a query on the left.</p>';
  CURRENT=null;
}

/* show the connection fields that fit the adapter kind */
function applyKind(kind){
  const tufin = (kind==='tufin');
  document.getElementById('f_port').classList.toggle('hidden', tufin);
  document.getElementById('f_basepath').classList.toggle('hidden', !tufin);
  document.getElementById('c_host').placeholder = tufin
    ? 'securetrack.example.com  ·  10.0.0.5'
    : '10.0.0.5  ·  host:9200  ·  https://host:9200';
  document.getElementById('c_user').placeholder = tufin ? 'securetrack-api-user' : 'elastic';
  document.getElementById('c_timeout').value = tufin ? '30' : '60';
  document.getElementById('c_hint').innerHTML = tufin
    ? 'Credentials are held in this local server\'s memory only — never written to disk. '+
      'Connects to the SecureTrack REST API at <code>https://host/securetrack/api</code>.'
    : 'Credentials are held in this local server\'s memory only — never written to disk. '+
      'Fetched results are saved to a local SQLite database. Bare hostnames default to <code>https://host:9200</code>.';
}

/* generic sortable/filterable table mounted into any container */
function mountTable(container, cols, rows, opts){
  opts=opts||{}; let sort={col:null,dir:1};
  container.innerHTML=(opts.filter===false?'':'<input type="text" class="tfilter" placeholder="filter…"/>')+
    '<div class="tablewrap"></div>';
  const tw=container.querySelector('.tablewrap'), fin=container.querySelector('.tfilter');
  function draw(){
    let rs=rows.slice();
    const f=fin?fin.value.toLowerCase():'';
    if(f) rs=rs.filter(r=>r.some(v=>String(v==null?'':v).toLowerCase().includes(f)));
    if(sort.col!==null){const i=sort.col; rs.sort((a,b)=>{
      const x=a[i],y=b[i]; if(x==null)return 1; if(y==null)return -1;
      const nx=parseFloat(x),ny=parseFloat(y);
      if(!isNaN(nx)&&!isNaN(ny))return (nx-ny)*sort.dir;
      return String(x).localeCompare(String(y))*sort.dir;});}
    tw.innerHTML='<table><thead><tr>'+cols.map((c,i)=>'<th data-i="'+i+'">'+esc(c)+
      (sort.col===i?(sort.dir>0?' ▲':' ▼'):'')+'</th>').join('')+'</tr></thead><tbody>'+
      rs.map(r=>'<tr>'+r.map(v=>'<td>'+esc(v)+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
    tw.querySelectorAll('th').forEach(th=>th.onclick=()=>{
      const i=+th.dataset.i; if(sort.col===i)sort.dir*=-1; else{sort.col=i;sort.dir=1;} draw();});
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
  if(main.rows.length) mountTable(mt, main.columns.map(c=>c.name), main.rows, {});
  else mt.innerHTML='<p class="hint">No host-keyed results saved yet. Run a host query (e.g. AI001) first.</p>';
  d.sheets.forEach(sh=>sh.queries.forEach(q=>{ if(q.has_data){
    const el=document.querySelector('.mini[data-q="'+q.query_id+'"]');
    if(el) mountTable(el, q.columns.map(c=>c.name), q.rows, {filter:false});
  }}));
}

function renderSidebar(){
  const qById={}; DETAIL.queries.forEach(q=>qById[q.id]=q);
  const side=document.getElementById('sidebar'); side.innerHTML='';
  const ovh=document.createElement('div'); ovh.className='feed'; ovh.textContent='OVERVIEW'; side.appendChild(ovh);
  const all=document.createElement('div'); all.className='q ov'; all.id='ovAll';
  all.innerHTML='<span class="qid">★ All Fetched Results</span>';
  all.onclick=openMerged; side.appendChild(all);
  DETAIL.feeds.forEach(f=>{
    const h=document.createElement('div'); h.className='feed'; h.textContent=f.name; side.appendChild(h);
    f.query_ids.forEach(qid=>{
      const q=qById[qid]; if(!q) return;
      const row=document.createElement('div'); row.className='q'; row.dataset.id=q.id;
      row.innerHTML='<span><span class="qid">'+esc(q.id)+'</span> <span class="qname">'+esc(q.name)+'</span></span>'+
        '<span class="badge b-'+q.status+'">'+q.status.replace(/_/g,' ')+'</span>';
      row.onclick=()=>select(q.id); side.appendChild(row);
    });
  });
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
    '<pre>'+esc(q.esql_query.trim()||(q.resource?('SecureTrack resource: '+q.resource):'(no query — placeholder)'))+'</pre>'+
    '<div class="controls">'+
      (q.is_runnable
        ? '<button id="runbtn">Run</button>'+
          '<label class="hint">limit <input type="number" id="limit" min="1" value="100"></label>'+
          '<label class="hint">range <select id="range">'+
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
  const res=document.getElementById('results');
  res.innerHTML=
    '<div class="meta">'+rec.row_count+' row(s)'+(rec.limit?(' · limit '+rec.limit):'')+
      (rec.time_range?(' · range '+esc(rec.time_range)):'')+
      ' · <a class="dl" href="/api/adapters/'+ADAPTER+'/export/'+rec.query_id+'.csv">Download CSV</a>'+
      ' · <a class="dl" href="/api/adapters/'+ADAPTER+'/export/'+rec.query_id+'.json">Download JSON</a></div>'+
    '<input type="text" id="filter" placeholder="filter rows…"/>'+
    '<div class="tablewrap" id="tw"></div>';
  document.getElementById('filter').oninput=drawTable;
  drawTable();
}

function drawTable(){
  const cols=LASTROWS.cols; let rows=LASTROWS.rows.slice();
  const f=(document.getElementById('filter')||{}).value||'';
  if(f){const nf=f.toLowerCase(); rows=rows.filter(r=>r.some(v=>String(v==null?'':v).toLowerCase().includes(nf)));}
  if(SORT.col!==null){const i=SORT.col; rows.sort((a,b)=>{
    const x=a[i],y=b[i]; if(x==null)return 1; if(y==null)return -1;
    const nx=parseFloat(x),ny=parseFloat(y);
    if(!isNaN(nx)&&!isNaN(ny))return (nx-ny)*SORT.dir;
    return String(x).localeCompare(String(y))*SORT.dir;});}
  let h='<table><thead><tr>'+cols.map((c,i)=>'<th data-i="'+i+'">'+esc(c)+
    (SORT.col===i?(SORT.dir>0?' ▲':' ▼'):'')+'</th>').join('')+'</tr></thead><tbody>'+
    rows.map(r=>'<tr>'+r.map(v=>'<td>'+esc(v)+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
  const tw=document.getElementById('tw'); tw.innerHTML=h;
  tw.querySelectorAll('th').forEach(th=>th.onclick=()=>{
    const i=+th.dataset.i; if(SORT.col===i)SORT.dir*=-1; else{SORT.col=i;SORT.dir=1;} drawTable();});
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
              request_timeout:parseInt(val('c_timeout'))||60};
  try{
    const d=await j('/api/adapters/'+ADAPTER+'/connect',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(d.ok){
      st.innerHTML='<span style="color:var(--ok)">✓ Connected · '+esc(connSummary(d))+'</span>';
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
