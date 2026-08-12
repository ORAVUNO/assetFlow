"""Local web UI for browsing feeds/queries and viewing fetched results.

Run with ``assetflow serve``. Binds to 127.0.0.1 by default, so the app, your
credentials, and your data stay on your machine. The page talks to a small
JSON API defined here; queries run live against Elasticsearch and the latest
result per query is cached to disk (see cache.py).
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException, Query as QueryParam
from fastapi.responses import HTMLResponse, JSONResponse, Response

from . import cache
from . import client as client_mod
from . import runner as runner_mod
from .models import Registry
from .registry import load_registry
from .runner import QueryResult

# The client is built lazily on first use and reused across requests.
_state: dict = {"client": None, "registry": None}


def _get_client():
    if _state["client"] is None:
        _state["client"] = client_mod.build_client_from_env()
    return _state["client"]


def _query_public(reg: Registry, query) -> dict:
    return {
        "id": query.id,
        "name": query.name,
        "category": query.category,
        "status": query.status.value,
        "validated": query.validated,
        "purpose": query.purpose,
        "notes": query.notes,
        "esql_query": query.esql_query,
        "expected_output_fields": query.expected_output_fields,
        "recommended_refresh_frequency": query.recommended_refresh_frequency,
        "is_runnable": query.is_runnable,
        "cached_at": cache.cached_at(query.id),
    }


def create_app(registry_path: Optional[str] = None) -> FastAPI:
    reg = load_registry(registry_path)
    _state["registry"] = reg
    app = FastAPI(title="assetFlow", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return INDEX_HTML

    @app.get("/api/registry")
    def api_registry() -> dict:
        return {
            "metadata": {
                "version": reg.metadata.version,
                "description": reg.metadata.description,
            },
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
            "queries": [_query_public(reg, q) for q in reg.queries],
        }

    @app.get("/api/connection")
    def api_connection() -> JSONResponse:
        try:
            info = client_mod.ping(_get_client())
            return JSONResponse({"ok": True, **info})
        except client_mod.ConnectionConfigError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=200)
        except Exception as exc:  # connection/auth failures
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=200)

    @app.post("/api/run/{query_id}")
    def api_run(query_id: str, limit: Optional[int] = QueryParam(default=None, ge=1)) -> dict:
        try:
            query = reg.get_query(query_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown query {query_id}")
        if not query.is_runnable:
            raise HTTPException(
                status_code=422,
                detail=f"{query.id} has no ES|QL (status {query.status.value}); nothing to run",
            )
        try:
            client = _get_client()
        except client_mod.ConnectionConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        try:
            result = runner_mod.run_query(client, query, limit=limit)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"query failed: {exc}")
        record = cache.save_result(query, result, limit)
        return record

    @app.get("/api/cache/{query_id}")
    def api_cache(query_id: str) -> dict:
        record = cache.load_result(query_id)
        if record is None:
            raise HTTPException(status_code=404, detail="no cached result; run the query first")
        return record

    @app.get("/api/export/{query_id}.{fmt}")
    def api_export(query_id: str, fmt: str) -> Response:
        record = cache.load_result(query_id)
        if record is None:
            raise HTTPException(status_code=404, detail="no cached result; run the query first")
        result = QueryResult(columns=record["columns"], rows=record["rows"])
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
  header{display:flex;align-items:center;gap:12px;padding:12px 18px;background:var(--panel);
         border-bottom:1px solid var(--border);position:sticky;top:0;z-index:5}
  header h1{font-size:16px;margin:0;font-weight:650}
  #conn{margin-left:auto;font-size:12px;color:var(--muted)}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;background:var(--muted)}
  .dot.ok{background:var(--ok)} .dot.bad{background:var(--bad)}
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
  button{background:var(--accent);color:var(--accent-fg);border:0;border-radius:7px;
         padding:8px 16px;font-size:13px;font-weight:600;cursor:pointer}
  button:disabled{opacity:.5;cursor:not-allowed}
  button.ghost{background:transparent;color:var(--accent);border:1px solid var(--border)}
  input[type=number]{width:90px;padding:7px;border:1px solid var(--border);border-radius:7px;
                     background:var(--panel);color:var(--text)}
  input[type=text]{padding:7px 10px;border:1px solid var(--border);border-radius:7px;
                   background:var(--panel);color:var(--text);min-width:200px}
  .meta{font-size:12px;color:var(--muted);margin:6px 0}
  .tablewrap{overflow:auto;border:1px solid var(--border);border-radius:8px;margin-top:10px}
  table{border-collapse:collapse;width:100%;font-size:12.5px}
  th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);white-space:nowrap}
  th{background:var(--panel);position:sticky;top:0;cursor:pointer;user-select:none}
  th:hover{color:var(--accent)} tr:nth-child(even) td{background:var(--row)}
  .err{color:var(--bad);background:color-mix(in srgb,var(--bad) 10%,transparent);
       border:1px solid color-mix(in srgb,var(--bad) 30%,transparent);border-radius:8px;padding:10px 12px}
  .hint{color:var(--muted)} .fields{font-size:12px;color:var(--muted)}
  a.dl{font-size:12px}
</style>
</head>
<body>
<header>
  <h1>assetFlow</h1>
  <span id="conn"><span class="dot"></span>checking connection…</span>
</header>
<div class="wrap">
  <aside id="sidebar"></aside>
  <main id="main"><p class="hint">Select a query on the left.</p></main>
</div>
<script>
let REG=null, CURRENT=null, LASTROWS=null, SORT={col:null,dir:1};

async function j(url,opts){const r=await fetch(url,opts);const d=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(d.detail||('HTTP '+r.status)); return d;}

function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

async function loadConn(){
  const el=document.getElementById('conn');
  try{const d=await j('/api/connection');
    if(d.ok){el.innerHTML='<span class="dot ok"></span>connected · '+esc(d.cluster_name||'')+' · v'+esc(d.version||'');}
    else{el.innerHTML='<span class="dot bad"></span>'+esc(d.error||'not connected');}
  }catch(e){el.innerHTML='<span class="dot bad"></span>'+esc(e.message);}
}

async function loadReg(){
  REG=await j('/api/registry');
  const qById={}; REG.queries.forEach(q=>qById[q.id]=q);
  const side=document.getElementById('sidebar'); side.innerHTML='';
  REG.feeds.forEach(f=>{
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
  CURRENT=REG.queries.find(q=>q.id===id); LASTROWS=null; SORT={col:null,dir:1};
  document.querySelectorAll('.q').forEach(e=>e.classList.toggle('active',e.dataset.id===id));
  const q=CURRENT, m=document.getElementById('main');
  const cached=q.cached_at?('last fetched '+new Date(q.cached_at).toLocaleString()):'not fetched yet';
  m.innerHTML=
    '<h2>'+esc(q.id)+' — '+esc(q.name)+' <span class="badge b-'+q.status+'">'+q.status.replace(/_/g,' ')+'</span></h2>'+
    '<div class="sub">'+esc(q.purpose)+'</div>'+
    (q.expected_output_fields.length?'<div class="fields">Fields: '+q.expected_output_fields.map(esc).join(', ')+'</div>':'')+
    '<pre>'+esc(q.esql_query.trim()||'(no ES|QL — placeholder)')+'</pre>'+
    '<div class="controls">'+
      (q.is_runnable
        ? '<button id="runbtn">Run</button><label class="hint">limit <input type="number" id="limit" min="1" value="100"></label>'
        : '<span class="hint">This query is a placeholder with no ES|QL and cannot be run.</span>')+
      '<span class="meta" id="runmeta">'+esc(cached)+'</span>'+
    '</div>'+
    '<div id="results"></div>';
  if(q.is_runnable){
    document.getElementById('runbtn').onclick=run;
    if(q.cached_at) loadCache(q.id);
  }
}

async function loadCache(id){
  try{const rec=await j('/api/cache/'+id); render(rec);}catch(e){/* none */}
}

async function run(){
  const btn=document.getElementById('runbtn'); const res=document.getElementById('results');
  const limit=document.getElementById('limit').value;
  btn.disabled=true; btn.textContent='Running…'; res.innerHTML='';
  try{
    const rec=await j('/api/run/'+CURRENT.id+(limit?('?limit='+encodeURIComponent(limit)):''),{method:'POST'});
    document.getElementById('runmeta').textContent='fetched '+new Date(rec.ran_at).toLocaleString();
    render(rec);
    const q=REG.queries.find(x=>x.id===CURRENT.id); if(q) q.cached_at=rec.ran_at;
  }catch(e){res.innerHTML='<div class="err">'+esc(e.message)+'</div>';}
  finally{btn.disabled=false; btn.textContent='Run';}
}

function render(rec){
  LASTROWS={cols:rec.columns.map(c=>c.name),rows:rec.rows.slice()};
  const res=document.getElementById('results');
  res.innerHTML=
    '<div class="meta">'+rec.row_count+' row(s)'+(rec.limit?(' · limit '+rec.limit):'')+
      ' · <a class="dl" href="/api/export/'+rec.query_id+'.csv">Download CSV</a>'+
      ' · <a class="dl" href="/api/export/'+rec.query_id+'.json">Download JSON</a></div>'+
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

loadConn(); loadReg();
</script>
</body>
</html>
"""
