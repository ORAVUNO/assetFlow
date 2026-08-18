# assetFlow

Asset-intelligence tool that fetches assets from pluggable **adapters** (data
sources), shows them in a local web UI, and persists every fetch to a local
database. Elasticsearch is the first adapter; more sources plug in beside it,
grouped by category, so results from many sources can later be merged.

- **Adapters:** each adapter has its own metadata, query registry, and live
  connection. The UI lists adapters by category; you open one adapter's panel
  to connect and fetch. Today: **Elasticsearch** (category *SIEM / Log
  Analytics*).
- **Registry:** `config/asset_intelligence_registry.yaml` — the Elasticsearch
  adapter's 17 ES|QL queries grouped into 6 feeds (Identity, User Management,
  Service Change, Application Discovery, Database Discovery, File Integrity).
- **Database:** fetched results are saved to a local SQLite file
  (`assetflow.db`, gitignored). The newest run per query is the panel's saved
  view; older runs form the history. Real telemetry never leaves your machine.
  Point `DATABASE_URL` at Postgres to scale later — no code changes.
- **CLI:** `assetflow` validates the registry, connects, runs queries, and
  serves the web UI.

## Requirements

- Python 3.9+
- Network access to your Elasticsearch (8.11+ for ES|QL) and credentials
  (an API key, or a username/password).

## Setup

```bash
git clone <this-repo> && cd assetFlow

python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

pip install -e .                     # add ".[dev]" to also get pytest
```

## Configure credentials

Credentials are read from environment variables. The easiest way is a local
`.env` file (it is gitignored — never commit real credentials):

```bash
cp .env.example .env
# edit .env and set your connection + auth
```

Set **one connection target**:

- `ELASTICSEARCH_URL` — e.g. `https://your-host:9200`, or
- `ELASTIC_CLOUD_ID` — the Cloud ID from Elastic Cloud

and **one auth style**:

- `ELASTIC_API_KEY` — a base64 API key (recommended), or
- `ELASTIC_USERNAME` + `ELASTIC_PASSWORD` — basic auth

Optional: `ELASTIC_CA_CERTS` (path to a CA bundle), `ELASTIC_VERIFY_CERTS`
(`false` to disable TLS verification — local testing only),
`ELASTIC_REQUEST_TIMEOUT` (seconds).

## Verify it works

```bash
# 1. The registry loads and validates (no Elasticsearch needed):
assetflow validate

# 2. Your credentials connect to the cluster:
assetflow test-connection
#   -> Connected.  cluster=... node=... version=...

# 3. Fetch real data with a validated query:
assetflow run AI001 --limit 25
```

## Web UI

Prefer clicking to typing? Launch the local web app:

```bash
assetflow serve            # -> http://127.0.0.1:8000
```

Open the URL in your browser. You land on the **adapter gallery** — adapters
grouped by category, each showing its connection status. Click one to open its
**workspace**: a sidebar of feeds/queries with status badges, the query text,
a **Run** button with row-limit and time-range controls, and results in a
sortable, filterable table with **Download CSV/JSON**. The breadcrumb
(`assetFlow › Elasticsearch`) shows which adapter you're in; click **assetFlow**
to return to the gallery. Every run is **saved to the database** automatically
and reloaded when you reopen that query.

**Exporting saved data** happens at three levels:

- **Per query** — the Download CSV / JSON links under a query's results.
- **Per adapter** — the *export this adapter* links in the workspace header
  bundle every saved query for that adapter.
- **Whole platform** — the *Export all saved data* links on the gallery bundle
  every saved query across every adapter.

Adapter and platform exports come in two formats: **JSON** (one structured file
— scope, timestamp, and each query's columns + rows) and **ZIP** (a
`manifest.json` plus one `<adapter>/<query>.csv` per saved query, for
Excel/Sheets). Exports read from the local database, so they reflect your most
recent saved fetch of each query.

## Unified view (asset correlation)

Each adapter has an **All Fetched Results** entry (top of its sidebar) that
builds a unified, host-keyed view from everything saved for that adapter:

- **Main table (golden records)** — one row per host, correlated across every
  saved query that carries a `host.name` column. Each cell summarizes what a
  query captured for that host (e.g. its users, applications, services,
  databases). Downloadable as CSV/JSON.
- **Sheets (mini tables)** — the per-query saved results, grouped by feed
  (Login Activity, Applications, Services, Databases, …). Queries not yet run
  are shown as *not fetched*.

Queries that aren't host-keyed (e.g. service-aggregated `AI010`/`AI012`) can't
be a host row; they're listed as *not host-keyed* and appear only as sheets.
This is the intra-adapter merge; cross-adapter reconciliation (merging the same
host/asset seen by multiple adapters) builds on the same shape in a later
round.

**Connecting from the browser:** click **Connection** in the header to open a
form — enter your **hostname or IP** (a bare host becomes `https://host:9200`;
you can also paste a full URL), **username**, **password**, toggle **Verify TLS
certificate**, and hit **Test & connect**. On success the header turns green
with the cluster name and version. Credentials entered this way are held in the
local server's memory only and are never written to disk. Setting them in
`.env` still works and auto-connects on startup — the form is just an
alternative so you don't have to edit files.

Each query also has a **time-range** dropdown (All time / 24h / 7d / 30d / 90d)
next to Run. Picking a range injects a `@timestamp` lower-bound filter right
after `FROM` at run time — the query in the registry is unchanged. Use it to
bound heavy all-index aggregations (e.g. AI001) so they finish quickly instead
of timing out.

Queries run live against your Elasticsearch, and the latest result per query is
cached under `.assetflow_cache/` (gitignored) so reopening the page shows your
last fetch without re-querying. The server binds to `127.0.0.1` by default, so
your credentials and data never leave your machine. Change the bind with
`assetflow serve --host 0.0.0.0 --port 9000` if you need to (localhost is
recommended).

## CLI reference

| Command | What it does |
|---|---|
| `assetflow validate` | Load and validate the registry; print a summary. |
| `assetflow feeds` | List the data feeds and their member queries. |
| `assetflow list [--status S] [--category C] [--feed F]` | List queries with optional filters. |
| `assetflow show <ID>` | Show one query's full definition and ES|QL. |
| `assetflow test-connection` | Verify Elasticsearch connectivity. |
| `assetflow run <ID> [--limit N] [--range 24h\|7d\|30d\|90d] [--output table\|json\|csv]` | Execute one query and print results. |
| `assetflow run-feed <FEED_ID> [--limit N]` | Execute every runnable query in a feed. |

Point at a registry elsewhere with the global `--registry` option, e.g.
`assetflow --registry /path/to/registry.yaml validate`.

### Examples

```bash
assetflow list --feed FEED-USER-MGMT
assetflow run AI010 --output json > applications.json
assetflow run AI001 --limit 100 --output csv > user_device_mapping.csv
assetflow run-feed FEED-IDENTITY
```

Queries with status `not_validated` (the placeholders AI016, AI017) have no
ES|QL yet and are skipped by `run-feed`; `run` reports a clear message if you
target one directly.

## Using the registry from Python

```python
from assetflow import load_registry
from assetflow.client import build_client_from_env
from assetflow.runner import run_query

reg = load_registry()                      # loads config/asset_intelligence_registry.yaml
client = build_client_from_env()           # reads env / .env
result = run_query(client, reg.get_query("AI001"), limit=50)

for row in result.to_dicts():
    print(row)
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

The tests validate the shipped registry and the result/runner logic using a
fake Elasticsearch client, so they run without a live cluster.

## Status values

| Status | Meaning |
|---|---|
| `validated` | Confirmed working against live data. |
| `partially_validated` | Runs, but some fields/behaviour need further mapping validation. |
| `investigation_required` | Additional research needed before relying on it. |
| `not_validated` | Not yet tested (placeholders with no ES|QL). |
