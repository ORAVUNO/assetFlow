# assetFlow

Preloaded **Elastic Asset Intelligence** ES|QL query registry, plus a small
Python CLI to connect to your live Elasticsearch and fetch data.

- **Registry:** `config/asset_intelligence_registry.yaml` — 17 queries grouped
  into 6 category-level data feeds (Identity, User Management, Service Change,
  Application Discovery, Database Discovery, File Integrity).
- **Runner:** the `assetflow` CLI validates the registry, connects to
  Elasticsearch with your credentials, and executes the ES|QL queries.

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

Open the URL in your browser. You get a sidebar of feeds/queries with status
badges, the ES|QL for each query, a **Run** button with a row-limit box, and
results in a sortable, filterable table with **Download CSV/JSON**. Connection
status (cluster + version) shows top-right.

**Connecting from the browser:** click **Connection** in the header to open a
form — enter your **hostname or IP** (a bare host becomes `https://host:9200`;
you can also paste a full URL), **username**, **password**, toggle **Verify TLS
certificate**, and hit **Test & connect**. On success the header turns green
with the cluster name and version. Credentials entered this way are held in the
local server's memory only and are never written to disk. Setting them in
`.env` still works and auto-connects on startup — the form is just an
alternative so you don't have to edit files.

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
| `assetflow run <ID> [--limit N] [--output table\|json\|csv]` | Execute one query and print results. |
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
