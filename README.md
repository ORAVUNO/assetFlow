# assetFlow

Asset-intelligence tool that fetches assets from pluggable **adapters** (data
sources), shows them in a local web UI, and persists every fetch to a local
database. Elasticsearch is the first adapter and Tufin SecureTrack is the
second; more sources plug in beside them, grouped by category, so results from
many sources can later be merged.

- **Adapters:** each adapter has its own metadata, query registry, and live
  connection. The UI lists adapters by category; you open one adapter's panel
  to connect and fetch. Today: **Elasticsearch** (category *SIEM / Log
  Analytics*) and **Tufin SecureTrack** (category *Network Security Policy* —
  see [Tufin adapter](#tufin-securetrack-adapter)).
- **Registry:** `config/asset_intelligence_registry.yaml` — the Elasticsearch
  adapter's 25 ES|QL queries grouped into 8 feeds (Identity, User Management,
  Service Change, Application Discovery, Database Discovery, File Integrity,
  Authentication & Access Changes, Security Configuration Changes).
  `config/tufin_registry.yaml` — the Tufin adapter's 8 SecureTrack resources in
  7 feeds (Device Inventory, Change History, Policy Rules, Network Objects &
  Services, Segmentation, Policy Hygiene, Audit Events).
- **Database:** fetched results are saved to a local SQLite file
  (`assetflow.db`, gitignored). The newest run per query is the panel's saved
  view; older runs form the history. Real telemetry never leaves your machine.
  Point `DATABASE_URL` at Postgres to scale later — no code changes.
- **CLI:** `assetflow` validates the registry, connects, runs queries, and
  serves the web UI.

**Developer guides** (how the code works, per adapter):
[`docs/elasticsearch_integration.md`](docs/elasticsearch_integration.md) ·
[`docs/tufin_integration.md`](docs/tufin_integration.md) ·
[`docs/tufin_securetrack_api_reference.md`](docs/tufin_securetrack_api_reference.md).

## Requirements

- Python 3.9+
- For the Elasticsearch adapter: network access to your Elasticsearch (8.11+
  for ES|QL) and credentials (an API key, or a username/password).
- For the Tufin adapter: network access to your Tufin SecureTrack host and a
  SecureTrack API user (host + username + password).

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
with the cluster name and version. By default credentials entered this way are
held in the local server's memory only and are never written to disk. Tick
**Remember on this machine** before connecting to save the connection to `.env`
(gitignored) on success — it then auto-connects on every startup with no
re-entry, and the panel shows a **Forget saved credentials** link to clear it.
Setting `.env` by hand still works too — the form is just an alternative so you
don't have to edit files.

> **Note:** *Remember on this machine* writes the host/username/password to the
> local `.env` in plaintext (the same as editing `.env` yourself). It's opt-in;
> leave it unticked to keep the memory-only default. Saving a connection is also
> what lets the background **scheduler** run unattended after a restart, since it
> needs the adapter already connected.

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

## Fetch all & scheduling

Two controls in an adapter's workspace header (next to **Connection**):

- **Fetch all** — runs *every* runnable query for the adapter once, saves each,
  and reports how many ran/failed (and any new change-log entries). Placeholders
  are skipped; one query failing doesn't stop the rest.
- **Schedules** — opens a panel to run fetches automatically on an interval. Pick
  a query (or **All endpoints**), an interval in minutes, a **Mode** (All time /
  Since last check / 24h / 7d / 30d / 90d), and an optional row limit. Schedules
  are saved in the database (`schedules` table) and run by a background worker
  while `assetflow serve` is up — **only while the adapter is connected** (they
  resume automatically once it reconnects). Enable/disable or delete each from
  the same panel.

For continuous Tufin change monitoring, schedule **All endpoints** (or just the
Change Detail query) with **Since last check** every 5–15 minutes: each run
appends deduplicated changes to the change log with no gaps or repeats.

## Tufin SecureTrack adapter

The second adapter fetches **network security policy** asset intelligence from
[Tufin SecureTrack](https://www.tufin.com/tufin-orchestration-suite/securetrack)
over its REST API (`https://<host>/securetrack/api/`, HTTP Basic auth with a
SecureTrack API user). It plugs into the same framework as Elasticsearch: a
registry of resources, a live connection, saved fetches, the unified host view,
and CSV/JSON/ZIP export.

Instead of an ES|QL body, each Tufin registry entry names a **resource** that
the adapter maps to one or more SecureTrack endpoints and normalizes into the
same column/row shape. Device-scoped resources emit a `host.name` column (the
device/CI name), so they fold into the *All Fetched Results* golden records
right alongside the Elasticsearch host-keyed queries.

### What it fetches

| ID | Resource | Feed | SecureTrack endpoint(s) |
|---|---|---|---|
| TUF001 | Device inventory | Device Inventory | `devices.json?show_os_version=true` |
| TUF002 | **Device revisions — who changed what, when** | Change History | `devices/{id}/revisions.json` |
| TUF003 | Effective policy rules | Policy Rules | `revisions/{latest}/rules.json`, `devices/{id}/rules.json` |
| TUF004 | Network objects | Network Objects & Services | `devices/{id}/network_objects.json` |
| TUF005 | Services | Network Objects & Services | `devices/{id}/services.json` |
| TUF006 | Zones (segmentation) | Segmentation & Topology | `zones.json` |
| TUF007 | Rule cleanups (shadowed/unused) | Policy Hygiene | `devices/{id}/cleanups.json` |
| TUF008 | **Change detail — what changed, who, when, authorized** | Change Detection | `devices/{id}/revisions` + `revisions/{id}/rules` + `change_authorization` |

### Rich per-revision change intelligence (the headline)

`TUF002` is the resource that answers *"who changed what, and when?"*. Each
SecureTrack **revision** is a point-in-time snapshot of a device's policy, and
the API exposes, per revision:

- **`changed_by`** — the administrator who made the change (SecureTrack's
  `admin`). For most vendors this is exposed directly; for Cisco, Fortinet,
  Juniper, and Palo Alto it is populated when the device is monitored with
  **syslog**.
- **`gui_client`** — the client/tool the change was made from (`guiClient`).
- **`@timestamp`** — when the revision was created (`date` + `time`).
- **`action`** — the operation performed (e.g. "Policy Installed").
- **`ticket`** — the change ticket(s) linked to the revision
  (`tickets.ticket[].id`), the seam to change-management/approval workflows.
- **`policy_package`**, **`authorization_status`**, the revision **comment**,
  plus the revision id and its per-device order number.

The **time-range** control (24h/7d/30d/90d) bounds a revisions fetch to recent
changes, filtered on the revision timestamp.

`TUF002` gives the revision *history* (a snapshot per revision). To see **what
actually changed** in each revision, `TUF008` (**Change Detail**) diffs a
device's revisions rule-by-rule and emits one row per change — `change_type`
(added/modified/removed) with a `before → after` summary, plus the acting admin
and timestamp. When SecureChange ticket authorization is enabled
(`/change_authorization`), it also fills in whether each change was
**authorized** and who **requested** it. (SecureTrack exposes revision
snapshots, not a field-level changelog, so this "what changed" view is computed
by comparison; a pure rule rename is intentionally *not* counted as a change.)

**Which revisions get compared** is driven by the range control, which offers
three modes for `TUF008`:

- **Since last check** (incremental — the change-monitoring mode) — diffs only
  the revisions newer than each device's stored **watermark**, then advances it.
  Every change is reported **exactly once**, with no missed intermediate
  revisions and no re-processing, regardless of how long between runs; the first
  run just records a baseline. This is the mode to schedule for follow-up.
- **24h / 7d / 30d / 90d** (window) — diffs every revision in that period (plus
  the one just before it as a baseline). Best for on-demand audits — *"what
  changed last week"* — and re-reports the whole window each run.
- **All time** — diffs only the two most recent revisions (the quick "latest
  change" peek).

The number of pairs per device is capped so a wide window on a busy firewall
stays bounded. The watermark is stored per (adapter, device) in the database
(`tufin_change_watermarks`), so incremental coverage survives restarts. For
continuous monitoring, run **Since last check** on a schedule (every 5–15 min).

**Deduplicated change log.** However you fetch — different modes, repeated runs
— each detected change also upserts into a cumulative **change log**
(`tufin_changes`), keyed by the globally-unique revision id plus rule and change
type. So a change is stored **exactly once** no matter how many times or in
which mode it is fetched. Open it from the **⟳ Change Log** entry at the top of
the Tufin sidebar: one row per unique change, accumulated across every fetch —
separate from the per-fetch snapshots. (The per-query saved view still shows the
latest fetch; the change log is the deduplicated, growing history.)

### Other asset-intelligence data available from Tufin

Beyond change detection, SecureTrack is a rich asset source: the **device
inventory** (vendor/model/OS), the **effective rulebase** per device, the
**network object** and **service** inventories (the hosts, subnets, groups, and
ports each firewall protects), **zones** for segmentation matrices, and
**cleanup** findings (shadowed/unused/disabled rules) that flag policy drift and
risk. Follow-ups the REST API also supports include topology interfaces and
paths, security-policy (USP) matrices, rule documentation, and policy-analysis
queries — natural next resources to add to the registry.

### Connecting

In the web UI, open the **Tufin SecureTrack** card and click **Connection**:
enter the **host** (or IP), **username**, **password**, the **API base path**
(defaults to `/securetrack/api`), and toggle **Verify TLS certificate** (keep it
on for production certs; disable only for a lab/self-signed environment). Or set
`TOS_HOSTNAME` / `TOS_USERNAME` / `TOS_PASSWORD` in `.env` (see `.env.example`)
to auto-connect on startup. As with Elasticsearch, credentials entered in the
form are held in the local server's memory only and never written to disk.

> **Developer guide.** For a full walkthrough of how the Tufin integration
> works — architecture, module map, data flow, change-detection logic, and how
> to add a new resource — see
> [`docs/tufin_integration.md`](docs/tufin_integration.md). The confirmed
> endpoint/DTO field reference is
> [`docs/tufin_securetrack_api_reference.md`](docs/tufin_securetrack_api_reference.md).

> **Validation status.** Endpoint paths **and** field mappings are confirmed
> against the **SecureTrack 25.2 (TOS R25-2)** Swagger — see the field reference
> above for the DTO details. Resources stay marked `partially_validated` /
> `investigation_required` until also run against a live TOS box (the same
> honest labeling the Elasticsearch registry uses); the schema is now accurate,
> the live run is the remaining step. Point the adapter at a different release
> and re-check the fields against that box's `/securetrack/apidoc/`.

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
`assetflow --registry /path/to/registry.yaml validate`. The registry commands
(`validate`, `feeds`, `list`, `show`) are adapter-agnostic and work with the
Tufin registry too — e.g. `assetflow --registry config/tufin_registry.yaml
list`. Live fetching from the CLI (`run`, `run-feed`, `test-connection`) targets
Elasticsearch; **the Tufin adapter is driven from the web UI** (`assetflow
serve`), which is the multi-adapter surface.

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
