# Elasticsearch Integration — Developer Guide

A single place to understand **how the Elasticsearch integration works** in
assetFlow: architecture, every module, the data flow, the ES|QL query model,
and how run-all, scheduling, persistence, and deduplication behave. Its sibling
is [`tufin_integration.md`](tufin_integration.md); the two adapters share the
same framework, so this guide highlights what is Elasticsearch-specific.

## Contents
- [Big picture](#big-picture)
- [Where everything lives](#where-everything-lives)
- [Data flow](#data-flow)
- [Connection](#connection)
- [Registry: queries & feeds](#registry-queries--feeds)
- [Runner: ES|QL execution](#runner-esql-execution)
- [Time range](#time-range)
- [Unified host view](#unified-host-view)
- [Run-all & scheduler](#run-all--scheduler)
- [Deduplication](#deduplication)
- [Persistence](#persistence)
- [HTTP API & CLI](#http-api--cli)
- [How to add a new ES|QL query](#how-to-add-a-new-esql-query)
- [Testing](#testing)
- [Design decisions & caveats](#design-decisions--caveats)

---

## Big picture

Elasticsearch is assetFlow's **first adapter**. Like every adapter
(`assetflow/adapters.py::Adapter`) it implements one small contract so the web
UI, database, export, unified view, Fetch-all, and scheduler treat it
uniformly:

```
connect_form(form) -> dict      # open a live connection from UI fields
try_auto_connect() -> bool      # best-effort connect from env vars
ping() -> dict                  # cluster info
run(query, limit, time_range) -> QueryResult
```

A **`Query`** (`models.py`) carries an `esql_query` string (Tufin uses
`resource` instead); `is_runnable` is true when the ES|QL body is non-empty.
`run()` executes the ES|QL and returns a **`QueryResult`** (`runner.py`):
`columns` + `rows`. That shared shape is why the same UI, DB, and exports serve
both adapters.

## Where everything lives

| File | Responsibility |
|---|---|
| `assetflow/adapters.py` | `ElasticsearchAdapter` (connect / ping / run) + `default_manager()` |
| `assetflow/client.py` | Cluster connection: `build_client[_from_env]()`, `ping()`, `normalize_host()`, `ConnectionConfigError` |
| `assetflow/runner.py` | `run_query()` / `run_esql()`, `apply_time_range()`, and `QueryResult` (shared with Tufin) |
| `config/asset_intelligence_registry.yaml` | 17 ES|QL queries (AI001–AI017) in 6 feeds, with statuses/notes |
| `assetflow/models.py` | `Query.esql_query`, `Registry` validation (ids unique, categories declared, feeds reference real queries) |
| `assetflow/merge.py` | Unified host view — golden records keyed on `host.name` |
| `assetflow/db.py` | `FetchRun` snapshots + `Schedule` (both adapter-agnostic) |
| `assetflow/service.py` | `run_and_save` / `save_result` / `run_all` (shared) |
| `assetflow/scheduler.py` | `tick_once` + `Scheduler` (shared) |
| `assetflow/cli.py` | `validate/feeds/list/show/test-connection/run/run-feed/serve` |
| `assetflow/webapp.py` | FastAPI endpoints + single-page UI |

## Data flow

```mermaid
flowchart TD
    UI["Web UI / Fetch all / Scheduler / CLI"] -->|run query| ADP["ElasticsearchAdapter.run"]
    ADP --> RUN["runner.run_query"]
    RUN -->|apply_time_range + LIMIT| ESQL["run_esql"]
    ESQL -->|client.esql.query| ES[("Elasticsearch (ES|QL)")]
    ESQL --> QR["QueryResult (columns + rows)"]
    QR --> SVC["service.save_result"]
    SVC --> FR[("fetch_runs (snapshot)")]
    FR --> VIEW["Saved view / Unified host view / Export"]
```

## Connection

`client.py` builds an `elasticsearch.Elasticsearch` client. Two connection
targets and two auth styles are supported:

- **Target (one of):** `ELASTICSEARCH_URL` (e.g. `https://host:9200`) or
  `ELASTIC_CLOUD_ID`.
- **Auth (one of):** `ELASTIC_API_KEY` (recommended) or `ELASTIC_USERNAME` +
  `ELASTIC_PASSWORD`.
- **Optional:** `ELASTIC_CA_CERTS`, `ELASTIC_VERIFY_CERTS`,
  `ELASTIC_REQUEST_TIMEOUT` (each also has an `ES_*` alias).

Paths into a connection:
- **UI:** `ElasticsearchAdapter.connect_form(form)` turns a bare host + port
  into a URL via `normalize_host` (a bare host becomes `https://host:9200`),
  then `build_client` + `ping`. Returns cluster info plus the `resolved_url`.
- **Env:** `try_auto_connect()` → `build_client_from_env()`; called at startup.

`ping()` returns `{name, cluster_name, version}` — the UI's connected banner
shows `cluster_name · v<version>`. Credentials are held in memory only.

## Registry: queries & feeds

`config/asset_intelligence_registry.yaml` — **17 queries** in **6 feeds**,
validated by the pydantic `Registry` model (duplicate ids, undeclared
categories, and feeds pointing at missing queries all fail the load).

| Feed | Queries | Theme |
|---|---|---|
| Identity Intelligence | AI001 | user ↔ device mapping |
| User Management Changes | AI002–AI006 | account create/enable/disable/delete, group membership (Windows event codes 4720/4722/4725/4726/4728…) |
| Service Change Intelligence | AI007–AI009 | service installed/created, startup-type changes (7045/4697/7040) |
| Application Discovery | AI010–AI012, AI016 | app/service footprint, software versions |
| Database Discovery | AI013–AI015 | DB process/host/version discovery |
| File Integrity Monitoring | AI017 | placeholder |

Each query has a **status** (`validated` / `partially_validated` /
`investigation_required` / `not_validated`) and `expected_output_fields`.
`AI016`/`AI017` are placeholders with empty `esql_query` → `is_runnable` is
false, so they are skipped by run-all and `run-feed` and rejected (422) by a
direct run.

## Runner: ES|QL execution

`runner.run_query(client, query, limit, time_range)`:
1. Guards against placeholder queries (empty ES|QL).
2. `apply_time_range()` optionally injects a `@timestamp` filter (below).
3. `run_esql()` appends `| LIMIT n` when a limit is given, calls
   `client.esql.query(query=...)`, and normalizes the response body into a
   `QueryResult` (`columns` = ES|QL column metadata, `rows` = values).

`QueryResult` provides `to_dicts()`, `to_json()`, `to_csv()`, `column_names`,
`row_count` — the same object Tufin produces, so DB/export/merge are shared.

## Time range

`apply_time_range(esql, token)` maps a UI token (`24h`/`7d`/`30d`/`90d`) to an
ES|QL timespan and injects `| WHERE @timestamp >= NOW() - <interval>` **right
after the `FROM` command**, so Elasticsearch prunes early. Unknown/empty tokens
(e.g. `all`) leave the query unchanged; the registry text is never modified.
Use it to bound heavy all-index aggregations (e.g. AI001) so they finish fast.

## Unified host view

`merge.build_host_view(records)` folds every saved result carrying a
`host.name` column into one **golden record per host** — the *All Fetched
Results* main table. Each cell summarizes what a query captured for that host
(distinct values of its most identifying column, or a record count). Results
without `host.name` (e.g. service-aggregated AI010/AI012) are reported as
`excluded` and shown as standalone sheets. This is the intra-adapter merge;
Tufin's device resources reuse the same shape by emitting `host.name`.

## Run-all & scheduler

Both are **adapter-agnostic**, so they work for Elasticsearch with no
ES-specific code:
- **Fetch all** (`service.run_all`, `POST /api/adapters/elasticsearch/run-all`)
  runs every runnable AI query once, saving each; placeholders are skipped and
  per-query errors are captured. The header **Fetch all** button drives it.
  Because some AI aggregations are heavy, the button caps rows (`limit=200`);
  pick a time range for the heaviest ones.
- **Schedules** (`db.Schedule` + `scheduler.tick_once`) run a query — or `*`
  (all runnable) — on an interval while the adapter is connected. Configure them
  from the **Schedules** panel; the background thread (started by
  `assetflow serve`) fires due schedules and the panel shows the live heartbeat.

The **Change Log** sidebar entry is Tufin-only (it depends on revision-based
change detection); Elasticsearch has no equivalent resource, so it is correctly
absent.

## Deduplication

This is the main conceptual difference from Tufin, so it's worth being precise:

- **Snapshot semantics.** Every Elasticsearch fetch is stored as an independent
  `FetchRun` (columns/rows JSON). The newest run per (adapter, query) is the
  saved view; older runs are history. Re-running a query **replaces the view**
  with a fresh snapshot — it does not accumulate rows, so there is nothing to
  deduplicate at the storage layer.
- **Aggregation queries dedupe by construction.** Most AI queries are `STATS …
  BY host.name` aggregations (AI001, AI010–AI014). Each returns one row per
  group regardless of how many underlying events exist, so repeated fetches
  never produce duplicate rows.
- **Raw-event feeds are inherently point-in-time.** The user-management and
  service-change feeds (AI002–AI009) return raw Windows events. A snapshot is a
  window of "the latest matching events," so overlapping fetches *can* show the
  same event twice **across different snapshots** — but within any one snapshot
  there are no duplicates, and the latest-wins view keeps things clean.

There is deliberately **no ES change-log table** like Tufin's
`tufin_changes`. Tufin's dedup exists because change detection is computed by
diffing revisions and the results accumulate; the natural key there is the
globally-unique revision id. Elasticsearch events do have natural keys
(`event.id`, or `@timestamp`+`host.name`+`event.code`+`user.name`), so an
**event-level dedup sink** for the raw-event feeds is a viable future extension
— it just isn't needed for the current snapshot model. If you want a cumulative,
deduplicated Elasticsearch event log, that's the shape to add (mirroring
`db.record_changes` / `change_log`).

## Persistence

Shared with Tufin (`db.py`, SQLAlchemy; SQLite by default, `DATABASE_URL` for
Postgres):

| Table | Used by Elasticsearch? |
|---|---|
| `fetch_runs` | yes — every fetch snapshot |
| `schedules` | yes — recurring fetches |
| `tufin_changes`, `tufin_change_watermarks` | no — Tufin-only |

## HTTP API & CLI

Elasticsearch uses the shared adapter endpoints: `.../connect`,
`.../run/{query_id}`, `.../run-all`, `.../latest|history/{query_id}`,
`.../merged[.csv|.json]`, `.../export…`, plus `/api/schedules*` and
`/api/scheduler`.

Unlike Tufin, Elasticsearch is also fully driven from the **CLI**:

| Command | What it does |
|---|---|
| `assetflow validate` | Load & validate the registry |
| `assetflow feeds` / `list` / `show <ID>` | Browse the registry |
| `assetflow test-connection` | Verify cluster connectivity |
| `assetflow run <ID> [--limit --range --output]` | Execute one query |
| `assetflow run-feed <FEED_ID>` | Run every runnable query in a feed |
| `assetflow serve` | Launch the web UI (+ scheduler) |

(The CLI's `run`/`test-connection` are Elasticsearch-specific; Tufin is
web-UI-driven.)

## How to add a new ES|QL query

1. **Add the entry** to `config/asset_intelligence_registry.yaml` under an
   existing feed's category:
   ```yaml
   - id: AI018
     category: Application Discovery
     name: Listening Ports By Host
     status: partially_validated
     validated: false
     purpose: Map listening ports to hosts.
     esql_query: |
       FROM logs-*
       | WHERE destination.port IS NOT NULL
       | STATS Ports = VALUES(destination.port) BY host.name
       | SORT host.name ASC
     expected_output_fields: [host.name, Ports]
     recommended_refresh_frequency: Daily
   ```
2. **Reference it** from a feed's `query_ids` (or add a new feed).
3. **That's it** — the CLI, web UI, run-all, scheduler, DB, export, and (because
   it emits `host.name`) the unified view pick it up automatically. Emit
   `host.name` for host-keyed queries; validate the fields against your cluster.
4. **Tests** in `tests/test_registry.py` re-validate the shipped registry, so a
   malformed entry fails fast.

## Testing

Tests use a **fake Elasticsearch client** (see `tests/test_runner.py`,
`tests/test_adapters.py`, `tests/test_webapp.py`) — `client.esql.query` is
monkeypatched to return a canned body, so no live cluster is needed.
`tests/test_registry.py` validates the shipped registry (unique ids, declared
categories, `validated` flag matches status, feeds reference real queries).
`tests/test_merge.py` covers the golden-record logic. Run `pytest`.

## Design decisions & caveats

- **ES|QL requires Elasticsearch 8.11+.** The client pins `elasticsearch>=8.11`.
- **Latest-wins snapshots, no accumulation.** Good for "current state"; for a
  cumulative event log, add an event-level dedup sink (see
  [Deduplication](#deduplication)).
- **Field mappings vary by data source.** Several queries are
  `partially_validated` / `investigation_required` because field availability
  (e.g. `winlog.event_data.*`, `process.pe.*`) depends on the ingest pipeline;
  placeholders (AI016/AI017) have no ES|QL yet.
- **Heavy aggregations.** All-index `STATS` queries (AI001) can be slow — use
  the time-range control and row limit, or raise the request timeout in the
  connection panel.
