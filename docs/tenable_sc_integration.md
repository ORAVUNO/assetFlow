# Tenable.sc (SecurityCenter) Integration — Developer Guide

A single place to understand **how the Tenable.sc integration works** in
assetFlow: what it fetches, how the code is laid out, how a fetch flows from the
UI to a normalized result, how authentication works, and how the two things the
integration explicitly asked for — **custom fields** and **asset tags** — are
handled.

## Contents

- [Where Tenable.sc fits](#where-tenablesc-fits)
- [Module map](#module-map)
- [Data flow](#data-flow)
- [Authentication](#authentication)
- [The REST surface: analysis vs. object listings](#the-rest-surface-analysis-vs-object-listings)
- [The registry](#the-registry)
- [The runner and collectors](#the-runner-and-collectors)
- [Custom fields (the `custom.` prefix)](#custom-fields-the-custom-prefix)
- [Asset tags (asset lists)](#asset-tags-asset-lists)
- [SaaS applications](#saas-applications)
- [How to add a new Tenable.sc resource](#how-to-add-a-new-tenablesc-resource)
- [API references](#api-references)

## Where Tenable.sc fits

assetFlow fetches assets from pluggable **adapters**. Elasticsearch is the first,
**Tufin SecureTrack** the second, **VMware vCenter** the third, **SolarWinds
Orion** the fourth, and **Tenable.sc (SecurityCenter)** the fifth. Every adapter
implements the same `Adapter` interface (`connect_form` / `ping` / `run`) and
produces the same normalized `QueryResult` (columns + rows), so the database,
exports, and unified host view treat all adapters identically.

Like Tufin, VMware, and SolarWinds, Tenable.sc is a **resource adapter**: a
registry query carries a `resource` name (not an ES|QL body), and the runner maps
that name to the REST call(s) that fetch it. What makes Tenable.sc distinct:

- **A vulnerability-management source.** Its category is *Vulnerability
  Management*. It fetches the estate Tenable has scanned — **devices, aggregated
  security findings, installed software, users, asset lists (tags), alerts, and
  tickets (incidents)**.
- **Two request shapes.** Most of the interesting data (devices, findings,
  software) comes from one endpoint — `POST /rest/analysis` — where a *tool*
  selects the view. The rest are plain object listings (`GET /rest/user`,
  `/rest/asset`, `/rest/alert`, `/rest/ticket`).
- **A stateful session.** Unlike the Basic-auth REST adapters, username/password
  auth establishes a **session token** (`/rest/token`) carried in the
  `X-SecurityCenter` header on every subsequent request.

## Module map

| File | Responsibility |
|---|---|
| `assetflow/tenable_sc_client.py` | Connection, auth (session token **or** API keys), the `get` / `post` primitives, the paginating `analysis()` helper, envelope handling, and `ping`. No data mapping. |
| `assetflow/tenable_sc_runner.py` | Maps each registry `resource` to REST calls and flattens the responses into `QueryResult` (columns + rows). All field mapping, the `custom.*` sweep, and asset-tag enrichment live here. |
| `config/tenable_sc_registry.yaml` | The resource catalog: 8 queries (`TSC001`–`TSC008`) in 7 feeds, with purpose, expected fields, and notes. |
| `assetflow/adapters.py` | `TenableScAdapter` (the `Adapter` subclass) + its registration in `available_kinds`. |
| `assetflow/webapp.py` | The `tenable_sc` logo mark and the `applyKind` connection-form branch. |
| `tests/test_tenable_sc.py` | Unit tests against a `FakeClient` — no live server. |

## Data flow

```
UI Connection form ──▶ TenableScAdapter.connect_form(form)
                          └─ tenable_sc_client.build_client(...) ─▶ ping() ─▶ login()/currentUser/system
Run a query (UI) ─────▶ TenableScAdapter.run(query, limit, time_range)
                          └─ tenable_sc_runner.run_query(client, query, ...)
                               └─ _COLLECTORS[resource](client, time_range)
                                    ├─ client.analysis(tool, filters=...)   (devices/findings/software)
                                    └─ client.get("user"|"asset"|"alert"|"ticket")
                               └─ QueryResult(columns, rows) ─▶ saved to DB, shown, exported, unified
```

Everything downstream (database, CSV/JSON/ZIP export, the *All Fetched Results*
golden records, the cross-adapter unified inventory) is shared with the other
adapters because the output is the same `QueryResult`.

## Authentication

Tenable.sc supports three credential styles; the client implements the two
documented as primary:

- **Username + password (session token).** `POST /rest/token` with
  `{"username", "password"}` returns a numeric `token` and sets a `TNS_SESSIONID`
  cookie. Every subsequent request carries the token in the `X-SecurityCenter`
  header and the session cookie; `DELETE /rest/token` logs out. This is the
  "connect with IP, username and password" path the integration asked for. When
  `requests` is installed, a `requests.Session` holds the cookie; the urllib
  fallback uses a `http.cookiejar.CookieJar`.
- **Access key + secret key (preferred, session-less).** Every request carries
  `x-apikey: accesskey=<ak>; secretkey=<sk>` and no login round-trip is needed —
  `login()` is a no-op for this style.

The connecting account needs the **Security Manager** role with access to the
required repositories.

> **Envelope gotcha.** Tenable.sc wraps every reply as
> `{"error_code", "error_msg", "response"}` and often returns **HTTP 200 even for
> API errors**, signalling failure only through `error_code`. `_unwrap()` always
> inspects `error_code` and raises on a non-zero value, so a bad request or a
> permission problem doesn't silently look like an empty result.

## The REST surface: analysis vs. object listings

**`POST /rest/analysis`** is the workhorse. The request names an analysis `type`
(`vuln`), a `sourceType` (`cumulative`), and a `query` carrying a `tool` plus
`startOffset` / `endOffset` for paging and a `filters` list. The `tool` selects
the shape of the results:

| Resource | Tool | Result shape |
|---|---|---|
| `devices` | `sumip` | one record per host (IP, DNS, MAC, OS, repository, score, per-severity counts, scan times) |
| `findings` | `vulndetails` | one record per (host, plugin) detection |
| `software` | `listsoftware` | one record per distinct software string with a host count |

`client.analysis(tool, filters=...)` pages through with `startOffset` /
`endOffset` until the server reports no more records (`returnedRecords` < page
size, or `totalRecords` reached), capped at `ANALYSIS_MAX_RECORDS` so a huge
estate stays bounded.

**Object listings** are plain `GET`s with a `?fields=...` selector (Tenable.sc
returns only `id`/`name` unless you ask for more). `GET /rest/user` returns a
plain list; `/rest/asset`, `/rest/alert`, and `/rest/ticket` return
`{"usable": [...], "manageable": [...]}` — the two overlap, so `_listing()`
merges and de-duplicates them by `id`.

The UI **time-range** control (24h / 7d / 30d / 90d) is applied to the vuln
analysis resources (`devices` / `findings`) as a `lastSeen` filter; the object
listings are point-in-time and ignore it.

## The registry

`config/tenable_sc_registry.yaml` lists 8 queries in 7 feeds. Each query carries
a `resource` (the key into the runner's `_COLLECTORS`), a `purpose`, the
`expected_output_fields` (documenting the Tenable source key behind each column),
and `notes`. Statuses follow the same honest labeling as the other registries:
`partially_validated` for the seven live resources (mapping follows Tenable's API
docs / pyTenable but hasn't been run against a live box here), and `not_validated`
for the SaaS placeholder.

## The runner and collectors

`tenable_sc_runner.run_query` dispatches on `query.resource` into `_COLLECTORS`.
Each collector returns `(columns, rows)`; `_result` wraps them (applying `limit`).

- **`_collect_devices`** — `sumip` analysis → `_flatten_analysis` with
  `_DEVICE_SPEC`, then inserts a constant `asset.type = "Host"` and stamps asset
  tags (below). Emits `host.name` (DNS/NetBIOS/IP) so it folds into the unified
  host view.
- **`_collect_findings`** — `vulndetails` analysis → `_flatten_analysis` with
  `_FINDING_SPEC`. Large text fields (`pluginText`, `description`, `xref`, …) are
  excluded from the `custom.*` sweep (`_FINDING_SKIP`) so the table stays legible.
- **`_collect_software`** — `listsoftware` analysis; not host-keyed.
- **`_collect_users` / `_collect_asset_lists` / `_collect_alerts` /
  `_collect_incidents`** — object listings with explicit field mapping. Nested
  objects (`role`, `group`, `status`, `owner`, `assignee`) are reduced to their
  human name by `_obj_name`; epoch-seconds timestamps are converted to ISO-8601
  UTC by `_epoch` (with `-1`/`0` meaning "never" → blank).
- **`_collect_saas_applications`** — returns no rows (see below).

## Custom fields (the `custom.` prefix)

The integration asked to "collect custom fields as well". For the analysis
resources (`devices`, `findings`), `_flatten_analysis` maps the known Tenable keys
to named columns via a spec, then sweeps **every remaining scalar key** present on
any record into a column prefixed `custom.` — discovered as the union across
records, so site-specific extras ride along. This is the same convention the
SolarWinds and VMware adapters use, so a system field is never confused with an
extra one, and nothing Tenable returns is silently dropped. (Nested list/dict
blobs are skipped from the sweep — they're noise in a flat table; the named specs
already pull the useful nested names out.)

## Asset tags (asset lists)

Tenable.sc models tags / groupings as **asset lists**. Two places surface them:

1. **`asset_lists` (TSC005)** — the catalog: each asset list with its `tags`
   field, type (static / dynamic / DNS / LDAP / combination), owner, group, and
   member-IP count, from `GET /rest/asset`.
2. **`devices` (TSC001) `tags` column** — each host is stamped with the asset
   lists its IP belongs to. `_ip_tag_map` builds an `ip → [asset-list names]` map
   by expanding each asset list into its member IPs (a `sumip` analysis filtered
   by `assetID`). It is **bounded** (`MAX_ASSET_LISTS_FOR_TAGS`) and
   **best-effort** — on any failure the affected host simply contributes no tags,
   and the device inventory is unaffected.

## SaaS applications

`saas_applications` (TSC008) is an honest placeholder that returns no rows. The
Tenable.sc *core* REST API does not enumerate SaaS applications — that is a
Tenable One / Tenable.io (Vulnerability Management) capability. The resource
exists so the asset type is visible in the UI with an empty result rather than
silently missing; if the estate runs Tenable.io, add a separate adapter against
the Tenable VM API.

## How to add a new Tenable.sc resource

1. **Pick the endpoint / tool.** For vuln data, choose an analysis tool (e.g.
   `sumcve`, `sumfamily`, `listos`, `vulnipdetail`); for objects, a `GET` path.
2. **Write a collector** in `tenable_sc_runner.py` returning `(columns, rows)`.
   Reuse `_flatten_analysis` (with a spec) for analysis tools, or `_listing` +
   explicit mapping for object endpoints. Emit `host.name` if the rows are
   host-keyed so they fold into the unified view. Use `_obj_name` for nested
   objects and `_epoch` for timestamps.
3. **Register it** in `_COLLECTORS`.
4. **Add a registry entry** (`TSC00N`) in `config/tenable_sc_registry.yaml` with
   its `resource`, `purpose`, `expected_output_fields`, and a feed reference.
5. **Add a test** in `tests/test_tenable_sc.py` using `FakeClient` with a canned
   rule for the new tool/path.

## API references

- Tenable Security Center API overview: <https://docs.tenable.com/security-center/api/index.htm>
- pyTenable (the official Python SDK) — Tenable.sc modules mirror these endpoints
  and field names: <https://github.com/tenable/pyTenable> (`tenable/sc/`)
- Analysis tools reference (the `tool` values): the `analysis` module in pyTenable.
- User roles / required permissions: <https://docs.tenable.com/tenablesc/Content/UserRoles.htm>
