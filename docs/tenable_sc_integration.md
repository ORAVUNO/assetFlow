# Tenable.sc (SecurityCenter) Integration — Developer Guide

The single place to understand **how the Tenable.sc integration works** in
assetFlow, and — just as important — **why every non-obvious decision was made**.
It is written so a developer who has never seen the adapter can read it top to
bottom and then confidently change any part of it.

Most of the subtle behaviour here exists because of things learned running the
adapter against a **live Tenable Security Center 6.8.0 deployment**. Those lessons
are called out inline and collected in [Design decisions & gotchas](#design-decisions--gotchas)
and the [Decision log](#decision-log-what-changed-and-why). If you only read one
section before editing, read those two.

## Contents

- [Where Tenable.sc fits](#where-tenablesc-fits)
- [Module map](#module-map)
- [Resource catalog (all 15)](#resource-catalog-all-15)
- [Data flow](#data-flow)
- [Authentication & the response envelope](#authentication--the-response-envelope)
- [The REST surface: analysis vs. object listings](#the-rest-surface-analysis-vs-object-listings)
- [Pagination, limits & performance](#pagination-limits--performance)
- [Field normalization helpers](#field-normalization-helpers)
- [Per-resource details & decisions](#per-resource-details--decisions)
- [Custom fields (the `custom.` prefix)](#custom-fields-the-custom-prefix)
- [Asset tags (asset lists)](#asset-tags-asset-lists)
- [Aggregated summaries (host counts)](#aggregated-summaries-host-counts)
- [How everything links to a host](#how-everything-links-to-a-host)
- [Configuration (environment variables)](#configuration-environment-variables)
- [Version notes (Security Center 6.x / "Plus")](#version-notes-security-center-6x--plus)
- [Design decisions & gotchas](#design-decisions--gotchas)
- [Decision log (what changed and why)](#decision-log-what-changed-and-why)
- [How to add a new Tenable.sc resource](#how-to-add-a-new-tenablesc-resource)
- [Testing](#testing)
- [API references](#api-references)

## Where Tenable.sc fits

assetFlow fetches assets from pluggable **adapters** (Elasticsearch, Tufin
SecureTrack, VMware vCenter, SolarWinds Orion, Tenable.sc). Every adapter
implements the same `Adapter` interface (`connect_form` / `ping` / `run`) and
produces the same normalized `QueryResult` (columns + rows), so the database,
CSV/JSON/ZIP export, the per-adapter *All Fetched Results* golden records, and the
cross-adapter unified inventory treat every adapter identically.

Tenable.sc is a **resource adapter** (like Tufin/VMware/SolarWinds): a registry
query carries a `resource` name (not an ES|QL body), and the runner maps that name
to the REST call(s) that fetch it. What makes it distinct:

- **Category *Vulnerability Management*.** It fetches the estate Tenable has
  scanned — devices, security findings, installed software, applications,
  databases, users, asset lists (tags), alerts, incidents — plus aggregated
  "host count" summaries.
- **Two request shapes.** The vulnerability/device/software data comes from one
  endpoint, `POST /rest/analysis`, where a *tool* selects the view. The rest are
  plain object listings (`GET /rest/user|asset|alert|ticket|pluginFamily|hosts`).
- **A stateful session.** Username/password auth establishes a **session token**
  (`/rest/token`) carried in the `X-SecurityCenter` header on every subsequent
  request (unlike the Basic-auth REST adapters).

## Module map

| File | Responsibility |
|---|---|
| `assetflow/tenable_sc_client.py` | Connection, auth (session token **or** API keys), `get`/`post` primitives, the paginating `analysis()` helper, response-envelope handling, `ping`. **No data mapping.** |
| `assetflow/tenable_sc_runner.py` | Maps each registry `resource` to REST calls and flattens responses into `QueryResult`. **All** field mapping, parsers, classifiers, the `custom.*` sweep, tag enrichment, and summaries live here. |
| `config/tenable_sc_registry.yaml` | The resource catalog: 15 queries (`TSC001`–`TSC015`) in 9 feeds, each with `resource`, `purpose`, `expected_output_fields`, `notes`, and validation `status`. |
| `assetflow/adapters.py` | `TenableScAdapter` (the `Adapter` subclass) + registration in `available_kinds` under kind `tenable_sc`, category *Vulnerability Management*. |
| `assetflow/webapp.py` | The `tenable_sc` logo mark and the `applyKind` connection-form branch (host + username + password; no port/base-path). Also the estate-wide **table render cap** (see below). |
| `tests/test_tenable_sc.py` | Unit tests against a `FakeClient` — no live server. |

## Resource catalog (all 15)

Each row is a registry query (`config/tenable_sc_registry.yaml`) → a collector in
`_COLLECTORS` (`tenable_sc_runner.py`). "Host-keyed" means the rows carry
`host.name`/`host.ip` and fold into the unified host view.

| ID | resource | Feed | Endpoint / tool | Host-keyed | Notes |
|---|---|---|---|---|---|
| TSC001 | `devices` | Device Inventory | `analysis` `sumip` | ✅ | inventory + ACR/AES + asset-list tags + `custom.*` |
| TSC002 | `findings` | Security Findings | `analysis` `vulndetails` | ✅ | Info severity excluded by default |
| TSC003 | `software` | Software | `analysis` `vulndetails` (plugins 20811/22869) | ✅ | full per-host package list; dpkg/rpm/Windows parsed |
| TSC004 | `users` | Users | `GET /rest/user` | user-keyed | role/group/org/auth/lastLogin |
| TSC005 | `asset_lists` | Asset Tags | `GET /rest/asset` | ✖ | the tag catalog |
| TSC006 | `alerts` | Alerts & Incidents | `GET /rest/alert` | ✖ | |
| TSC007 | `incidents` | Alerts & Incidents | `GET /rest/ticket` | ✖ | tickets = incidents |
| TSC008 | `saas_applications` | SaaS Applications | — | ✖ | placeholder (no rows) — `not_validated` |
| TSC009 | `hosts` | Device Inventory | `GET /rest/hosts` | ✅ | 6.x Explore Assets; bare ping-only hosts dropped |
| TSC010 | `databases` | Software | `analysis` `vulndetails` (Databases family) | ✅ | product + version per host |
| TSC011 | `applications` | Applications | `analysis` `vulndetails` (20811/22869) + classifier | ✅ | notable apps only (OS libs filtered) |
| TSC012 | `findings_summary` | Summaries | `analysis` `sumid` | ✖ | vuln → hosts-affected count |
| TSC013 | `software_summary` | Summaries | `analysis` `listsoftware` | ✖ | package → host count (native) |
| TSC014 | `application_summary` | Summaries | group of `applications` | ✖ | app → host count + versions |
| TSC015 | `database_summary` | Summaries | group of `databases` | ✖ | database → host count + versions |

## Data flow

```
UI Connection form ─▶ TenableScAdapter.connect_form(form)
                        └─ tenable_sc_client.build_client(...) ─▶ ping() ─▶ login() ─▶ currentUser/system
Run a query (UI) ────▶ TenableScAdapter.run(query, limit, time_range)
                        └─ tenable_sc_runner.run_query(client, query, ...)
                             └─ _COLLECTORS[resource](client, time_range)  ─▶ (columns, rows)
                                  ├─ client.analysis(tool, filters=...)          (analysis resources)
                                  ├─ client.get("user"|"asset"|"alert"|...)      (listing resources)
                                  └─ _iter_software / _collect_databases         (derived resources)
                             └─ QueryResult(columns, rows) ─▶ DB, UI table, export, unified views
```

Everything downstream is shared with the other adapters because the output is the
same `QueryResult`. **The UI shows the last *saved* fetch** — re-running a query is
what regenerates rows with any code change. (This trips people up: after a code
update you must **Fetch all** / **Run** to see new behaviour; opening a query just
reloads old saved rows.)

## Authentication & the response envelope

Tenable.sc supports three credential styles; the client implements the two
documented as primary (`tenable_sc_client.py`):

- **Username + password (session token).** `POST /rest/token` with
  `{"username", "password"}` returns a numeric `token` and sets a `TNS_SESSIONID`
  cookie. Every later request carries the token in `X-SecurityCenter` **and** the
  session cookie; `DELETE /rest/token` logs out. This is the "connect with IP,
  username and password" path. With `requests` installed a `requests.Session`
  holds the cookie; the urllib fallback uses `http.cookiejar.CookieJar`.
- **Access key + secret key (session-less, Tenable's preferred).** Every request
  carries `x-apikey: accesskey=<ak>; secretkey=<sk>`; `login()` is a no-op.

The connecting account needs the **Security Manager** role with access to the
required repositories.

> **Envelope gotcha (important).** Tenable.sc wraps every reply as
> `{"error_code", "error_msg", "response"}` and **often returns HTTP 200 even for
> API errors**, signalling failure only via `error_code`. `_unwrap()` always
> inspects `error_code` and raises on a non-zero value, so a bad request or a
> permission problem surfaces as an error instead of silently looking like an
> empty result. Login errors are the same — HTTP 200 with an `error_code`.

## The REST surface: analysis vs. object listings

**`POST /rest/analysis`** is the workhorse. The body is
`{"type": "vuln", "sourceType": "cumulative", "query": {tool, startOffset,
endOffset, filters, …}}`. The `tool` selects the shape:

| Tool | Used by | Result shape |
|---|---|---|
| `sumip` | devices | one record per host (IP/DNS/MAC/OS/repo/score/severity counts/scan times/ACR/AES) |
| `vulndetails` | findings, software, databases, applications | one record per (host, plugin) detection |
| `listsoftware` | software_summary | one record per software string + host `count` |
| `sumid` | findings_summary | one record per plugin + `hostTotal` (hosts affected) |

`client.analysis(tool, filters=...)` pages with `startOffset`/`endOffset` (see
[Pagination](#pagination-limits--performance)). The software/database/application
resources all use `vulndetails` **filtered to specific plugins/families** rather
than a dedicated tool — see their sections.

**Object listings** are plain `GET`s with a `?fields=...` selector (Tenable.sc
returns only `id`/`name` unless you ask for more). `GET /rest/user` returns a
**plain list**; `/rest/asset`, `/rest/alert`, `/rest/ticket` return
`{"usable": [...], "manageable": [...]}` (the two overlap). `_listing()` handles
both: a plain list passes through; buckets are merged and de-duplicated by `id`.

The UI **time-range** control (24h/7d/30d/90d) becomes a `lastSeen` analysis
filter on the vuln resources; object listings ignore it.

## Pagination, limits & performance

Real estates are large (a single device fetch returned **69,405 hosts**; the
per-host software list was **1.2M rows**). Three mechanisms keep this workable:

1. **`analysis()` paging with partial-result resilience.** Pages by
   `ANALYSIS_PAGE_SIZE` (default 1000, env `TENABLE_SC_PAGE_SIZE`) until
   `returnedRecords < page size` or `totalRecords` is reached, capped at
   `ANALYSIS_MAX_RECORDS` (default 1,000,000; env `TENABLE_SC_MAX_RECORDS`, `0` =
   unlimited). **A failure on the *first* page raises** (a real error), but a
   failure on a *later* page (e.g. a timeout deep into a huge `vulndetails` fetch)
   **returns what was gathered so far** instead of losing everything. This was
   added after large fetches intermittently returned nothing.
2. **"Fetch all" passes `limit=None`** so it truly fetches every row; the cap
   above is the only backstop.
3. **Front-end render cap** (`webapp.py`, `mountTable`): the browser paints at most
   `opts.renderCap` (default 2000) rows, with a banner, while filtering/sorting/
   export still operate on the full set. Without this a 69k-row table froze the
   tab ("Page Unresponsive"). This is a *general* webapp fix, not Tenable-specific.

## Field normalization helpers

All in `tenable_sc_runner.py`; use these instead of touching raw values:

- **`textish(v)`** — render any scalar/list/dict as a compact string. For dicts it
  prefers `name`/`username`/`description`/`displayName`/`value`.
- **`_obj_name(v)`** — the human name of a nested object (`{"id":…, "name":…}`),
  used for `severity`, `family`, `repository`, `role`, `group`, `status`, `owner`,
  `assignee`.
- **`_epoch(v)`** — Unix epoch-seconds → ISO-8601 UTC. `-1`/`0`/empty ⇒ `""`
  ("never"); a non-numeric string is returned unchanged (so an already-formatted
  date isn't mangled).
- **`_pick(rec, *keys)`** — first non-empty value among keys, for fields Tenable
  renamed across releases (`netbiosName`/`netBios`, `acrScore`/
  `assetCriticalityRating`, …).
- **`_flatten_analysis(records, spec, …)`** — maps known keys to named columns via
  a `spec` of `(out_col, src_key, transform)`, then sweeps **every remaining scalar
  key** into `custom.<key>` (union across records; nested list/dict blobs skipped).
  `tag_map` inserts a `tags` column; `skip_custom` excludes noisy/huge keys.

## Per-resource details & decisions

### `devices` (TSC001) — `sumip`
`_DEVICE_SPEC` maps the sumip fields; then `asset.type = "Host"` is inserted (Tenable
has no per-host role field) and asset-list **tags** are stamped. Emits `host.name`
(DNS/NetBIOS/IP). ACR/AES are 6.x additions promoted to named columns (see
[Version notes](#version-notes-security-center-6x--plus)). Everything unmapped
rides along as `custom.*`.

### `hosts` (TSC009) — `GET /rest/hosts` (6.x Explore Assets)
The modern asset model. `_fetch_hosts` pages it like analysis and tolerates both
`{"results":[...]}` and a plain list, falling back to an unfielded request if the
`fields` selector is rejected. `_collect_hosts` reads each field with per-release
fallbacks and sweeps the rest into `custom.*`.
**Decision — drop bare hosts.** `/rest/hosts` lists *every known repository IP*,
including addresses that only answered a ping (no name/OS/MAC/repo). `_host_has_data`
keeps a row only if it carries real data. **Gotcha:** Tenable sets `name` to the
**IP** for DNS-less hosts, so a `name` equal to the IP does **not** count as data
(that's why the first filter attempt failed). Opt out with
`TENABLE_SC_HOSTS_INCLUDE_BARE=true`.

### `findings` (TSC002) — `vulndetails`
`_FINDING_SPEC` + a `_FINDING_SKIP` set that excludes huge text fields
(`pluginText`, `description`, `xref`, …) from the `custom.*` sweep so the table
stays legible.
**Decision — exclude Info severity.** By default a `severity` filter of `1,2,3,4`
(Low–Critical) is applied so the view is real vulnerabilities, not informational
noise like "Ping the remote host" / scan-info / OS fingerprints (which dominated
the raw output and matched what Tenable's own vulnerabilities GUI hides). Override
with `TENABLE_SC_FINDINGS_SEVERITIES` (e.g. `all` or `0,1,2,3,4`). Severity ids:
0=Info,1=Low,2=Medium,3=High,4=Critical.

### `software` (TSC003) — `vulndetails` on the enumeration plugins
Fetched from the **software-enumeration plugins** (`SOFTWARE_ENUM_PLUGINS` =
20811 Windows, 22869 SSH), so it is **host-linked** (one row per host+package),
replacing the old estate-wide `listsoftware` view. `_iter_software()` is the shared
generator (also used by applications and the summaries); `_software_lines()` splits
the plugin output into package lines and `_split_software()` splits each line into
`(name, version, cpe)`.
**Decision — format-aware parsing.** The live box returns Debian/Ubuntu `dpkg -l`
output wrapped in `<plugin_output>` tags. `_split_software` handles, in order:
1. **dpkg** — `ii   name  version  arch  desc` split on runs of **2+ spaces** after
   a status flag (`_DPKG_FLAG_RE`, e.g. `ii`, `iU`, `rc`); `name=cols[1]`,
   `version=cols[2]`;
2. **CPE** — `cpe:/a:vendor:product:version`;
3. **Windows** — `Name  [version X]`;
4. **rpm-ish** — `name-<digit…>`;
5. **fallback** — trailing dotted-number token.
`_software_lines` and `_split_software` strip `<plugin_output>` wrappers and header
prose. **Gotcha:** the version regex `_VERSION_RE` intentionally accepts trailing
alphanumerics (`3.137ubuntu1`, `2.4.58-1ubuntu8.8`); an earlier `\b`-anchored regex
failed on those. The raw line is always kept in `software.raw`, so nothing is lost
even if a format isn't recognized.

### `applications` (TSC011) — the notable apps within `software`
A **classifier** over the same enumeration. `_is_application(name, plugin_id)`:
- **all Windows entries** (plugin 20811) are apps (Windows only lists real apps);
- **Linux** packages are apps only if the name matches `_APP_KEYWORDS` (web/app
  servers, databases, runtimes, containers, infra tools, desktop apps), dropping
  `lib*`, `-dev`/`-common`/`-doc`, fonts, kernel, etc.
Extend the allowlist with `TENABLE_SC_APP_KEYWORDS` (comma-separated). Emits
`application.name` so it feeds the unified Applications inventory as real apps.
**Why an allowlist:** the Applications asset type keys on `software.name`/
`application.name`, so without filtering all ~1.2M OS packages become "Application"
assets. Allowlist keeps it meaningful at the cost of possibly missing a niche app
until you add its keyword. TSC003 remains the complete inventory.

### `databases` (TSC010) — `vulndetails` on the Databases family
`_plugin_family_id(client, "Databases")` resolves the family id via
`GET /rest/pluginFamily`, then `vulndetails` is filtered to it. `_db_product()`
maps the plugin name to a clean product label (MySQL/MariaDB/Oracle Database/
Microsoft SQL Server/PostgreSQL/…); the full plugin name stays in `plugin.name`.
**Gotcha — version source.** The version is taken from the plugin output's
`Version : X` line, else a version token in the plugin **name**. The record's own
`version` field is **deliberately ignored** — it is the Nessus **plugin revision**
(e.g. `1.49`), not the database version, and using it produced bogus versions on
every remote-detection row. The Databases family also contains some *vulnerability*
plugins (not only detections), so filter `plugin.name` if you want detections only.

### `users` / `asset_lists` / `alerts` / `incidents` — object listings
Explicit field mapping over `_listing()`. Nested objects reduced with `_obj_name`,
timestamps with `_epoch`. `users` emits the username as `host.name` so it folds into
the unified **Users** inventory. `alerts` summarizes the `action[]` list to its
types; `alerts`/`incidents`/`asset_lists` merge the usable+manageable buckets.

### `saas_applications` (TSC008) — placeholder
Returns no rows. The Tenable.sc **core** REST API does not enumerate SaaS
applications (that is a Tenable One / Tenable.io capability). The resource exists so
the asset type is visible with an honest empty result; `not_validated`. For real
SaaS data, add a separate adapter against the Tenable Vulnerability Management API.

### Summaries (TSC012–TSC015)
See [Aggregated summaries](#aggregated-summaries-host-counts).

## Custom fields (the `custom.` prefix)

For the analysis resources (`devices`, `findings`, `hosts`), `_flatten_analysis`
maps known keys to named columns, then sweeps **every remaining scalar key** into a
`custom.<key>` column — discovered as the union across records, so site-specific
extras ride along. Same convention as the SolarWinds/VMware adapters: a system field
is never confused with an extra one, and nothing Tenable returns is silently
dropped. Nested list/dict blobs are skipped (noise in a flat table). This also makes
the adapter **forward/backward compatible**: a field a release omits yields a blank
column; a field a newer release adds appears automatically.

## Asset tags (asset lists)

Tenable.sc models tags/groupings as **asset lists**. Two surfaces:

1. **`asset_lists` (TSC005)** — the catalog (`GET /rest/asset`): each list's `tags`
   field, type (static/dynamic/DNS/LDAP/combination), owner, group, member-IP count.
2. **`devices` (TSC001) `tags` column** — each host stamped with the asset lists its
   IP belongs to.

**Decision — how tag membership is resolved (performance-critical).** The *first*
implementation expanded each asset list with a **paginated `sumip` analysis** per
list — up to 150× per device fetch, which **hung** the device fetch on a real
estate. It was replaced with a single lightweight **`GET /rest/asset/{id}`** per
list, reading the resolved `viewableIPs` (which covers static *and* dynamic lists —
Tenable resolves membership for us) with a `typeFields.definedIPs` fallback. It is
capped (`TENABLE_SC_TAG_ASSET_CAP`, default 200), best-effort (any failure ⇒ no tags
for that host), and can be disabled entirely with `TENABLE_SC_DEVICE_TAGS=false`.

## Aggregated summaries (host counts)

The per-host resources answer *"which host has X?"*; the summaries answer *"how
widespread is X?"* — one row per item with a **`host.count`**, sorted
most-widespread first:

- **`findings_summary` (TSC012)** — `analysis` `sumid`: Tenable computes `hostTotal`
  (hosts affected) per plugin. Same Info-excluded severity filter as `findings`.
- **`software_summary` (TSC013)** — `analysis` `listsoftware`: native per-package
  host `count` (this is the original estate-wide software tool, repurposed).
- **`application_summary` (TSC014)** / **`database_summary` (TSC015)** — group the
  `applications` / `databases` collectors by name/product, counting **distinct**
  hosts and listing distinct versions (`_summarize` helper for databases; inline
  aggregation for applications).

Summary rows are aggregates (not a single host), so they are **not host-keyed** and
appear as their own tables rather than folding into the unified host view — the same
way the estate-wide Elasticsearch queries do.

## How everything links to a host

There is **no per-resource "join to host" code** — linking is automatic. Every
host-scoped resource emits `host.name` **and** `host.ip`, and the correlation layer
(`assetflow/merge.py`) groups rows sharing those:

- `build_merged()` (keyed on `HOST_KEY = "host.name"`) → the per-adapter *All
  Fetched Results* golden records (one row per host, each query's data folded in).
- `correlate()` → the cross-adapter **unified inventory**, matching on
  `host.name`/`host.ip`/MAC/serial; the **Applications** type keys on
  `application.name`/`software.name`, the **Users** type on `user.name` (the adapter
  emits the username as `host.name`, which the user identity map also reads).

So software, findings, databases, and applications correlate to their host purely
because they carry the same identifiers.

## Configuration (environment variables)

Set in `.env` (see `.env.example`). Host + either credential pair is required; the
rest are optional tuning knobs.

| Variable | Default | Purpose |
|---|---|---|
| `TENABLE_SC_HOST` | — | SecurityCenter host/IP |
| `TENABLE_SC_USERNAME` / `TENABLE_SC_PASSWORD` | — | session-token auth |
| `TENABLE_SC_ACCESS_KEY` / `TENABLE_SC_SECRET_KEY` | — | API-key auth (alternative) |
| `TENABLE_SC_API_PREFIX` | — | path prefix before `/rest` if behind a gateway |
| `TENABLE_SC_VERIFY_CERTS` | `true` | TLS verification (lab only: `false`) |
| `TENABLE_SC_REQUEST_TIMEOUT` | `60` | per-request seconds |
| `TENABLE_SC_MAX_RECORDS` | `1000000` | analysis fetch cap (`0` = unlimited) |
| `TENABLE_SC_PAGE_SIZE` | `1000` | analysis page size |
| `TENABLE_SC_FINDINGS_SEVERITIES` | `1,2,3,4` | findings severities (`all` includes Info) |
| `TENABLE_SC_DEVICE_TAGS` | `true` | stamp asset-list tags on devices |
| `TENABLE_SC_TAG_ASSET_CAP` | `200` | max asset lists resolved for tags |
| `TENABLE_SC_HOSTS_INCLUDE_BARE` | `false` | keep bare ping-only hosts in TSC009 |
| `TENABLE_SC_APP_KEYWORDS` | — | extra application-name keywords (comma-separated) |

## Version notes (Security Center 6.x / "Plus")

Validated against **Tenable Security Center 6.8.0 "Plus"**. "Plus" is a *licensing
tier* of the same product (adds Explore Assets + editable ACR), **not a different
product** — the REST surface is identical. (Note: "Security Center **Plus**" is
Tenable's tier; do not confuse it with ManageEngine's unrelated product of a similar
name.)

6.x additions handled:
- `sumip` returns `acrScore` (Asset Criticality Rating; editable in Plus) and
  `assetExposureScore` (Asset Exposure Score) → promoted to the `acr`/`aes` columns.
- The dedicated `/rest/hosts` **Explore Assets** endpoint → the `hosts` resource
  (TSC009). Older releases won't expose it (returns no rows there — use `devices`).

Because unmapped fields sweep into `custom.*`, the adapter degrades gracefully across
releases without code changes.

## Design decisions & gotchas

A quick-reference index of the non-obvious choices (details in the sections above):

1. **HTTP 200 ≠ success.** Always trust `error_code`, not the status line.
   (`_unwrap`)
2. **The UI shows the last saved fetch.** Code changes only appear after a re-run /
   Fetch all.
3. **Device tags via `GET /rest/asset/{id}` `viewableIPs`, not per-asset `sumip`.**
   The analysis approach paginated 150× and hung the device fetch.
4. **Findings exclude Info severity by default.** Otherwise "Ping the remote host"
   drowns real vulns. Tunable.
5. **Software is host-linked from enumeration plugins**, not the estate-wide
   `listsoftware` — so software correlates to hosts. Format-aware parser (dpkg/CPE/
   Windows/rpm) with the raw line preserved.
6. **Version regex accepts trailing alphanumerics** (`3.137ubuntu1`); the earlier
   `\b` version failed on Debian versions.
7. **Databases: never use the record's `version` field** — it's the plugin revision
   (`1.49`), not the DB version. Use the plugin output's `Version :` line.
8. **Applications use an allowlist classifier** because the Applications asset type
   keys on software names — unfiltered, every OS library becomes an "app".
9. **Bare `/rest/hosts` IPs are dropped**, and `name == ip` does not count as real
   data (Tenable names DNS-less hosts by their IP).
10. **Summaries are not host-keyed** — aggregate rows, shown as their own tables.
11. **Front-end render cap (2000 rows).** A 69k-row table froze the browser.
12. **`analysis()` returns partial results** on a late-page failure; only a first-
    page failure raises.

## Decision log (what changed and why)

Chronological, for context on why the code looks the way it does. (Each shipped as a
separate PR against `main`.)

1. **Initial adapter** — 8 resources over `/rest/analysis` + object listings; token
   & API-key auth; `custom.*` sweep; asset-tag enrichment; SaaS placeholder.
2. **6.8 "Plus" support** — promoted `acrScore`/`assetExposureScore` to `acr`/`aes`.
3. **Explore Assets** — added the `hosts` (`/rest/hosts`) resource.
4. **Live-data round 1** — host-linked software with name/version split; new
   `databases` resource; unlimited Fetch all; **fixed the device-fetch hang** (tag
   enrichment → `viewableIPs`); resilient analysis pagination.
5. **Render cap** — capped table rendering so huge result sets don't freeze the tab.
6. **Live-data round 2** — real dpkg parsing (`<plugin_output>` strip, columns,
   version regex); clean DB product + reliable version; `hosts` `asset.type` N/A→Host.
7. **Findings noise** — excluded Info severity from findings by default.
8. **Live-data round 3** — fixed bogus DB versions (ignore record `version`); fixed
   the `hosts` bare-host filter (`name == ip`).
9. **Applications** — added the `applications` resource (classifier over software).
10. **Summaries** — added the four host-count summary resources.
11. **Validation** — all resources marked `validated` except SaaS Applications.

## How to add a new Tenable.sc resource

1. **Pick the endpoint / tool.** For vuln data choose an analysis tool
   (`sumcve`, `sumfamily`, `listos`, `vulnipdetail`, …) or a filtered `vulndetails`;
   for objects, a `GET` path.
2. **Write a collector** in `tenable_sc_runner.py` returning `(columns, rows)`.
   Reuse `_flatten_analysis` (with a spec) for analysis tools, `_listing` + explicit
   mapping for object endpoints, or `_iter_software` for software-derived data. Emit
   `host.name` (+ `host.ip`) if host-scoped so it folds into the unified view. Use
   `_obj_name` for nested objects and `_epoch` for timestamps.
3. **Register it** in `_COLLECTORS`.
4. **Add a registry entry** (`TSC0NN`) in `config/tenable_sc_registry.yaml` with
   `resource`, `purpose`, `expected_output_fields`, `notes`, `status`, and add it to
   a feed (create the category in `metadata.categories` if new).
5. **Add a test** in `tests/test_tenable_sc.py` using `FakeClient` with a canned rule
   for the new tool/path.
6. Update this guide's [resource catalog](#resource-catalog-all-15) and, if it's a
   decision worth remembering, the [decision log](#decision-log-what-changed-and-why).

## Testing

`tests/test_tenable_sc.py` runs entirely against a `FakeClient` (no live server):
`analysis(tool, …)` and `get(path)` are answered from canned rules (the `sumip`
rule is filter-aware so tag enrichment can be exercised; `get` matches on path
substrings — order matters, e.g. `asset/100` before `asset`). Coverage includes the
envelope handling, pagination, every collector, the dpkg/CPE/Windows software
parser, the DB product/version rules (including the plugin-revision guard), the
application classifier, the bare-host filter (`name == ip`), the findings severity
filter, and the summaries' host counts. Run `pytest tests/test_tenable_sc.py`; the
registry self-validates via `assetflow --registry config/tenable_sc_registry.yaml
validate`.

## API references

- Tenable Security Center API overview: <https://docs.tenable.com/security-center/api/index.htm>
- Asset API (asset lists / tags): <https://docs.tenable.com/security-center/api/Asset.htm>
- pyTenable (official Python SDK) — the `tenable/sc/` modules mirror these endpoints
  and field names, and the `analysis` module lists every `tool` value:
  <https://github.com/tenable/pyTenable>
- User roles / required permissions (Security Manager):
  <https://docs.tenable.com/tenablesc/Content/UserRoles.htm>
