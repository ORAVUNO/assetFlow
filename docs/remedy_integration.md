# BMC Remedy Integration — Developer Guide

A single place to understand **how the BMC Remedy (AR System / Atrium CMDB)
integration works** in assetFlow: what it fetches, how the code is laid out, how
a fetch flows from the UI to a normalized result, and how the standard fields and
the site-defined custom fields fit together.

## Contents

- [Where Remedy fits](#where-remedy-fits)
- [Module map](#module-map)
- [Data flow](#data-flow)
- [Connecting](#connecting)
- [The registry](#the-registry)
- [The runner and collectors](#the-runner-and-collectors)
- [Standard fields vs. custom fields](#standard-fields-vs-custom-fields)
- [How to add a new Remedy resource](#how-to-add-a-new-remedy-resource)

## Where Remedy fits

assetFlow fetches assets from pluggable **adapters**. Elasticsearch is the first,
and **BMC Remedy** is the eighth. Every adapter implements the same `Adapter`
interface (`connect_form` / `ping` / `run`) and produces the same normalized
`QueryResult` (columns + rows), so the database, exports, and unified host view
treat all adapters identically.

Like VMware and AssetExplorer, Remedy is a **resource adapter**: a registry query
carries a `resource` name (not an ES|QL body), and the runner maps that name to a
BMC Remedy AR *form* that fetches it. What makes Remedy distinct:

- **Asset kind is explicit.** Every row carries an `asset.type` column, so CMDB
  computer systems (classified `Server` / `Workstation` / `Computer System` from
  their `SystemRole`), `Software`, `Business Service`, `Person`, `Incident`, and
  `Change Request` rows are distinguishable at a glance.
- **One REST API, JWT-authenticated.** All forms are read over the AR System
  REST API; a JWT obtained from `/api/jwt/login` authorizes every entry read.
- **Custom fields are discovered dynamically.** AR forms routinely carry
  site-added fields; any field label the runner doesn't map to a standard column
  (and that isn't AR plumbing) is emitted under a `custom.`-prefixed column.

## Module map

| File | Responsibility |
|---|---|
| `assetflow/remedy_client.py` | Connection + transport: `RemedyClient` (JWT login, paged `get_entries`), `build_client` / `build_client_from_env`, `ping`, `RemedyConfigError`. Standard-library HTTP (`requests` used when installed). |
| `assetflow/remedy_runner.py` | Per-resource collectors that read an AR form and normalize its entries into `(columns, rows)`; the `custom.*` discovery/merge; `run_query` dispatch. |
| `config/remedy_registry.yaml` | The declarative registry: metadata, feeds, and the six queries (each naming a `resource`). |
| `assetflow/adapters.py` | `RemedyAdapter` (wires the client + runner into the `Adapter` interface) and its registration in `available_kinds` under kind `remedy`. |
| `tests/test_remedy.py` | Client construction/env, runner normalization + custom fields, registry validation, adapter wiring — all against a `FakeClient`, no live Remedy. |

## Data flow

1. The UI (or `try_auto_connect` from env) calls `RemedyAdapter.connect_form`,
   which builds a `RemedyClient` and calls `remedy_client.ping` — a JWT login
   plus a one-entry probe read to confirm form access.
2. Running a feed/query calls `RemedyAdapter.run(query)` → `remedy_runner.run_query`.
3. `run_query` looks up the collector and the AR form for the query's `resource`,
   fetches the form's entries via `client.get_entries` (paged by `offset`/`limit`
   up to the record cap), and normalizes them.
4. The result is the shared `QueryResult` (columns + rows) — persisted, exported,
   and folded into the unified inventory exactly like every other adapter.

## Connecting

`RemedyClient` needs a host, username, and password; port (default 443), TLS
(`use_ssl`, default on — an `http://` host forces plain HTTP), `verify_certs`,
`request_timeout`, and the paging knobs (`page_size`, `max_records`) are optional.

Authentication is JWT-based, per the AR System REST API:

- `POST /api/jwt/login` with form-encoded `username`/`password` returns a bare
  token as `text/plain`; it is cached and sent as `Authorization: AR-JWT <token>`.
- A call that returns `401` triggers one automatic re-login and retry.
- `POST /api/jwt/logout` releases the token on `close()` (best effort).

Environment variables (see `.env.example`): `REMEDY_HOST` / `REMEDY_USERNAME` /
`REMEDY_PASSWORD` (with `AR_*` / `BMC_REMEDY_*` aliases), plus optional
`REMEDY_PORT`, `REMEDY_USE_SSL`, `REMEDY_VERIFY_CERTS`, `REMEDY_REQUEST_TIMEOUT`,
`REMEDY_PAGE_SIZE`, `REMEDY_MAX_RECORDS`.

## The registry

`config/remedy_registry.yaml` follows the same schema the other adapters use
(validated by `assetflow/models.py`). Each query names a `resource` the runner
knows how to fetch:

| Resource | AR form | `asset.type` |
|---|---|---|
| `computer_systems` | `BMC.CORE:BMC_ComputerSystem` | `Server` / `Workstation` / `Computer System` |
| `software` | `BMC.CORE:BMC_Product` | `Software` |
| `business_services` | `BMC.CORE:BMC_BusinessService` | `Business Service` |
| `people` | `CTM:People` | `Person` |
| `incidents` | `HPD:Help Desk` | `Incident` |
| `changes` | `CHG:Infrastructure Change` | `Change Request` |

The resource → form mapping lives in `remedy_runner._RESOURCE_FORMS`, so the
registry stays declarative (a query only names its resource).

## The runner and collectors

`remedy_runner.run_query` validates the query's `resource`, resolves its form and
collector, fetches the entries, and returns a normalized `QueryResult`.

Each collector fetches its form's entries and defines a per-row builder
(`row_fn`) that returns `(standard_cell_values, consumed_labels)`. The shared
`_build` helper then:

- reads each entry's `values` mapping (AR field label → value),
- maps the known labels to the standard columns (`g(values, "Name", "…")` picks
  the first non-empty candidate),
- computes the `custom.*` columns for every remaining non-plumbing field, and
- appends the sorted union of those custom columns, padding each row so nothing
  is misaligned.

Asset-bearing resources (computer systems, software, business services, people)
emit a `host.name` column so they fold into the unified **All Fetched Results**
view; incidents and changes are keyed by their record id (`incident.id` /
`change.id`) and carry the affected CI where the form denormalizes it.

## Standard fields vs. custom fields

The AR entry `values` come back keyed by **field label**. Two rules keep the
custom columns meaningful:

- **Consumed labels** — the labels a collector maps to standard columns — are
  never re-emitted as `custom.*`.
- **AR plumbing is dropped** — `remedy_runner._IGNORE_FIELDS` (Request ID,
  Submitter, Status History, `InstanceId`, …) plus a `z*` prefix heuristic
  (Remedy's temporary/workflow/display fields) are excluded, and empty values are
  skipped.

Everything else surfaces as `custom.<label>` (e.g. `custom.Cost Center`), so a
site's added fields ride along without ever being confused with system fields —
the same convention the VMware and AssetExplorer adapters use.

## How to add a new Remedy resource

1. **Pick the AR form** (e.g. `BMC.CORE:BMC_NetworkPort`) and the standard field
   labels you want as columns.
2. **Write a collector** in `remedy_runner.py`: fetch `client.get_entries(form)`,
   define a `row_fn` returning the standard cells + the set of consumed labels,
   and return `_build(entries, columns, row_fn)`. Emit `host.name` if the rows
   should fold into the unified inventory, and set a static or derived
   `asset.type`.
3. **Register it** in `_COLLECTORS` and `_RESOURCE_FORMS` (keyed by the resource
   name).
4. **Add a query (and feed)** to `config/remedy_registry.yaml` naming the new
   resource, with `expected_output_fields` and `notes`. Add the new category to
   `metadata.categories` if it's a new one.
5. **Add a test** in `tests/test_remedy.py` with a `FakeClient` returning canned
   entries for the form, asserting the columns, `asset.type`, and `custom.*`
   behavior.

No changes to the database, exports, or unified inventory are needed — they
consume the shared `QueryResult` shape.
