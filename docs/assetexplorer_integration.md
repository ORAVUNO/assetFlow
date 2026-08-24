# ManageEngine AssetExplorer Integration — Developer Guide

This guide explains how the **ManageEngine AssetExplorer** adapter works: how it
connects, what it fetches, how assets are bucketed into their asset types, and how
default and custom (UDF) fields are normalized. It mirrors the structure of the
other adapter guides ([Tenable.sc](tenable_sc_integration.md),
[SolarWinds](solarwinds_integration.md), [VMware](vmware_integration.md)).

## Contents

- [Where AssetExplorer fits](#where-assetexplorer-fits)
- [Module map](#module-map)
- [Resource catalog (all 19)](#resource-catalog-all-19)
- [Data flow](#data-flow)
- [Authentication](#authentication)
- [The response envelope & pagination](#the-response-envelope--pagination)
- [Asset flattening: default + custom fields](#asset-flattening-default--custom-fields)
- [Bucketing assets into asset types](#bucketing-assets-into-asset-types)
- [CMDB, contracts & purchases](#cmdb-contracts--purchases)
- [Configuration (environment variables)](#configuration-environment-variables)
- [Design decisions & gotchas](#design-decisions--gotchas)
- [How to add a new AssetExplorer resource](#how-to-add-a-new-assetexplorer-resource)
- [Testing](#testing)
- [API references](#api-references)

## Where AssetExplorer fits

AssetExplorer is ManageEngine's IT asset management / CMDB product. The adapter
sits beside the other data sources (category *IT Asset Management / CMDB*) and, as
the sample AssetExplorer report does, presents every asset **grouped by its asset
type** — servers, workstations, routers, switches, firewalls, access points,
printers, storage, UPS, and so on — with all of its default fields and every
site-specific custom (UDF) field. It also fetches the CMDB configuration items,
contracts, and purchase orders.

## Module map

| File | Responsibility |
| --- | --- |
| `assetflow/assetexplorer_client.py` | REST connection: OAuth / technician-key auth, the `input_data`/`list_info` list pager, the `response_status` envelope check, `build_client` / `build_client_from_env` / `ping`. |
| `assetflow/assetexplorer_runner.py` | Turns a registry `resource` into v3 REST calls and flattens the JSON into `QueryResult` (named default columns + `custom.*` sweep). Holds the asset-type buckets and the per-resource collectors. |
| `config/assetexplorer_registry.yaml` | The 19 resources in 9 feeds, with purpose, expected output fields, and notes. |
| `assetflow/adapters.py` | `AssetExplorerAdapter` (connect/ping/run + env mapping) and its registration in `available_kinds`. |
| `assetflow/webapp.py` | The connection-panel wiring (portal / OAuth / API-key fields) and the adapter logo. |

## Resource catalog (all 19)

| ID | Resource | Feed | Endpoint |
| --- | --- | --- | --- |
| AE001 | `assets` | Asset Inventory | `GET /api/v3/assets` |
| AE002 | `servers` | Servers & Compute | `assets`, product type ∈ {server, mainframe, esx, blade} |
| AE003 | `workstations` | Servers & Compute | `assets`, product type ∈ {workstation, desktop, laptop} |
| AE004 | `virtual_machines` | Servers & Compute | `assets`, product type ∈ {virtual machine/server, vm} |
| AE005 | `clusters` | Servers & Compute | `assets`, product type ∈ {cluster} |
| AE006 | `routers` | Network Devices | `assets`, product type ∈ {router} |
| AE007 | `switches` | Network Devices | `assets`, product type ∈ {switch} |
| AE008 | `firewalls` | Network Devices | `assets`, product type ∈ {firewall} |
| AE009 | `access_points` | Network Devices | `assets`, product type ∈ {access point, wireless} |
| AE010 | `printers` | Peripherals & Facilities | `assets`, product type ∈ {printer, mfp, scanner} |
| AE011 | `storage_devices` | Peripherals & Facilities | `assets`, product type ∈ {storage, san, nas, tape} |
| AE012 | `ups` | Peripherals & Facilities | `assets`, product type ∈ {ups, pdu} |
| AE013 | `network_devices` | Network Devices | `assets`, any network product type (superset of AE006–AE009) |
| AE014 | `mobile_devices` | End-User Devices | `assets`, product type ∈ {mobile, phone, tablet} |
| AE015 | `cmdb` | CMDB | `GET /api/v3/cmdb/{ci_type}` for each configured CI type |
| AE016 | `contracts` | Contracts | `GET /api/v3/contracts` |
| AE017 | `purchases` | Purchase | `GET /api/v3/purchase_orders` |
| AE018 | `asset_types` | Catalog | `GET /api/v3/asset_types` |
| AE019 | `products` | Catalog | `GET /api/v3/products` |

## Data flow

```
registry query (resource) ──► AssetExplorerAdapter.run
    └► assetexplorer_runner.run_query
        └► _COLLECTORS[resource](client, time_range)
            └► client.list(path, key)  ──►  v3 REST (paged)
        └► _flatten_assets / _flatten_generic   (named cols + custom.* sweep)
    ◄── QueryResult(columns, rows)  ──► DB / exports / unified inventory
```

The per-asset-type resources all fetch `GET /api/v3/assets` once and filter the
result by product type, so they share the exact flattening of AE001.

## Authentication

AssetExplorer supports two credential styles; the client implements both
(`_auth_headers`):

- **OAuth 2.0 (AssetExplorer Cloud).** Every request carries
  `Authorization: Zoho-oauthtoken <access_token>`. Access tokens are short-lived,
  so the preferred setup supplies a long-lived **refresh token** plus the OAuth
  **client id/secret**; `_ensure_access_token` mints a fresh access token from the
  Zoho accounts server on demand, and a `401` mid-fetch triggers one refresh +
  retry (`_request`, `refresh_access_token`). Pick the accounts server for your
  data center with `AE_ACCOUNTS_URL` (US/EU/IN/AU/JP/CN).
- **Technician API key (on-premises).** Every request carries the key in the
  `TECHNICIAN_KEY` and `authtoken` headers (both, so the same key works across
  releases).

The Cloud URL is `https://<host>/app/<portal>/api/v3/...`; on-prem (no portal) is
`https://<host>/api/v3/...` (`url_for`).

## The response envelope & pagination

Every v3 reply is wrapped as `{"response_status": {...}, "list_info": {...},
"<resource>": [ ... ]}`. Like many ManageEngine APIs, an API error is reported *in
the body* through `response_status.status_code` (2000 = success), often with HTTP
200 — so `_check_status` always inspects the envelope, not just the HTTP code
(it accepts `response_status` as a dict or a single-item list).

`client.list(path, key)` pages a list endpoint: it sends an `input_data` query
parameter carrying a `list_info` block (`start_index`, `row_count`,
`get_total_count`) and follows `list_info.has_more_rows` until the estate is
exhausted (or `AE_MAX_RECORDS` is hit). `_extract_list` pulls the record list out
by the resource key, falling back to the first list-valued key — needed for CMDB,
where the list is keyed by the CI-type name rather than a fixed `ci` key. As with
the other adapters, a **first-page** failure is raised (a real error) while a
**later-page** failure returns the records gathered so far.

## Asset flattening: default + custom fields

`_flatten_assets` turns asset JSON into `(columns, rows)`:

- Leading **`host.name`** and **`asset.type`** fold each asset into the unified
  inventory. `asset.type` is the asset's **product type** (`_product_type` reads
  either `product_type` or the nested `product.product_type`), which is exactly
  what buckets it into servers/routers/… .
- **Default columns** come from `_ASSET_SPEC` — asset tag, state, IP, MAC, OS,
  product, vendor, serial number, barcode, department, site, location, region,
  assigned user, technical owner, acquisition/expiry dates, and the four cost
  fields — each read with `_pick` key fallbacks so the mapping survives API
  version / product-type differences. Nested objects are reduced to their name
  (`_name`); date fields (the `{value, display_value}` shape, epoch **ms**) are
  rendered by `_date` (display value preferred, else the epoch converted to ISO).
- **Custom columns.** Every entry in the asset's `udf_fields` object, plus any
  other unmapped scalar top-level key, is emitted as `custom.<key>` (the union
  across assets, first-seen order). Keys already consumed by the named columns are
  listed in `_ASSET_CONSUMED` so they aren't duplicated. This is how the site's
  UDF fields ride along without being confused with the system columns — the same
  `custom.` convention the SolarWinds / VMware / Tenable.sc adapters use.

## Bucketing assets into asset types

`ASSET_TYPE_BUCKETS` maps each per-type resource name to a set of product-type
keywords (lower-cased substring match). `_bucket_collector(keywords)` builds a
collector that fetches all assets and keeps those whose product type matches. The
buckets mirror the CI types the sample report separates assets into; `asset.type`
on each row stays the asset's actual product type. Extend or retune the keyword
sets in `ASSET_TYPE_BUCKETS` for a site's product-type naming.

## CMDB, contracts & purchases

- **CMDB (AE015).** `_collect_cmdb` iterates the configured CI types
  (`AE_CMDB_CI_TYPES`, default a common IT set) and fetches
  `GET /api/v3/cmdb/{ci_type}` for each, best-effort — a CI type the deployment
  doesn't have simply raises and is skipped. Each row is stamped with its CI type
  in `ci.type` / `asset.type`. CI-type api names vary by deployment, which is why
  AE015 is marked `investigation_required`.
- **Contracts (AE016)** and **Purchases (AE017)** use `_flatten_generic` with a
  small named `lead` (name, type/number, status, vendor, owner, cost, dates) plus
  the same `custom.*` sweep. `asset.type` is a constant (`Contract` /
  `Purchase Order`) so they read as their own entity types.
- **Catalog (AE018/AE019).** `asset_types` and `products` list the categories
  and models assets are instances of — useful for confirming how your estate's
  product types map onto the buckets.

## Configuration (environment variables)

| Variable | Purpose |
| --- | --- |
| `AE_HOST` | AssetExplorer service domain / hostname (required). |
| `AE_PORTAL` | Cloud portal (the segment after `/app/`); omit on-prem. |
| `AE_ACCESS_TOKEN` | A current OAuth access token (Cloud). |
| `AE_REFRESH_TOKEN` + `AE_CLIENT_ID` + `AE_CLIENT_SECRET` | Refresh-token flow (Cloud, preferred — auto-renews). |
| `AE_API_KEY` | Technician API key (on-premises). |
| `AE_ACCOUNTS_URL` | Zoho accounts server for token refresh (data-center specific). |
| `AE_VERIFY_CERTS` | `false` only for a lab / self-signed on-prem box. |
| `AE_REQUEST_TIMEOUT` | Request timeout seconds (default 60). |
| `AE_PAGE_SIZE` | List page size (default 100 — AssetExplorer's cap). |
| `AE_MAX_RECORDS` | Safety cap per list fetch (default 1,000,000; 0 = unlimited). |
| `AE_CMDB_CI_TYPES` | Comma-separated CI-type api names AE015 fetches. |

## Design decisions & gotchas

- **Product type is the categorizer.** The report groups by product type (e.g.
  "Access Points"), so `asset.type` = product type and the buckets filter on it —
  no reliance on the coarse `type` (Asset/Software) field.
- **UDFs come from the list endpoint.** The Asset-level UDFs (the report's
  `UDF_CHAR*` / `UDF_DATE*`) are returned by `GET /api/v3/assets` under
  `udf_fields`. Product-type **subform** fields are *not* returned by the list
  endpoint and would need a per-asset `GET /api/v3/assets/{id}`; that per-asset
  enrichment is intentionally not done by default (it is O(assets) requests) and
  is the main reason the resources are `partially_validated`.
- **Dates are epoch milliseconds.** AssetExplorer uses ms (not seconds like
  Tenable.sc); `_epoch_millis` divides by 1000. The display value is preferred
  when present so the column reads as the UI shows it.
- **Best-effort CMDB.** CI-type api names differ per deployment; skipping missing
  types keeps the resource robust rather than failing the whole fetch.

## How to add a new AssetExplorer resource

1. Add a collector `_collect_x(client, time_range) -> (columns, rows)` in
   `assetexplorer_runner.py` (use `_flatten_generic` for a simple listing, or
   `_flatten_assets` if it is asset-shaped), and register it in `_COLLECTORS`. For
   a new asset-type bucket, just add an entry to `ASSET_TYPE_BUCKETS`.
2. Add a `query` (and, if needed, a `feed`) to
   `config/assetexplorer_registry.yaml` naming that `resource`.
3. Add a test to `tests/test_assetexplorer.py` with a `FakeClient` rule.

## Testing

`tests/test_assetexplorer.py` exercises the registry, the asset flattening
(default + `custom.udf_*`, product-type buckets, date handling), the CMDB merge /
skip, contracts / purchases / catalog, and the client itself (envelope check, list
extraction, pagination, URL building, credential validation) plus the adapter
wiring (kind registration, `connect_form` token mapping, `env_for_form`). No live
AssetExplorer is contacted — a `FakeClient` answers from canned rules.

## On-premises: confirmed behavior

Verified against a live on-prem instance (`https://<host>:8443`, an
AssetExplorer 6.x deployment):

- **Base URL** `https://<host>:8443` — HTTPS on a **custom port**. The client
  honors the scheme + port (`scheme_of` / `clean_host`); on-prem hosts that run
  plain HTTP work too (`AE_HOST=http://host:8080`).
- **Endpoint** `GET /api/v3/assets` — same v3 path as Cloud.
- **Auth header** `authtoken: <technician key>` (the client also sends
  `TECHNICIAN_KEY` for older builds; both are harmless).
- **Paging** `input_data={"list_info": {row_count, start_index, sort_field,
  sort_order, fields_required}}`, following `list_info.has_more_rows`.
- **IP field** the list endpoint returns **`ip_addresses`** (a comma-separated
  string); the per-asset shape nests IP/MAC under **`network_adapters[]`**
  (`{ip_address, mac_address}`). `_ip` / `_mac` read both.
- **Custom fields** live under **`udf_fields`**, keyed by `udf_*` api names —
  including pick lists like `udf_pick_8919` ("Network type"). All are swept into
  `custom.*`.
- **`product`** is a controlled list; in this estate its values are exactly
  `Server`, `Routers`, `Switches`, `Firewall`, `Access Points` — the same names
  the asset-type buckets match on.
- **Owner** is the **`user`** field (the API rejects `owner` / `asset_owner`);
  **`location`** is a plain string. `department` / `user` are only populated when
  the asset state mandates ownership (e.g. *In Use*).
- **Success envelope** accepts `response_status.status_code` of **2000 or 200**
  (and a `status` of `"success"`); a `status_code` of `7001` signals the
  asset/license limit.

## Matching an AssetExplorer report (row & field parity)

Validated against a real AssetExplorer report export (8,059 assets) vs. the
adapter's `assets` pull, which revealed — and this section's features close —
three gaps:

- **Disposed assets.** The `/api/v3/assets` list endpoint omits disposed /
  retired assets by default (the report included 1,128 of them; `8059 − 1128`
  was exactly what the adapter returned). `_fetch_assets` now also fetches the
  `AE_DISPOSED_STATES` (default `Disposed, Expired, Retired`) via a state
  `search_criteria` and merges them, deduped by id, so counts match. Disable with
  `AE_INCLUDE_DISPOSED=false`.
- **Sparse default projection.** The list endpoint returns only a default field
  set — so serial, MAC, OS, category, and dates came back empty even though the
  data exists. The adapter now sends a broad `fields_required` projection
  (`_DEFAULT_ASSET_FIELDS`, override with `AE_ASSET_FIELDS`); a rejected field
  name makes the fetch retry without the projection. Serial in particular is read
  from `org_serial_number` (where this estate keeps it). Note: costs, "Associated
  To", and "Loan Start/End" are genuinely empty in the source report too — not a
  fetch gap.
- **Unreadable custom fields.** UDF columns came through as raw api names
  (`custom.udf_pick_8909`). The adapter now resolves a UDF api_name → label map —
  best-effort from AssetExplorer field metadata, overridden by `AE_UDF_LABELS`
  (inline JSON or `@file`) — and renames the columns (`BCM Rating`, `Network
  type`, …). UDF labels are deployment-specific; a **complete** recovered map for
  the reference instance (all 34 asset UDFs — `UDF_CHAR1..24` + `UDF_DATE1..10`,
  derived from the report definition and value-confirmed) ships at
  `config/assetexplorer_udf_labels.example.json`. With no `AE_UDF_LABELS` set, a
  file at `config/assetexplorer_udf_labels.json` is auto-loaded, so a site can drop
  its map in place with zero config.

## API references

- [AssetExplorer Cloud v3 REST API](https://www.manageengine.com/products/asset-explorer/aecloud-v3-api/)
- [OAuth 2.0 for the v3 API](https://www.manageengine.com/products/asset-explorer/aecloud-v3-api/getting-started/oauth-2.0.html)
- [CMDB / Configuration Item API](https://www.manageengine.com/products/asset-explorer/aecloud-v3-api/cmdb/configuration_item.html)
