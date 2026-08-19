# Unified Inventory — design, decisions, and flow

This document records **why** the unified inventory works the way it does, so the
decisions and data flow survive past the conversation that produced them. It is a
living design note: update it when the model changes.

The unified inventory is assetFlow's **CAASM layer** (Cyber Asset Attack Surface
Management, à la Axonius): it takes the partial views many adapters have of the
same estate and reconciles them into one asset per real-world entity, showing
which sources saw each one and where they disagree.

---

## 1. The layered model

Correlation happens in three layers. Each builds on the one below; only layer 3
is cross-source.

| Layer | Scope | Code | Output |
|-------|-------|------|--------|
| **1 — Fetch** | one query, one connection | `runner.py`, `tufin_runner.py` → `db.fetch_runs` | raw rows, persisted per `(connection, query)` |
| **2 — Intra-adapter merge** | one connection, all its queries | `merge.build_host_view` | golden record per host *within* a connection ("All Fetched Results") |
| **3 — Cross-adapter correlation** | every connection, every adapter | `merge.correlate` → `build_unified_inventory` / `build_asset_detail` | one asset per correlated entity, across the whole platform |

The rest of this doc is about **layer 3**.

---

## 2. Correlation engine (`merge.correlate`)

**Entity resolution by shared identifiers, via union-find.**

- Every row that carries an asset type's *primary* column becomes an
  *observation*.
- Each row contributes **identity tokens** — `(kind, normalized_value)` — drawn
  from that type's identity columns.
- Two observations that share **any** token are unioned into one asset
  (connected components over tokens). So a machine reported as `WIN-DC01` by one
  adapter and `dc01.corp.local` by another collapses into one asset when they
  share, e.g., an IP or MAC.

**Normalization** (`_norm_ident`): MACs are reduced to bare lowercase hex
(`AA:BB:CC` == `aa-bb-cc`); hostnames are lowercased with the trailing dot
stripped; everything else is lowercased/trimmed.

**Junk guarding** (`_JUNK_IDENTS`): placeholder values that would over-merge
everything — empty, `0.0.0.0`, `127.0.0.1`, `::1`, all-zero / broadcast MACs,
`unknown`, `n/a`, … — are dropped and never correlate.

Each resulting asset carries: `primary_name`, `names`/`aliases`, `identities`
(all IPs/MACs/…), the contributing `adapters`, `match_by` (the identifiers that
merged it — surfaced as "correlated by"), and the per-query rows that belong to
it (used to build fields and detail tables).

---

## 3. Asset types — a key space *per type*

**Decision:** the inventory is multi-type. **Devices, Users, and Applications**
are each correlated **separately, in their own namespace** — a user is never
merged into a device even if a value coincides. (Chosen over device-only; this is
the Axonius Devices/Users split, extended with Applications.)

Each type (`merge.ASSET_TYPES`) declares its **primary** display column(s) and its
**identity** columns → kinds:

| Type | Primary | Correlation keys |
|------|---------|------------------|
| **device** | `host.name` | host.name, host.ip, host.mac, serial, cloud id |
| **user** | `user.name`, `user.email` | user.name, email, SID, UPN, user id |
| **application** | `application.name`, `package.name`, `service.name`, … | the app/service/package/process name |

**A single row can feed several types.** A "user on host" row (`host.name` +
`user.name`) contributes a Device *and* a User — correlation just runs once per
type over the same blocks. That's why opening the `admin` user shows every host
it appears on (host.name becomes a field of the user).

`inventory_types()` reports per-type asset counts; the UI shows a
Devices/Users/Applications switch.

---

## 4. Device categories — an attribute, not a namespace

**Decision:** router / firewall / switch / server are **one Device type with a
derived `category` attribute**, not separate types or separate key spaces.
(Chosen scope: category attribute + inventory sub-filter. We deliberately did
**not** make correlation *trust* category-aware — see Open items.)

Rationale: everything network-y is still a Device; the correlation key set is the
same, and each device only carries the identifiers its source provides (a server
has hostname+MAC+serial; a firewall has device-name+management-IP+vendor+model).
They correlate on whatever overlaps.

**Derivation** (`_classify_device`): classify from any vendor / model / OS / type
columns the sources carry, first match wins —

- Palo Alto, Check Point, Fortinet, ASA, SonicWall, SRX → **firewall**
- Catalyst, Nexus, Arista, Aruba, ProCurve → **switch**
- ASR, ISR, IOS-XE, Juniper MX → **router**
- BIG-IP, NetScaler, Citrix ADC → **load balancer**
- Windows Server, Linux, ESXi → **server**
- Windows 10/11, macOS, workstation/laptop → **workstation**
- otherwise, fall back to the source **adapter's data category**: "Network
  Security Policy" → `network device`; SIEM/log/endpoint → `server`; else
  `unknown`.

The Devices inventory shows a `category` column and a category sub-filter; the
category also appears on each asset's detail.

---

## 5. Aggregated / preferred fields & the drill-down

Opening an asset (`build_asset_detail`) gives three views:

- **Fields — aggregated & preferred:** every attribute flattened to distinct
  values, each tagged **common** (reported by 2+ adapters) or **specific** (one
  source). A **preferred** best-guess value is the one the most adapters report,
  ties broken by adapter order; a **differs** flag marks common fields whose
  adapters disagree. The type's primary columns are excluded (they *are* the
  asset).
- **View by adapter:** the same fields filtered to one source, still tagged
  common/specific.
- **Detail tables:** each contributing query's rows for this asset, kept as
  expandable mini-tables (users, revisions, applications…).

Lookup is by primary name **or any alias**.

---

## 6. Connections — multiple instances per adapter kind

**Decision:** adapter *kinds* (Elasticsearch, Tufin, …) are templates;
**connections** (instances) with user-chosen **labels** sit on top. You can run
several of the same kind — two Tufin servers, three Elasticsearch clusters —
each with its own connection, its own isolated data, and its own column in the
unified inventory.

- `adapters.AdapterKind` = template (metadata + shared registry).
  `AdapterManager` holds kinds and instances (`add_instance` / `rename` /
  `remove` / `unique_label`).
- Instances persist in the `connections` DB table (id, kind, label, remembered
  secrets), so they survive restarts. On a **fresh** database, one default
  connection per kind is seeded (id == kind), keeping historical data
  (`adapter` == kind) aligned.
- Every `adapter` column in the DB (`fetch_runs`, `schedules`, watermarks,
  changes) is the **connection id**, so each instance's data stays separate.
- "Remember" stores that connection's credentials in the DB (local plaintext,
  gitignored — same posture as `.env`), and each connection auto-connects from
  them on startup (falling back to environment vars for the default instance).

Labels are kept unique (a duplicate becomes `Label (2)`) because they title the
per-connection inventory columns.

---

## 7. Decision log

| # | Decision | Chosen | Alternatives considered |
|---|----------|--------|-------------------------|
| D1 | Cross-adapter correlation key | Shared identifiers (hostname/IP/MAC/serial/cloud id) via union-find | Hostname only |
| D2 | Weak/junk identifiers | Drop a fixed junk list; still merge on IP | Never merge on IP; fanout guards |
| D3 | Asset types | Devices + Users + Applications, separate namespaces | Device-only; Devices + Users |
| D4 | Device sub-kinds (fw/router/switch/server) | Derived `category` attribute + filter | Separate asset types; category-aware key trust |
| D5 | Multiple sources of one kind | Connections (instances) with labels, DB-persisted | One connection per kind |
| D6 | Remembered credentials | Per-connection secrets in local DB | Shared `.env` (previous behavior) |
| D7 | Preferred field value | Majority vote across adapters, tie-break by adapter order | Per-adapter trust ranking; most-recent |

---

## 8. Open items / future

- **Tiered correlation confidence (D2/D4 refinement).** IP correlation is
  inherently ambiguous (DHCP/NAT reuse). A confidence model — strong IDs
  (serial/MAC/mgmt-IP) merge freely, IP only *corroborates* — would cut
  over-merge, especially for multi-interface network gear.
- **Category-aware key trust (D4).** For network devices, avoid merging on weak
  interface-MAC/interface-IP; trust serial / management-IP / device-name.
- **Coverage-gap view.** "Seen by adapter X but *not* Y" — the classic Axonius
  gap finder for unmanaged/unprotected assets. The `seen_by` data already
  supports it.
- **Richer application identity.** Applications key on name only today; add
  version/vendor, and explode list-valued columns (`Applications` VALUES()) into
  per-app assets instead of device attributes.
- **Field-level trust ranking (D7).** Let an admin rank which adapter "wins" per
  field, instead of majority vote.
- **New asset types / kinds.** A new type is one entry in `ASSET_TYPES`; a new
  adapter kind (e.g. VMware) needs a client + registry + `AdapterKind`.

---

## 9. Where the code lives

| Concern | File |
|---------|------|
| Correlation engine, types, categories, inventory, detail | `assetflow/merge.py` |
| Connections, secrets, fetch persistence | `assetflow/db.py` |
| Adapter kinds & instances (manager) | `assetflow/adapters.py` |
| API endpoints + UI | `assetflow/webapp.py` |

**Key API endpoints**

- `GET /api/inventory/types` → `[{type, label, count}]`
- `GET /api/inventory?type=device|user|application` (+ `/api/inventory.{csv,json}?type=`)
- `GET /api/inventory/asset?host=<name-or-alias>&type=<type>`
- `GET /api/kinds`; `POST /api/connections`; `PATCH|DELETE /api/connections/{id}`

Tests: `tests/test_merge.py` (correlation, types, categories, drill-down) and
`tests/test_webapp.py` (the API surface).
