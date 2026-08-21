# Tufin Integration — Complete Guide

A single place to understand **how the Tufin SecureTrack integration works** in
assetFlow, end to end: what it collects, how it fetches at scale, how change
intelligence is derived, and how changes are reconciled against change-request
tickets to decide whether each one was **authorized**.

If you only need the raw SecureTrack field/endpoint reference, see
[`tufin_securetrack_api_reference.md`](tufin_securetrack_api_reference.md). This
guide is about *what the integration does and how the code does it*.

## Contents
- [What it delivers](#what-it-delivers)
- [Architecture — where everything lives](#architecture--where-everything-lives)
- [Connecting to SecureTrack](#connecting-to-securetrack)
- [The registry — resources (TUF001–TUF010)](#the-registry--resources-tuf001tuf010)
- [Fetch mechanics — pagination, whole estate, parallelism](#fetch-mechanics--pagination-whole-estate-parallelism)
- [Revisions — the change model](#revisions--the-change-model)
- [Change detection (TUF008)](#change-detection-tuf008)
- [Deduplicated change log & dashboard](#deduplicated-change-log--dashboard)
- [Revision snapshots, Compare & Policy (TUF009 / TUF010)](#revision-snapshots-compare--policy-tuf009--tuf010)
- [Discover — the unified device profile](#discover--the-unified-device-profile)
- [Access Impact — what a member inherits](#access-impact--what-a-member-inherits)
- [Authorization — ticket reconciliation](#authorization--ticket-reconciliation)
- [HTTP API reference](#http-api-reference)
- [Environment variables](#environment-variables)
- [Persistence & migrations](#persistence--migrations)
- [Testing](#testing)
- [Design decisions & caveats](#design-decisions--caveats)
- [How to extend](#how-to-extend)

---

## What it delivers

Three layers, built on one connection:

1. **Asset intelligence** — every device SecureTrack manages (firewalls, virtual
   contexts, management servers), their rulebases, network objects, services,
   zones, and policy-hygiene findings.
2. **Change intelligence** — *what changed, who changed it, when, and what it
   was* — derived by diffing policy revisions, covering both **rule** and
   **network-object** edits, each with a plain-language summary and the
   security signals (widening, blast radius).
3. **Authorization** — reconcile every detected change against your ticketing
   system's approved requests, verdicting each **authorized / over-provisioned /
   unauthorized**.

Everything is driven from a single **🔎 Discover** action (fetch all + build the
unified view) or from individual feeds; the raw feeds sit behind an *Advanced*
toggle so day-to-day users never touch them.

---

## Architecture — where everything lives

assetFlow is built around **adapters** — pluggable data sources sharing one
small contract so the web UI, database, export, unified view, scheduler and
reconciliation treat them uniformly.

| File | Responsibility |
|---|---|
| `assetflow/adapters.py` (`TufinAdapter`) | connect / ping / run; resolves the device-scan setting |
| `assetflow/tufin_client.py` | minimal SecureTrack REST client (Basic auth, JSON, `get(path)`) |
| `assetflow/tufin_runner.py` | maps a registry `resource` → SecureTrack endpoint(s), paginates, parallelises, normalises to `QueryResult`; all change-detection logic lives here |
| `config/tufin_registry.yaml` | the resources (TUF001–010) and feeds |
| `assetflow/db.py` | persistence — fetch snapshots, the deduped change log, tickets; SQLite migrations |
| `assetflow/tufin_profile.py` | folds all saved fetches into one device-keyed **Discover** profile |
| `assetflow/impact.py` | which rules apply to an object / a member added to it (Access Impact) |
| `assetflow/reconcile.py` | matches changes against tickets → authorization verdicts |
| `assetflow/service.py` | run-and-save, run-all (fetch all), change-log dedup wiring |
| `assetflow/scheduler.py` | periodic fetches |
| `assetflow/webapp.py` | FastAPI endpoints + the single-page UI |

The adapter contract:

```
connect_form(form) -> dict                    # open a live connection from UI fields
try_auto_connect() -> bool                    # best-effort connect from env vars
ping() -> dict                                # re-check connectivity
run(query, limit, time_range) -> QueryResult  # fetch one registry resource
```

`QueryResult` is `{columns: [{name}], rows: [[...]]}` — the shared shape the DB,
exports, unified view, and reconciliation all understand.

---

## Connecting to SecureTrack

SecureTrack exposes a REST API rooted at `https://<host>/securetrack/api/`,
authenticated with **HTTP Basic auth** (a SecureTrack API user). Provide
credentials via the UI Connection panel or environment variables — never
hard-coded.

| Env var | Meaning |
|---|---|
| `TOS_HOSTNAME` | SecureTrack host or IP |
| `TOS_USERNAME` | a SecureTrack API user |
| `TOS_PASSWORD` | that user's password |
| `TUFIN_BASE_PATH` | API base path (default `/securetrack/api`) |
| `TUFIN_VERIFY_CERTS` | `false` to disable TLS verification (lab only) |
| `TUFIN_REQUEST_TIMEOUT` | seconds (default 30) |

The Connection panel can **save credentials to `.env`** (opt-in) so the adapter
reconnects on restart. Local plaintext, same posture as `.env`; gitignored.

> **API user scope matters.** The API user only sees the devices/domains it is
> permitted to. If SecureTrack's GUI shows more devices than assetFlow, it is
> almost always a **permissions or multi-domain scoping** difference on that API
> user — not a fetch limit.

---

## The registry — resources (TUF001–TUF010)

Each registry entry names a `resource` that the runner maps to SecureTrack
endpoint(s). Statuses: `validated` (confirmed against live data),
`partially_validated`, `investigation_required`, `not_validated`.

| ID | Resource | What it fetches |
|---|---|---|
| **TUF001** | `devices` | Every device: name, id, **asset.type** (derived), vendor, model, virtual_type, **context_name**, ip, os.version, **domain + domain.id**, status, **latest_revision**, **module_type/uid**, **topology**, installed_policy |
| **TUF002** | `revisions` | Per-device revision history — who/when/action/ticket/policy package/authorization status/comment |
| **TUF003** | `rules` | Effective (latest-revision) rulebase per device — zones, source, destination, service, action, track, disabled |
| **TUF004** | `network_objects` | Network objects (hosts, subnets, ranges, groups) per device — name, type, ip |
| **TUF005** | `services` | Service objects — protocol, port |
| **TUF006** | `zones` | Per-device zones (segmentation) |
| **TUF007** | `cleanups` | Fully-shadowed rules (policy hygiene, `?code=C01`) |
| **TUF008** | `change_detail` | **Per-change diff** of consecutive revisions — the change-intelligence headline (see below) |
| **TUF009** | `revision_rules` | **Snapshot** of recent revisions' rulebases — backs Compare / Policy |
| **TUF010** | `revision_objects` | **Snapshot** of recent revisions' network objects — backs object-level compare & change detection |

`asset.type` is **derived** (SecureTrack has no device-type field): a device that
is the parent of others or whose model names a manager (Panorama, FMC,
FortiManager, CMA, MDS…) is *Firewall Management*; one with a `virtual_type` is a
*Virtual Firewall*; router/switch and load-balancer models are labelled; else
*Firewall*.

---

## Fetch mechanics — pagination, whole estate, parallelism

The runner is built to pull the **entire** estate accurately, then bound cost.

- **Pagination.** SecureTrack caps list endpoints (~200 rows) and reports a
  `total`. `_fetch_list()` walks **every page** (advancing by the count actually
  returned, so a server that caps below the request is still walked fully). When
  a page carries no `total`, it keeps paging while pages come back *full* and
  stops on the first short page — so nothing is silently truncated. Tune the
  request size with `TUFIN_PAGE_SIZE` (default 2000).
- **Whole estate by default.** `device_scan_limit` defaults to **all devices**.
  Cap it with `TUFIN_DEVICE_SCAN` (a positive int; `0`/blank = all).
- **Bounded parallelism.** Per-device REST calls run in a thread pool
  (`TUFIN_CONCURRENCY`, default 8, max 32). The client is stateless per request,
  so this is safe; change-detail reads watermarks up front and writes them on the
  main thread to keep DB access single-threaded.
- **Device-list cache.** A full Discover runs ~10 collectors that each need the
  device list; it's cached per client (short TTL) so `/devices` is hit once.

**Fetch all** and **Discover** run with **no row limit** — they fetch every row
of every feed. (The per-feed manual *Run* button defaults to `limit 100`; that's
a convenience only.)

---

## Revisions — the change model

A **revision is a full snapshot of one device's policy at a point in time** —
like a git commit of the whole rulebase + objects. SecureTrack creates a new
revision whenever it detects the installed policy changed (via polling or
real-time monitoring).

Key consequences:

- **One revision bundles many changes.** An admin may add 3 rules, modify 2,
  delete 1 and edit objects, then install once → all land in one revision. That's
  why one `revision.id` appears on many rows in the change log.
- **Changes are *derived*, not given.** SecureTrack stores snapshots, not a
  field-level changelog. assetFlow computes "what changed" by **diffing
  consecutive revisions' rulebases and object sets**.
- **Two different "action" fields.** `revision.action` = *how* it was installed
  (`automatic` / `installed` …). `rule.action` = the rule's own accept/drop.
  They are separate columns; don't confuse them.
- **Automatic installs have no actor.** SecureTrack leaves the admin blank for
  system/automatic changes, so `changed_by` is filled with `(automatic)` or
  `(unattributed)` rather than an empty cell.

---

## Change detection (TUF008)

For each device the runner selects revision pairs to diff (latest two by
default; every revision in the time-range window plus a baseline; or the
incremental "since last check" mode driven by a per-device watermark), fetches
each revision's rules **and** objects (cached, paginated), and emits one row per
**unit change**. Columns:

```
host.name, revision.id, @timestamp, changed_by, revision.action, policy_package,
change_type, entity, rule.uid, summary, changed_fields, risk, blast_radius,
src_zone, source, dst_zone, destination, service, rule.action,
before, after, authorized, requester
```

- **entity** — `rule` or `object`. Network-object edits are folded into the same
  stream, because editing a named object changes what every rule using it permits
  while the rule text is unchanged.
- **change_type** — `added` / `modified` / `removed` / `moved`. *Moved* (a
  reorder with unchanged content) is told apart from a rule that merely shifted
  because neighbours changed, via a longest-common-subsequence over the rules
  common to both revisions. A pure rename is **not** a change (the fingerprint
  excludes the name).
- **summary** — plain language: `Added rule — 10.1.1.1 → web : tcp/443 (accept)`,
  `Modified — service: tcp/8443 → tcp/443; action: accept → drop`,
  `Disabled rule`, `Moved — reordered…`, `Modified object 'srv-a' — value: 10.0.0.9 → 10.0.0.10`.
- **changed_fields** — for a modification, exactly which fields changed.
- **rule 5-tuple** — `host.name` + `source` + `destination` + `service` +
  `rule.action` (blank for object rows) — the fields reconciliation matches on.
- **before / after** — the compact effect delta (object rows carry the object's
  `type: value`).
- **authorized / requester** — SecureTrack's own change-authorization verdict for
  the revision pair, when SecureChange ticketing is enabled (best-effort).

### Object-change security signals

For object changes (`entity = object`) two extra columns quantify risk:

- **risk** — did the edit *widen* access? `widened (members added)` /
  `widened (broader subnet)` (e.g. `/24 → /16`) vs `narrowed …` / `changed`.
  Widening is the security-relevant direction.
- **blast_radius** — how many rules in the revision reference the changed object.
  One object edit can alter what many rules permit; this is the impact count.

> Blast radius is computed within the changed object's device. Objects shared
> across devices (referenced by rules on *other* devices) are under-counted; an
> estate-wide blast radius is a possible enhancement.

When a modified object gains or loses members, the change **summary** names them
— e.g. `Modified object 'Web-Servers' — value: … [members +10.1.1.9]` — so a
reviewer sees exactly *which* IP was added. To see what that member now
*inherits*, use **Access Impact** (below).

### Modes (the `range` control)

- **All time / latest** → diffs the latest two revisions per device.
- **24h / 7d / 30d / 90d** → every revision in the window plus the one before it
  (a baseline), diffing each consecutive pair so every change in the period is
  reported with its own actor/timestamp.
- **Since last check (incremental)** → diffs only revisions newer than each
  device's stored watermark, then advances it — every change reported exactly
  once, first run records a baseline silently.

---

## Deduplicated change log & dashboard

Every change-detail fetch (any mode) upserts into the **`tufin_changes`** table,
keyed by `(adapter, revision_id, rule_uid, change_type)` — so the same change is
stored **exactly once** no matter how often or in which mode it's fetched. This
is the cumulative change log (`⟳ Change Log`).

The **📊 Changes Dashboard** aggregates it: totals by type, **Automatic vs
Manual** (from `revision.action`), **Widened access** (from `risk`), top changed
devices/administrators, and recent changes.

---

## Revision snapshots, Compare & Policy (TUF009 / TUF010)

The **Compare Revisions** and **Revision Policy** views operate on *saved*
snapshots, not live calls — fetch once, then compare offline.

- **TUF009** snapshots recent revisions' full rulebases (latest 5 per device by
  default, or the time-range window, capped at 30) into the DB.
- **TUF010** does the same for network objects.

- **🔀 Compare Revisions** — pick a device and two revisions; get a Summary
  (New/Deleted/Modified/Moved for Security Rules, and — when TUF010 is present —
  Network Objects) plus per-rule and per-object **before→after** detail,
  colour-coded. Defaults to the latest two; any pair can be picked.
- **📜 Revision Policy** — view any one revision's full rulebase exactly as it
  stood then.

---

## Discover — the unified device profile

**🔎 Discover** is the headline view. One click **fetches every feed** then folds
the latest saved fetches + the change log into one **device-keyed profile**
(`tufin_profile.build_profile`):

- **Estate dashboard** — stat tiles (devices / rules / objects / services / zones
  / revisions / cleanups + change totals + unauthorized) and a by-asset-type
  breakdown.
- **Device table** — one expandable row per device (attrs + counts + a change
  badge); expand → tabbed nested sub-tables for Rules / Objects / Services /
  Zones / Revisions / Cleanups / recent Changes.
- **Download JSON** — the whole estate as one nested object, for pipelines.

`GET …/tufin/profile` rebuilds instantly from saved data; `POST …/tufin/discover`
fetches everything first, then builds.

---

## Access Impact — what a member inherits

`assetflow/impact.py` answers, in plain language a non-firewall admin can read:
**which rules apply to an object — and therefore to any IP added to it — who can
reach it, and what it can reach.**

### Why it exists

A common workflow: instead of writing a new rule for a requested "A → B" flow,
an admin adds the requestor's IP to an **object** already used by an existing
"A → B" rule. Two things follow that are easy to miss:

1. **The new member silently inherits every rule that references the object.**
   Access Impact lists them: *"App-Tier → 10.9.9.9 : tcp/443 (accept)"* — the
   member is now reachable exactly as the object is.
2. **Unintended reachability.** If the rule's *source* holds several addresses,
   they can **all** now reach the newly added destination member. Because the
   impact line carries the rule's *full* source, that exposure is explicit:
   *"Admin-Jump, 10.0.0.7 → 10.9.9.9 : tcp/22 (accept)"* — both `Admin-Jump` and
   `10.0.0.7` can now reach it, even if only one was intended.

### How it works

It reads the saved **effective rulebase** (TUF003) and matches the object by
name in each rule's flattened `source` / `destination` cell (token match, so
`DB` never matches `DB-Servers`; disabled rules are skipped). No live call and
no group-membership expansion is needed — a member inherits exactly the rules
that reference the object. Results split by side:

- **as_source** — the object's members are a *source* → they *can reach* the
  rule's destination.
- **as_destination** — the object's members are a *destination* → they are
  *reachable by* the rule's source (the exposure to watch).

### Using it (UI)

**🎯 Access Impact** (Tufin) — pick an optional device, type the object name
(and optionally the member IP being added) → two tables: **Can reach** (member
as source) and **Reachable by** (member as destination, with the *reachable by /
exposure* column listing every source that can now reach it).

`GET …/tufin/object-impact?object=&device=&member=` returns the same data
(`as_source`, `as_destination`, and framed `sentences`).

> Matching is by object **name** as it appears in the rulebase; if a rule
> references the member's address directly (not via the object) that is a
> separate rule and shows under the address, not the object.

---

## Authorization — ticket reconciliation

The change log tells you *what* changed; your ITSM holds *what was approved*.
Reconciliation joins them so **every change gets a verdict**, without depending
on the implementer stamping a ticket id into the revision comment.

### The idea

For each **rule** change, does an **approved** ticket for the same device,
within its change window, request access that **covers** the implemented
5-tuple (`device + source + destination + service + action`)?

- **CIDR containment** — a ticket's `10.1.0.0/16` covers an implemented
  `10.1.2.0/24`.
- **Object resolution** — a change referencing `Web-Servers` is resolved to its
  address (from the TUF004 object inventory) so it matches a ticket written in
  CIDRs.
- **Per-field relation** — for each of source/destination/service the ticket
  either `equals` / `covers` (⊇) / is `broader` (change ⊋ ticket) / is
  `disjoint` (no overlap → not this ticket).

### Verdicts

| Verdict | Meaning |
|---|---|
| **authorized** | an approved ticket covers the 5-tuple, in window (exact = high confidence, covered-by-broader = medium) |
| **over_provisioned** | matched a ticket but implemented **broader** than requested (e.g. opened `any` source when a `/24` was asked) |
| **unauthorized** | no approved ticket covers it — the headline alert |
| **not_applicable** | object or moved change (reconciled differently) |

Only `approved / scheduled / implemented / closed / completed` tickets
authorize; the **change window** is enforced (a change outside every window
can't be authorized by them).

### What the ticket must contain

Because we can't rely on the comment link, the **ticket** is the source of
truth. Provide it as CSV (any ITSM export). Header aliases are honoured
(`Firewall→device`, `Src→source`, `Dest→destination`, `Port→service`,
`Permit→action`, `Approval→status`, `Type→change_type`, `Start/End→window`).

```
ticket_id,status,change_type,device,source,destination,service,action,window_start,window_end,requester,approver,expiry
CR-1001,approved,add,MBEZI-VPN-ASA-FW,10.1.1.0/24,10.2.0.0/16,tcp/443,allow,2026-08-01,2026-08-31,jdoe,asmith,
```

**Must-have** (without these, matching is guesswork): `device` (matching
SecureTrack's `host.name`), `source`, `destination`, `service`, `action`,
`status`, `change_type`, and ideally a **change window**. **Best practice:** one
row per requested flow (atomic line items), structured values (CIDRs or the same
object names your firewall uses).

### How to use it (UI)

**🔐 Authorization** view:
1. Download the **CSV template**, fill it from your ITSM export.
2. Paste or upload it → **Import tickets** (re-import replaces the set).
3. See the verdict tiles + the reconciled change table, colour-coded, with a
   filter (all / unauthorized / over-provisioned / authorized).

### Endpoints

- `POST …/tickets/import` (JSON `{csv}`), `GET`/`DELETE …/tickets`
- `GET …/reconcile` — the change log annotated with `authorization`,
  `matched_ticket`, `auth_confidence`, `auth_reason`, plus a summary.

### Honest limits

Reconciliation is **probabilistic** where the ticket is loose: free-text intent,
missing device identity, or wide/overlapping windows produce weaker matches. The
value is that the tool does the correlation and hands a reviewer a short list —
"these changes match no approved request" — instead of nothing. The tighter the
ticket schema (real device names, CIDRs/object names, tight windows), the more
lands as a confident authorized/unauthorized. If your ITSM names firewalls
differently from SecureTrack, a **device name-mapping** step is the natural next
addition.

---

## HTTP API reference

All under `/api/adapters/{adapter_id}`:

| Method & path | Purpose |
|---|---|
| `POST /connect` | open a connection from form fields (optionally save to `.env`) |
| `POST /run/{query_id}` | fetch one resource (`?limit`, `?range`) |
| `POST /run-all` | fetch every runnable resource (no limit) |
| `GET /latest/{query_id}` · `GET /history/{query_id}` | saved results |
| `GET /changelog` | the deduplicated change log |
| `GET /change-dashboard` | change aggregates |
| `GET /tufin/profile` · `POST /tufin/discover` | unified profile / fetch-all-then-build |
| `GET /tufin/revision-index` | devices + revisions from the saved snapshot |
| `GET /tufin/revision-compare` | compare two revisions (`device_id`, `old_rev`, `new_rev`) |
| `GET /tufin/revision-policy` | one revision's full rulebase |
| `GET /tufin/object-impact` | rules applying to an object / a member added to it (`object`, `device`, `member`) |
| `POST /tickets/import` · `GET`/`DELETE /tickets` | change-request tickets |
| `GET /reconcile` | changes annotated with authorization verdicts |

---

## Environment variables

| Var | Effect |
|---|---|
| `TOS_HOSTNAME` / `TOS_USERNAME` / `TOS_PASSWORD` | connection + credentials |
| `TUFIN_BASE_PATH` / `TUFIN_VERIFY_CERTS` / `TUFIN_REQUEST_TIMEOUT` | connection options |
| `TUFIN_DEVICE_SCAN` | cap devices scanned (unset/`0` = whole estate) |
| `TUFIN_CONCURRENCY` | parallel per-device calls (default 8, max 32) |
| `TUFIN_PAGE_SIZE` | rows requested per page (default 2000; server may cap lower) |
| `ASSETFLOW_ENV_FILE` | which `.env` UI-saved credentials write to |

---

## Persistence & migrations

- **`fetch_runs`** — every fetch (columns + rows as JSON); latest per
  (adapter, query) is the "current" result, older runs are history.
- **`tufin_changes`** — the deduplicated change log.
- **`tickets`** — imported change-request tickets (replaced wholesale on import).
- **`tufin_change_watermarks`** — per-device incremental watermark.

The DB is a single local SQLite file (gitignored). New columns added after a
release are migrated in place on startup (`_migrate_added_columns` runs
`ALTER TABLE ADD COLUMN`, since `create_all` only adds missing *tables*). Point
`DATABASE_URL` at Postgres later without changing callers.

---

## Testing

No live SecureTrack is contacted. `tests/test_tufin.py` uses a `FakeClient`
(path → canned JSON) plus paging fakes to exercise normalization, pagination,
whole-estate scan, change detection (rule + object, summary, move/disable,
widening, blast radius), and the compare/policy snapshots.
`tests/test_tufin_profile.py` covers the Discover profile;
`tests/test_reconcile.py` covers ticket import and every authorization verdict.
Run `python -m pytest -q`.

---

## Design decisions & caveats

- **Changes are derived from snapshots**, so fidelity depends on how granular the
  revisions are — one bulk install shows as many unit changes under one revision.
- **`authorized` on a change is per-revision** (SecureTrack authorizes the
  install, not each rule). The `reconcile` verdict is assetFlow's own per-change
  judgement against *your* tickets — a separate, finer signal.
- **Object indirection** is why object tracking matters: a change to a named
  object alters access without touching a rule. It's caught in the change stream
  (`entity=object`) and the compare view.
- **Reconciliation is only as good as the ticket data** — see the honest limits
  above.
- **Device count differences vs the GUI** are almost always API-user
  permissions / multi-domain scoping, not a fetch bug.

---

## How to extend

1. **New resource** — add a collector in `tufin_runner.py` (`(client, scan) →
   (columns, rows)`, using `_fetch_list` for pagination and `_map_devices` for
   parallelism), register it in `_COLLECTORS`, and add a `TUFxxx` entry +
   feed in `config/tufin_registry.yaml`. It automatically flows into save,
   fetch-all, export, and (if host-keyed) the unified views.
2. **New change signal** — extend `_collect_change_detail`'s emit and the
   `tufin_changes` columns (+ migration).
3. **Reconciliation tuning** — matching lives in `reconcile.py`
   (`match_change`); add a device name-map or service-name normalization there.
