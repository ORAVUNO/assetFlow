"""Tests for the ManageEngine AssetExplorer adapter, registry, and normalization.

No live AssetExplorer is contacted: a FakeClient answers ``list`` / ``get`` from
canned rules, mirroring how the real v3 REST client behaves. The client's own
envelope handling and list pagination are exercised directly against a stubbed
``get``.
"""

from pathlib import Path

import pytest

from assetflow import adapters as adapters_mod
from assetflow import assetexplorer_client as ae_client_mod
from assetflow import assetexplorer_runner as ae_runner_mod
from assetflow.models import Query, Status
from assetflow.registry import load_registry

AE_REGISTRY = Path(__file__).resolve().parent.parent / "config" / "assetexplorer_registry.yaml"


class FakeClient:
    """Answer ``list(path, key)`` and ``get(path)`` from canned rules.

    ``list_rules`` maps an exact endpoint path to its record list; a path with no
    rule raises (so the CMDB collector's best-effort per-CI-type skipping is
    exercised). ``get_rules`` maps a path substring to a full response payload.
    """

    def __init__(self, list_rules=None, get_rules=None, host="ae.test",
                 portal="itdesk", api_key=""):
        self.list_rules = list_rules or {}
        self.get_rules = get_rules or {}
        self.host = host
        self.portal = portal
        self.api_key = api_key

    def list(self, path, resource_key, **kw):
        if path not in self.list_rules:
            raise RuntimeError(f"no list rule for {path}")
        return list(self.list_rules[path])

    def get(self, path, input_data=None):
        for needle, resp in self.get_rules.items():
            if needle in path:
                return resp
        raise RuntimeError(f"no get rule for {path}")


@pytest.fixture(autouse=True)
def _no_ambient_udf_labels(monkeypatch):
    """Keep tests hermetic: the repo ships config/assetexplorer_udf_labels.json,
    which the runner auto-loads. Default it off (the disable token) so tests that
    assert on raw custom.udf_* columns aren't affected; label tests override this.
    """
    monkeypatch.setenv("AE_UDF_LABELS", "none")


def _q(resource: str, qid: str = "AE999", category: str = "Asset Inventory") -> Query:
    return Query(
        id=qid, category=category, name="test",
        status=Status.partially_validated, purpose="test", resource=resource,
    )


# --------------------------------------------------------------------------- #
# Sample assets (v3 JSON shape) — an access point, a server, a router
# --------------------------------------------------------------------------- #

ACCESS_POINT = {
    "id": "1", "name": "PLM-7FL-AP01.vodacomtz.corp", "ip_address": "10.12.80.129",
    "state": {"name": "In Use"}, "asset_tag": "AT-1", "type": {"name": "Asset"},
    "product": {"name": "AIR-AP3802I-E-K9",
                "product_type": {"name": "Access Points"}},
    "vendor": {"name": "Jackson Shao, Vodacom"}, "department": {"name": "IT"},
    "site": {"name": "Vodacom Tower Paloma"}, "serial_number": "FCW2117JJZ3",
    "acquisition_date": {"value": "1513890000000", "display_value": "Dec 21, 2017"},
    "udf_fields": {"udf_char5": "Internal Only", "udf_char3": "BC"},
}
SERVER = {
    "id": "2", "name": "srv01", "ip_address": "10.0.0.5",
    "product": {"name": "PowerEdge", "product_type": {"name": "Servers"}},
    "operating_system": {"name": "Linux"},
    "udf_fields": {"udf_char5": "Confidential"},
}
ROUTER = {
    "id": "3", "name": "rtr01", "ip_address": "10.0.0.1",
    # product_type given directly on the asset (the other supported shape)
    "product_type": {"name": "Routers"}, "vendor": {"name": "Cisco"},
}

ALL_ASSETS = [ACCESS_POINT, SERVER, ROUTER]


def _assets_client():
    return FakeClient(list_rules={"assets": ALL_ASSETS})


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

def test_registry_loads_and_validates():
    reg = load_registry(str(AE_REGISTRY))
    assert reg.metadata.version == 1
    resources = {q.resource for q in reg.queries}
    assert {
        "assets", "servers", "workstations", "virtual_machines", "clusters",
        "routers", "switches", "firewalls", "access_points", "printers",
        "storage_devices", "ups", "network_devices", "mobile_devices",
        "cmdb", "contracts", "purchases", "asset_types", "products",
    } <= resources


def test_every_feed_references_known_queries():
    reg = load_registry(str(AE_REGISTRY))
    ids = {q.id for q in reg.queries}
    for feed in reg.feeds:
        for qid in feed.query_ids:
            assert qid in ids


def test_registry_resources_all_have_collectors():
    """Every resource named in the registry must have a runner collector."""
    reg = load_registry(str(AE_REGISTRY))
    for q in reg.queries:
        assert q.resource in ae_runner_mod._COLLECTORS, q.resource


# --------------------------------------------------------------------------- #
# Assets — flattening, asset.type = product type, custom.udf_*, dates
# --------------------------------------------------------------------------- #

def test_assets_flatten_named_and_custom():
    result = ae_runner_mod.run_query(_assets_client(), _q("assets"))
    cols = result.column_names
    assert cols[0] == "host.name"
    assert cols[1] == "asset.type"
    # Every UDF becomes a custom.* column.
    assert "custom.udf_char5" in cols
    assert "custom.udf_char3" in cols

    rows = {r[0]: r for r in result.rows}
    ap = rows["PLM-7FL-AP01.vodacomtz.corp"]
    d = dict(zip(cols, ap))
    assert d["asset.type"] == "Access Points"           # product type buckets it
    assert d["host.ip"] == "10.12.80.129"
    assert d["asset.state"] == "In Use"
    assert d["serial.number"] == "FCW2117JJZ3"
    assert d["vendor"] == "Jackson Shao, Vodacom"
    assert d["department"] == "IT"
    assert d["custom.udf_char5"] == "Internal Only"     # custom field carried
    assert d["acquisition.date"] == "Dec 21, 2017"      # display_value preferred


def test_assets_product_type_from_nested_or_direct():
    result = ae_runner_mod.run_query(_assets_client(), _q("assets"))
    cols = result.column_names
    rows = {r[0]: dict(zip(cols, r)) for r in result.rows}
    assert rows["srv01"]["asset.type"] == "Servers"     # nested under product
    assert rows["rtr01"]["asset.type"] == "Routers"     # direct on the asset


def test_ip_from_ip_addresses_and_network_adapters():
    """On-prem shapes: the list endpoint returns `ip_addresses` (comma string);
    the per-asset shape nests IP/MAC under `network_adapters`."""
    listing = {"name": "a1", "product_type": {"name": "Servers"},
               "ip_addresses": "10.0.0.5, 10.0.0.6"}
    nested = {"name": "a2", "product_type": {"name": "Routers"},
              "network_adapters": [{"ip_address": "10.0.0.9",
                                    "mac_address": "28-c7-ce-88-4b-c1"}]}
    result = ae_runner_mod.run_query(
        FakeClient(list_rules={"assets": [listing, nested]}), _q("assets"))
    rows = {r[0]: dict(zip(result.column_names, r)) for r in result.rows}
    assert rows["a1"]["host.ip"] == "10.0.0.5, 10.0.0.6"
    assert rows["a2"]["host.ip"] == "10.0.0.9"
    assert rows["a2"]["mac"] == "28-c7-ce-88-4b-c1"


def test_udf_pick_field_swept_to_custom():
    """A pick-list UDF (e.g. udf_pick_8919 "Network type") rides along as custom.*."""
    asset = {"name": "a", "product_type": {"name": "Routers"},
             "udf_fields": {"udf_pick_8919": "CDN"}}
    result = ae_runner_mod.run_query(
        FakeClient(list_rules={"assets": [asset]}), _q("assets"))
    d = dict(zip(result.column_names, result.rows[0]))
    assert d["custom.udf_pick_8919"] == "CDN"


def test_udf_labels_rename_columns(monkeypatch):
    """AE_UDF_LABELS renames custom.udf_* columns to friendly labels."""
    monkeypatch.setenv("AE_UDF_LABELS",
                       '{"udf_pick_8909": "BCM Rating", "udf_pick_8919": "Network type"}')
    monkeypatch.setenv("AE_INCLUDE_DISPOSED", "false")
    asset = {"name": "a", "product_type": {"name": "Routers"},
             "udf_fields": {"udf_pick_8909": "BC", "udf_pick_8919": "CDN",
                            "udf_sline_9999": "raw"}}
    result = ae_runner_mod.run_query(
        FakeClient(list_rules={"assets": [asset]}), _q("assets"))
    cols = result.column_names
    assert "BCM Rating" in cols and "Network type" in cols
    assert "custom.udf_pick_8909" not in cols
    assert "custom.udf_sline_9999" in cols          # unlabeled UDF keeps custom.*
    d = dict(zip(cols, result.rows[0]))
    assert d["BCM Rating"] == "BC"
    assert d["Network type"] == "CDN"


def test_udf_labels_autoload_from_file(monkeypatch, tmp_path):
    """With no AE_UDF_LABELS env, a labels file on the conventional path is loaded."""
    monkeypatch.delenv("AE_UDF_LABELS", raising=False)
    monkeypatch.setenv("AE_INCLUDE_DISPOSED", "false")
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "assetexplorer_udf_labels.json").write_text(
        '{"udf_pick_8909": "BCM Rating"}', encoding="utf-8")
    asset = {"name": "a", "product_type": {"name": "Routers"},
             "udf_fields": {"udf_pick_8909": "BC"}}
    result = ae_runner_mod.run_query(
        FakeClient(list_rules={"assets": [asset]}), _q("assets"))
    assert "BCM Rating" in result.column_names
    assert "custom.udf_pick_8909" not in result.column_names


def test_example_udf_label_map_is_complete():
    """The shipped example map covers all 34 asset UDF slots (CHAR1-24, DATE1-10)."""
    import json as _json
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent / "config" / "assetexplorer_udf_labels.example.json"
    data = _json.loads(p.read_text())
    labels = {k: v for k, v in data.items() if not k.startswith("_")}
    assert len(labels) == 34
    # the two value-confirmed anchors
    assert labels["udf_date_8945"] == "Created date"
    assert labels["udf_date_8949"] == "Updated at"


def test_unresolvable_labels_path_falls_back_to_autoload(monkeypatch, tmp_path):
    """A set-but-broken AE_UDF_LABELS @path doesn't block the auto-load file."""
    monkeypatch.setenv("AE_INCLUDE_DISPOSED", "false")
    monkeypatch.setenv("AE_UDF_LABELS", "@/does/not/exist.json")  # unresolvable
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "assetexplorer_udf_labels.json").write_text(
        '{"udf_pick_8909": "BCM Rating"}', encoding="utf-8")
    asset = {"name": "a", "product_type": {"name": "Routers"},
             "udf_fields": {"udf_pick_8909": "BC"}}
    result = ae_runner_mod.run_query(
        FakeClient(list_rules={"assets": [asset]}), _q("assets"))
    assert "BCM Rating" in result.column_names   # fell through to the file


def test_label_cache_not_stuck_empty(monkeypatch, tmp_path):
    """An empty label result isn't cached, so a labels file added after the first
    fetch is picked up on the next one without reconnecting."""
    monkeypatch.setenv("AE_INCLUDE_DISPOSED", "false")
    monkeypatch.setenv("AE_UDF_LABELS", "none")   # disabled on first fetch
    monkeypatch.chdir(tmp_path)
    client = FakeClient(list_rules={"assets": [
        {"name": "a", "product_type": {"name": "Routers"},
         "udf_fields": {"udf_pick_8909": "BC"}}]})
    r1 = ae_runner_mod.run_query(client, _q("assets"))
    assert "custom.udf_pick_8909" in r1.column_names   # no labels yet

    # Now enable labels; the same client must pick them up (nothing cached).
    monkeypatch.setenv("AE_UDF_LABELS", '{"udf_pick_8909": "BCM Rating"}')
    r2 = ae_runner_mod.run_query(client, _q("assets"))
    assert "BCM Rating" in r2.column_names


def test_serial_from_org_serial_number(monkeypatch):
    monkeypatch.setenv("AE_INCLUDE_DISPOSED", "false")
    asset = {"name": "a", "product_type": {"name": "Access Points"},
             "org_serial_number": "FCW2117JJZ3"}
    result = ae_runner_mod.run_query(
        FakeClient(list_rules={"assets": [asset]}), _q("assets"))
    d = dict(zip(result.column_names, result.rows[0]))
    assert d["serial.number"] == "FCW2117JJZ3"
    assert "custom.org_serial_number" not in result.column_names


class _StateFilterClient:
    """Returns disposed assets only when a state search_criteria is applied —
    mirroring how the list endpoint hides disposed assets by default."""
    host, portal, api_key = "h", "", "k"

    def get(self, path, input_data=None):
        raise RuntimeError("no metadata")

    def list(self, path, resource_key, *, list_info=None, **kw):
        info = list_info or {}
        sc = info.get("search_criteria")
        if sc:
            if sc.get("value") == "Disposed":
                return [{"id": "D1", "name": "disp1", "state": {"name": "Disposed"},
                         "product_type": {"name": "Workstations"}}]
            return []  # Expired / Retired: none
        return [{"id": "A1", "name": "act1", "state": {"name": "Active"},
                 "product_type": {"name": "Servers"}}]


def test_include_disposed_merges(monkeypatch):
    monkeypatch.delenv("AE_INCLUDE_DISPOSED", raising=False)  # default = on
    result = ae_runner_mod.run_query(_StateFilterClient(), _q("assets"))
    names = {r[0] for r in result.rows}
    assert names == {"act1", "disp1"}                # disposed merged in


def test_exclude_disposed_when_disabled(monkeypatch):
    monkeypatch.setenv("AE_INCLUDE_DISPOSED", "false")
    result = ae_runner_mod.run_query(_StateFilterClient(), _q("assets"))
    assert {r[0] for r in result.rows} == {"act1"}


class _PickyFieldsClient:
    """Rejects any request that carries a fields_required projection, so the
    runner's retry-without-projection fallback is exercised."""
    host, portal, api_key = "h", "", "k"

    def get(self, path, input_data=None):
        raise RuntimeError("no metadata")

    def list(self, path, resource_key, *, list_info=None, **kw):
        if list_info and "fields_required" in list_info:
            raise RuntimeError("unknown field in fields_required")
        return [{"id": "1", "name": "x", "product_type": {"name": "Servers"}}]


def test_fields_projection_fallback(monkeypatch):
    monkeypatch.setenv("AE_INCLUDE_DISPOSED", "false")
    result = ae_runner_mod.run_query(_PickyFieldsClient(), _q("assets"))
    assert {r[0] for r in result.rows} == {"x"}       # still returns data


class _CountingClient:
    """Counts how many times the assets list endpoint is scanned."""
    host, portal, api_key = "h", "", "k"

    def __init__(self, assets):
        self._assets = assets
        self.assets_calls = 0

    def get(self, path, input_data=None):
        raise RuntimeError("no metadata")

    def list(self, path, resource_key, *, list_info=None, **kw):
        if path == "assets":
            self.assets_calls += 1
        return list(self._assets)


def test_asset_fetch_cached_across_resources(monkeypatch):
    """A fetch-all runs assets + every bucket; the estate must be scanned once,
    not re-scanned per resource (the cache prevents the timeout storm)."""
    monkeypatch.setenv("AE_INCLUDE_DISPOSED", "false")
    monkeypatch.setenv("AE_ASSET_CACHE_TTL", "120")
    client = _CountingClient([
        {"id": "1", "name": "s1", "product_type": {"name": "Servers"}},
        {"id": "2", "name": "r1", "product_type": {"name": "Routers"}},
    ])
    for res in ("assets", "servers", "routers", "switches", "workstations"):
        ae_runner_mod.run_query(client, _q(res, category="Network Devices"))
    assert client.assets_calls == 1          # scanned once, reused from cache


def test_asset_cache_disabled(monkeypatch):
    monkeypatch.setenv("AE_INCLUDE_DISPOSED", "false")
    monkeypatch.setenv("AE_ASSET_CACHE_TTL", "0")
    client = _CountingClient([{"id": "1", "name": "s1",
                               "product_type": {"name": "Servers"}}])
    ae_runner_mod.run_query(client, _q("assets"))
    ae_runner_mod.run_query(client, _q("servers", category="Servers & Compute"))
    assert client.assets_calls == 2          # no cache -> scanned each time


def test_disposed_early_abort_when_filter_ignored(monkeypatch):
    """If a state filter is ignored (echoes the live set), disposed merging stops
    after the first extra scan instead of re-scanning for every state."""
    monkeypatch.delenv("AE_INCLUDE_DISPOSED", raising=False)  # default on
    monkeypatch.setenv("AE_ASSET_CACHE_TTL", "0")
    client = _CountingClient([{"id": "1", "name": "s1",
                               "product_type": {"name": "Servers"}}])
    result = ae_runner_mod.run_query(client, _q("assets"))
    # 1 base scan + 1 disposed scan (adds nothing new -> abort), not 1 + 3.
    assert client.assets_calls == 2
    assert {r[0] for r in result.rows} == {"s1"}   # no duplicates from the echo


class _AbsentEndpointClient:
    host, portal, api_key = "h", "", "k"

    def get(self, path, input_data=None):
        raise RuntimeError("no metadata")

    def list(self, path, resource_key, *, list_info=None, **kw):
        raise RuntimeError("HTTP 404: URL_NOT_FOUND")


def test_catalog_endpoints_are_optional():
    """The optional catalog endpoints (contracts / purchases / asset_types /
    products) return empty rows on ANY error — including edition-specific ones an
    on-prem build returns instead of a clean 404 — so they never fail a fetch-all."""
    class _ErrClient(_AbsentEndpointClient):
        def list(self, path, resource_key, *, list_info=None, **kw):
            raise RuntimeError("HTTP 400: URL_NO_MATCHING (edition-specific)")
    client = _ErrClient()
    for res, cat in [("contracts", "Contracts"), ("purchases", "Purchase"),
                     ("asset_types", "Catalog"), ("products", "Catalog")]:
        result = ae_runner_mod.run_query(client, _q(res, category=cat))
        assert result.rows == []             # empty, but did not raise


def test_epoch_millis_fallback_without_display_value():
    """A date object with only an epoch-ms value converts to ISO."""
    asset = {"name": "x", "product_type": {"name": "Servers"},
             "acquisition_date": {"value": "1513890000000"}}
    result = ae_runner_mod.run_query(
        FakeClient(list_rules={"assets": [asset]}), _q("assets"))
    d = dict(zip(result.column_names, result.rows[0]))
    assert d["acquisition.date"].startswith("2017-")


# --------------------------------------------------------------------------- #
# Per-asset-type bucketing
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("resource,expected", [
    ("servers", {"srv01"}),
    ("routers", {"rtr01"}),
    ("access_points", {"PLM-7FL-AP01.vodacomtz.corp"}),
    ("network_devices", {"rtr01", "PLM-7FL-AP01.vodacomtz.corp"}),
    ("printers", set()),
])
def test_asset_type_buckets(resource, expected):
    result = ae_runner_mod.run_query(_assets_client(), _q(resource, category="Network Devices"))
    names = {r[0] for r in result.rows}
    assert names == expected


# --------------------------------------------------------------------------- #
# CMDB — merges CI types, stamps asset.type, skips missing types
# --------------------------------------------------------------------------- #

def test_cmdb_merges_ci_types_and_stamps_type(monkeypatch):
    monkeypatch.setenv("AE_CMDB_CI_TYPES", "server,router")
    ci_server = {"name": "ci-srv01", "ip_address": "10.0.0.5",
                 "state": {"name": "Managed"}, "udf_fields": {"udf_char1": "x"}}
    ci_router = {"name": "ci-rtr01", "ip_address": "10.0.0.1"}
    client = FakeClient(list_rules={"cmdb/server": [ci_server], "cmdb/router": [ci_router]})
    result = ae_runner_mod.run_query(client, _q("cmdb", category="CMDB"))
    cols = result.column_names
    rows = {r[0]: dict(zip(cols, r)) for r in result.rows}
    assert set(rows) == {"ci-srv01", "ci-rtr01"}
    assert rows["ci-srv01"]["asset.type"] == "server"   # stamped from CI type
    assert rows["ci-srv01"]["ci.type"] == "server"
    assert rows["ci-rtr01"]["asset.type"] == "router"
    assert "custom.udf_char1" in cols


def test_cmdb_skips_ci_types_without_data(monkeypatch):
    monkeypatch.setenv("AE_CMDB_CI_TYPES", "server,router,firewall")
    # Only "server" has a rule; router/firewall raise and are skipped.
    client = FakeClient(list_rules={"cmdb/server": [{"name": "ci-srv01"}]})
    result = ae_runner_mod.run_query(client, _q("cmdb", category="CMDB"))
    assert {r[0] for r in result.rows} == {"ci-srv01"}


# --------------------------------------------------------------------------- #
# Contracts / Purchases / catalog
# --------------------------------------------------------------------------- #

def test_contracts_collect():
    contract = {"name": "Cisco Smartnet", "type": {"name": "Maintenance"},
                "status": "Active", "vendor": {"name": "Cisco"}, "cost": "1200.00",
                "expiry_date": {"display_value": "Dec 31, 2026"}}
    client = FakeClient(list_rules={"contracts": [contract]})
    result = ae_runner_mod.run_query(client, _q("contracts", category="Contracts"))
    d = dict(zip(result.column_names, result.rows[0]))
    assert d["host.name"] == "Cisco Smartnet"
    assert d["asset.type"] == "Contract"
    assert d["contract.type"] == "Maintenance"
    assert d["vendor"] == "Cisco"
    assert d["end.date"] == "Dec 31, 2026"


def test_purchases_collect():
    po = {"name": "PO-1001", "po_number": "1001", "status": "Approved",
          "vendor": {"name": "Dell"}, "total_cost": "5000.00"}
    client = FakeClient(list_rules={"purchase_orders": [po]})
    result = ae_runner_mod.run_query(client, _q("purchases", category="Purchase"))
    d = dict(zip(result.column_names, result.rows[0]))
    assert d["asset.type"] == "Purchase Order"
    assert d["po.number"] == "1001"
    assert d["vendor"] == "Dell"


def test_asset_types_and_products_collect():
    at_client = FakeClient(list_rules={"asset_types": [
        {"name": "Access Points", "id": "9", "type": {"name": "IT"}}]})
    r1 = ae_runner_mod.run_query(at_client, _q("asset_types", category="Catalog"))
    d1 = dict(zip(r1.column_names, r1.rows[0]))
    assert d1["asset.type"] == "Access Points"
    assert d1["category"] == "IT"

    p_client = FakeClient(list_rules={"products": [
        {"name": "AIR-AP3802I-E-K9", "product_type": {"name": "Access Points"},
         "manufacturer": {"name": "Cisco"}}]})
    r2 = ae_runner_mod.run_query(p_client, _q("products", category="Catalog"))
    d2 = dict(zip(r2.column_names, r2.rows[0]))
    assert d2["product"] == "AIR-AP3802I-E-K9"
    assert d2["product.type"] == "Access Points"
    assert d2["manufacturer"] == "Cisco"


def test_unknown_resource_raises():
    with pytest.raises(ValueError):
        ae_runner_mod.run_query(_assets_client(), _q("nope"))


# --------------------------------------------------------------------------- #
# Client — envelope, list extraction, pagination, config
# --------------------------------------------------------------------------- #

def _client(**kw):
    kw.setdefault("host", "ae.test")
    kw.setdefault("api_key", "tech-key")  # on-prem key so no OAuth round-trip
    return ae_client_mod.build_client(**kw)


def test_check_status_raises_on_error_envelope():
    c = _client()
    with pytest.raises(RuntimeError, match="boom"):
        c._check_status({"response_status": {"status_code": 4000,
                                             "messages": [{"message": "boom"}]}})
    # Success envelope passes through unchanged.
    ok = {"response_status": {"status_code": 2000}, "assets": []}
    assert c._check_status(ok) is ok


def test_check_status_accepts_list_form():
    c = _client()
    ok = {"response_status": [{"status_code": 2000}], "assets": [{"id": "1"}]}
    assert c._check_status(ok) is ok


def test_check_status_accepts_200_and_status_success():
    """Some on-prem releases signal success with status_code 200 or status=success."""
    c = _client()
    ok200 = {"response_status": {"status_code": 200}, "assets": []}
    assert c._check_status(ok200) is ok200
    ok_str = {"response_status": {"status": "success"}, "assets": []}
    assert c._check_status(ok_str) is ok_str


def test_extract_list_by_key_and_fallback():
    c = _client()
    assert c._extract_list({"assets": [{"id": "1"}]}, "assets") == [{"id": "1"}]
    # CMDB keys the list by the CI type name; fall back to the first list value.
    payload = {"response_status": {"status_code": 2000},
               "list_info": {"has_more_rows": False}, "server": [{"id": "9"}]}
    assert c._extract_list(payload, "ci") == [{"id": "9"}]


def test_list_paginates_until_no_more_rows(monkeypatch):
    c = _client()
    pages = [
        {"response_status": {"status_code": 2000},
         "list_info": {"has_more_rows": True}, "assets": [{"id": str(i)} for i in range(100)]},
        {"response_status": {"status_code": 2000},
         "list_info": {"has_more_rows": False}, "assets": [{"id": "100"}]},
    ]
    calls = {"n": 0}

    def fake_get(path, input_data=None):
        i = calls["n"]
        calls["n"] += 1
        return pages[i]

    monkeypatch.setattr(c, "get", fake_get)
    records = c.list("assets", "assets")
    assert len(records) == 101
    assert calls["n"] == 2


def test_url_for_cloud_and_onprem():
    cloud = _client(portal="itdesk")
    assert cloud.url_for("assets") == "https://ae.test/app/itdesk/api/v3/assets"
    onprem = _client(portal="")
    assert onprem.url_for("assets") == "https://ae.test/api/v3/assets"


def test_url_for_onprem_http_and_custom_port():
    """On-prem often runs plain HTTP on a custom port — the scheme/port is honored."""
    c = _client(host="http://assetexplorer.corp:8080", portal="")
    assert c.scheme == "http"
    assert c.host == "assetexplorer.corp:8080"
    assert c.url_for("assets") == "http://assetexplorer.corp:8080/api/v3/assets"
    # https default and a custom port together.
    c2 = _client(host="assetexplorer.corp:8443", portal="")
    assert c2.url_for("cmdb/server") == "https://assetexplorer.corp:8443/api/v3/cmdb/server"


def test_env_for_form_preserves_http_scheme():
    mgr = adapters_mod.AdapterManager(adapters_mod.available_kinds())
    a = mgr.add_instance("assetexplorer", "AE onprem")
    env = a.env_for_form({"host": "http://assetexplorer.corp:8080",
                          "api_key": "k", "verify_certs": False})
    assert env["AE_HOST"] == "http://assetexplorer.corp:8080"
    assert env["AE_VERIFY_CERTS"] == "false"


def test_build_client_requires_credentials():
    with pytest.raises(ae_client_mod.AssetExplorerConfigError):
        ae_client_mod.build_client(host="ae.test")  # no token / key


def test_build_client_requires_host():
    with pytest.raises(ae_client_mod.AssetExplorerConfigError):
        ae_client_mod.build_client(host="", api_key="k")


def test_build_client_from_env_needs_creds(monkeypatch):
    for var in ("AE_HOST", "AE_ACCESS_TOKEN", "AE_REFRESH_TOKEN", "AE_API_KEY",
                "AE_CLIENT_ID", "AE_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ae_client_mod.AssetExplorerConfigError):
        ae_client_mod.build_client_from_env()


# --------------------------------------------------------------------------- #
# Adapter wiring
# --------------------------------------------------------------------------- #

def test_kind_registered():
    kinds = adapters_mod.available_kinds()
    assert "assetexplorer" in kinds
    kind = kinds["assetexplorer"]
    assert kind.adapter_cls is adapters_mod.AssetExplorerAdapter
    assert "CMDB" in kind.category or "Asset" in kind.category


def test_connect_form_maps_password_to_access_token(monkeypatch):
    """The shared form's password field is used as an OAuth access token when no
    client id/secret are given; connect() then pings, so stub the client build."""
    captured = {}

    def fake_build_client(**kw):
        captured.update(kw)
        return object()

    def fake_ping(client):
        return {"summary": "ok"}

    monkeypatch.setattr(ae_client_mod, "build_client", fake_build_client)
    monkeypatch.setattr(ae_client_mod, "ping", fake_ping)

    mgr = adapters_mod.AdapterManager(adapters_mod.available_kinds())
    a = mgr.add_instance("assetexplorer", "AE test")
    a.connect_form({"host": "ae.test", "portal": "itdesk", "password": "AT-123"})
    assert captured["access_token"] == "AT-123"
    assert captured["refresh_token"] == ""
    assert captured["portal"] == "itdesk"


def test_connect_form_maps_password_to_refresh_token(monkeypatch):
    captured = {}
    monkeypatch.setattr(ae_client_mod, "build_client",
                        lambda **kw: captured.update(kw) or object())
    monkeypatch.setattr(ae_client_mod, "ping", lambda c: {"summary": "ok"})
    mgr = adapters_mod.AdapterManager(adapters_mod.available_kinds())
    a = mgr.add_instance("assetexplorer", "AE test")
    a.connect_form({"host": "ae.test", "portal": "itdesk", "password": "RT-123",
                    "client_id": "cid", "client_secret": "csec"})
    assert captured["refresh_token"] == "RT-123"
    assert captured["access_token"] == ""
    assert captured["client_id"] == "cid"


def test_env_for_form_persists_credentials():
    mgr = adapters_mod.AdapterManager(adapters_mod.available_kinds())
    a = mgr.add_instance("assetexplorer", "AE test")
    env = a.env_for_form({"host": "https://ae.test/app/x", "portal": "itdesk",
                          "api_key": "tech-key", "verify_certs": True})
    assert env["AE_HOST"] == "ae.test"
    assert env["AE_PORTAL"] == "itdesk"
    assert env["AE_API_KEY"] == "tech-key"
    assert env["AE_VERIFY_CERTS"] == "true"
