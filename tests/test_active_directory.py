"""Tests for the Active Directory adapter, registry, and LDAP normalization.

No live directory is contacted and ldap3 is not required: a FakeClient returns
canned :class:`Entry` records keyed by (base, filter), mirroring how the real
client's ``search`` behaves. Binary attributes (objectSid, objectGUID,
userCertificate, dnsRecord) are supplied as bytes under each entry's ``raw`` map,
exactly as the real client hands them over.
"""

import struct
from pathlib import Path

import pytest

from assetflow import active_directory_client as ad_client_mod
from assetflow import active_directory_runner as ad_runner_mod
from assetflow import adapters as adapters_mod
from assetflow.active_directory_client import Entry
from assetflow.models import Query, Status
from assetflow.registry import load_registry

AD_REGISTRY = Path(__file__).resolve().parent.parent / "config" / "active_directory_registry.yaml"


# --------------------------------------------------------------------------- #
# Fake client
# --------------------------------------------------------------------------- #

class FakeClient:
    """Returns canned entries; matches searches by a substring of the filter.

    ``responses`` maps a filter-substring -> list[Entry]. The first substring
    found in the search filter wins, so tests can key on the object class.
    """

    def __init__(self, responses=None, base_dn="DC=corp,DC=local",
                 config_nc="CN=Configuration,DC=corp,DC=local", dns_partitions=None,
                 root=None):
        self.responses = responses or {}
        self.base_dn = base_dn
        self.config_nc = config_nc
        self.dns_partitions = dns_partitions or []
        self._root = root or {}
        self.calls = []

    def root_dse(self):
        return dict(self._root)

    def search(self, base_dn, ldap_filter, attributes, scope="subtree", size_limit=0):
        self.calls.append((base_dn, ldap_filter, scope))
        for needle, entries in self.responses.items():
            if needle in ldap_filter:
                return list(entries)
        return []


def _q(resource: str) -> Query:
    return Query(
        id="AD999", category="Users", name="test",
        status=Status.partially_validated, purpose="test", resource=resource,
    )


def _sid(*subauths):
    return bytes([1, len(subauths)]) + (5).to_bytes(6, "big") + b"".join(
        struct.pack("<I", s) for s in subauths
    )


def _dns_blob(rtype, rdata, ttl=3600):
    return (struct.pack("<HH", len(rdata), rtype) + b"\x05\xf0"
            + struct.pack("<H", 0) + struct.pack("<I", 1) + struct.pack(">I", ttl)
            + b"\x00" * 8 + rdata)


def _count_name(name):
    labels = name.split(".")
    body = b"".join(bytes([len(l)]) + l.encode() for l in labels)
    total = sum(len(l) for l in labels) + len(labels)
    return bytes([total, len(labels)]) + body


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

def test_ad_registry_loads_and_validates():
    reg = load_registry(str(AD_REGISTRY))
    assert reg.metadata.version == 1
    assert len(reg.queries) == 13
    resources = {q.resource for q in reg.queries}
    assert {"users", "groups", "organizational_units", "computers", "job_titles",
            "domain", "managed_service_accounts", "certificate_templates",
            "certificate_authorities", "published_certificates",
            "dns_zones", "dns_records"} <= resources


def test_every_feed_references_known_queries():
    reg = load_registry(str(AD_REGISTRY))
    ids = {q.id for q in reg.queries}
    for feed in reg.feeds:
        for qid in feed.query_ids:
            assert qid in ids


def test_registry_resources_all_have_a_collector():
    reg = load_registry(str(AD_REGISTRY))
    for q in reg.queries:
        assert q.resource in ad_runner_mod._COLLECTORS


# --------------------------------------------------------------------------- #
# Binary / value parsers
# --------------------------------------------------------------------------- #

def test_format_sid():
    assert ad_runner_mod.format_sid(_sid(21, 111, 222, 333, 1105)) == \
        "S-1-5-21-111-222-333-1105"
    assert ad_runner_mod.format_sid(b"") == ""


def test_format_guid():
    guid = ad_runner_mod.format_guid(bytes(range(16)))
    assert len(guid) == 36 and guid.count("-") == 4


def test_account_enabled_from_uac():
    assert ad_runner_mod.account_enabled("512") is True     # normal account
    assert ad_runner_mod.account_enabled("514") is False    # + ACCOUNTDISABLE
    assert ad_runner_mod.account_enabled("") is None


def test_group_type_labels():
    security_global = str(0x80000002 - 2 ** 32)  # signed groupType
    assert ad_runner_mod.group_type_labels(security_global) == ("Global", "Security")
    assert ad_runner_mod.group_type_labels(str(0x00000008)) == ("Universal", "Distribution")


def test_filetime_and_gentime():
    assert ad_runner_mod.filetime_to_iso("0") == ""                # never
    assert ad_runner_mod.filetime_to_iso(str(0x7FFFFFFFFFFFFFFF)) == ""
    assert ad_runner_mod.filetime_to_iso("133200000000000000").startswith("20")
    assert ad_runner_mod.gentime_to_iso("20230115080000.0Z") == "2023-01-15 08:00:00"


def test_parse_dns_record_types():
    assert ad_runner_mod.parse_dns_record(_dns_blob(1, bytes([10, 0, 0, 5]))) == \
        ("A", "10.0.0.5", "3600")
    aaaa = ad_runner_mod.parse_dns_record(_dns_blob(28, bytes(range(16))))
    assert aaaa[0] == "AAAA" and aaaa[1].count(":") == 7
    cname = ad_runner_mod.parse_dns_record(_dns_blob(5, _count_name("web.corp.local")))
    assert cname[0] == "CNAME" and cname[1] == "web.corp.local"
    mx = ad_runner_mod.parse_dns_record(
        _dns_blob(15, struct.pack(">H", 10) + _count_name("mail.corp.local"))
    )
    assert mx[0] == "MX" and mx[1] == "10 mail.corp.local"


# --------------------------------------------------------------------------- #
# Collectors
# --------------------------------------------------------------------------- #

def test_users_identity_columns_and_decoding():
    client = FakeClient({
        "objectClass=user": [
            Entry(
                dn="CN=Bob,OU=Staff,DC=corp,DC=local",
                attributes={
                    "sAMAccountName": "bob", "userPrincipalName": "bob@corp.local",
                    "mail": "bob@corp.local", "title": "Engineer",
                    "department": "IT", "manager": "CN=Alice,OU=Staff,DC=corp,DC=local",
                    "userAccountControl": "512", "whenCreated": "20230115080000.0Z",
                },
                raw={"objectSid": [_sid(21, 5, 5, 5, 1105)]},
            ),
        ]
    })
    result = ad_runner_mod.run_query(client, _q("users"))
    cols = result.column_names
    assert cols[:3] == ["user.name", "user.principal_name", "user.email"]
    row = result.rows[0]
    assert row[cols.index("user.sid")] == "S-1-5-21-5-5-5-1105"
    assert row[cols.index("enabled")] == "true"
    assert row[cols.index("manager")] == "Alice"          # CN pulled from DN
    assert row[cols.index("when_created")] == "2023-01-15 08:00:00"


def test_groups_scope_category_and_member_count():
    client = FakeClient({
        "objectClass=group": [
            Entry(
                dn="CN=Admins,DC=corp,DC=local",
                attributes={
                    "sAMAccountName": "Admins",
                    "groupType": str(0x80000004 - 2 ** 32),   # domain-local security
                    "description": "admins",
                    "member": ["CN=Bob,DC=corp,DC=local", "CN=Alice,DC=corp,DC=local"],
                },
                raw={"objectSid": [_sid(21, 5, 5, 5, 512)]},
            ),
        ]
    })
    result = ad_runner_mod.run_query(client, _q("groups"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("group.scope")] == "Domain Local"
    assert row[cols.index("group.category")] == "Security"
    assert row[cols.index("member.count")] == "2"


def test_group_members_expands_edges():
    client = FakeClient({
        "objectClass=group": [
            Entry(dn="CN=Admins,DC=corp,DC=local",
                  attributes={"sAMAccountName": "Admins",
                              "member": ["CN=Bob,DC=corp,DC=local",
                                         "CN=Alice,OU=Staff,DC=corp,DC=local"]}),
        ]
    })
    result = ad_runner_mod.run_query(client, _q("group_members"))
    cols = result.column_names
    assert len(result.rows) == 2
    names = {r[cols.index("member.name")] for r in result.rows}
    assert names == {"Bob", "Alice"}
    assert all(r[cols.index("group.name")] == "Admins" for r in result.rows)


def test_computers_fold_into_devices():
    client = FakeClient({
        "objectClass=computer": [
            Entry(
                dn="CN=WEB01,OU=Servers,DC=corp,DC=local",
                attributes={
                    "dNSHostName": "web01.corp.local", "name": "WEB01",
                    "operatingSystem": "Windows Server 2022",
                    "operatingSystemVersion": "10.0 (20348)",
                    "userAccountControl": "4096",
                },
                raw={"objectGUID": [bytes(range(16))]},
            ),
        ]
    })
    result = ad_runner_mod.run_query(client, _q("computers"))
    cols = result.column_names
    assert cols[0] == "host.name"       # Devices-inventory key
    row = result.rows[0]
    assert row[cols.index("host.name")] == "web01.corp.local"
    assert row[cols.index("os.name")] == "Windows Server 2022"
    assert row[cols.index("host.id")]  # decoded GUID present


def test_job_titles_aggregate_counts():
    client = FakeClient({
        "title=*": [
            Entry(attributes={"title": "Engineer"}),
            Entry(attributes={"title": "Engineer"}),
            Entry(attributes={"title": "Manager"}),
        ]
    })
    result = ad_runner_mod.run_query(client, _q("job_titles"))
    cols = result.column_names
    rows = {r[cols.index("title")]: r[cols.index("user.count")] for r in result.rows}
    assert rows["Engineer"] == "2" and rows["Manager"] == "1"
    # Sorted by count desc: Engineer first.
    assert result.rows[0][cols.index("title")] == "Engineer"


def test_domain_derives_dns_name_and_levels():
    client = FakeClient(
        {"objectClass=domainDNS": [
            Entry(dn="DC=corp,DC=local",
                  attributes={"whenCreated": "20200101000000.0Z"},
                  raw={"objectSid": [_sid(21, 9, 9, 9)]})
        ]},
        root={"domainFunctionality": "7", "forestFunctionality": "7",
              "rootDomainNamingContext": "DC=corp,DC=local"},
    )
    result = ad_runner_mod.run_query(client, _q("domain"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("domain.name")] == "corp.local"
    assert row[cols.index("domain.functional_level")] == "7"


def test_managed_service_accounts_typed():
    client = FakeClient({
        "ManagedServiceAccount": [
            Entry(dn="CN=svc01,CN=Managed Service Accounts,DC=corp,DC=local",
                  attributes={"sAMAccountName": "svc01$",
                              "objectClass": ["top", "msDS-GroupManagedServiceAccount"],
                              "dNSHostName": "svc01.corp.local",
                              "userAccountControl": "4096"}),
        ]
    })
    result = ad_runner_mod.run_query(client, _q("managed_service_accounts"))
    cols = result.column_names
    assert result.rows[0][cols.index("msa.type")] == "gMSA"


def test_certificate_templates_flag_server_auth():
    client = FakeClient({
        "pKICertificateTemplate": [
            Entry(dn="CN=WebServer,CN=Certificate Templates,...",
                  attributes={"cn": "WebServer", "displayName": "Web Server",
                              "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.1"]}),
            Entry(dn="CN=User,CN=Certificate Templates,...",
                  attributes={"cn": "User", "displayName": "User",
                              "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2",
                                                      "1.3.6.1.4.1.311.20.2.2"]}),
        ]
    })
    result = ad_runner_mod.run_query(client, _q("certificate_templates"))
    cols = result.column_names
    rows = {r[cols.index("template.name")]: r for r in result.rows}
    assert rows["WebServer"][cols.index("is_server_auth")] == "true"
    assert "Server Authentication" in rows["WebServer"][cols.index("key_usage")]
    assert rows["User"][cols.index("is_server_auth")] == "false"
    assert "Smart Card Logon" in rows["User"][cols.index("key_usage")]


def test_published_certificates_thumbprint_without_cryptography():
    # A non-cert byte blob still yields a SHA-1 thumbprint (never dropped).
    client = FakeClient({
        "userCertificate=*": [
            Entry(dn="CN=Bob,DC=corp,DC=local",
                  attributes={"sAMAccountName": "bob"},
                  raw={"userCertificate": [b"not-a-real-cert", b"second-cert"]}),
        ]
    })
    result = ad_runner_mod.run_query(client, _q("published_certificates"))
    cols = result.column_names
    assert len(result.rows) == 2                       # one row per cert
    assert all(r[cols.index("owner")] == "bob" for r in result.rows)
    assert all(len(r[cols.index("thumbprint_sha1")]) == 40 for r in result.rows)


def test_dns_zones_across_partitions():
    client = FakeClient(
        {"objectClass=dnsZone": [
            Entry(dn="DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local",
                  attributes={"name": "corp.local", "whenCreated": "20200101000000.0Z"})
        ]},
        dns_partitions=["DC=DomainDnsZones,DC=corp,DC=local"],
    )
    result = ad_runner_mod.run_query(client, _q("dns_zones"))
    cols = result.column_names
    assert result.rows[0][cols.index("zone.name")] == "corp.local"
    assert result.rows[0][cols.index("dns.partition")] == "DC=DomainDnsZones,DC=corp,DC=local"


def test_dns_records_decode_and_fold_a_records():
    client = FakeClient(
        {"objectClass=dnsNode": [
            Entry(dn="DC=web01,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local",
                  attributes={"name": "web01"},
                  raw={"dnsRecord": [_dns_blob(1, bytes([10, 0, 0, 5]))]}),
            Entry(dn="DC=alias,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local",
                  attributes={"name": "alias"},
                  raw={"dnsRecord": [_dns_blob(5, _count_name("web01.corp.local"))]}),
        ]},
        dns_partitions=["DC=DomainDnsZones,DC=corp,DC=local"],
    )
    result = ad_runner_mod.run_query(client, _q("dns_records"))
    cols = result.column_names
    by_type = {r[cols.index("record.type")]: r for r in result.rows}
    # A record folds into Devices via host.name + host.ip.
    assert by_type["A"][cols.index("host.name")] == "web01.corp.local"
    assert by_type["A"][cols.index("host.ip")] == "10.0.0.5"
    assert by_type["A"][cols.index("zone")] == "corp.local"
    # CNAME carries no host.ip (not an address record).
    assert by_type["CNAME"][cols.index("record.data")] == "web01.corp.local"
    assert by_type["CNAME"][cols.index("host.ip")] == ""


def test_limit_caps_rows():
    client = FakeClient({
        "objectClass=user": [Entry(attributes={"sAMAccountName": f"u{i}"}) for i in range(5)]
    })
    result = ad_runner_mod.run_query(client, _q("users"), limit=2)
    assert len(result.rows) == 2


def test_unknown_resource_raises():
    with pytest.raises(ValueError):
        ad_runner_mod.run_query(FakeClient(), _q("nope"))


def test_blank_resource_raises():
    with pytest.raises(ValueError):
        ad_runner_mod.run_query(FakeClient(), _q(""))


# --------------------------------------------------------------------------- #
# Client construction / env
# --------------------------------------------------------------------------- #

def test_build_client_requires_host_and_creds():
    with pytest.raises(ad_client_mod.ActiveDirectoryConfigError):
        ad_client_mod.build_client(host="", username="u", password="p")
    with pytest.raises(ad_client_mod.ActiveDirectoryConfigError):
        ad_client_mod.build_client(host="dc", username="", password="")


def test_clean_host_strips_scheme_and_port():
    assert ad_client_mod.clean_host("ldaps://dc.corp.local:636") == "dc.corp.local"
    assert ad_client_mod.clean_host("  dc.corp.local  ") == "dc.corp.local"


def test_dns_partition_candidates_derives_app_partitions():
    # Even when the RootDSE advertises nothing, the DomainDnsZones /
    # ForestDnsZones app partitions are derived from the base / root-domain NCs,
    # so real zones are searched — not just the legacy RootDNSServers container.
    parts = ad_client_mod.dns_partition_candidates("DC=corp,DC=local")
    assert "DC=DomainDnsZones,DC=corp,DC=local" in parts
    assert "DC=ForestDnsZones,DC=corp,DC=local" in parts
    assert "CN=MicrosoftDNS,CN=System,DC=corp,DC=local" in parts


def test_dns_partition_candidates_uses_forest_root_and_dedupes():
    parts = ad_client_mod.dns_partition_candidates(
        "DC=child,DC=corp,DC=local",
        root_domain_nc="DC=corp,DC=local",
        advertised=["DC=DomainDnsZones,DC=child,DC=corp,DC=local", "DC=corp,DC=local"],
    )
    # Forest partition follows the forest root, not the child domain.
    assert "DC=ForestDnsZones,DC=corp,DC=local" in parts
    # Advertised app partition kept; non-DnsZones context ignored; no duplicates.
    assert parts.count("DC=DomainDnsZones,DC=child,DC=corp,DC=local") == 1
    assert "DC=corp,DC=local" not in parts


def test_default_port_follows_ssl():
    assert ad_client_mod.build_client(host="dc", username="u", password="p",
                                      use_ssl=True).port == 636
    assert ad_client_mod.build_client(host="dc", username="u", password="p",
                                      use_ssl=False).port == 389


def test_build_client_from_env(monkeypatch):
    monkeypatch.setenv("AD_HOST", "dc.corp.local")
    monkeypatch.setenv("AD_USERNAME", "svc@corp.local")
    monkeypatch.setenv("AD_PASSWORD", "secret")
    monkeypatch.setenv("AD_PORT", "389")
    monkeypatch.setenv("AD_USE_SSL", "false")
    client = ad_client_mod.build_client_from_env()
    assert client.host == "dc.corp.local" and client.port == 389 and client.use_ssl is False


def test_build_client_from_env_missing(monkeypatch):
    for var in ("AD_HOST", "AD_HOSTNAME", "ACTIVE_DIRECTORY_HOST", "LDAP_HOST",
                "AD_USERNAME", "AD_USER", "AD_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ad_client_mod.ActiveDirectoryConfigError):
        ad_client_mod.build_client_from_env()


# --------------------------------------------------------------------------- #
# Adapter wiring
# --------------------------------------------------------------------------- #

def test_ad_adapter_registered():
    manager = adapters_mod.default_manager()
    adapter = manager.get("active_directory")
    assert adapter.info.kind == "active_directory"
    assert adapter.info.category == "Identity / Directory"


def test_ad_adapter_env_for_form_infers_ssl_from_port():
    manager = adapters_mod.default_manager()
    adapter = manager.get("active_directory")
    env = adapter.env_for_form(
        {"host": "ldaps://dc.corp.local:636", "username": "svc@corp.local",
         "password": "secret", "base_dn": "DC=corp,DC=local"}
    )
    assert env["AD_HOST"] == "dc.corp.local"
    assert env["AD_USE_SSL"] == "true"
    assert env["AD_BASE_DN"] == "DC=corp,DC=local"
    env389 = adapter.env_for_form(
        {"host": "dc", "username": "u", "password": "p", "port": "389"}
    )
    assert env389["AD_USE_SSL"] == "false"


def test_ad_adapter_run_before_connect_raises():
    manager = adapters_mod.default_manager()
    adapter = manager.get("active_directory")
    q = adapter.registry.get_query("AD001")
    with pytest.raises(ad_client_mod.ActiveDirectoryConfigError):
        adapter.run(q)


def test_ad_adapter_connect_form(monkeypatch):
    manager = adapters_mod.default_manager()
    adapter = manager.get("active_directory")
    monkeypatch.setattr(ad_client_mod, "build_client", lambda **kw: object())
    monkeypatch.setattr(
        ad_client_mod, "ping",
        lambda cl: {"product": "Microsoft Active Directory", "summary": "AD @ dc"},
    )
    info = adapter.connect_form(
        {"host": "dc.corp.local", "username": "svc@corp.local", "password": "secret",
         "port": 636, "verify_certs": True, "request_timeout": 30}
    )
    assert info["product"] == "Microsoft Active Directory"
    assert adapter.connected is True
