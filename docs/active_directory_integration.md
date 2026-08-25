# Active Directory (AD DS) integration — developer guide

The **Microsoft Active Directory** adapter (category *Identity / Directory*)
fetches identity and infrastructure inventory from on-prem **AD DS over LDAP**
and folds it into the same saved-fetch, unified-inventory, and export machinery
as every other adapter. This guide is the map of how the code works and how to
extend it.

## Where it sits

It plugs into the same framework as the other adapters (see
[`docs/unified_inventory.md`](unified_inventory.md) for the cross-adapter
correlation it feeds):

| Concern | Module |
|---|---|
| LDAP connection, RootDSE discovery, `search` primitive, `ping` | `assetflow/active_directory_client.py` |
| Resource collectors + binary/value parsers + `run_query` dispatch | `assetflow/active_directory_runner.py` |
| Resource registry (feeds, queries, honest status labels) | `config/active_directory_registry.yaml` |
| Adapter class + kind registration + UI connection form | `assetflow/adapters.py`, `assetflow/webapp.py` |
| Tests (fake client, no live DC) | `tests/test_active_directory.py` |

The shape mirrors the VMware and Tufin adapters exactly: a thin client owns the
transport, the runner dispatches a registry query's `resource` name to a
collector that returns `(columns, rows)`, and everything is normalized to the
shared `QueryResult`.

## Transport & discovery

On-prem AD DS speaks **LDAP** (`ldaps://dc:636` by default, or `ldap://dc:389`).
The client binds with a read account (`user@domain` → SIMPLE bind, or
`DOMAIN\user` → NTLM) and reads the **RootDSE** to discover the directory's
naming contexts, so the collectors don't hard-code them:

- `defaultNamingContext` → the domain NC (users, groups, OUs, computers, MSAs,
  the domain object)
- `configurationNamingContext` → the forest config, home of the **PKI**
  containers (`CN=Public Key Services,CN=Services,…`) — certificate templates
  and enterprise CAs
- `namingContexts` entries containing `DnsZones` → the **AD-integrated DNS**
  application partitions (`DomainDnsZones` / `ForestDnsZones`), plus the legacy
  `CN=MicrosoftDNS,CN=System,<domain>` container

The collectors reach everything through one primitive:

```python
client.search(base_dn, ldap_filter, attributes, scope="subtree", size_limit=0)
# -> List[Entry]   where Entry = {"dn": str, "attributes": {..}, "raw": {..bytes}}
```

`attributes` holds ldap3's decoded string values; `raw` holds the **bytes** for
the binary attributes the runner decodes itself. Because the whole runner is
driven through this one method, it is unit-tested with a `FakeClient` and no
live directory — the same approach VMware uses for its REST client.

`ldap3` is an **optional** dependency: the modules import and construct without
it, and only `connect`/`ping`/`search` require it (raising an actionable error
when it is absent). Install it with `pip install ldap3` (or
`pip install -e ".[active_directory]"`).

## Resources

| ID | Resource | Feed | LDAP source |
|---|---|---|---|
| AD001 | Users (`users`) | Users | `(&(objectCategory=person)(objectClass=user))` |
| AD002 | Groups (`groups`) | Groups | `(objectClass=group)` |
| AD003 | Group Memberships (`group_members`) | Groups | `member` expanded to edges |
| AD004 | Organizational Units (`organizational_units`) | Organizational Units | `(objectClass=organizationalUnit)` |
| AD005 | Computers (`computers`) | Computers | `(objectClass=computer)` |
| AD006 | Job Titles (`job_titles`) | Job Titles | distinct `title` across users |
| AD007 | Domain (`domain`) | Accounts/Tenants | `(objectClass=domainDNS)` + RootDSE |
| AD008 | Managed Service Accounts (`managed_service_accounts`) | Managed Identities | gMSA / sMSA classes |
| AD009 | Certificate Templates (`certificate_templates`) | Certificates | `(objectClass=pKICertificateTemplate)` in the config NC |
| AD010 | Certification Authorities (`certificate_authorities`) | Certificates | `(objectClass=pKIEnrollmentService)` in the config NC |
| AD011 | Published Certificates (`published_certificates`) | Certificates | `(userCertificate=*)` |
| AD012 | DNS Zones (`dns_zones`) | DNS | `(objectClass=dnsZone)` across DNS partitions |
| AD013 | DNS Records (`dns_records`) | DNS | `(objectClass=dnsNode)`, `dnsRecord` decoded |

### How rows fold into the unified inventory

The identity/device keys come straight from `merge.py`'s type specs:

- **Users** emit `user.name` (sAMAccountName), `user.principal_name` (UPN),
  `user.email` (mail), and `user.sid` — the columns the *Users* namespace
  correlates on.
- **Computers** emit `host.name` (dNSHostName) and `os.name`
  (operatingSystem) — so they land in the *Devices* namespace and get
  categorized (server/workstation) from the OS string.
- **DNS A/AAAA records** additionally emit `host.name` (the FQDN) and `host.ip`,
  so name→address records correlate to the very devices other adapters report.

## Binary attribute parsers

AD hands several attributes back as packed bytes. The runner decodes them itself
(deterministic and unit-tested) rather than relying on the LDAP layer:

- `format_sid(bytes)` — `objectSid` → `S-1-5-21-…`
- `format_guid(bytes)` — `objectGUID` → canonical `{8-4-4-4-12}`
- `account_enabled(uac)` — `userAccountControl` ACCOUNTDISABLE bit → enabled?
- `group_type_labels(groupType)` — bit field → (scope, category)
- `filetime_to_iso(v)` — Windows FILETIME (100 ns ticks since 1601) →
  date-time, with the `0` / `0x7FFFFFFFFFFFFFFF` "never" sentinels blanked
- `gentime_to_iso(v)` — LDAP generalized time (`20230115080000.0Z`) → ISO
- `cert_summary(der)` — X.509 → subject/issuer/serial/validity/EKUs, always
  with a SHA-1 thumbprint (see certificates below)
- `parse_dns_record(blob)` — the `dnsRecord` blob → (type, data, ttl)

### The `dnsRecord` blob

Each `dnsNode` carries one or more `dnsRecord` values, a fixed header followed
by type-specific RDATA:

```
0  DataLength(u16 LE)  2  Type(u16 LE)  4 Version 5 Rank  6 Flags(u16)
8  Serial(u32 LE)     12  TtlSeconds(u32 BE)             16 Reserved  20 Timestamp
24 Data(DataLength bytes)
```

Names inside RDATA use `DNS_COUNT_NAME` (a total length, a label count, then
length-prefixed labels). `_parse_dns_rdata` handles A, AAAA, NS, CNAME, PTR, MX,
SRV, TXT, and SOA; unknown types fall back to a hex dump so nothing is lost.

## Certificates — scope and the AD CS caveat

Over LDAP you get **two slices** of the PKI, and one is deliberately *not* here:

1. **PKI config** (AD009/AD010) — certificate templates and enterprise CAs from
   the Configuration NC. `is_server_auth` on a template marks the ones that
   issue **SSL/TLS** certificates (EKU `1.3.6.1.5.5.7.3.1`).
2. **Published certs** (AD011) — the `userCertificate` attribute on
   users/computers. These are typically smartcard/user-auth certs; **most
   server/SSL certs are not published to AD**, so this is a small subset.

**The full AD CS issued-certificate inventory is not in LDAP.** Every issued /
revoked / pending certificate lives in the **CA database** (an ESE DB on the CA
host), read with `certutil -view` or PSPKI — a Windows/RPC path with no
cross-platform equivalent. If you need that inventory, add it as a **separate
feed** that ingests a `certutil`/PSPKI export rather than trying to reach it over
LDAP. The registry notes on AD010/AD011 say so in-product.

Rich cert parsing (subject/issuer/validity/EKU) uses the optional
`cryptography` package; without it, each cert still surfaces with its SHA-1
thumbprint and byte length, never dropped.

## DNS — scope

Only **AD-integrated** zones live in the directory (and are therefore fetchable
here). **File-backed standalone Windows DNS** or **third-party DNS**
(BIND/Infoblox) is not in AD — point a different source at those. For typed
records without the blob parsing, the Windows `DnsServer` PowerShell module is
the alternative (a separate RPC transport).

## Adding a resource

1. Add a collector `_collect_<name>(client, base_dn="") -> (columns, rows)` in
   `active_directory_runner.py`, using `_search(...)` (which degrades a missing
   container to no rows) and the `_val` / `_vals` / `_raw_vals` field helpers.
2. Register it in `_COLLECTORS`.
3. Add the query (and, if new, a feed + category) to
   `config/active_directory_registry.yaml` with an honest `status`.
4. Add a test in `tests/test_active_directory.py` driving it through the
   `FakeClient` — supply binary attributes as bytes under the entry's `raw` map.

## Connecting

In the web UI, open the **Microsoft Active Directory** card and click
**Connection**: enter the **host** (a domain controller), **username**
(`user@corp.local` or `CORP\user`), **password**, optional **port** (636 LDAPS /
389 LDAP), and an optional **Base DN** (auto-detected from the RootDSE when
blank). Or set `AD_HOST` / `AD_USERNAME` / `AD_PASSWORD` in `.env` (see
[`.env.example`](../.env.example)) to auto-connect on startup. Credentials
entered in the form are held in the local server's memory only unless you tick
**Remember**.

> **Validation status.** Filters and attribute mappings follow the documented AD
> schema; resources are marked `partially_validated` (or `investigation_required`
> where availability varies by deployment — AD CS, AD-integrated DNS, MSAs) until
> run against a live directory, the same honest labeling the other registries
> use.
