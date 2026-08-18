# Tufin SecureTrack REST API — field reference

Confirmed against the **SecureTrack 25.2 (TOS R25-2)** Swagger
(`https://<host>/securetrack/apidoc/`). This is the source of truth for the
Tufin adapter's endpoint paths and field mappings (`config/tufin_registry.yaml`,
`assetflow/tufin_runner.py`). Base path: `/securetrack/api`. Auth: HTTP Basic
(a SecureTrack API user).

## Endpoints the adapter uses

| Registry ID | Endpoint | Notes |
|---|---|---|
| TUF001 | `GET /devices` | `?show_os_version=true&show_license=true` |
| TUF002 | `GET /devices/{id}/revisions` | change history; also `GET /devices/{id}/latest_revision`, `GET /revisions/{revId}` |
| TUF003 | `GET /devices/{id}/rules` | also `GET /revisions/{id}/rules` for a specific revision |
| TUF004 | `GET /devices/{id}/network_objects` | also `GET /revisions/{id}/network_objects`, `GET /network_objects/search` |
| TUF005 | `GET /devices/{id}/services` | `min`/`max` port range, numeric `protocol` |
| TUF006 | `GET /devices/{id}/zones` | R25-2 has no global `/zones`; device zones are used (host-keyed) |
| TUF007 | `GET /devices/{device_id}/cleanups?code=C01` | requires the category code; C01 = fully shadowed rules (nested under `shadowed_rule`) |
| TUF008 | `GET /devices/{id}/revisions` + `GET /revisions/{id}/rules` + `GET /change_authorization` | change detail: diff consecutive revisions, attach authorization verdict |

## Key DTO fields (R25-2)

### DetailedDeviceDTO (`/devices`)
`name`, `id`, `vendor`, `model`, `ip`, `OS_Version`, `domain_name`/`domain_id`,
`status`, `offline`, `latest_revision`, `installed_policy`, `topology`,
`parent_id`, `module_type`, `licenses.license[]` (`type`, `status`, `expiration`).

### RevisionDTO (`/devices/{id}/revisions`) — the "who / what / when"
- `id` — globally unique revision id (used by `/revisions/{id}`)
- `revisionId` — the revision's order number on the device
- `date`, `time` — split date and time of the revision
- `admin` — **the administrator who caused the revision**
- `guiClient` — the client/tool used to make the change
- `action` — the operation (e.g. "Policy Installed")
- `policyPackage` — the policy package
- `authorizationStatus`, `automaticAuthorizationStatus` — authorization result
- `comment` — nested `RevisionCommentDTO` (`comment`, `date`, `editor`)
- `tickets.ticket[]` — linked tickets (`id`, `source`)
- `manualAuthorization` — `status`, `user` (who authorized), `dateTime`
- `auditLog`, `modules_and_policy`, `ready`, `firewall_status`

### singleServiceDTO (`/devices/{id}/services`)
`name`, `id`/`uid`, `protocol` (numeric), `min`/`max` (port range),
`@xsi.type`, `comment`.

### ChangeAuthorizationDTO (`/change_authorization?old_version=&new_version=`)
Used by TUF008. `status` (authorized/unauthorized), `tickets.ticket[]`
(WorkflowTicketDTO: `id`, `requester_display_name`, `requester_email`,
`expiration_date`, `ticket_status`), and `change_authorization_bindings[]` with
`unauthorized_opened_access` / `unauthorized_closed_access` rule lists. Requires
"Authorize Revisions with Tickets" enabled in SecureTrack.

## High-value endpoints NOT yet in the registry (follow-ups)

- **Rule usage / last-hit** and `GET /devices/{id}/rules/{rule_id}/documentation`
  (rule documentation, business justification, owner, expiration).
- **Topology**: `GET /devices/{id}/interfaces`, `/bindings`,
  `/topology_interfaces`, and USP `GET /security_policies` matrices.
- **NAT**: `GET /revisions/{id}/nat_rules/bindings`, `/nat_objects`.
- **`GET /revisions/{id}/config`** — full textual device configuration by revision.

The full vendor Swagger (~1 MB) is intentionally not committed; regenerate it
from `https://<host>/securetrack/apidoc/` on the target release when extending
the registry.
