# Exploring configuration writes

**Status: DHCP reservation creation and deletion are live-tested; updates and other writes remain source-derived and untested on hardware.** Explicitly authorized configuration POSTs created and subsequently removed a synthetic test reservation. The Python reference client still blocks every non-authentication POST; those tests used separate one-shot requests. The Go `hmesh` CLI now implements guarded DHCP create/update/delete with mock tests; its writes have not been live-tested. DNS and forwarding writes are not implemented in the CLI. Examples below document the protocol, not instructions to apply a change without review.

This extends [API.md](API.md) for firmware `2.0.0.512`. Additional authenticated GETs confirmed the application/port data model and existing reservation/DNS field types; see [write-exploration.json](write-exploration.json). Values, identifiers, addresses and credentials were not retained in that file.

## Common write envelope

Use the authenticated cookie and current CSRF pair from the login flow in `API.md`. The web UI performs writes sequentially and uses refreshed CSRF fields from each response. Don't replay a captured token or send parallel writes.

Collection operations use a **top-level** `action`, not an action nested inside `data`:

```json
{
  "action": "create",
  "data": {"ID": "", "otherFields": "..."},
  "csrf": {"csrf_param": "<current>", "csrf_token": "<current>"}
}
```

For collection updates use `"action": "update"` with the exact existing `ID`. The source also implements `"delete"`; DHCP deletion was subsequently verified during cleanup of the approved test. Successful configuration writes are checked with **`errcode == 0`**, unlike login's `err == 0`. Check field-specific errors and GET the affected resources again before continuing.

Singleton settings such as `lan_server` instead use `{"data": <settings object>, "csrf": <current pair>}` with **no `action`**. These are not HTTP PATCH endpoints: don't assume a minimal field-only payload is supported.

## 1. Port forwarding

### Data model and reads

| Resource | Role |
|---|---|
| GET `/api/app/application` | Application parents: `ID`, `Name`, `ObjAcc`, feature-enable flags, and additional existing fields such as `Flag`, `Type`. |
| GET `/api/app/applicationitems` | Port definitions: `ID`, `Protocol`, `ExternalPort`, `ExternalPortEnd`, `InternalPort`, `InternalPortEnd`. |
| GET `/api/app/applicationitems?ID=<URL-encoded application ID>` | Definitions belonging to one parent. Tested successfully for both existing forwarding applications. |
| GET `/api/ntwk/portmapping` | Mapping: `ID`, `Name`, `Enable`, `ApplicationID`, `InternalHost`, `HostIPAddress`, `HostName`. |
| GET `/api/system/HostInfo` | Select the destination device and its MAC/IP/name. |

**`InternalHost` is the device MAC address**, not the target IP. The UI fills it from the selected device's MAC; `HostIPAddress` contains the IP. Copy server-provided IDs exactly, including punctuation/trailing dots. Don't construct IDs from numeric guesses.

### Create: two non-atomic POSTs

1. POST `/api/app/application`, ordinary JSON content type:

   ```json
   {
     "action": "create",
     "data": {
       "ID": "",
       "Name": "example-service_pm",
       "ObjAcc": 65535,
       "EnablePortmapping": true,
       "EnablePorttrigger": false,
       "EnableQos": false,
       "EnableFilter": false,
       "ItemList": [{
         "ID": "",
         "Protocol": "TCP",
         "ExternalPort": "18080",
         "ExternalPortEnd": "18080",
         "InternalPort": "8080",
         "InternalPortEnd": "8080",
         "index": 3
       }]
     },
     "csrf": {"csrf_param": "<current>", "csrf_token": "<current>"}
   }
   ```

   The example `index: 3` reflects a UI calculation with two existing application parents: the UI appends the new parent locally, then sets `index` to the resulting length. Recalculate from a fresh read; whether this field is required by the server is unknown. The example ports are arbitrary, not a recommended service to expose.

2. Require success; GET `/api/app/application` and resolve the new **server-assigned ID** by its unique `Name`. The UI suffixes forwarding application names with `_pm` and identifies the parent by that name. Resolve exactly one match; don't continue on ambiguity.
3. POST `/api/ntwk/portmapping`:

   ```json
   {
     "action": "create",
     "data": {
       "ID": "",
       "ApplicationID": "<new application ID>",
       "Name": "example-service",
       "Enable": true,
       "InternalHost": "<target MAC from HostInfo>",
       "HostIPAddress": "<target LAN IPv4>",
       "HostName": "<target device name>"
     },
     "csrf": {"csrf_param": "<refreshed>", "csrf_token": "<refreshed>"}
   }
   ```

4. Require success and reread the parent, items, and mapping. Their IDs and linkage must agree.

**Failure risk:** the first POST creates persistent configuration even if the second fails. An orphaned application can remain; don't blindly retry the entire create sequence. Reconcile by fresh reads, then review any cleanup separately. There is no observed transaction API.

### Update

The UI's sequence is:

1. Read and retain the original mapping, parent and selected parent's items in memory.
2. POST `/api/ntwk/portmapping` with `action: "update"`, the existing mapping object, its existing `ID` and `ApplicationID`, and intended mapping changes.
3. POST `/api/app/application` with `action: "update"`, the existing parent object, its existing `ID`, and `ItemList` containing the edited existing item (preserve its `ID`). Preserve unrelated parent flags.
4. Reread all three objects to verify.

The UI attempts to restore the original mapping if the application update fails. That is a best-effort compensating write, **not a transaction or guaranteed rollback**. A lost response can leave an uncertain outcome: read back before taking another action.

For an enable/disable-only change, the UI updates the existing mapping's `Enable` using a single `portmapping` update, without changing the parent. This is still a real configuration change.

### Constraints observed in the UI

- Protocol choices: literal `TCP`, `UDP`, `TCP/UDP`.
- Name: required, unique among forwarding mappings, input limit 29 characters.
- Port inputs: decimal integers from 1 through 65535; the UI starts with strings, while GET responses returned integers.
- UI creates **single-port** entries by setting each end equal to its start. General port-range write support is not verified.
- UI hides the add button at 32 mappings. This is a UI limit, not a measured backend capacity.
- External-port conflict checks exist, but are not sufficient evidence of all server-side conflict semantics. Check both protocol overlap and existing rules before proposing changes.
- External port 443 triggers an explicit warning in the UI. Avoid router-management ports and exposing management services generally.
- API success does not establish internet reachability: CGNAT, upstream NAT/firewalls, target service/firewall, and NAT-loopback behavior all matter. No external reachability test was performed.

## 2. DHCP reservations

### Verified create test — October 17, 2026

One POST using the create envelope below returned `errcode: 0`. A subsequent GET confirmed this enabled reservation:

- Test MAC: `02:A8:6C:B1:A5:31` (random, locally administered unicast address; not an existing device).
- Reserved IP: `192.168.50.254` (inside the current DHCP pool, absent from the router's host/reservation/forwarding records).
- Server-assigned ID: `InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPStaticAddress.44.`
- Reservation count changed from 19 to 20. All 19 original reservations and the DHCP-server settings were unchanged on readback.
- The test entry was subsequently **deleted at the user's request**. The delete POST used the exact existing object with top-level `action: "delete"`, returned `errcode: 0`, and GET readback confirmed the count returned to 19 with all other reservations and DHCP-server settings unchanged. See [dhcp-test-result.json](dhcp-test-result.json) for the non-secret verification receipt.

This confirms create/delete acceptance and configuration readback, **not an actual DHCP client's lease acquisition**, update behavior, or absence of silent static-IP hosts using the candidate IP. No write was retried.

### Create/update request format

Read GET `/api/ntwk/lan_ipaddressreserve`, `/api/ntwk/lan`, `/api/ntwk/lan_all`, and `/api/system/HostInfo` first.

POST `/api/ntwk/lan_ipaddressreserve`, ordinary JSON:

```json
{
  "action": "create",
  "data": {
    "ID": "",
    "Enable": true,
    "Chaddr": "<UPPERCASE:COLON:SEPARATED:MAC>",
    "Yiaddr": "<desired LAN IPv4>"
  },
  "csrf": {"csrf_param": "<current>", "csrf_token": "<current>"}
}
```

To update: copy the existing reservation, keep its exact `ID`, change the intended fields and use `action: "update"`. Toggling `Enable` is also an update. Don't create another entry to modify an existing reservation.

The UI normalizes MACs to uppercase colon-separated notation and checks that:

- MAC and IPv4 syntax are valid.
- The target IP is not the router's LAN address (`lan.FristIP`, firmware spelling).
- The target IP passes its LAN-range check.
- Neither MAC nor IP duplicates another reservation with a different `ID`.

For automation, additionally validate against the actual subnet mask from `lan_all`, excluding network/broadcast addresses; don't assume `/24`. Check for active leases/static hosts using the same IP. Whether reservations must lie inside the dynamic DHCP pool has not been established. Do not change the pool to test this without approval.

Source-handled server errors include `Yiaddr` conflict details, code `9004` with `lan.IpAddressReserve` for a capacity error, and code `9003` with `Chaddr` for a MAC error. None were intentionally triggered.

Changing a reservation does not prove an existing client's address changes immediately. DHCP renewal/reconnection may be needed and can disrupt that client. Use the actual stable MAC; Wi-Fi private/randomized MAC changes can break matching.

## 3. DNS: distinguish three settings

There is no verified general DNS-record CRUD API here. These are resolver settings, not an authoritative DNS server or custom hostname-record database.

### A. WAN/upstream IPv4 resolvers — source-derived write flow

- Read: GET `/api/ntwk/wan?type=active`.
- POST target used by the UI's `wan` alias: `/api/ntwk/wan?type=active`.
- Logical, **pre-encryption** body:

  ```text
  {
    action: "update",
    data: <complete, UI-prepared existing WAN object with intended DNS changes>,
    csrf: <current pair>
  }
  ```

- DNS fields: `DNSOverrideAllowed` (boolean), `IPv4DnsServers` (comma-separated IPv4 resolver addresses, no spaces), and `IPv4StaticDnsServers` for static mode. The UI strips a trailing comma when no secondary resolver is supplied. In static mode it sets both DNS strings to the same value.
- **Do not send that logical body as ordinary JSON.** The UI uses content type `application/json;charset=utf-8;enp` and encrypts the serialized whole envelope. It Base64-encodes the input string, splits it into 214-character chunks, RSA-OAEP encrypts the chunks with the authenticated public key, and concatenates the hexadecimal ciphertext. The bundled OAEP implementation defaults to SHA-1. The WAN flow also separately encrypts `Password` before whole-body encryption.
- Preserve connection mode, interface ID, VLAN, addressing, MAC-clone and other WAN settings. The UI prepares more fields than a GET/patch would; a raw GET clone plus two DNS fields is **not** a proven equivalent request.
- A GET's `Password` must not be assumed to be a reusable plaintext credential. Do not overwrite PPP credentials with a masked/empty read value.
- WAN reconfiguration may reconnect the uplink. The UI includes a 15-second waiting period, but actual outage duration has not been measured.

**Not implemented or live-tested.** A reviewable WAN request builder would need to reproduce the UI transformations and encryption first. Whether a smaller dedicated DNS-only payload is accepted is unknown; it was not probed.

### B. IPv4 DNS advertised to DHCP clients — incomplete write semantics

GET `/api/ntwk/lan_server` exposes:

```text
dnsmode: string
DNSServerone: string
DNSServertwo: string
```

The desktop LAN page writes this singleton endpoint by cloning the **entire existing DHCP-server object** and posting:

```text
POST /api/ntwk/lan_server
Content-Type: application/json; charset=utf-8

{data: <cloned existing settings>, csrf: <current pair>}
```

However, the inspected desktop page has **no DNS-mode selector or DNS-field editing code**. Thus `dnsmode`'s allowed values, whether the DNS fields are writable/active, and their exact behavior are **unverified**. Do not invent a `manual`, `static`, `0` or `1` mode or assume DNS changes will take effect just because these fields appear in GET responses.

Preserve `ServerEnable`, `MinIP`, `MaxIP`, `DHCPLeaseTime`, interface `ID` and passthrough settings in any eventual reviewed request. A DNS-only change must not disable DHCP or change the pool. Existing clients may need to renew leases; the router may advertise itself as a DNS proxy rather than the configured upstream addresses. Verify from a client, not just from API readback.

Next evidence needed: a DNS-specific UI/app workflow or a sanitized capture of an intentional DNS change, particularly the `dnsmode` transition. Captures can contain credentials/session cookies; do not commit raw HARs.

### C. IPv6 DNS — separate from IPv4

The desktop IPv6 page sets these fields on a cloned existing object:

- POST `/api/ntwk/ipv6_wan`: `X_IPv6DNSOverrideAllowed`, `X_IPv6DNSServerOne`, `X_IPv6DNSServerTwo`, alongside WAN addressing fields.
- POST `/api/ntwk/ipv6_lan`: nested `DHCP6s.DHCP6s_Dhcp6sDNSServerOne` and `DHCP6s.DHCP6s_Dhcp6sDNSServerTwo`, alongside existing DHCPv6/SLAAC settings.

Both use singleton JSON envelopes without `action`. The page writes WAN first, then LAN after success. These flows were not live-tested. Do not change addressing/prefix settings incidentally. IPv4 DNS changes alone may not determine which resolvers dual-stack clients actually use; router-advertisement and client behavior were not investigated.

## Evidence and next live-test boundary

Router-served source locations (downloaded during discovery, line numbers apply to this firmware):

| Source | Relevant lines |
|---|---|
| `/vuex/store.js` | 136–190: envelopes, optional encryption, CSRF refresh and post-write GET |
| `/views/nat/nat.js` | 195–247: defaults; 323–350: read existing items; 388–403: naming/port ends; 564–608: forwarding create/update order; 653–667: action wrapper |
| `/views/lan/lan.js` | 314–321: reservation defaults; 557–618: create/update selection and validation; 794–832: DHCP singleton and reservation POST flows |
| `/views/internet/internet.js` | 767–803: DNS/WAN fields and encrypted update |
| `/js/util.js` | 887–906: Base64, chunking and RSA-OAEP encryption |
| `/lib/cat_enc.js.jgz` | 791–796: OAEP's default SHA-1 (decompressed lines) |
| `/views/ipv6/ipv6.js` | 390–459: IPv6 DNS and related singleton updates |

Before any live write, agree on:

1. **Forwarding:** create or update, rule name/existing ID, protocol, external port, target MAC/IP, internal port, desired enabled state. Enabling a rule can expose the service externally.
2. **Reservation:** create or update, stable device MAC, desired IP and enabled state; check address conflicts first.
3. **DNS:** WAN/upstream versus DHCP-advertised, IPv4/IPv6 scope, primary/secondary resolver addresses, and acceptable interruption window.
4. Readback/verification and an explicitly reviewed recovery plan using the original objects. Do not persist unredacted configuration backups by default, automatically retry creates, or make rollback writes without an agreed scope.

The DHCP create test and subsequent cleanup above were explicitly approved and completed. Testing further writes requires agreement on the next operation. No-op updates are still writes and are not treated as harmless discovery.
