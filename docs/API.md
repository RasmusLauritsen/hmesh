# API reference

For configuration write flows, see [WRITE_API.md](WRITE_API.md). DHCP reservation creation and deletion have been live-tested; other writes remain source-derived. This catalog records retrieval behavior.

## Transport and response handling

Paths are relative to `https://192.168.50.1`. Paths and JSON field names are case-sensitive. Data is JSON: some endpoints return objects, others arrays, including empty arrays. There is no universal `data` response envelope. Do not treat missing fields as zero or empty lists as unsupported endpoints.

That address is specific to the installation used for discovery. Huawei's factory-default address, and the Go `hmesh` default, is `https://192.168.3.1`; use `--router` for a custom address.

The router web UI sends:

```http
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
_ResponseFormat: JSON
Referer: https://192.168.50.1/html/index.html
```

POST bodies use `Content-Type: application/json; charset=utf-8`. GETs have no body. The client uses `Accept: application/json`; this worked for the tested requests. Header necessity was not tested individually.

The authenticated cookie observed was **`SessionID_R3`**. Use a cookie jar; don't hardcode or export its value. JSON responses can include `csrf_param` and `csrf_token`; retain fresh pairs in memory if further authentication requests are necessary. HTTP 200 is not sufficient to establish success: inspect application error fields. Many authenticated endpoints returned **404 before login**, rather than 401/403.

## Authentication: Huawei-modified SCRAM-SHA256

Verified using the `admin` account and the BWS `router_password` credential. No login retries or password guessing were performed. The UI contains lockout handling; failed authentication should stop, not be retried automatically.

1. GET `/html/index.html`, maintaining cookies. Extract meta tag contents named `csrf_param` and `csrf_token`. The tested page has `g_userScram = 1`.
2. Generate 32 random bytes and encode as 64 lowercase hexadecimal characters: `firstnonce`.
3. POST `/api/system/user_login_nonce`:

   ```json
   {
     "data": {"username": "admin", "firstnonce": "<client nonce hex>"},
     "csrf": {"csrf_param": "<page value>", "csrf_token": "<page value>"}
   }
   ```

   Success includes `err: 0`, `salt` (hex), `iterations`, `servernonce`, and refreshed CSRF fields. Verify that `servernonce` extends the client nonce. Keep the returned CSRF pair for step 5.

4. Derive the proof. **This is not standard SCRAM.** Below `HMAC(key, message)` uses conventional argument order; text is UTF-8 and cryptographic intermediate values are raw bytes:

   ```text
   salted = PBKDF2-HMAC-SHA256(password, unhex(salt), iterations, dklen=32)
   clientKey = HMAC-SHA256(key="Client Key", message=salted)
   serverKey = HMAC-SHA256(key="Server Key", message=salted)
   storedKey = SHA256(clientKey)
   authMessage = firstnonce + "," + servernonce + "," + servernonce
   clientSignature = HMAC-SHA256(key=authMessage, message=storedKey)
   clientProof = hex(clientKey XOR clientSignature)
   ```

   Huawei's JavaScript uses `CryptoJS.HmacSHA256(message, key)` with arguments opposite the usual SCRAM construction. Using a generic SCRAM library without adapting it will produce the wrong proof.

5. POST `/api/system/user_login_proof`:

   ```json
   {
     "data": {"clientproof": "<proof hex>", "finalnonce": "<servernonce>"},
     "csrf": {"csrf_param": "<refreshed value>", "csrf_token": "<refreshed value>"}
   }
   ```

6. Require `err: 0` and verify these response signatures with constant-time comparison:

   ```text
   serversignature == hex(HMAC-SHA256(key=authMessage, message=serverKey))
   rsapubkeysignature == hex(HMAC-SHA256(key=serverKey, message=unhex(rsan)))
   ```

   The response includes `rsan`, `rsae`, and `level`. RSA encryption is not needed for the documented GET requests. Retain the session cookie and use it for subsequent GETs.

The historical Python reference client [`tools/reference/router_api.py`](../tools/reference/router_api.py) implements this flow in `Router.login`. It does not implement the legacy non-SCRAM login path, password decryption, or configuration writes. The Go CLI separately implements SCRAM authentication and guarded DHCP writes; see the root README for its command surface.

## Verified GET catalog

All paths below start with `/api/`. **Public** means a request without login returned HTTP 200, not that its response is identical to the authenticated version. All other successful rows returned 404 without login. Shapes and fields below describe authenticated responses; full observed shapes are in `observations.json`.

### Router, clients, and mesh

| Client alias | Path | Result and useful fields |
|---|---|---|
| `routerstatus` | `system/routerstatus` | Public object: `guide`, `isrepeater`, `issupportsmartapp`. |
| `deviceinfo` | `system/deviceinfo` | Public object; authenticated fields include `HardwareVersion`, `SoftwareVersion`, `HarmonyOSVersion`, `UpTime`, `SerialNumber`, `modcap`, `devcap`, and paired-unit identifiers under `other`. |
| `wlanmode` | `system/wlanmode` | Public object: `WLANMode`, `ConnectState`, `HilinkStatus`. Numeric enum meanings are not exhaustively verified. |
| `device_count` | `system/device_count` | Object: `ActiveDeviceNumbers`, `LanActiveNumber`, `HiLinkDevNum`, `UserNumber`, `isSupportWifiMps`. Don't assume counts exclude infrastructure nodes. |
| `HostInfo` | `system/HostInfo` | Array of client/infrastructure records; detailed below. |
| `topology` | `device/topology` | Array containing nested `ConnectedDevices` trees and a different router-self record. Join to `HostInfo` by `MACAddress`. |
| `slavedevinfo` | `hilink/slavedevinfo` | Empty array for the tested no-parameter request, despite the installed second unit. Any required selection parameters remain unknown. |
| `hilink_status` | `hilink/hilink_status` | Object: numeric `hilink_status`. |
| `onlinestate` | `system/onlinestate` | Public firmware/upgrade status object, **not** a general internet-online indicator. Includes current/candidate version fields, device identifiers, and a sensitive `Cookie` field. No update was initiated. |
| `onlinestate_all` | `system/onlinestate?devid=all` | Public HTTP 200; authenticated response is an array of **two** mesh-unit status objects. `IsMainDevice`, `CurrentVersion`, `DeviceType`, `DevId`, `IpAddress`, `DeviceName`; optional fields differ by node. Treat `Cookie` and `SN` as sensitive. |

#### `HostInfo` fields and units

- Identity: `ID`, `MACAddress`, `IPAddress`, `IPv6Address`, `ActualName`, `HostName`, `ActualManu`, `ActualType`, `ProdId`, `SerialNumber`.
- Activity: `Active`, `Active46`, `WlanActive`, `V6Active`; these are distinct fields. Don't infer that one is equivalent to another without checking your use case.
- Attachment: `InterfaceType`, `Layer2Interface`, `Frequency`, `IsGuest`, `IsSlave`, `HiLinkDevice`, `IsSetupSlave`, `HiLinkDevHide`.
- Traffic: `UpRate`, `DownRate` are integers. The UI multiplies each by **8**, labels that result Kbps, and divides by **1024** to display Mbps. Preserve raw values or reproduce that exact conversion rather than assuming bytes/second. `TxKBytes` and `RxKBytes` are **strings**; units are suggested by their names, not independently verified. `rate` and `rssi` are integers; their exact semantics/units are not confirmed.
- DHCP: `AddressSource`, `LeaseTime`, `VendorClassID`; timestamps/history appear in `AccessRecord`.
- Policies: `ParentControlEnable`, `ParentControl`, `DeviceDownRateEnable`, `DeviceMaxUpLoadRate`, `DeviceMaxDownLoadRate`, `MacFilterID`, `QosclassID`, `PolicerID`, `ClassQueue`.

`topology` is heterogeneous: tree nodes have `Active`, `HiLinkType`, `MACAddress`, `ConnectedDevices`; a router-self item instead has `routerSelf`, `UpdateState`, `IsSupportOnlineUpg`, and `MACAddress`. Don't require `ConnectedDevices` on every root item. The observed snapshot does not define all possible node types or enum values.

### WAN, LAN, and IPv6

| Client alias | Path | Result and useful fields |
|---|---|---|
| `wan` | `ntwk/wan?type=active` | Object: `AccessType`, `ConnectionType`, `ConnectionStatus`, `AccessStatus`, `IPv4Addr`, `IPv4Mask`, `IPv4Gateway`, `IPv4DnsServers`, IPv6 equivalents, `UpBandwidth`, `DownBandwidth`, `MTU`, `MSS`. Also includes credential-named fields: don't log raw responses. |
| `hilinkwaninfo` | `ntwk/hilinkwaninfo` | Object: `ConnState`, `Wlan24SSID`, `Wlan5SSID`. |
| `wandiagnose` | `ntwk/wandiagnose` | Passive status read used by home page: `LinkStatus`, `ConnectionStatus`, `ExternalIPAddress`, `DNSServers`, `DefaultGateway`, `Uptime`, link-rate/error fields and IPv6 equivalents. No diagnostic job POST was sent. |
| `getmacaddress` | `ntwk/getmacaddress` | Object: `macaddress`, `ipaddress`. Precise interface identity is not established. |
| `lan` | `ntwk/lan` | Object including `SourceIP`, `FristIP` (firmware spelling), `FirstMac`, `MinIP`, `MaxIP`, `DomainName`, `dhcpID`. |
| `lan_host` | `ntwk/lan_host` | Object: `FristIP`, `FirstMac`, `MACAddress`, `FirstEnable`, `DomainName`, `DevName`. |
| `lan_all` | `ntwk/lan_all` | Array: `ID`, `IPInterfaceIPAddress`, `IPInterfaceSubnetMask`. |
| `lan_server` | `ntwk/lan_server` | DHCP object: `ServerEnable`, `MinIP`, `MaxIP`, `DNSServerone`, `DNSServertwo`, `DHCPLeaseTime`. |
| `lan_ipaddressreserve` | `ntwk/lan_ipaddressreserve` | Reservations array: `ID`, `Enable`, `Chaddr`, `Yiaddr`. |
| `ipv6_enable` | `ntwk/ipv6_enable` | Object: numeric `Enable`, `ID` (not a JSON boolean). |
| `ipv6_wan` | `ntwk/ipv6_wan` | Object: `X_IPv6Address`, `X_IPv6PrefixLength`, `X_IPv6DefaultGateway`, DNS and address-mode settings. |
| `ipv6_lan` | `ntwk/ipv6_lan` | Object: `WanLinkAddr`, `LanLinkAddr`, nested `SLAAC` and `DHCP6s` settings. |
| `ethportmode` | `app/ethportmode` | Object: `Mode` string. |
| `ethnegotiation` | `ntwk/ethnegotiation` | Object: `ethintflist` array of `PortName`, numeric `Status`, numeric `Speed`; units/enums not independently verified. |
| `iptv` | `ntwk/iptv` | Object: `Enable`, `SnoopingEnable`, `ProxyEnable`, VLAN settings and `VLANData` array. |

The UI increments `wandiagnose.Uptime` once per second between polls; it is connection uptime. `deviceinfo.UpTime` is displayed separately as system uptime. Keep these counters distinct.

### Wi-Fi and backhaul

| Client alias | Path | Result and useful fields |
|---|---|---|
| `wlanradio` | `ntwk/wlanradio` | Object: `Enable2G`, `Enable5G`, initial-state equivalents, `PowerMode`, `WLANMode`. |
| `WlanGuideBasic` | `ntwk/WlanGuideBasic?type=notshowpassall` | Object containing `WifiConfig` array: `FrequencyBand`, `WifiSsid`, `WifiEnable`, `WifiSsidEnable`, `Channel`, `WlanStandard`, `BeaconType`, bandwidth/security settings. Also `DbhoEnable` and compatibility settings. |
| `guest_network` | `ntwk/guest_network?type=notshowpassall` | Array: `FrequencyBand`, `EnableFrequency`, `CanEnableFrequency`, `WifiSsid`, `SecOpt`, `ValidTime`, `RestTime`. |
| `guest_network_limitrate` | `ntwk/guest_network_limitrate` | Object: numeric `Enable`, `PeakRate`, `X_DownPeakRate`; rate units not confirmed. |
| `wlandbho` | `ntwk/wlandbho` | Object: `DbhoEnable` boolean (dual-band steering setting). |
| `wlanwifisync` | `ntwk/wlanwifisync` | Object: `wifiPowerStatus`, `WifisyncStatus`. |
| `wlanintelligent` | `ntwk/wlanintelligent` | Object: `enable`, `ID`. |
| `wlanaccess` | `ntwk/wlanfilterenhance` | Array: `FrequencyBand`, `MACAddressControlEnabled`, `MacFilterPolicy`, `BMACAddresses`, `WMACAddresses`. Alias is descriptive; path is from the UI. |
| `wlantimeswitch` | `ntwk/wlantimeswitch` | Object with `datelist` array, empty in this snapshot. |
| `backhaul` | `ntwk/backhaul` | **Sensitive:** object with `pwd` string. Not a backhaul signal/throughput endpoint. No value saved or printed during discovery. |
| `repeaterinfo` | `ntwk/repeaterinfo` | Object: `WLANMode`, `RepeaterEnable`, `Inputbyhand`. |
| `repeaterstate` | `ntwk/repeaterstate` | Object: `connstate`, `signal`, `channel`, `speed`, `radio`, `bssid`, SSID fields. Strings may not describe the whole mesh; do not assume this is per-node backhaul telemetry. |

The `notshowpassall` query is copied from the web UI to avoid requesting plaintext Wi-Fi passwords. **It is not a redaction guarantee:** key-named fields (`WpaPreSharedKey`, nested `WepKey`) still appear. Their values and masking behavior are deliberately not recorded. Treat all raw Wi-Fi responses as sensitive.

### Policy and system configuration reads

| Client alias | Path | Result and useful fields |
|---|---|---|
| `lan_upnp` | `ntwk/lan_upnp` | Object: `enable` boolean. |
| `lan_upnp_portmapping` | `ntwk/lan_upnp_portmapping` | Empty array; mapping item structure unknown. |
| `firewall` | `ntwk/firewall` | Object: `SynFlooding`, `IcmpFlooding`, `ArpAttack`, `CurrentLevel`, `SetLevel`. |
| `dmz` | `ntwk/dmz` | Object: `Enable`, `IPAddress`, `HostIPAddress`, `HostName`. |
| `portmapping` | `ntwk/portmapping` | Array: `ID`, `Name`, `Enable`, `InternalHost`, `HostIPAddress`, `HostName`, `ApplicationID`. This response is not a complete port-range specification. |
| `porttrigger` | `ntwk/porttrigger` | Empty array; item structure unknown. |
| `timecontrol` | `ntwk/timecontrol` | Empty parental-control rule array; item structure unknown. |
| `urlfilter` | `ntwk/urlfilter` | Empty URL-filter rule array; item structure unknown. |
| `qosclass_host` | `app/qosclass_host` | Array of objects with `Name`; no per-device speed metrics in the observed shape. |
| `sntp` | `ntwk/sntp` | Object: `NTPServer1`, `NTPServer2`, `CurrentLocalTime`, `LocalTimeZoneName`, `Status`, `SntpIsSynchronizedStatus`, `TimeZoneIdx`. |
| `autoupgrade` | `system/autoupgrade` | Settings object: `Enable`, `StartTime`, `EndTime`, `LatestHotaTime`. Retrieval only; no change or update check. |
| `nfc_switch` | `bsp/nfc_switch` | Object: numeric `nfcSwitch`. Retrieval only. |

## UI-listed paths that did not work

These returned **HTTP 404 both before and after authentication** for the exact requests listed. They may be unsupported, mode-specific, or require undocumented parameters. Do not interpret them as successful empty responses or evidence the feature itself is absent.

| Client alias | Exact GET path |
|---|---|
| `MultiHostInfo` | `/api/system/MultiHostInfo` |
| `l2topo` | `/api/device/l2topo` |
| `guest_network_resttime` | `/api/ntwk/guest_network_resttime` |
| `wlan_time_switch_list` | `/api/ntwk/wlan_time_switch_list` |
| `qos` | `/api/app/qos` |
| `rebootplan` | `/api/system/rebootplan` |

These remain in the Python reference client's allowlist to reproduce the observed outcome; they are not recommended monitoring endpoints and are not exposed as Go CLI commands. The catalog's client aliases refer to `tools/reference/router_api.py`, not Go command names.

## Scope, evidence, and untested areas

Discovery used the router-served `/js/api.js` alias map, `/js/util.js` transport wrapper, `/vuex/store.js` login logic, `/lib/cat_enc.js.jgz` cryptographic implementation, and page modules referenced by `/router/router.js`. Relevant source locations on the observed firmware:

- `/vuex/store.js:848–916`: SCRAM login and response signature checks.
- `/lib/cat_enc.js.jgz:7000–7075`: PBKDF2, HMAC argument order, proof derivation (decompressed asset lines).
- `/js/util.js:55–58,71–110,113–179`: request headers, GET/POST transport and refreshed CSRF handling.
- `/views/devices/devices.js:451–453`: UI traffic-rate conversion.
- `/views/home/home.js:171–202`: passive status GETs and five-second UI polling.
- `/views/upgrade/upgrade.js:293`: `onlinestate` with `devid=all` (status retrieval, not update initiation).

The endpoint map is shared across product variants; listing an alias does **not** prove support on Mesh 3. Success here establishes observed retrieval behavior, not all input parameters, exhaustive enum meanings, or complete documentation of hidden/mobile/cloud APIs. JSON shapes are snapshots; firmware, configuration and client types may change them.

During the initial read-only discovery, not invoked: Wi-Fi scans (`wifiscan`), speed tests, pairing, active diagnostic commands, exports/backups, password decryption, firmware-check/download/start commands, logout, reset, reboot, configuration POSTs, cloud/app APIs, or requests directly to the secondary unit. A later explicitly approved DHCP create/delete test did send configuration POSTs, as documented in [WRITE_API.md](WRITE_API.md). No parameter fuzzing was performed. Primary-unit aggregation provides the documented view of both units.

### Session cleanup

The firmware's `/components/head/head.js` implements logout through
`commonPost({name: 'user_logout', writeOnly: true})`. `/js/api.js` maps this to
`system/user_logout`, and `/vuex/store.js` supplies the current CSRF envelope
without a `data` field. The CLI follows this evidence with
`POST /api/system/user_logout`, using only its own in-memory cookies and current
CSRF tokens. Logout releases the CLI session; it is not a router configuration
write and does not clear locally saved keyring credentials. Lifecycle handling
is covered by offline mock-router tests, including command failures, cancellation,
and logout failures. No additional live login was used to test this change.

There is no verified CPU, RAM, temperature, per-link mesh signal, or per-link backhaul-rate API in this catalog. Do not label unrelated fields as those metrics. Anonymous 200 outcomes are observations only, not a completed security assessment; some public responses include device/firmware metadata and potentially sensitive fields. Keep management access LAN-restricted.
