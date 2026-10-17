# Huawei Mesh 3 read-only API

Unofficial, locally verified documentation for a two-unit Huawei Mesh 3 installation.

- Base URL: `https://192.168.50.1`
- Primary hardware: `VER.A`; firmware: `2.0.0.512`; HarmonyOS: `2.0.0`
- Discovery: October 17, 2026 (UTC timestamps in the observation file)
- Initial discovery used only retrieval requests and authentication. A subsequent explicitly authorized DHCP reservation create test and deletion succeeded; the synthetic entry has been removed (see `WRITE_API.md`). No other configuration changes, scans, speed tests, firmware checks/downloads, reboots, or diagnostic jobs were requested.

## Files

- [API.md](API.md): authentication, endpoint catalog, response semantics, limitations.
- [WRITE_API.md](WRITE_API.md): port-forwarding, DHCP-reservation and DNS write flows; **DHCP create/delete verified**, other writes untested.
- [dhcp-test-result.json](dhcp-test-result.json): synthetic reservation details and create/readback verification; no credentials or original configuration values.
- [write-exploration.json](write-exploration.json): additional value-free authenticated GET shapes for that exploration.
- [observations.json](observations.json): anonymous/authenticated HTTP outcomes and observed field/type shapes. **No response values**, except numeric result codes; empty arrays have unknown item shapes. This is an observation format, not JSON Schema or an exhaustive API contract.
- [router_api.py](router_api.py): standard-library Python client with an explicit GET allowlist and POST restricted to authentication.
- [inspect_api.py](inspect_api.py): repeats the reviewed GET inventory, anonymously and authenticated, and regenerates observations.

## Usage

Requires Python 3 and an authenticated `bws` CLI with access to exactly one secret whose key is `router_password`. The username is `admin`. The client does not print or persist the password or session cookies. BWS's list command returns accessible secrets into process memory; only the exact matching key is used.

```bash
# Field/type information only; safe default for sharing output:
python3 router_api.py HostInfo --insecure --schema

# Actual responses: private device names, addresses, SSIDs, etc. may be printed!
python3 router_api.py onlinestate_all --insecure
python3 router_api.py topology --insecure
python3 router_api.py wandiagnose --insecure

# Optional: rerun the inventory (about 110 GET requests plus login).
python3 inspect_api.py

# Offline tests; no BWS or router access:
python3 -m unittest -v
```

`--insecure` explicitly disables TLS certificate validation for this local router's certificate. Omit it when the certificate is trusted. The inventory script uses this mode for the stated local address. Do not use it on untrusted networks. Set `SSL_CERT_FILE` to a trusted CA bundle if appropriate.

Each client invocation creates a new in-memory session. For monitoring, reuse a `Router` instance and authenticate once rather than repeatedly logging in. Start with 30–60 second polling of a small subset. Avoid concurrent logins; session limits and expiration have not been measured. Sessions are left to expire, not explicitly logged out.

```python
from router_api import Router, bws_password

router = Router(insecure=True)
router.login(bws_password())
hosts = router.get('HostInfo')
mesh = router.get('topology')
# Process locally; don't log raw responses or credentials.
```

This is private, firmware-specific behavior, not a supported Huawei API. “Read-only” means a retrieval use observed in the web UI or reviewed by endpoint purpose; it is not a guarantee of zero internal side effects. The router still maintains session/access state. A successful GET does not make the same endpoint's POST safe.
