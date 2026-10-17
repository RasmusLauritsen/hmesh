# Historical Python discovery tools

These scripts were used to discover the router API before the Go CLI existed.
They are optional protocol-research tools, not a supported alternative CLI or a
dependency of `hmesh` or release builds. CI runs offline output-safety tests only;
duplicate protocol tests have been retired. The Go tests retain the vendor-JavaScript SCRAM test vector and
test authentication, request handling, and guarded reservation operations.

## Requirements and scope

- Python 3 (standard library only).
- An authenticated `bws` CLI with exactly one accessible secret named
  `router_password`; the reference tools do not support the Go CLI's other
  credential sources.
- Their default URL is the discovery installation's custom address,
  `https://192.168.50.1`, **not** Huawei's factory-default `192.168.3.1`.
- Retrieval requests and authentication only; configuration POSTs are blocked.
  Session cookies are kept in memory; raw response output can expose credentials.

## Usage from the repository root

```bash
# Show a response's field/types without private values (the default):
python3 tools/reference/router_api.py HostInfo --insecure --schema

# Override the reference client's router address:
python3 tools/reference/router_api.py deviceinfo \
  --base https://192.168.3.1 --insecure --schema

# Optional full inventory against the custom discovery address:
python3 tools/reference/inspect_api.py
```

The inventory script sends anonymous and authenticated GETs across its reviewed
allowlist and **overwrites the repository's `docs/observations.json`**, regardless
of the working directory. It hardcodes the custom discovery address via the
reference client's default and explicitly disables TLS verification. Do not run
it blindly on another network or expect it to use `hmesh` configuration.

For the reference client, `--insecure` explicitly disables certificate
verification; omit it when the router certificate is trusted. The reference
client defaults to schema-only output; `--schema` remains an explicit alias.
`--unsafe-raw` prints unfiltered responses and warns on stderr: output can contain
passwords, tokens and private network details. Do not publish or commit it.
The inventory script records field/type shapes and numeric result codes, not
private response values.

For normal use, prefer [hmesh](../../README.md). Protocol evidence and historical
observations are in [docs/API.md](../../docs/API.md) and
[docs/WRITE_API.md](../../docs/WRITE_API.md).
