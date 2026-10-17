# hmesh — Huawei Mesh 3 CLI

An unofficial Go CLI with a **Huh interactive menu** and **Cobra commands for automation**. No BWS dependency: use a hidden password prompt, OS keyring, stdin, environment variable, or protected password file. Optional BWS support is available.

Built from locally verified API discovery on a two-unit Huawei Mesh 3 installation, firmware `2.0.0.512`, HarmonyOS `2.0.0`, hardware `VER.A`. Not affiliated with or supported by Huawei. Other firmware/models may behave differently.

## Install

Requires **Go 1.26 or newer**. This repository is private; cloning/installing requires GitHub access.

```bash
git clone https://github.com/RasmusLauritsen/huawei-mesh3-cli.git
cd huawei-mesh3-cli
go build -o bin/hmesh .
./bin/hmesh --help

# Alternatively, build directly into your user-local binary directory:
mkdir -p "$HOME/.local/bin"
go build -o "$HOME/.local/bin/hmesh" .
```

Examples below assume `hmesh` is on your PATH: add the checkout's `bin/` or `$HOME/.local/bin` to PATH as appropriate. Plain `go install .` uses the module's name (`huawei-mesh3-cli`), not `hmesh`, so use one of the explicit output paths above. Builds are also possible for other Go-supported platforms, but OS-keyring availability and terminal behavior vary; automated tests currently run on Linux.

## Connect

The factory-default URL is **`https://192.168.3.1`**, username `admin`. Override with `--router`; the installation used for API discovery has a custom address, `https://192.168.50.1`.

```bash
# Interactive menu; hidden password prompt unless another source is available.
hmesh

# Custom router, explicitly trusting its local self-signed certificate:
hmesh --router https://192.168.50.1 --insecure

# Prefer TLS certificate validation with a trusted PEM certificate/CA:
hmesh --router https://192.168.50.1 --ca-cert /path/to/router-ca.pem status

# Optional: verify and save the password to your OS keyring.
hmesh --router https://192.168.50.1 --insecure auth login
```

`auth login` saves the router URL, username, and optional CA file path to the OS config directory's `hmesh/config.json`. **Passwords are saved only to the OS keyring**, not that file. `--config FILE` overrides its location. Explicit `--router`, `--username`, and `--ca-cert` override saved values. `--insecure` is deliberately **not saved**: pass it each time when required.

OS-keyring integration uses macOS Keychain, Windows Credential Manager, or Linux Secret Service. Keyring lookup and `auth login`/`auth logout` require an interactive terminal and are disabled in unattended mode, since OS keyrings may display their own unlock prompts. The CLI bounds its wait for keyring operations by `--timeout` and responds to cancellation; the underlying OS operation may finish separately. On headless Linux use stdin, environment, or a protected file instead. `auth logout` removes the locally stored credential for the selected router/user; it does not log out router sessions or delete the config file.

### Password sources

Precedence:

1. Explicit `--password-stdin`, `--password-file FILE`, **or** `--bws-secret KEY` (mutually exclusive).
2. `HMESH_PASSWORD` environment variable.
3. OS keyring entry for the selected router URL and username (interactive only).
4. Hidden terminal prompt, if interactive.

```bash
# Integrate any secret manager; no password appears in command arguments:
your-secret-manager read router-password |
  hmesh --password-stdin --non-interactive devices list --output json

# Mounted secret file: chmod 600 on Unix; regular files only.
hmesh --password-file /run/secrets/router-password --non-interactive status

# Existing BWS users can opt in:
hmesh --bws-secret router_password --router https://192.168.50.1 --insecure status
```

Stdin/files accept one nonempty line, preserving spaces and removing a trailing LF/CRLF, up to 64 KiB including that terminator. A stdin producer must **close the stream after writing**: input is read until EOF, and the router request timeout does not limit password input. There is deliberately **no `--password VALUE` flag**. Avoid entering passwords directly in shell history. Environment variables can leak through inherited processes or diagnostics; prefer a secret-manager pipe or a protected mounted file for agents. BWS lookup currently loads accessible secrets into process memory and selects exactly one matching key; no values are forwarded to output.

## Commands

```bash
hmesh status
hmesh devices list --output json
hmesh mesh topology --output json
hmesh dhcp list
hmesh dhcp reservations list
hmesh dhcp reservations list --output json
hmesh dns show --output json
hmesh port-forward list --output json
```

`dns show` is read-only and selects WAN IPv4, DHCP-advertised, and WAN IPv6 DNS fields; it does not inspect IPv6 LAN DHCP/RA DNS. `port-forward list` returns mapping records, **not** the separate protocol/port definitions. DNS and port-forward writes are not implemented.

### DHCP reservations

`hmesh dhcp list` is shorthand for `hmesh dhcp reservations list`; both accept the same global options. Reservation lists use a human-readable table by default, sorted numerically by IPv4 address. Internal IDs are hidden; empty lists display `No DHCP reservations found.` The menu's list view uses the same format. Use `--output json` to retain the full JSON array, including IDs, in router response order.

```text
IP ADDRESS       MAC ADDRESS        ENABLED
192.168.3.100    02:00:00:00:00:42   yes
192.168.3.101    02:00:00:00:00:43   no

2 reservations
```

```bash
# Preview only: authenticates and reads, but sends no configuration POST.
hmesh dhcp reservations create \
  --mac 02:00:00:00:00:42 --ip 192.168.3.100 --dry-run --output json

# Apply and verify (replace these illustrative values with your device's MAC/IP).
hmesh dhcp reservations create \
  --mac 02:00:00:00:00:42 --ip 192.168.3.100 \
  --yes --non-interactive --output json

hmesh dhcp reservations update \
  --mac 02:00:00:00:00:42 --ip 192.168.3.101 --dry-run

hmesh dhcp reservations update \
  --mac 02:00:00:00:00:42 --enabled=false --yes --non-interactive

hmesh dhcp reservations delete \
  --mac 02:00:00:00:00:42 --yes --non-interactive --output json
```

- Create defaults to enabled; update preserves enabled state unless `--enabled` is supplied. Update requires `--ip` and/or `--enabled`. MAC identifies an existing entry; changing the MAC is not supported.
- An identical create, unchanged update, or delete of an absent MAC returns `action: "unchanged"` without a POST. Create with different settings for an existing MAC fails: use update instead.
- Validation checks unicast MAC, IPv4, actual LAN subnet, network/broadcast/router addresses, pool membership, duplicate reservations, and conflicting router host records. Outside-pool reservations are intentionally unsupported pending firmware verification. This cannot detect every silent/static-IP device.
- A disable-only update can retain an existing problematic/outside-pool address so it can be deactivated; it does not require allocation validation. Snapshot checks and post-write verification still apply. Changing the address, even when also disabling, uses full validation.
- Interactive writes ask for confirmation. Without a usable terminal, writes require `--yes`. `--dry-run` takes precedence over `--yes` and affects reservation operations only.
- Before writing, the CLI rechecks reservations and DHCP-server settings for concurrent changes and refreshes applicable address/host checks. No-op applies also reread state before reporting it verified. This reduces, but cannot eliminate, races; the router has no observed atomic transaction API.
- Each operation sends **at most one configuration POST**; there are no automatic retries or rollback writes. Readback verifies the intended change, other reservations, and unchanged DHCP-server settings. A lost/rejected/unverifiable write response is reported as an uncertain outcome: inspect state before retrying.
- Reservation creation/deletion was previously live-verified using a synthetic entry that was removed afterward. The Go implementation is mock-tested; live Go writes and DHCP update behavior have **not** been tested on the router. A successful API readback is not proof of actual DHCP lease acquisition.

Go authentication (including stdin password input), status/device/reservation reads, and a create **dry-run** were also smoke-tested against the custom-address router without configuration writes.

## Automation contract

Use explicit subcommands, `--non-interactive`, `--output json`, and `--yes` for approved writes. Invoking `hmesh` without a subcommand opens a one-action menu and exits after the selected operation; without a terminal it fails rather than hanging. Password input via stdin disables other CLI prompts.

- With `--output json`, successful data-producing subcommands emit one compact JSON value on stdout. Default `text` output uses a table for DHCP reservation lists and indented JSON for other operations. Interactive Quit succeeds without output. Help/version are human-readable text, not part of the JSON data contract.
- Errors: stderr only; JSON error envelope when `--output json` is selected. No success output on an uncertain write; inspect readback via `dhcp reservations list`.
- Mutation results include `operation`, `action`, `reservation` (when present), `dry_run`, and `verified`. Plans have `dry_run: true`, `verified: false`; successful applies have `dry_run: false`, `verified: true`. `unchanged` means the desired state was observed without a write, not that a live lease was checked.
- Response fields containing `password`, `cookie`, `csrf` or `presharedkey` (case-insensitive), and exact `pwd`/`wepkey` fields, are filtered recursively. This is not comprehensive secret detection. Device names, MAC/IP addresses, serial numbers and configuration are still private data—do not publish raw output casually.

| Exit code | Meaning |
|---|---|
| 0 | Success, including a dry-run or idempotent no-op |
| 1 | Other/unclassified error |
| 2 | Usage, configuration, canceled menu/reservation/confirmation prompt, or output error |
| 3 | Credential/authentication error, including canceled password entry |
| 4 | Connection, TLS or timeout error outside login challenge/proof |
| 5 | Router HTTP/API/response error before a write |
| 6 | Conflict, failed precondition, or concurrent configuration change before a write |
| 7 | Write attempted but response and/or resulting state not fully confirmed; inspect before retrying |

Global options are listed by `hmesh --help`. Default request timeout is 20 seconds (`--timeout 30s` to override). Each invocation uses an in-memory cookie jar; no sessions are persisted. Login failures are not automatically retried. A canceled request during a write can still have reached the router; exit 7 requires checking current state.

## Development and API references

```bash
go test -race ./...
go vet ./...
python3 -m unittest -v  # Original reference-client tests
```

- [docs/API.md](docs/API.md): verified read APIs and Huawei-modified SCRAM-SHA256 authentication.
- [docs/WRITE_API.md](docs/WRITE_API.md): write-flow evidence, limitations, and historical DHCP create/delete test.
- [docs/observations.json](docs/observations.json): original anonymous/authenticated response shapes, without private values.
- [docs/write-exploration.json](docs/write-exploration.json): additional field/type observations for write exploration.
- [docs/dhcp-test-result.json](docs/dhcp-test-result.json): historical synthetic reservation test and cleanup receipt.
- `router_api.py`, `inspect_api.py`, `test_router_api.py`: original BWS-based Python discovery tools, retained as protocol references. Their default URL is the custom discovery address `https://192.168.50.1`, **not** Huawei's factory default. They are not required by the Go CLI. `python3 inspect_api.py` performs a fresh inventory of that installation and replaces `docs/observations.json`; that historical inventory script explicitly disables TLS verification.

TLS verification is enabled by default in the Go CLI. Obtain trusted certificates through a trusted local channel; `--insecure` disables server identity verification and should only be used knowingly on a trusted LAN. The firmware API is undocumented; writes can disrupt clients. Protect router administration from untrusted networks.
