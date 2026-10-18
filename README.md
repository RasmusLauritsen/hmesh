# hmesh — Huawei Mesh 3 CLI

An unofficial CLI for inspecting a Huawei Mesh 3 router and managing DHCP reservations. Use the interactive menu or explicit commands for scripts and automation.

<a href="https://consumer.huawei.com/en/routers/wifi-mesh3/">
  <img src="https://consumer.huawei.com/content/dam/huawei-cbg-site/common/mkt/pdp/routers/wifi-mesh3/imgs/homesec/huawei-wifi-mesh-3-design-3.jpg" alt="HUAWEI WiFi Mesh 3 router" width="480">
</a>

*HUAWEI WiFi Mesh 3. Product image: [Huawei](https://consumer.huawei.com/en/routers/wifi-mesh3/).*

Based on API discovery on a two-unit installation running firmware `2.0.0.512`, HarmonyOS `2.0.0`, hardware `VER.A`. Other firmware/models may behave differently. Not affiliated with or supported by Huawei.

## Install

### One-command install (Linux)

Install the latest release to `~/.local/bin`, with no sudo required:

```bash
curl -fsSL https://raw.githubusercontent.com/RasmusLauritsen/hmesh/main/install.sh | bash
```

This executes a downloaded script; [review it first](install.sh) if preferred. The installer detects AMD64/ARM64, verifies the release checksum, and replaces any existing `hmesh` in the install directory. Set `HMESH_INSTALL_DIR` to choose another directory. Checksums detect corruption, not a compromised publisher.

The installer uses authenticated GitHub CLI downloads when available; otherwise it uses public HTTPS downloads.

### Install with mise

With [mise](https://mise.jdx.dev/) installed, use its GitHub backend to install the latest release globally:

```bash
mise use -g github:RasmusLauritsen/hmesh@latest
```

### Download a release

Download a Linux archive from the [latest release](https://github.com/RasmusLauritsen/hmesh/releases/latest): choose `linux_amd64.tar.gz` for Intel/AMD or `linux_arm64.tar.gz` for ARM64.

Or use the [GitHub CLI](https://cli.github.com/) to download the latest Linux AMD64 release without specifying a version:

```bash
gh release download --repo RasmusLauritsen/hmesh \
  --pattern 'hmesh_*_linux_amd64.tar.gz' --pattern checksums.txt
```

For ARM64, replace `linux_amd64` with `linux_arm64`. Verify the archive against the release's `checksums.txt`, extract it, and put `hmesh` on your PATH.

macOS and Windows builds are also available on the [release page](https://github.com/RasmusLauritsen/hmesh/releases/latest).

## Connect

The default router is `https://192.168.3.1`, username `admin`. Run `hmesh` to open the menu and enter your password at a hidden prompt.

```bash
# Custom router with a trusted certificate/CA:
hmesh --router https://192.168.50.1 --ca-cert /path/to/router-ca.pem status

# Alternatively, explicitly trust a self-signed router on your trusted LAN:
hmesh --router https://192.168.50.1 --insecure

# Optional: verify and save credentials to your OS keyring.
hmesh --router https://192.168.50.1 --insecure auth login
```

TLS verification is enabled by default. `--insecure` disables server identity verification and is **never saved**; pass it each time if needed.

`auth login` saves the router URL, username, and optional CA path in the OS config directory's `hmesh/config.json`; passwords go only into the OS keyring. Explicit connection flags override saved values; `--config FILE` selects another config file. `auth logout` removes the selected router/user's stored password, not the config or router sessions. Keyring access requires an interactive terminal.

Commands automatically log out their own router session when finished, including on errors or Ctrl+C. This avoids filling the router's 10-user session limit. Cleanup makes one attempt with a timeout of at most five seconds; if it cannot be confirmed, a warning goes to stderr without changing the command's result. Forced termination (for example, SIGKILL) or a lost connection can still leave a session until it expires. Other users' sessions are never terminated.

### Password sources

The CLI uses the first available source:

1. `--password-stdin`, `--password-file FILE`, or `--bws-secret KEY` (mutually exclusive).
2. `HMESH_PASSWORD` environment variable.
3. OS keyring (interactive only).
4. Hidden terminal prompt.

```bash
your-secret-manager read router-password |
  hmesh --password-stdin --non-interactive devices list --output json

hmesh --password-file /run/secrets/router-password --non-interactive status
```

Password files must be protected (`chmod 600` on Unix). Stdin/files accept one nonempty line, up to 64 KiB; stdin must close after writing. Password input is not limited by the router request timeout. There is no `--password VALUE` flag; prefer a secret-manager pipe or protected file over environment variables. BWS is optional and requires an authenticated `bws` installation.

## Commands

| Command | Purpose |
|---|---|
| `hmesh status` | Router hardware and firmware |
| `hmesh devices list` | Connected and known devices |
| `hmesh mesh topology` | Mesh topology |
| `hmesh dhcp list` | DHCP reservations; alias for `dhcp reservations list` |
| `hmesh dns show` | WAN IPv4, DHCP-advertised, and WAN IPv6 DNS |
| `hmesh port-forward list` | Forwarding mappings, not separate protocol/port definitions |

Add `--output json` for machine-readable output. Text results and change previews use aligned tables, with nested fields shown as paths. Reservation lists retain their IP-sorted table. DNS and port-forward commands are read-only; IPv6 LAN DHCP/RA DNS is not included.

### Manage DHCP reservations

```bash
# Preview: authenticates and reads, but sends no configuration POST.
hmesh dhcp reservations create \
  --mac 02:00:00:00:00:42 --ip 192.168.3.100 --dry-run

# Apply an approved change (replace the example MAC/IP).
hmesh dhcp reservations create \
  --mac 02:00:00:00:00:42 --ip 192.168.3.100 --yes --non-interactive

hmesh dhcp reservations update --mac 02:00:00:00:00:42 --ip 192.168.3.101 --dry-run
hmesh dhcp reservations update --mac 02:00:00:00:00:42 --enabled=false --dry-run
hmesh dhcp reservations delete --mac 02:00:00:00:00:42 --dry-run
```

- Create defaults to enabled. Update identifies an entry by MAC and requires `--ip` and/or `--enabled`; changing its MAC is not supported. Identical requests return `action: "unchanged"` without a write; creating an existing MAC with different settings fails.
- Addresses are checked against the LAN subnet, DHCP pool, reservations, and known hosts. Outside-pool allocations are unsupported; unknown static-IP devices can still conflict. A disable-only update can retain an existing invalid/outside-pool address.
- Writes ask for confirmation, or require `--yes` without an interactive terminal. `--dry-run` always takes precedence and applies only to reservation changes.
- The CLI rechecks state before writing and verifies it afterward. Each operation sends at most one configuration POST, with **no automatic retries or rollback**. Concurrent-change checks are not atomic. If the outcome is uncertain, inspect `hmesh dhcp reservations list` before retrying.

**Write support is experimental:** historical API tests verified reservation creation/deletion and cleanup, but CLI writes and reservation updates have not been live-tested. Successful readback does not prove a device acquired its DHCP lease. See [write API evidence and limitations](docs/WRITE_API.md).

## Automation

Use explicit subcommands with `--non-interactive --output json`, plus `--yes` for approved writes. Without a subcommand, `hmesh` opens a one-action menu; without a terminal it fails. `--password-stdin` disables other CLI prompts.

- Successful data commands emit one compact JSON value on stdout. Errors go to stderr, as a JSON error envelope with `--output json`. Help/version remain plain text.
- Mutation results include `operation`, `action`, `reservation` (when present), `dry_run`, and `verified`. Dry-runs are unverified; successful applies and verified no-ops are verified. An uncertain write produces no success output.
- Known credential/session fields are filtered, but output still contains private device and network data. See [security guidance](https://github.com/RasmusLauritsen/hmesh/blob/main/SECURITY.md) before sharing it.

| Exit code | Meaning |
|---|---|
| 0 | Success, dry-run, or no-op |
| 1 | Unclassified error |
| 2 | Usage/configuration/output error or canceled menu/confirmation |
| 3 | Credential/authentication error or canceled password entry |
| 4 | Connection/TLS/timeout error outside login challenge/proof |
| 5 | Router API/response error before a write |
| 6 | Conflict or failed precondition before a write |
| 7 | Write outcome uncertain; inspect current state before retrying |

See `hmesh --help` for all options. The per-request timeout defaults to 20 seconds (`--timeout 30s` to override). Sessions are not persisted and login failures are not retried. A canceled write may still reach the router.

## API reference

- [Read API and authentication](docs/API.md): endpoints, response shapes, and Huawei-modified SCRAM-SHA256.
- [Write API](docs/WRITE_API.md): payloads, safety constraints, and verification evidence.
- [Read observations](docs/observations.json), [write observations](docs/write-exploration.json), and [historical DHCP test](docs/dhcp-test-result.json): sanitized discovery records.

The firmware API is undocumented. Configuration writes can disrupt clients; keep router administration restricted to trusted networks.

For development and protocol research, see [CONTRIBUTING.md](CONTRIBUTING.md).
