# Development

For CLI usage and API references, see [README.md](README.md).

## Build from source

Requires Go 1.26 or newer.

```bash
git clone https://github.com/RasmusLauritsen/huawei-mesh3-cli.git
cd huawei-mesh3-cli
go build -o bin/hmesh .
./bin/hmesh --help
```

To install as `hmesh` on your PATH:

```bash
mkdir -p "$HOME/.local/bin"
go build -o "$HOME/.local/bin/hmesh" .
```

Add `$HOME/.local/bin` to PATH if necessary. Plain `go install .` uses the module name (`huawei-mesh3-cli`), not `hmesh`.

## Tests

```bash
go test -race ./...
go vet ./...
python3 -m unittest discover -s tools/reference -p 'test_*.py'
python3 -m unittest discover -s tools -p 'test_install.py'
```

Automated tests run on Linux. Cross-compilation does not establish that terminal and OS-keyring behavior works on every target.

The CLI's authentication, stdin password input, status/device/reservation reads, and reservation-create dry-run were smoke-tested against the discovery router without configuration writes. CLI writes and reservation updates have not been live-tested. See [write API evidence](docs/WRITE_API.md) before testing changes on hardware; API readback alone does not prove DHCP lease acquisition.

## Secret scanning

Gitleaks scans pushes and pull requests, including all fetched Git history. Install Gitleaks **8.30.1** and enable the staged-content hook before committing:

```bash
git config --local core.hooksPath .githooks
```

If you already have hooks configured, integrate rather than replace them. See [SECURITY.md](SECURITY.md) for manual scans, detector limitations, safe router-output handling, and credential rotation.

## Dependency updates

Dependency updates use the [hosted Renovate GitHub App](https://github.com/apps/renovate), configured in [`renovate.json`](renovate.json). To activate it, install the app for `RasmusLauritsen/huawei-mesh3-cli` and merge the configuration into the default branch. No self-hosted workflow or repository token is needed.

Renovate updates Go modules (including indirect dependencies) and GitHub Actions. Minor, patch, and pin/digest updates automerge after CI passes, including pre-1.0 updates, which can contain breaking changes. Major updates remain open for manual review without a separate Dependency Dashboard approval step.

Renovate performs PR merges itself (`platformAutomerge: false`), so GitHub's **Allow auto-merge** setting is not required. Keep CI enabled and do not enable `ignoreTests`. Branch protection requiring review on every PR will also block non-major automerges; the app still needs permission to merge under the repository's rules.

## Releases

Pushing a semantic-version tag such as `v0.1.0` runs `.github/workflows/release.yml`. Formatting, race-enabled tests, and vet must pass before GoReleaser builds Linux, macOS, and Windows binaries for AMD64 and ARM64 and uploads archives plus `checksums.txt` to GitHub Releases. Prerelease tags such as `v0.2.0-rc.1` produce prereleases.

Release binaries report the tag through `hmesh --version`; source builds report a development version. Archives contain binaries and documentation, never router credentials, local config, cookies, or live router output. Builds use `CGO_ENABLED=0` and do not contact a router or BWS.

## Protocol research

[tools/reference/](tools/reference/) contains the original BWS-based Python discovery scripts. They are optional research tools, not required by the CLI or release builds. Their default router address is the custom discovery address `https://192.168.50.1`, not Huawei's factory default. See their README for usage and TLS warnings.

CI runs offline output-safety tests for these scripts. Protocol coverage, including the vendor-JavaScript SCRAM fixture, is maintained in the Go tests.
