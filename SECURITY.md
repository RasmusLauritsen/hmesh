# Security and secret handling

## Before committing

Install [Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
from its upstream release for your platform and verify its checksum. Put
`gitleaks` on your PATH. CI uses the same pinned CLI, without a commercial
GitHub Action or license requirement.

Enable the repository's staged-content hook (Git Bash on Windows):

```bash
git config --local core.hooksPath .githooks
```

This replaces the hook directory for this clone. If you already use hooks,
integrate `.githooks/pre-commit` with your existing hook manager instead.
The hook fails closed if Gitleaks is missing. Installation is per clone; CI
is the backup, but detects secrets only **after upload**. Make the
`Secret scanning / gitleaks` check required in GitHub branch protection.

Manual scans and offline safety tests:

```bash
# All locally available branches/tags (use a full clone, not a shallow clone):
gitleaks git --config .gitleaks.toml --log-opts="--all" --redact --no-banner .
# Current staged changes, exactly as the hook scans them:
gitleaks git --pre-commit --staged --config .gitleaks.toml --redact --no-banner .
python3 -m unittest discover -s tools/security -p 'test_*.py'
python3 -m unittest discover -s tools/reference -p 'test_*.py'
```

The standard Gitleaks rules are extended with literal router/Wi-Fi password,
`HMESH_PASSWORD`, session-cookie and CSRF assignment rules. Exceptions allow
specific fake fixture values in specific test paths, not whole test files.
Angle-bracket password placeholders are allowed; never use a real credential
as a fixture or a detection rule. Don't add a blanket ignore to silence a hit.
Scanner tests use generated synthetic credentials in temporary repositories.

Scanning is heuristic: arbitrary passwords, split/encoded values, unknown
field names, archives, runtime output and files outside Git history may escape
detection. A clean scan is not proof that credentials were never exposed.
Review captures and diagnostics before sharing, even in a private repository.

## Router data

- Prefer the OS keyring, hidden prompt, or secret-manager pipe. Don't put a
  password into command arguments, shell history, source code or documentation.
- Never commit `.env`, HAR captures, cookie jars, router backups, secret files,
  or raw API responses. `.gitignore` does not protect already-tracked files.
- The Go CLI filters known credential/session field names recursively. This
  does not remove all sensitive data: device names, addresses, serial numbers,
  configuration, and secrets under unexpected keys can still appear.
- Python reference output defaults to field/type schemas. `--unsafe-raw`
  explicitly prints unfiltered responses and warns on stderr; the warning does
  not sanitize redirected stdout. Some endpoints expose Wi-Fi/backhaul passwords.
- Prefer trusted TLS certificates. `--insecure` disables server identity
  checks; a trusted-looking LAN alone is not protection from interception.

## If a credential leaks

1. **Revoke or rotate first.** Change the router admin password, Wi-Fi/backhaul
   credential, or provider token that was exposed. If session cookies leaked,
   invalidate sessions using the router's supported controls; don't assume a
   password change necessarily invalidates every existing session.
2. Remove the secret from current files and check Git history, CI logs,
   artifacts, releases, shared captures and other copies. Coordinate any history
   rewrite with collaborators; deleting a file or making the repo private does
   not revoke a credential.
3. Scan again and add a **synthetic** regression case if the detector missed it.

Do not put credentials in GitHub issues. Contact the repository owner privately
to report a suspected exposure; share locations and context, not secret values.
