#!/usr/bin/env bash
set -euo pipefail

repo='RasmusLauritsen/hmesh'
install_dir="${HMESH_INSTALL_DIR:-$HOME/.local/bin}"

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail 'This installer supports Linux and macOS. Download Windows binaries from GitHub Releases.' ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail 'Unsupported architecture; release binaries require AMD64 or ARM64.' ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$1"; }
else
  fail 'Install sha256sum or shasum to verify the download.'
fi

use_gh=false
if command -v gh >/dev/null 2>&1 && gh auth status --hostname github.com >/dev/null 2>&1; then
  use_gh=true
else
  command -v curl >/dev/null 2>&1 || fail 'Install curl or authenticate the GitHub CLI (gh auth login).'
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT

if "$use_gh"; then
  tag=$(gh release view --repo "$repo" --json tagName --jq .tagName)
else
  # Resolve the latest release once so the archive and checksums use the same tag.
  release_url=$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --output /dev/null --write-out '%{url_effective}' "https://github.com/$repo/releases/latest") ||
    fail 'Cannot find the latest release. For a private repository, run gh auth login first.'
  tag=${release_url##*/}
fi

[[ "$tag" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || fail "Unexpected release tag: $tag"
archive="hmesh_${tag#v}_${os}_${arch}.tar.gz"
printf 'Downloading %s…\n' "$archive"

if "$use_gh"; then
  gh release download "$tag" --repo "$repo" --dir "$tmp_dir" \
    --pattern "$archive" --pattern checksums.txt
else
  for file in "$archive" checksums.txt; do
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --output "$tmp_dir/$file" "https://github.com/$repo/releases/download/$tag/$file"
  done
fi

expected=$(awk -v name="$archive" '$2 == name {print $1; count++} END {if (count != 1) exit 1}' "$tmp_dir/checksums.txt") ||
  fail 'Archive is missing or duplicated in checksums.txt.'
[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || fail 'Invalid SHA-256 checksum.'
actual=$(checksum "$tmp_dir/$archive")
[[ "${actual%% *}" == "$expected" ]] || fail 'Checksum verification failed; nothing was installed.'

# Extract only the executable, not documentation or arbitrary archive paths.
tar -xzf "$tmp_dir/$archive" -C "$tmp_dir" hmesh
[[ -f "$tmp_dir/hmesh" && ! -L "$tmp_dir/hmesh" ]] || fail 'Archive does not contain a regular hmesh binary.'
mkdir -p "$install_dir"
install -m 755 "$tmp_dir/hmesh" "$install_dir/hmesh"
printf 'Installed %s to %s/hmesh\n' "$tag" "$install_dir"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) printf 'Add this directory to your PATH: %s\n' "$install_dir" ;;
esac
