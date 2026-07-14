#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=$(awk -F '"' '/^version = / {print $2; exit}' "$ROOT/Cargo.toml")
DIST="$ROOT/dist"
tmp_dir=$(mktemp -d /tmp/xpad2-release-verify.XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT

(
  cd "$DIST"
  shasum -a 256 -c SHA256SUMS
)
unzip -q "$DIST/xpad2-cache-v$VERSION.zip" -d "$tmp_dir"
unzip -q "$DIST/xpad2-v$VERSION-android-arm64.zip" -d "$tmp_dir"
openssl dgst -sha256 -verify "$ROOT/keys/catalog-release-public.pem" \
  -signature "$tmp_dir/xpad2-cache/catalog.sig" \
  "$tmp_dir/xpad2-cache/catalog.json" >/dev/null

while IFS=$'\t' read -r id sha size; do
  blob="$tmp_dir/xpad2-cache/blobs/$sha"
  [[ -f "$blob" ]] || {
    printf 'cache blob missing: %s\n' "$id" >&2
    exit 1
  }
  [[ "$(wc -c < "$blob" | tr -d ' ')" == "$size" ]] || {
    printf 'cache blob size mismatch: %s\n' "$id" >&2
    exit 1
  }
  [[ "$(shasum -a 256 "$blob" | awk '{print $1}')" == "$sha" ]] || {
    printf 'cache blob SHA-256 mismatch: %s\n' "$id" >&2
    exit 1
  }
done < <(jq -r '.artifacts[] | select(.embedded == true) | [.id,.sha256,(.size|tostring)] | @tsv' "$tmp_dir/xpad2-cache/catalog.json")

package="$tmp_dir/xpad2-v$VERSION-android-arm64"
(
  cd "$package"
  shasum -a 256 -c SHA256SUMS >/dev/null
)
cmp -s "$DIST/xpad2-v$VERSION-android-arm64" "$package/xpad2"
for required in \
  licenses/Rust-THIRD-PARTY.md \
  licenses/BoomInstaller-LICENSE \
  licenses/BoomInstaller-NOTICE.md \
  licenses/KernelSU-userspace-GPL-3.0-LICENSE \
  licenses/KernelSU-kernel-GPL-2.0-LICENSE \
  licenses/xpad-installer-LICENSE \
  licenses/xpad2-ionstack-poc-LICENSE \
  licenses/xpad2-ionstack-poc-Apache-2.0-LICENSE; do
  [[ -s "$package/$required" ]] || {
    printf 'release license material missing: %s\n' "$required" >&2
    exit 1
  }
done
expected_crates=$(cargo metadata --format-version 1 --locked --manifest-path "$ROOT/Cargo.toml" |
  jq '[.packages[] | select(.source != null)] | length')
actual_crates=$(find "$package/licenses/rust" -mindepth 1 -maxdepth 1 -type d |
  wc -l | tr -d ' ')
[[ "$actual_crates" == "$expected_crates" ]] || {
  printf 'Rust license inventory mismatch: expected=%s actual=%s\n' \
    "$expected_crates" "$actual_crates" >&2
  exit 1
}
jq -e '.sources[] | select(.component == "boominstaller") |
  .repository == "https://github.com/yoyicue/BoomInstaller"' \
  "$package/sources.lock.json" >/dev/null
jq -e '[.sources[] | select(.component == "ksud-xpad2" or .component == "ksu-module") |
  .repository == "https://github.com/yoyicue/xpad2-ksu-lateload"] |
  length == 2 and all' \
  "$package/sources.lock.json" >/dev/null

file "$DIST/xpad2-v$VERSION-android-arm64" | grep -q 'ARM aarch64'
printf 'XPAD2_RELEASE_VERIFY_OK version=%s\n' "$VERSION"
