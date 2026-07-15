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
manager_filename=$(jq -r '.artifacts[] | select(.id == "ksu-manager") | .filename' \
  "$ROOT/assets.lock.json")
manager_sha=$(jq -r '.artifacts[] | select(.id == "ksu-manager") | .sha256' \
  "$ROOT/assets.lock.json")
manager_size=$(jq -r '.artifacts[] | select(.id == "ksu-manager") | .size' \
  "$ROOT/assets.lock.json")
[[ "$(shasum -a 256 "$DIST/$manager_filename" | awk '{print $1}')" == \
  "$manager_sha" ]] || {
  printf 'standalone Manager SHA-256 mismatch\n' >&2
  exit 1
}
[[ "$(wc -c < "$DIST/$manager_filename" | tr -d ' ')" == "$manager_size" ]] || {
  printf 'standalone Manager size mismatch\n' >&2
  exit 1
}
unzip -q "$DIST/xpad2-cache-v$VERSION.zip" -d "$tmp_dir"
unzip -q "$DIST/xpad2-v$VERSION-android-arm64.zip" -d "$tmp_dir"
unzip -q "$DIST/xpad2-update-v$VERSION.zip" -d "$tmp_dir"
openssl dgst -sha256 -verify "$ROOT/keys/catalog-release-public.pem" \
  -signature "$tmp_dir/xpad2-cache/catalog.sig" \
  "$tmp_dir/xpad2-cache/catalog.json" >/dev/null
openssl dgst -sha256 -verify "$ROOT/keys/catalog-release-public.pem" \
  -signature "$DIST/xpad2-update.json.sig" \
  "$DIST/xpad2-update.json" >/dev/null
cp "$DIST/xpad2-update.json" "$tmp_dir/tampered-update.json"
printf '\n' >> "$tmp_dir/tampered-update.json"
if openssl dgst -sha256 -verify "$ROOT/keys/catalog-release-public.pem" \
  -signature "$DIST/xpad2-update.json.sig" \
  "$tmp_dir/tampered-update.json" >/dev/null 2>&1; then
  printf 'tampered update manifest unexpectedly verified\n' >&2
  exit 1
fi

binary_filename="xpad2-v$VERSION-android-arm64"
cache_filename="xpad2-cache-v$VERSION.zip"
binary_sha=$(shasum -a 256 "$DIST/$binary_filename" | awk '{print $1}')
binary_size=$(wc -c < "$DIST/$binary_filename" | tr -d ' ')
cache_sha=$(shasum -a 256 "$DIST/$cache_filename" | awk '{print $1}')
cache_size=$(wc -c < "$DIST/$cache_filename" | tr -d ' ')
catalog_sha=$(shasum -a 256 "$ROOT/assets.lock.json" | awk '{print $1}')
catalog_size=$(wc -c < "$ROOT/assets.lock.json" | tr -d ' ')
catalog_version=$(jq -r '.catalog_version' "$ROOT/assets.lock.json")
jq -e \
  --arg version "$VERSION" \
  --arg catalog_version "$catalog_version" \
  --arg binary_filename "$binary_filename" \
  --arg binary_sha "$binary_sha" \
  --argjson binary_size "$binary_size" \
  --arg cache_filename "$cache_filename" \
  --arg cache_sha "$cache_sha" \
  --argjson cache_size "$cache_size" \
  --arg catalog_sha "$catalog_sha" \
  --argjson catalog_size "$catalog_size" \
  --argjson profile "$(jq -c '.profile' "$ROOT/assets.lock.json")" '
  (keys | sort) == (["binary","cache","catalog","catalog_version","channel","kind","profile","release_url","repository","schema","version"] | sort) and
  .schema == 1 and .kind == "xpad2-update" and .channel == "stable" and
  .repository == "https://github.com/yoyicue/xpad2-cli" and
  .version == $version and .catalog_version == $catalog_version and
  .profile == $profile and
  (.binary | keys | sort) == (["filename","sha256","size","url"] | sort) and
  .binary.filename == $binary_filename and .binary.sha256 == $binary_sha and
  .binary.size == $binary_size and
  .binary.url == ("https://github.com/yoyicue/xpad2-cli/releases/download/v" + $version + "/" + $binary_filename) and
  (.cache | keys | sort) == (["filename","sha256","size","url"] | sort) and
  .cache.filename == $cache_filename and .cache.sha256 == $cache_sha and
  .cache.size == $cache_size and
  .cache.url == ("https://github.com/yoyicue/xpad2-cli/releases/download/v" + $version + "/" + $cache_filename) and
  .catalog == {filename:"catalog.json",size:$catalog_size,sha256:$catalog_sha} and
  .release_url == ("https://github.com/yoyicue/xpad2-cli/releases/tag/v" + $version)
' "$DIST/xpad2-update.json" >/dev/null

update_package="$tmp_dir/xpad2-update"
[[ "$(find "$update_package" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == 4 ]]
cmp -s "$DIST/xpad2-update.json" "$update_package/xpad2-update.json"
cmp -s "$DIST/xpad2-update.json.sig" "$update_package/xpad2-update.json.sig"
cmp -s "$DIST/$binary_filename" "$update_package/$binary_filename"
cmp -s "$DIST/$cache_filename" "$update_package/$cache_filename"

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
