#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=$(awk -F '"' '/^version = / {print $2; exit}' "$ROOT/Cargo.toml")
DIST="$ROOT/dist"
tmp_dir=$(mktemp -d /tmp/xpad2-release-verify.XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT

ionstack_commit=$(jq -r '.sources[] | select(.component == "ionstack") | .commit' \
  "$ROOT/sources.lock.json")
upstream_profiles=$(git -C "$ROOT/../xpad2-ionstack-poc" show \
  "$ionstack_commit:profiles/xpad2_profiles.json")
jq -e --argjson upstream "$upstream_profiles" '
  ([.ionstack_profiles[] |
      {name:.id,kernel_version}] | sort_by(.name)) ==
    ([$upstream.profiles[] | select(.release) |
      {name,kernel_version}] | sort_by(.name)) and
  ([.ionstack_discovery_profiles[] |
      {name:.profile_id,offsets}] | sort_by(.name)) ==
    ([$upstream.profiles[] | select(.release) |
      {name,offsets}] | sort_by(.name))
' "$ROOT/assets.lock.json" >/dev/null || {
  printf 'signed IonStack profile/discovery catalog drifted from locked upstream source\n' >&2
  exit 1
}

(
  cd "$DIST"
  shasum -a 256 -c SHA256SUMS
)
while IFS=$'\t' read -r manager_id manager_filename manager_sha manager_size; do
  [[ "$(shasum -a 256 "$DIST/$manager_filename" | awk '{print $1}')" == \
    "$manager_sha" ]] || {
    printf 'standalone Manager SHA-256 mismatch: %s\n' "$manager_id" >&2
    exit 1
  }
  [[ "$(wc -c < "$DIST/$manager_filename" | tr -d ' ')" == "$manager_size" ]] || {
    printf 'standalone Manager size mismatch: %s\n' "$manager_id" >&2
    exit 1
  }
done < <(jq -r '.artifacts[] | select(.id == "ksu-manager" or .id == "suu-manager") |
  [.id,.filename,.sha256,(.size|tostring)] | @tsv' "$ROOT/assets.lock.json")
unzip -q "$DIST/xpad2-cache-v$VERSION.zip" -d "$tmp_dir"
unzip -q "$DIST/xpad2-v$VERSION-android-arm64.zip" -d "$tmp_dir"
unzip -q "$DIST/xpad2-update-v$VERSION.zip" -d "$tmp_dir"
openssl dgst -sha256 -verify "$ROOT/keys/catalog-release-public.pem" \
  -signature "$tmp_dir/xpad2-cache/catalog.sig" \
  "$tmp_dir/xpad2-cache/catalog.json" >/dev/null
openssl dgst -sha256 -verify "$ROOT/keys/catalog-release-public.pem" \
  -signature "$DIST/xpad2-update.json.sig" \
  "$DIST/xpad2-update.json" >/dev/null
openssl dgst -sha256 -verify "$ROOT/keys/catalog-release-public.pem" \
  -signature "$DIST/catalog.sig" \
  "$ROOT/assets.lock.json" >/dev/null
openssl dgst -sha256 -verify "$ROOT/keys/catalog-release-public.pem" \
  -signature "$DIST/xpad2-deltas.json.sig" \
  "$DIST/xpad2-deltas.json" >/dev/null
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
  --argjson profile "$(jq -c '.profile | {build_fingerprint,kernel_release_prefix,abi}' "$ROOT/assets.lock.json")" '
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

delta_base_version=$(jq -r '.deltas[0].from_version' "$DIST/xpad2-deltas.json")
delta_filename="xpad2-delta-v$delta_base_version-to-v$VERSION-android-arm64.zst"
delta_base="$DIST/xpad2-v$delta_base_version-android-arm64"
[[ -f "$delta_base" ]] || {
  printf 'delta base binary missing during verification: %s\n' "$delta_base" >&2
  exit 1
}
delta_base_sha=$(shasum -a 256 "$delta_base" | awk '{print $1}')
delta_base_size=$(wc -c < "$delta_base" | tr -d ' ')
delta_sha=$(shasum -a 256 "$DIST/$delta_filename" | awk '{print $1}')
delta_size=$(wc -c < "$DIST/$delta_filename" | tr -d ' ')
jq -e \
  --arg repository "https://github.com/yoyicue/xpad2-cli" \
  --arg target_version "$VERSION" \
  --argjson target_binary "$(jq -c '.binary' "$DIST/xpad2-update.json")" \
  --arg from_version "$delta_base_version" \
  --argjson from_size "$delta_base_size" \
  --arg from_sha "$delta_base_sha" \
  --arg patch_filename "$delta_filename" \
  --arg patch_sha "$delta_sha" \
  --argjson patch_size "$delta_size" '
  (keys | sort) == (["deltas","kind","repository","schema","target_binary","target_version"] | sort) and
  .schema == 1 and .kind == "xpad2-deltas" and .repository == $repository and
  .target_version == $target_version and .target_binary == $target_binary and
  (.deltas | length) == 1 and
  (.deltas[0] | keys | sort) == (["from_sha256","from_size","from_version","patch"] | sort) and
  .deltas[0].from_version == $from_version and
  .deltas[0].from_size == $from_size and .deltas[0].from_sha256 == $from_sha and
  (.deltas[0].patch | keys | sort) == (["filename","sha256","size","url"] | sort) and
  .deltas[0].patch.filename == $patch_filename and
  .deltas[0].patch.size == $patch_size and .deltas[0].patch.sha256 == $patch_sha and
  .deltas[0].patch.url == ($repository + "/releases/download/v" + $target_version + "/" + $patch_filename)
' "$DIST/xpad2-deltas.json" >/dev/null
zstd -q -d --patch-from="$delta_base" "$DIST/$delta_filename" -f \
  -o "$tmp_dir/delta-reconstructed"
cmp -s "$DIST/$binary_filename" "$tmp_dir/delta-reconstructed" || {
  printf 'delta did not reconstruct the exact target binary\n' >&2
  exit 1
}

update_package="$tmp_dir/xpad2-update"
[[ "$(find "$update_package" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == 8 ]]
cmp -s "$DIST/xpad2-update.json" "$update_package/xpad2-update.json"
cmp -s "$DIST/xpad2-update.json.sig" "$update_package/xpad2-update.json.sig"
cmp -s "$DIST/catalog.sig" "$update_package/catalog.sig"
cmp -s "$DIST/xpad2-deltas.json" "$update_package/xpad2-deltas.json"
cmp -s "$DIST/xpad2-deltas.json.sig" "$update_package/xpad2-deltas.json.sig"
cmp -s "$DIST/$delta_filename" "$update_package/$delta_filename"
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
  licenses/SukiSU-userspace-GPL-3.0-LICENSE \
  licenses/SukiSU-kernel-GPL-2.0-LICENSE \
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
jq -e '[.sources[] | select(.component == "suu-ksud" or .component == "suu-module" or .component == "sukisu-manager") |
  .repository == "https://github.com/yoyicue/xpad2-sukisu-lateload"] |
  length == 3 and all' \
  "$package/sources.lock.json" >/dev/null

file "$DIST/xpad2-v$VERSION-android-arm64" | grep -q 'ARM aarch64'
printf 'XPAD2_RELEASE_VERIFY_OK version=%s\n' "$VERSION"
