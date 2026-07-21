#!/usr/bin/env bash
set -euo pipefail

umask 022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PARENT=$(dirname "$ROOT")
VERSION=$(awk -F '"' '/^version = / {print $2; exit}' "$ROOT/Cargo.toml")
ARTIFACT_DIR=${XPAD2_ARTIFACT_DIR:-}
IONSTACK_SOURCE=${XPAD2_IONSTACK_SOURCE:-$PARENT/xpad2-ionstack-poc}
DIST="$ROOT/dist"
STAGE="$DIST/.stage-v$VERSION"
PACKAGE="$STAGE/xpad2-v$VERSION-android-arm64"
CACHE="$STAGE/xpad2-cache"
UPDATE_PACKAGE="$STAGE/xpad2-update"
BINARY="$ROOT/target/aarch64-linux-android/release/xpad2"
UPDATE_MANIFEST="$DIST/xpad2-update.json"
UPDATE_SIGNATURE="$DIST/xpad2-update.json.sig"
CATALOG_SIGNATURE="$DIST/catalog.sig"
DELTA_INDEX="$DIST/xpad2-deltas.json"
DELTA_SIGNATURE="$DIST/xpad2-deltas.json.sig"
UPDATE_BUNDLE="$DIST/xpad2-update-v$VERSION.zip"
REPOSITORY="https://github.com/yoyicue/xpad2-cli"

DELTA_BASE_VERSION=${XPAD2_DELTA_BASE_VERSION:-}
if [[ -z "$DELTA_BASE_VERSION" ]]; then
  while IFS= read -r tag; do
    candidate=${tag#v}
    if [[ "$candidate" != "$VERSION" ]]; then
      DELTA_BASE_VERSION=$candidate
      break
    fi
  done < <(git -C "$ROOT" tag --list 'v[0-9]*' --sort=-v:refname)
fi
[[ "$DELTA_BASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  printf 'cannot determine a stable delta base version\n' >&2
  exit 1
}
DELTA_BASE_BINARY=${XPAD2_DELTA_BASE_BINARY:-$DIST/xpad2-v$DELTA_BASE_VERSION-android-arm64}
DELTA_FILENAME="xpad2-delta-v$DELTA_BASE_VERSION-to-v$VERSION-android-arm64.zst"
DELTA_PATH="$DIST/$DELTA_FILENAME"

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

source_for() {
  local id=$1 filename=$2 candidate
  if [[ -n "$ARTIFACT_DIR" ]]; then
    for candidate in "$ARTIFACT_DIR/$filename" "$ARTIFACT_DIR/$id"; do
      [[ -f "$candidate" ]] && {
        printf '%s\n' "$candidate"
        return
      }
    done
  fi
  case "$id" in
    ionstack-runner-v19-a) printf '%s\n' "$IONSTACK_SOURCE/dist/xpad2-19-260/profiles/xpad2-v19-a/ionstack_reroot_device" ;;
    ionstack-preload-v19-a) printf '%s\n' "$IONSTACK_SOURCE/dist/xpad2-19-260/profiles/xpad2-v19-a/ionstack_preload.so" ;;
    ionstack-runner-v19-b) printf '%s\n' "$IONSTACK_SOURCE/dist/xpad2-19-260/profiles/xpad2-v19-b/ionstack_reroot_device" ;;
    ionstack-preload-v19-b) printf '%s\n' "$IONSTACK_SOURCE/dist/xpad2-19-260/profiles/xpad2-v19-b/ionstack_preload.so" ;;
    ionstack-runner-v260) printf '%s\n' "$IONSTACK_SOURCE/dist/xpad2-19-260/profiles/xpad2-v260/ionstack_reroot_device" ;;
    ionstack-preload-v260) printf '%s\n' "$IONSTACK_SOURCE/dist/xpad2-19-260/profiles/xpad2-v260/ionstack_preload.so" ;;
    ionstack-perf-target) printf '%s\n' "$IONSTACK_SOURCE/dist/xpad2-19-260/profiles/xpad2-v260/ionstack_perf_target" ;;
    ionstack-chainwalk-probe) printf '%s\n' "$IONSTACK_SOURCE/dist/xpad2-19-260/profiles/xpad2-v260/cve_2026_43499_chainwalk_probe_arm32" ;;
    ksud) printf '%s\n' "$PARENT/xpad2-ksu-lateload/artifacts/ksud-xpad2" ;;
    suu-ksud) printf '%s\n' "$PARENT/xpad2-sukisu-lateload/artifacts/ksud-sukisu-xpad2" ;;
    ksu-manager) printf '%s\n' "$PARENT/xpad2-reroot-android/app/src/main/res/raw/kernelsu_manager_v3_2_5_22_gccfee6dc_32547.apk" ;;
    suu-manager) printf '%s\n' "$PARENT/xpad2-sukisu-lateload/artifacts/SukiSU_v4.1.3_40796-release.apk" ;;
    xpad-installer) printf '%s\n' "$PARENT/xpad-installer/dist/xpad-install" ;;
    boominstaller) printf '%s\n' "$PARENT/BoomInstaller/out/apk/BoomInstaller-v13.6.0.r24.2f6e7c2-production.apk" ;;
    neozygisk-module) printf '%s\n' "$ROOT/.xpad2-artifacts/NeoZygisk-v2.3-275-release.zip" ;;
    vector-module) printf '%s\n' "$ROOT/.xpad2-artifacts/Vector-v2.0-3021-Release.zip" ;;
    magiskpolicy) printf '%s\n' "$ROOT/.xpad2-artifacts/magiskpolicy-v30.7-arm64" ;;
    *) return 1 ;;
  esac
}

command -v jq >/dev/null || {
  printf 'jq is required\n' >&2
  exit 1
}
command -v zstd >/dev/null || {
  printf 'zstd is required\n' >&2
  exit 1
}
[[ -f "$DELTA_BASE_BINARY" ]] || {
  printf 'delta base binary missing: %s\n' "$DELTA_BASE_BINARY" >&2
  exit 1
}
MANAGER_FILES=()
while IFS=$'\t' read -r manager_id manager_filename; do
  manager_source=$(source_for "$manager_id" "$manager_filename")
  MANAGER_FILES+=("$manager_filename")
done < <(jq -r '.artifacts[] | select(.id == "ksu-manager" or .id == "suu-manager") |
  [.id,.filename] | @tsv' "$ROOT/assets.lock.json")
"$ROOT/tools/build_android.sh"

rm -rf "$STAGE"
mkdir -p "$PACKAGE/licenses" "$CACHE/blobs"
cp "$BINARY" "$PACKAGE/xpad2"
chmod 755 "$PACKAGE/xpad2"
cp "$ROOT/README.md" "$ROOT/BEGINNER_GUIDE.md" "$ROOT/DESIGN.md" \
  "$ROOT/NOTICE.md" "$ROOT/LICENSE" "$ROOT/assets.lock.json" \
  "$ROOT/sources.lock.json" "$PACKAGE/"

cp "$IONSTACK_SOURCE/LICENSE" "$PACKAGE/licenses/xpad2-ionstack-poc-LICENSE"
cp "$IONSTACK_SOURCE/NOTICE" "$PACKAGE/licenses/xpad2-ionstack-poc-NOTICE"
cp "$IONSTACK_SOURCE/licenses/Apache-2.0.txt" \
  "$PACKAGE/licenses/xpad2-ionstack-poc-Apache-2.0-LICENSE"
cp "$PARENT/xpad2-ksu-lateload/LICENSE" "$PACKAGE/licenses/KernelSU-userspace-GPL-3.0-LICENSE"
cp "$PARENT/xpad2-ksu-lateload/kernel/LICENSE" "$PACKAGE/licenses/KernelSU-kernel-GPL-2.0-LICENSE"
cp "$PARENT/xpad2-sukisu-lateload/LICENSE" "$PACKAGE/licenses/SukiSU-userspace-GPL-3.0-LICENSE"
cp "$PARENT/xpad2-sukisu-lateload/kernel/LICENSE" "$PACKAGE/licenses/SukiSU-kernel-GPL-2.0-LICENSE"
cp "$PARENT/xpad-installer/LICENSE" "$PACKAGE/licenses/xpad-installer-LICENSE"
cp "$PARENT/BoomInstaller/LICENSE" "$PACKAGE/licenses/BoomInstaller-LICENSE"
cp "$PARENT/BoomInstaller/NOTICE.md" "$PACKAGE/licenses/BoomInstaller-NOTICE.md"
cp "$ROOT/LICENSE" "$PACKAGE/licenses/NeoZygisk-GPL-3.0-LICENSE"
cp "$ROOT/LICENSE" "$PACKAGE/licenses/Vector-GPL-3.0-LICENSE"
cp "$ROOT/LICENSE" "$PACKAGE/licenses/MagiskPolicy-GPL-3.0-LICENSE"
"$ROOT/tools/collect_rust_licenses.sh" "$PACKAGE/licenses" \
  "$PACKAGE/licenses/BoomInstaller-LICENSE"

cp "$ROOT/assets.lock.json" "$CACHE/catalog.json"
while IFS=$'\t' read -r id filename expected_sha expected_size; do
  source=$(source_for "$id" "$filename") || {
    printf 'missing source mapping for %s\n' "$id" >&2
    exit 1
  }
  [[ -f "$source" ]] || {
    printf 'missing locked artifact %s: %s\n' "$id" "$source" >&2
    exit 1
  }
  actual_size=$(wc -c < "$source" | tr -d ' ')
  actual_sha=$(sha256_file "$source")
  [[ "$actual_size" == "$expected_size" ]] || {
    printf 'size mismatch for %s\n' "$id" >&2
    exit 1
  }
  [[ "$actual_sha" == "$expected_sha" ]] || {
    printf 'SHA-256 mismatch for %s\n' "$id" >&2
    exit 1
  }
  cp "$source" "$CACHE/blobs/$expected_sha"
  chmod 600 "$CACHE/blobs/$expected_sha"
done < <(jq -r '.artifacts[] | select(.embedded == true) | [.id,.filename,.sha256,(.size|tostring)] | @tsv' "$ROOT/assets.lock.json")

"$ROOT/tools/sign_catalog.sh" "$CACHE/catalog.json" "$CACHE/catalog.sig"

(
  cd "$PACKAGE"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | \
    xargs -0 shasum -a 256 > SHA256SUMS
)

rm -f "$DIST/xpad2-v$VERSION-android-arm64" \
  "$DIST/xpad2-v$VERSION-android-arm64.zip" \
  "$DIST/xpad2-cache-v$VERSION.zip" \
  "$UPDATE_MANIFEST" "$UPDATE_SIGNATURE" "$CATALOG_SIGNATURE" \
  "$DELTA_INDEX" "$DELTA_SIGNATURE" "$DELTA_PATH" "$UPDATE_BUNDLE" \
  "$DIST/SHA256SUMS"
for manager_filename in "${MANAGER_FILES[@]}"; do
  rm -f "$DIST/$manager_filename"
done
cp "$BINARY" "$DIST/xpad2-v$VERSION-android-arm64"
chmod 755 "$DIST/xpad2-v$VERSION-android-arm64"
while IFS=$'\t' read -r manager_id manager_filename; do
  manager_source=$(source_for "$manager_id" "$manager_filename")
  cp "$manager_source" "$DIST/$manager_filename"
  chmod 644 "$DIST/$manager_filename"
done < <(jq -r '.artifacts[] | select(.id == "ksu-manager" or .id == "suu-manager") |
  [.id,.filename] | @tsv' "$ROOT/assets.lock.json")
(
  cd "$STAGE"
  zip -X -q -r "$DIST/xpad2-v$VERSION-android-arm64.zip" "xpad2-v$VERSION-android-arm64"
  zip -X -q -r "$DIST/xpad2-cache-v$VERSION.zip" xpad2-cache
)
cp "$ROOT/assets.lock.json" "$ROOT/sources.lock.json" "$DIST/"
cp "$CACHE/catalog.sig" "$CATALOG_SIGNATURE"
chmod 644 "$CATALOG_SIGNATURE"

BINARY_FILENAME="xpad2-v$VERSION-android-arm64"
CACHE_FILENAME="xpad2-cache-v$VERSION.zip"
BINARY_SIZE=$(wc -c < "$DIST/$BINARY_FILENAME" | tr -d ' ')
BINARY_SHA=$(sha256_file "$DIST/$BINARY_FILENAME")
CACHE_SIZE=$(wc -c < "$DIST/$CACHE_FILENAME" | tr -d ' ')
CACHE_SHA=$(sha256_file "$DIST/$CACHE_FILENAME")
CATALOG_SIZE=$(wc -c < "$ROOT/assets.lock.json" | tr -d ' ')
CATALOG_SHA=$(sha256_file "$ROOT/assets.lock.json")
CATALOG_VERSION=$(jq -r '.catalog_version' "$ROOT/assets.lock.json")
# Keep the network update manifest readable by pre-range v0.4.14 updaters.
# The complete signed range policy lives in catalog.json/catalog.sig and is
# independently checked by the candidate; /260 remains the compatibility
# anchor used by the legacy manifest schema.
PROFILE=$(jq -c '.profile | {build_fingerprint,kernel_release_prefix,abi}' \
  "$ROOT/assets.lock.json")

jq -n \
  --arg repository "$REPOSITORY" \
  --arg version "$VERSION" \
  --arg catalog_version "$CATALOG_VERSION" \
  --argjson profile "$PROFILE" \
  --arg binary_filename "$BINARY_FILENAME" \
  --arg binary_url "$REPOSITORY/releases/download/v$VERSION/$BINARY_FILENAME" \
  --argjson binary_size "$BINARY_SIZE" \
  --arg binary_sha "$BINARY_SHA" \
  --arg cache_filename "$CACHE_FILENAME" \
  --arg cache_url "$REPOSITORY/releases/download/v$VERSION/$CACHE_FILENAME" \
  --argjson cache_size "$CACHE_SIZE" \
  --arg cache_sha "$CACHE_SHA" \
  --argjson catalog_size "$CATALOG_SIZE" \
  --arg catalog_sha "$CATALOG_SHA" \
  --arg release_url "$REPOSITORY/releases/tag/v$VERSION" \
  '{
    schema: 1,
    kind: "xpad2-update",
    channel: "stable",
    repository: $repository,
    version: $version,
    catalog_version: $catalog_version,
    profile: $profile,
    binary: {
      filename: $binary_filename,
      url: $binary_url,
      size: $binary_size,
      sha256: $binary_sha
    },
    cache: {
      filename: $cache_filename,
      url: $cache_url,
      size: $cache_size,
      sha256: $cache_sha
    },
    catalog: {
      filename: "catalog.json",
      size: $catalog_size,
      sha256: $catalog_sha
    },
    release_url: $release_url
  }' > "$UPDATE_MANIFEST"
chmod 644 "$UPDATE_MANIFEST"
"$ROOT/tools/sign_catalog.sh" "$UPDATE_MANIFEST" "$UPDATE_SIGNATURE"

DELTA_BASE_SIZE=$(wc -c < "$DELTA_BASE_BINARY" | tr -d ' ')
DELTA_BASE_SHA=$(sha256_file "$DELTA_BASE_BINARY")
zstd --patch-from="$DELTA_BASE_BINARY" "$DIST/$BINARY_FILENAME" -19 -q -f \
  -o "$DELTA_PATH"
chmod 644 "$DELTA_PATH"
DELTA_SIZE=$(wc -c < "$DELTA_PATH" | tr -d ' ')
DELTA_SHA=$(sha256_file "$DELTA_PATH")
((DELTA_SIZE < BINARY_SIZE)) || {
  printf 'delta is not smaller than the target binary\n' >&2
  exit 1
}
jq -n \
  --arg repository "$REPOSITORY" \
  --arg target_version "$VERSION" \
  --argjson target_binary "$(jq -c '.binary' "$UPDATE_MANIFEST")" \
  --arg from_version "$DELTA_BASE_VERSION" \
  --argjson from_size "$DELTA_BASE_SIZE" \
  --arg from_sha "$DELTA_BASE_SHA" \
  --arg patch_filename "$DELTA_FILENAME" \
  --arg patch_url "$REPOSITORY/releases/download/v$VERSION/$DELTA_FILENAME" \
  --argjson patch_size "$DELTA_SIZE" \
  --arg patch_sha "$DELTA_SHA" \
  '{
    schema: 1,
    kind: "xpad2-deltas",
    repository: $repository,
    target_version: $target_version,
    target_binary: $target_binary,
    deltas: [{
      from_version: $from_version,
      from_size: $from_size,
      from_sha256: $from_sha,
      patch: {
        filename: $patch_filename,
        url: $patch_url,
        size: $patch_size,
        sha256: $patch_sha
      }
    }]
  }' > "$DELTA_INDEX"
chmod 644 "$DELTA_INDEX"
"$ROOT/tools/sign_catalog.sh" "$DELTA_INDEX" "$DELTA_SIGNATURE"

rm -rf "$UPDATE_PACKAGE"
mkdir -p "$UPDATE_PACKAGE"
cp "$UPDATE_MANIFEST" "$UPDATE_SIGNATURE" "$CATALOG_SIGNATURE" "$DIST/$BINARY_FILENAME" \
  "$DIST/$CACHE_FILENAME" "$DELTA_INDEX" "$DELTA_SIGNATURE" "$DELTA_PATH" \
  "$UPDATE_PACKAGE/"
chmod 755 "$UPDATE_PACKAGE/$BINARY_FILENAME"
chmod 644 "$UPDATE_PACKAGE/xpad2-update.json" \
  "$UPDATE_PACKAGE/xpad2-update.json.sig" \
  "$UPDATE_PACKAGE/catalog.sig" \
  "$UPDATE_PACKAGE/xpad2-deltas.json" \
  "$UPDATE_PACKAGE/xpad2-deltas.json.sig" \
  "$UPDATE_PACKAGE/$DELTA_FILENAME" \
  "$UPDATE_PACKAGE/$CACHE_FILENAME"
(
  cd "$STAGE"
  zip -X -q -r "$UPDATE_BUNDLE" xpad2-update
)

(
  cd "$DIST"
  shasum -a 256 \
    "xpad2-v$VERSION-android-arm64" \
    "xpad2-v$VERSION-android-arm64.zip" \
    "xpad2-cache-v$VERSION.zip" \
    "${MANAGER_FILES[@]}" \
    assets.lock.json sources.lock.json \
    xpad2-update.json xpad2-update.json.sig catalog.sig \
    xpad2-deltas.json xpad2-deltas.json.sig "$DELTA_FILENAME" \
    "xpad2-update-v$VERSION.zip" > SHA256SUMS
)
rm -rf "$STAGE"

printf 'XPAD2_RELEASE_OK version=%s dist=%s\n' "$VERSION" "$DIST"
