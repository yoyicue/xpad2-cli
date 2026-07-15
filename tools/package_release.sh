#!/usr/bin/env bash
set -euo pipefail

umask 022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PARENT=$(dirname "$ROOT")
VERSION=$(awk -F '"' '/^version = / {print $2; exit}' "$ROOT/Cargo.toml")
ARTIFACT_DIR=${XPAD2_ARTIFACT_DIR:-}
DIST="$ROOT/dist"
STAGE="$DIST/.stage-v$VERSION"
PACKAGE="$STAGE/xpad2-v$VERSION-android-arm64"
CACHE="$STAGE/xpad2-cache"
BINARY="$ROOT/target/aarch64-linux-android/release/xpad2"

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
    ionstack-runner) printf '%s\n' "$PARENT/xpad2-ionstack-poc/build/ionstack_reroot_device" ;;
    ionstack-perf-target) printf '%s\n' "$PARENT/xpad2-ionstack-poc/build/ionstack_perf_target" ;;
    ionstack-preload) printf '%s\n' "$PARENT/xpad2-ionstack-poc/build/ionstack_preload.so" ;;
    ionstack-chainwalk-probe) printf '%s\n' "$PARENT/xpad2-ionstack-poc/build/cve_2026_43499_chainwalk_probe_arm32" ;;
    ksud) printf '%s\n' "$PARENT/xpad2-ksu-lateload/artifacts/ksud-xpad2" ;;
    ksu-manager) printf '%s\n' "$PARENT/xpad2-reroot-android/app/src/main/res/raw/kernelsu_manager_v3_2_4_32457.apk" ;;
    xpad-installer) printf '%s\n' "$PARENT/xpad-installer/dist/xpad-install" ;;
    boominstaller) printf '%s\n' "$PARENT/BoomInstaller/out/apk/BoomInstaller-v13.6.0.r9.2f1ac6f-production.apk" ;;
    *) return 1 ;;
  esac
}

command -v jq >/dev/null || {
  printf 'jq is required\n' >&2
  exit 1
}
"$ROOT/tools/build_android.sh"

rm -rf "$STAGE"
mkdir -p "$PACKAGE/licenses" "$CACHE/blobs"
cp "$BINARY" "$PACKAGE/xpad2"
chmod 755 "$PACKAGE/xpad2"
cp "$ROOT/README.md" "$ROOT/BEGINNER_GUIDE.md" "$ROOT/DESIGN.md" \
  "$ROOT/NOTICE.md" "$ROOT/LICENSE" "$ROOT/assets.lock.json" \
  "$ROOT/sources.lock.json" "$PACKAGE/"

cp "$PARENT/xpad2-ionstack-poc/LICENSE" "$PACKAGE/licenses/xpad2-ionstack-poc-LICENSE"
cp "$PARENT/xpad2-ionstack-poc/NOTICE" "$PACKAGE/licenses/xpad2-ionstack-poc-NOTICE"
cp "$PARENT/xpad2-ionstack-poc/licenses/Apache-2.0.txt" \
  "$PACKAGE/licenses/xpad2-ionstack-poc-Apache-2.0-LICENSE"
cp "$PARENT/xpad2-ksu-lateload/LICENSE" "$PACKAGE/licenses/KernelSU-userspace-GPL-3.0-LICENSE"
cp "$PARENT/xpad2-ksu-lateload/kernel/LICENSE" "$PACKAGE/licenses/KernelSU-kernel-GPL-2.0-LICENSE"
cp "$PARENT/xpad-installer/LICENSE" "$PACKAGE/licenses/xpad-installer-LICENSE"
cp "$PARENT/BoomInstaller/LICENSE" "$PACKAGE/licenses/BoomInstaller-LICENSE"
cp "$PARENT/BoomInstaller/NOTICE.md" "$PACKAGE/licenses/BoomInstaller-NOTICE.md"
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
  "$DIST/xpad2-cache-v$VERSION.zip" "$DIST/SHA256SUMS"
cp "$BINARY" "$DIST/xpad2-v$VERSION-android-arm64"
chmod 755 "$DIST/xpad2-v$VERSION-android-arm64"
(
  cd "$STAGE"
  zip -X -q -r "$DIST/xpad2-v$VERSION-android-arm64.zip" "xpad2-v$VERSION-android-arm64"
  zip -X -q -r "$DIST/xpad2-cache-v$VERSION.zip" xpad2-cache
)
cp "$ROOT/assets.lock.json" "$ROOT/sources.lock.json" "$DIST/"
(
  cd "$DIST"
  shasum -a 256 \
    "xpad2-v$VERSION-android-arm64" \
    "xpad2-v$VERSION-android-arm64.zip" \
    "xpad2-cache-v$VERSION.zip" \
    assets.lock.json sources.lock.json > SHA256SUMS
)
rm -rf "$STAGE"

printf 'XPAD2_RELEASE_OK version=%s dist=%s\n' "$VERSION" "$DIST"
