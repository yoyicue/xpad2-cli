#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

command -v cargo >/dev/null || {
  printf 'cargo is required\n' >&2
  exit 1
}
cargo ndk --help >/dev/null 2>&1 || {
  printf 'cargo-ndk is required: cargo install cargo-ndk\n' >&2
  exit 1
}

cargo test --all
cargo ndk -t arm64-v8a -P 33 build --release

target_dir=${CARGO_TARGET_DIR:-$ROOT/target}
binary="$target_dir/aarch64-linux-android/release/xpad2"
[[ -x "$binary" ]] || {
  printf 'Android binary missing: %s\n' "$binary" >&2
  exit 1
}
file "$binary" | grep -q 'ARM aarch64' || {
  printf 'refusing non-AArch64 output: %s\n' "$binary" >&2
  exit 1
}

printf 'XPAD2_ANDROID_BUILD_OK path=%s sha256=%s\n' \
  "$binary" "$(shasum -a 256 "$binary" | awk '{print $1}')"
