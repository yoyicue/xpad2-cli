#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEST=${1:-}
APACHE_FALLBACK=${2:-}

die() {
  printf 'XPAD2_RUST_LICENSES_REFUSED reason=%s\n' "$1" >&2
  exit 1
}

[[ -n "$DEST" ]] || die destination-required
command -v cargo >/dev/null || die cargo-missing
command -v jq >/dev/null || die jq-missing

metadata=$(mktemp /tmp/xpad2-cargo-metadata.XXXXXX)
trap 'rm -f "$metadata"' EXIT
(
  cd "$ROOT"
  cargo metadata --format-version 1 --locked > "$metadata"
)

mkdir -p "$DEST/rust"
index="$DEST/Rust-THIRD-PARTY.md"
{
  printf '# Rust third-party licenses\n\n'
  printf 'Generated from the exact dependency graph selected by `Cargo.lock`.\n\n'
  printf '| Crate | Version | SPDX expression | Repository |\n'
  printf '| --- | --- | --- | --- |\n'
  jq -r '.packages[] | select(.source != null) |
    [.name,.version,(.license // "UNKNOWN"),(.repository // "-")] | @tsv' \
    "$metadata" | sort | while IFS=$'\t' read -r name version license repository; do
      printf '| `%s` | `%s` | `%s` | %s |\n' \
        "$name" "$version" "$license" "$repository"
    done
} > "$index"

count=0
while IFS=$'\t' read -r name version license manifest; do
  count=$((count + 1))
  crate_dir=$(dirname "$manifest")
  crate_dest="$DEST/rust/$name-$version"
  mkdir -p "$crate_dest"
  copied=0
  while IFS= read -r -d '' license_file; do
    cp "$license_file" "$crate_dest/$(basename "$license_file")"
    copied=$((copied + 1))
  done < <(find "$crate_dir" -maxdepth 1 -type f \
    \( -iname 'license*' -o -iname 'copying*' -o -iname 'notice*' \) \
    -print0 | sort -z)

  # Some crates publish a valid SPDX choice but omit license text from the
  # crates.io archive. Select Apache-2.0 when the expression explicitly
  # permits it, and ship the canonical text supplied by the release tree.
  if ((copied == 0)) && [[ "$license" == *"Apache-2.0"* && -f "$APACHE_FALLBACK" ]]; then
    cp "$APACHE_FALLBACK" "$crate_dest/LICENSE-APACHE-2.0"
    copied=1
  fi
  ((copied > 0)) || die "license-files-missing-$name-$version"
done < <(jq -r '.packages[] | select(.source != null) |
  [.name,.version,(.license // "UNKNOWN"),.manifest_path] | @tsv' "$metadata" | sort)

printf 'XPAD2_RUST_LICENSES_OK packages=%s destination=%s\n' "$count" "$DEST"
