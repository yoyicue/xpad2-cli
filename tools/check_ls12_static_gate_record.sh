#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CATALOG="$ROOT/assets.lock.json"
REPORT="$ROOT/static-validation/ls12-260-308.json"

command -v jq >/dev/null || {
  printf 'jq is required to verify the LS12 static-gate record\n' >&2
  exit 1
}
[[ -f "$REPORT" ]] || {
  printf 'LS12 static-gate record is missing: %s\n' "$REPORT" >&2
  exit 1
}

jq -e --slurpfile catalog "$CATALOG" '
  .schema == 1 and
  .kind == "xpad2-ls12-static-validation" and
  .status == "pass" and
  (.profiles | length) == 3 and
  (.kernel_modules | keys | sort) == ["ksu", "suu"] and
  (.hook_artifacts | keys | sort) == ["neozygisk", "vector"] and
  ([.profiles[] | .fingerprint_incremental] | sort) == [260, 272, 308] and
  ([.profiles[] | {fingerprint_incremental, kernel_version}] |
    sort_by(.fingerprint_incremental)) ==
    ([$catalog[0].ionstack_profiles_v2[] |
        select(.id == "xpad2-v260-v308") | .exact_tuples[]] |
      sort_by(.fingerprint_incremental)) and
  ([.profiles[] | select(.fingerprint_incremental == 308) | .config_sha256] ==
    [.profiles[] | select(.fingerprint_incremental == 260) | .config_sha256]) and
  ([.kernel_modules[] |
    . as $module |
    $module.missing_imports == 0 and
    $module.vermagic ==
      "4.19.191 SMP preempt mod_unload modversions aarch64" and
    $module.module_layout_crc_le == "bfc5a373" and
    $module.sha256 ==
      ($catalog[0].artifacts[] |
        select(.id == $module.artifact_id) | .sha256)] | all) and
  ([.hook_artifacts[] |
    . as $hook |
    $hook.architecture == "aarch64" and
    $hook.patch_anchor_count == 1 and
    $hook.sha256 ==
      ($catalog[0].artifacts[] |
        select(.id == $hook.artifact_id) | .sha256)] | all) and
  .checks.ls12_260_272_config_identical and
  .checks.ls12_260_272_absolute_kallsyms_identical and
  .checks.ls12_260_272_uncompressed_image_byte_differences == 48 and
  .checks.ls12_308_config_sha256_matches_260_272 and
  .checks.ls12_308_offset_anchors_match_catalog and
  (.checks.ls12_308_offset_anchor_symbols | length) >= 7 and
  .checks.ls12_260523_to_308_uncompressed_image_byte_differences == 50 and
  .checks.ls12_308_differences_confined_to_banner_build_id_timestamps and
  .checks.ls12_308_post_sdk_level == 33 and
  .checks.ls12_308_post_security_patch_level == "2023-06-05" and
  .checks.module_layout_crc_unique_in_both_kernels and
  .checks.module_imported_symbol_addresses_identical and
  .checks.android_release == "13" and
  .checks.android_sdk == 33 and
  .checks.zygote_mode == "zygote64_32" and
  .checks.byte_identical_hook_core_files == 9 and
  (.checks.hook_core_set | sort) ==
    (["app_process64", "libandroid_runtime.so", "libbinder.so",
      "libart.so", "libartbase.so", "libnativebridge.so",
      "libnativeloader.so", "libc.so", "linker64"] | sort) and
  ($catalog[0].device_profiles[] |
    select(.id == "xpad2") |
    .fingerprint_incremental_min == 19 and
    .fingerprint_incremental_max == 308 and
    .late_load_supported and .hooks_supported)
' "$REPORT" >/dev/null || {
  printf 'LS12 static-gate record does not authorize the locked catalog\n' >&2
  exit 1
}

printf 'XPAD2_LS12_STATIC_GATE_RECORD_OK profiles=260,272,308\n'
