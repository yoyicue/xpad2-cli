#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CATALOG="$ROOT/assets.lock.json"
REPORT="$ROOT/static-validation/ls14-262-272.json"

command -v jq >/dev/null || {
  printf 'jq is required to verify the LS14 static-gate record\n' >&2
  exit 1
}
[[ -f "$REPORT" ]] || {
  printf 'LS14 static-gate record is missing: %s\n' "$REPORT" >&2
  exit 1
}

jq -e --slurpfile catalog "$CATALOG" '
  .schema == 1 and
  .kind == "xpad2-ls14-static-validation" and
  .status == "pass" and
  (.profiles | length) == 3 and
  (.kernel_modules | keys | sort) == ["ksu", "suu"] and
  (.hook_artifacts | keys | sort) == ["neozygisk", "vector"] and
  ([.profiles[] | select(.device_profile_id == "xpad2p") |
      .fingerprint_incremental] | sort) == [262, 272] and
  ([.profiles[] | select(.device_profile_id == "xpad2p") |
      {fingerprint_incremental, kernel_version}] | sort_by(.fingerprint_incremental)) ==
    ([$catalog[0].ionstack_profiles_v2[] |
        select(.device_profile_id == "xpad2p") | .exact_tuples[]] |
      sort_by(.fingerprint_incremental)) and
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
  .checks.ls14_262_272_config_identical and
  .checks.ls14_262_272_absolute_kallsyms_identical and
  .checks.abi_critical_kernel_config_equal_to_ls12 and
  .checks.module_layout_crc_unique_in_all_kernels and
  .checks.ls14_imported_symbol_addresses_identical and
  .checks.android_release == "13" and
  .checks.android_sdk == 33 and
  .checks.zygote_mode == "zygote64_32" and
  .checks.byte_identical_hook_core_files == 9 and
  (.checks.hook_core_set | sort) ==
    (["app_process64", "libandroid_runtime.so", "libbinder.so",
      "libart.so", "libartbase.so", "libnativebridge.so",
      "libnativeloader.so", "libc.so", "linker64"] | sort) and
  ($catalog[0].device_profiles[] |
    select(.id == "xpad2p") |
    .late_load_supported and .hooks_supported)
' "$REPORT" >/dev/null || {
  printf 'LS14 static-gate record does not authorize the locked catalog\n' >&2
  exit 1
}

printf 'XPAD2_LS14_STATIC_GATE_RECORD_OK profiles=262,272\n'
