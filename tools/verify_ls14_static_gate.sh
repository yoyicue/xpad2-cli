#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tools/verify_ls14_static_gate.sh \
  LS12_260_BOOT LS12_260_SYSTEM LS12_260_VENDOR \
  LS14_262_BOOT LS14_262_SYSTEM LS14_262_VENDOR \
  LS14_272_BOOT LS14_272_SYSTEM LS14_272_VENDOR \
  KSU_MODULE SUU_MODULE NEOZYGISK_ZIP VECTOR_ZIP

Environment overrides:
  KALLSYMS_FINDER=/path/to/kallsyms-finder
  DEBUGFS=/path/to/debugfs
EOF
  exit 2
}

[[ $# -eq 13 ]] || usage

LS12_BOOT=$1
LS12_SYSTEM=$2
LS12_VENDOR=$3
LS14_262_BOOT=$4
LS14_262_SYSTEM=$5
LS14_262_VENDOR=$6
LS14_272_BOOT=$7
LS14_272_SYSTEM=$8
LS14_272_VENDOR=$9
KSU_MODULE=${10}
SUU_MODULE=${11}
NEOZYGISK_ZIP=${12}
VECTOR_ZIP=${13}

for input_file in "$@"; do
  [[ -f "$input_file" ]] || {
    printf 'missing static-gate input: %s\n' "$input_file" >&2
    exit 1
  }
done

KALLSYMS_FINDER=${KALLSYMS_FINDER:-$(command -v kallsyms-finder || true)}
if [[ -z "$KALLSYMS_FINDER" ]]; then
  printf 'kallsyms-finder is required\n' >&2
  exit 1
fi

if [[ -z "${DEBUGFS:-}" ]]; then
  if command -v debugfs >/dev/null 2>&1; then
    DEBUGFS=$(command -v debugfs)
  elif [[ -x /opt/homebrew/opt/e2fsprogs/sbin/debugfs ]]; then
    DEBUGFS=/opt/homebrew/opt/e2fsprogs/sbin/debugfs
  else
    printf 'debugfs from e2fsprogs is required\n' >&2
    exit 1
  fi
fi

for required_command in awk cmp cut dd file grep gzip od readelf sed sha256sum sort strings unzip wc; do
  command -v "$required_command" >/dev/null 2>&1 || {
    printf 'required command is missing: %s\n' "$required_command" >&2
    exit 1
  }
done

AUDIT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/xpad2-ls14-static.XXXXXX")
trap 'rm -rf "$AUDIT_DIR"' EXIT

fail() {
  printf 'STATIC_GATE_FAIL %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'STATIC_GATE_OK %s\n' "$*"
}

expect_sha256() {
  local input_file=$1
  local expected=$2
  local actual
  actual=$(sha256sum "$input_file" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] || fail "sha256 file=$input_file expected=$expected actual=$actual"
}

le32_at() {
  local input_file=$1
  local offset=$2
  od -An -tu4 -j "$offset" -N 4 "$input_file" | awk '{print $1}'
}

extract_kernel_evidence() {
  local label=$1
  local boot_image=$2
  local output_dir="$AUDIT_DIR/$label"
  local kernel_size
  local page_size
  local config_offset

  mkdir -p "$output_dir"
  [[ "$(dd if="$boot_image" bs=8 count=1 2>/dev/null)" == "ANDROID!" ]] ||
    fail "$label boot image has no ANDROID! magic"
  kernel_size=$(le32_at "$boot_image" 8)
  page_size=$(le32_at "$boot_image" 36)
  [[ "$kernel_size" -gt 0 && "$page_size" -ge 2048 ]] ||
    fail "$label has invalid kernel size or page size"

  dd if="$boot_image" of="$output_dir/kernel.gz" bs=1 skip="$page_size" \
    count="$kernel_size" status=none
  gzip -dc "$output_dir/kernel.gz" >"$output_dir/Image"

  strings -a "$output_dir/Image" >"$output_dir/strings"
  grep -m1 '^Linux version 4\.19\.191+' "$output_dir/strings" \
    >"$output_dir/linux-version" ||
    fail "$label is not the audited Linux 4.19.191 kernel"

  config_offset=$(LC_ALL=C grep -aob -m1 'IKCFG_ST' "$output_dir/Image" |
    cut -d: -f1)
  [[ -n "$config_offset" ]] || fail "$label has no embedded IKCONFIG"
  dd if="$output_dir/Image" bs=1 skip="$((config_offset + 8))" status=none |
    gzip -dc >"$output_dir/config" 2>/dev/null || [[ -s "$output_dir/config" ]]

  "$KALLSYMS_FINDER" --use-absolute "$output_dir/Image" \
    >"$output_dir/kallsyms" 2>"$output_dir/kallsyms.log"
  awk '{print $3}' "$output_dir/kallsyms" | LC_ALL=C sort -u >"$output_dir/names"
  pass "$label kernel=$(sha256sum "$output_dir/Image" | awk '{print $1}')"
}

extract_kernel_evidence ls12-260 "$LS12_BOOT"
extract_kernel_evidence ls14-262 "$LS14_262_BOOT"
extract_kernel_evidence ls14-272 "$LS14_272_BOOT"

grep -q '#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026' \
  "$AUDIT_DIR/ls12-260/linux-version" || fail "LS12 /260 kernel build string mismatch"
grep -q '#1 SMP PREEMPT Mon Jun 29 05:28:07 CST 2026' \
  "$AUDIT_DIR/ls14-262/linux-version" || fail "LS14 /262 kernel build string mismatch"
grep -q '#1 SMP PREEMPT Thu Jul 23 20:38:25 CST 2026' \
  "$AUDIT_DIR/ls14-272/linux-version" || fail "LS14 /272 kernel build string mismatch"

cmp -s "$AUDIT_DIR/ls14-262/config" "$AUDIT_DIR/ls14-272/config" ||
  fail "LS14 /262 and /272 kernel configs differ"
cmp -s "$AUDIT_DIR/ls14-262/kallsyms" "$AUDIT_DIR/ls14-272/kallsyms" ||
  fail "LS14 /262 and /272 absolute kallsyms differ"
pass "LS14 /262 and /272 configs and absolute kallsyms are identical"

for config_key in \
  CONFIG_MODULES CONFIG_MODULE_UNLOAD CONFIG_MODVERSIONS CONFIG_SMP \
  CONFIG_PREEMPT CONFIG_THREAD_INFO_IN_TASK CONFIG_TRACEPOINTS CONFIG_FTRACE \
  CONFIG_ARM64 CONFIG_ARM64_4K_PAGES CONFIG_ARM64_VA_BITS \
  CONFIG_ARM64_MODULE_PLTS CONFIG_STACKPROTECTOR_STRONG CONFIG_LTO_NONE \
  CONFIG_SECURITY_SELINUX; do
  expected_line=$(grep -m1 "^${config_key}=" "$AUDIT_DIR/ls12-260/config" || true)
  [[ -n "$expected_line" ]] || fail "LS12 baseline lacks required $config_key"
  grep -qxF "$expected_line" "$AUDIT_DIR/ls14-262/config" ||
    fail "LS14 changed ABI-critical setting $config_key"
done
pass "LS12-to-LS14 ABI-critical kernel config is unchanged"

check_module() {
  local label=$1
  local module_file=$2
  local expected_sha=$3
  local module_dir="$AUDIT_DIR/module-$label"
  local vermagic
  local crc_hex

  mkdir -p "$module_dir"
  expect_sha256 "$module_file" "$expected_sha"
  vermagic=$(readelf -p .modinfo "$module_file" |
    sed -n 's/.*vermagic=//p' | head -1)
  [[ "$vermagic" == "4.19.191 SMP preempt mod_unload modversions aarch64" ]] ||
    fail "$label vermagic mismatch: $vermagic"
  crc_hex=$(readelf -x __versions "$module_file" |
    awk '$1 == "0x00000000" {print $2; exit}')
  [[ "$crc_hex" == "bfc5a373" ]] ||
    fail "$label module_layout CRC mismatch: $crc_hex"

  readelf -Ws "$module_file" |
    awk '$7 == "UND" && $8 != "" {print $8}' |
    LC_ALL=C sort -u >"$module_dir/imports"
  [[ -s "$module_dir/imports" ]] || fail "$label has no audited kernel imports"

  for kernel_label in ls12-260 ls14-262 ls14-272; do
    LC_ALL=C comm -23 "$module_dir/imports" "$AUDIT_DIR/$kernel_label/names" \
      >"$module_dir/missing-$kernel_label"
    [[ ! -s "$module_dir/missing-$kernel_label" ]] ||
      fail "$label has missing imports on $kernel_label"
    awk 'NR == FNR {wanted[$1] = 1; next} ($3 in wanted) {print $3, $1}' \
      "$module_dir/imports" "$AUDIT_DIR/$kernel_label/kallsyms" |
      LC_ALL=C sort -u >"$module_dir/addresses-$kernel_label"
  done
  cmp -s "$module_dir/addresses-ls14-262" "$module_dir/addresses-ls14-272" ||
    fail "$label imported-symbol addresses differ between LS14 /262 and /272"

  for kernel_label in ls12-260 ls14-262 ls14-272; do
    CRC_HEX=$crc_hex perl -0777 -ne '
      BEGIN { $needle = pack("H*", $ENV{"CRC_HEX"}); $count = 0 }
      $count++ while /\Q$needle\E/g;
      END { exit($count == 1 ? 0 : 1) }
    ' "$AUDIT_DIR/$kernel_label/Image" ||
      fail "$label module_layout CRC is not uniquely present in $kernel_label"
  done
  pass "$label imports=$(wc -l <"$module_dir/imports" | tr -d ' ') vermagic-and-crc=match"
}

check_module ksu "$KSU_MODULE" \
  e930a6929c6cd156f394e6b15bed2258b19205cc17fa3410db7f68cef7b8fb21
check_module suu "$SUU_MODULE" \
  5835dbed566e9711fab02c3b729e6dce495b996481af53c474f2be4816e7fd81

expect_prop() {
  local label=$1
  local system_image=$2
  local vendor_image=$3
  "$DEBUGFS" -R 'cat /system/build.prop' "$system_image" \
    >"$AUDIT_DIR/$label-system-build.prop" 2>/dev/null
  grep -qx 'ro.system.build.version.release=13' \
    "$AUDIT_DIR/$label-system-build.prop" || fail "$label is not Android 13"
  grep -qx 'ro.system.build.version.sdk=33' \
    "$AUDIT_DIR/$label-system-build.prop" || fail "$label is not SDK 33"
  "$DEBUGFS" -R 'cat /build.prop' "$vendor_image" \
    >"$AUDIT_DIR/$label-vendor-build.prop" 2>/dev/null
  grep -qx 'ro.zygote=zygote64_32' \
    "$AUDIT_DIR/$label-vendor-build.prop" || fail "$label is not zygote64_32"
}

expect_prop ls12-260 "$LS12_SYSTEM" "$LS12_VENDOR"
expect_prop ls14-262 "$LS14_262_SYSTEM" "$LS14_262_VENDOR"
expect_prop ls14-272 "$LS14_272_SYSTEM" "$LS14_272_VENDOR"

declare -a SYSTEM_FILES=(
  "app_process64:/system/bin/app_process64"
  "libandroid_runtime:/system/lib64/libandroid_runtime.so"
  "libbinder:/system/lib64/libbinder.so"
  "libart:/system/apex/com.android.art/lib64/libart.so"
  "libartbase:/system/apex/com.android.art/lib64/libartbase.so"
  "libnativebridge:/system/apex/com.android.art/lib64/libnativebridge.so"
  "libnativeloader:/system/apex/com.android.art/lib64/libnativeloader.so"
  "libc:/system/apex/com.android.runtime/lib64/bionic/libc.so"
  "linker64:/system/apex/com.android.runtime/bin/linker64"
)

for system_spec in "${SYSTEM_FILES[@]}"; do
  system_name=${system_spec%%:*}
  system_source=${system_spec#*:}
  for system_pair in \
    "ls12-260:$LS12_SYSTEM" \
    "ls14-262:$LS14_262_SYSTEM" \
    "ls14-272:$LS14_272_SYSTEM"; do
    system_label=${system_pair%%:*}
    system_image=${system_pair#*:}
    system_output="$AUDIT_DIR/$system_label-$system_name"
    "$DEBUGFS" -R "dump -p $system_source $system_output" \
      "$system_image" >/dev/null 2>&1
    [[ -s "$system_output" ]] || fail "$system_label lacks $system_source"
  done
  cmp -s "$AUDIT_DIR/ls12-260-$system_name" "$AUDIT_DIR/ls14-262-$system_name" ||
    fail "$system_name differs between LS12 /260 and LS14 /262"
  cmp -s "$AUDIT_DIR/ls12-260-$system_name" "$AUDIT_DIR/ls14-272-$system_name" ||
    fail "$system_name differs between LS12 /260 and LS14 /272"
done
pass "Android 13 zygote, ART, Binder, Bionic and linker compatibility set is byte-identical"

expect_sha256 "$NEOZYGISK_ZIP" \
  5c84df9f962c04855b3523a3a75022cf5e4f3ad3dfd94794ed92b43e911f3b9a
expect_sha256 "$VECTOR_ZIP" \
  d5e39669c02c2c699ab948eb8f3639b348eefb7749553224a9c62fa4a2f2dc18
unzip -tq "$NEOZYGISK_ZIP" >/dev/null
unzip -tq "$VECTOR_ZIP" >/dev/null
mkdir -p "$AUDIT_DIR/neo" "$AUDIT_DIR/vector"
unzip -q "$NEOZYGISK_ZIP" -d "$AUDIT_DIR/neo"
unzip -q "$VECTOR_ZIP" -d "$AUDIT_DIR/vector"

for hook_elf in \
  "$AUDIT_DIR/neo/bin/arm64-v8a/zygiskd" \
  "$AUDIT_DIR/neo/lib/arm64-v8a/libzygisk.so" \
  "$AUDIT_DIR/vector/lib/arm64-v8a/libzygisk.so" \
  "$AUDIT_DIR/vector/bin/arm64-v8a/liboat_hook.so"; do
  file "$hook_elf" | grep -q 'ARM aarch64' ||
    fail "hook artifact is not AArch64: $hook_elf"
done

context_hits=$(LC_ALL=C grep -aob 'u:object_r:zygisk_file:s0' \
  "$AUDIT_DIR/neo/bin/arm64-v8a/zygiskd" | wc -l | tr -d ' ')
[[ "$context_hits" == "1" ]] ||
  fail "NeoZygisk context replacement anchor count is $context_hits"
grep -q -- '--system-server-max-retry=3' "$AUDIT_DIR/vector/service.sh" ||
  fail "Vector retry-policy patch anchor is missing"
grep -q '/data/adb/neozygisk' "$AUDIT_DIR/neo/post-fs-data.sh" ||
  fail "NeoZygisk workdir patch anchor is missing"
pass "locked NeoZygisk and Vector arm64 patch anchors are exact"

printf 'XPAD2_LS14_STATIC_GATE status=pass profiles=262,272 ksu_imports=%s suu_imports=%s hook_core_files=%s\n' \
  "$(wc -l <"$AUDIT_DIR/module-ksu/imports" | tr -d ' ')" \
  "$(wc -l <"$AUDIT_DIR/module-suu/imports" | tr -d ' ')" \
  "${#SYSTEM_FILES[@]}"
