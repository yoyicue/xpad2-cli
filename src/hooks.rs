use crate::catalog::Catalog;
use crate::device;
use crate::error::{IoContext, Result, msg};
use crate::logging::TransactionLog;
use crate::model::{ComponentState, ComponentStatus};
use crate::root::{self, RootSession};
use crate::runtime;
use crate::util::{Paths, atomic_write, sha256_bytes, shell_quote};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

const KSU_MODULES_UPDATE: &str = "/data/adb/modules_update";
const KSUD: &str = "/data/adb/ksud";
const MAGISKPOLICY_ARTIFACT: &str = "magiskpolicy";
const MAGISKPOLICY: &str = "/data/adb/xpad2/bin/magiskpolicy";
const VECTOR_POLICY_MARKER: &str = "minimal-live-vector-dex2oat-v1";
const VECTOR_LIVE_POLICY_RULES: &str = "\
allow system_server system_server process execmem
allow dex2oat dex2oat_exec file execute_no_trans
allow dex2oat system_linker_exec file execute_no_trans
allow dex2oat tmpfs file { ioctl read write create getattr setattr lock append map execute open }
allow zygote dex2oat unix_stream_socket { read write getattr getopt setopt shutdown connectto }
allow shell shell dir write
type xposed_file file_type
typeattribute xposed_file mlstrustedobject
allow dex2oat xposed_file file { read getattr map open }
allow zygote xposed_file file { read getattr map open }
allow installd xposed_file file { ioctl read write create getattr setattr lock unlink rename open }
allow installd xposed_file dir { ioctl read write create getattr setattr lock unlink rename open search add_name remove_name rmdir }
allow shell xposed_file file { ioctl read write create getattr setattr lock append map unlink rename open }
allow shell xposed_file dir { ioctl read write create getattr setattr lock unlink rename open search add_name remove_name rmdir }
allow isolated_app xposed_file file { read getattr map open }
allow isolated_app xposed_file dir { read getattr open search }
type xposed_data file_type
typeattribute xposed_data mlstrustedobject
allow appdomain xposed_data file { ioctl read getattr lock map execute open }
allow appdomain xposed_data dir { ioctl read getattr open search }
allow system_server xposed_data file { ioctl read getattr lock map execute open }
allow system_server xposed_data dir { ioctl read getattr open search }
";
const VECTOR_REVOKE_CORE_RULES: &str = "\
deny system_server system_server process execmem
deny dex2oat dex2oat_exec file execute_no_trans
deny dex2oat system_linker_exec file execute_no_trans
deny dex2oat tmpfs file { ioctl write create setattr lock append execute open }
deny zygote dex2oat unix_stream_socket { read write getattr getopt setopt shutdown connectto }
deny shell shell dir write
";
const VECTOR_REVOKE_XPOSED_FILE_RULES: &str = "\
deny dex2oat xposed_file file *
deny zygote xposed_file file *
deny installd xposed_file { file dir } *
deny shell xposed_file { file dir } *
deny isolated_app xposed_file { file dir } *
";
const VECTOR_REVOKE_XPOSED_DATA_RULES: &str = "\
deny appdomain xposed_data { file dir } *
deny system_server xposed_data { file dir } *
";
const UNMOUNT_DEX2OAT_BINDS: &str = r#"for xpad2_target in \
  /apex/com.android.art/bin/dex2oat32 \
  /apex/com.android.art/bin/dex2oatd32 \
  /apex/com.android.art/bin/dex2oat64 \
  /apex/com.android.art/bin/dex2oatd64 \
  /system/apex/com.android.art/bin/dex2oat32 \
  /system/apex/com.android.art/bin/dex2oatd32 \
  /system/apex/com.android.art/bin/dex2oat64 \
  /system/apex/com.android.art/bin/dex2oatd64; do
  while grep -q " $xpad2_target " /proc/1/mountinfo 2>/dev/null; do
    umount -l "$xpad2_target" 2>/dev/null || umount "$xpad2_target" 2>/dev/null || break
  done
done
"#;

const VECTOR_POLICY_AWK_CHECK: &str = r#"awk '
  /^allow system_server system_server process / && /execmem/ { r1=1 }
  /^allow dex2oat dex2oat_exec file / && /execute_no_trans/ { r2=1 }
  /^allow dex2oat system_linker_exec file / && /execute_no_trans/ { r3=1 }
  /^allow dex2oat tmpfs file / && /execute/ && /write/ { r4=1 }
  /^allow zygote dex2oat unix_stream_socket / && /connectto/ { r5=1 }
  /^allow shell shell dir / && /write/ { r10=1 }
  /^type xposed_file / { r6=1 }
  /^type xposed_data / { r7=1 }
  /^allow dex2oat xposed_file file / && /read/ { r8=1 }
  /^allow appdomain xposed_data file / && /read/ { r9=1 }
  /^allow untrusted_app dex2oat_exec file / && /(execute|execute_no_trans)/ { bad=1 }
  END { exit (r1 && r2 && r3 && r4 && r5 && r6 && r7 && r8 && r9 && r10 && !bad) ? 0 : 1 }
'"#;

const ZYGISK_ARTIFACT: &str = "neozygisk-module";
const ZYGISK_MODULE: &str = "zygisksu";
const ZYGISK_VERSION_CODE: &str = "289";
const ZYGISK_MARKER: &str = "xpad2-ls12-compat";

const VECTOR_ARTIFACT: &str = "vector-module";
const VECTOR_MODULE: &str = "zygisk_vector";
const VECTOR_VERSION_CODE: &str = "3080";
const VECTOR_MARKER: &str = "xpad2-ls12-compat";

const STOCK_ZYGISK_CONTEXT: &[u8] = b"u:object_r:zygisk_file:s0";
const LS12_ZYGISK_CONTEXT: &[u8] = b"u:object_r:ksu_file:s0:c0";
const STOCK_ZYGISK_WORKDIR: &[u8] = b"/data/adb/neozygisk\0";
const LS12_ZYGISK_WORKDIR: &[u8] = b"/dev/neozygisk\0\0\0\0\0\0";

#[derive(Clone, Copy)]
struct HookSpec {
    id: &'static str,
    artifact: &'static str,
    module: &'static str,
    version_code: &'static str,
}

const ZYGISK: HookSpec = HookSpec {
    id: "zygisk",
    artifact: ZYGISK_ARTIFACT,
    module: ZYGISK_MODULE,
    version_code: ZYGISK_VERSION_CODE,
};

const VECTOR: HookSpec = HookSpec {
    id: "vector",
    artifact: VECTOR_ARTIFACT,
    module: VECTOR_MODULE,
    version_code: VECTOR_VERSION_CODE,
};

struct ModuleInfo {
    enabled: bool,
    update: bool,
    version_code: String,
}

pub fn canonical_id(id: &str) -> &str {
    match id {
        "lsposed" => "vector",
        other => other,
    }
}

pub fn status(id: &str) -> ComponentStatus {
    match canonical_id(id) {
        "zygisk" => zygisk_status(),
        "vector" => vector_status(),
        _ => component_status(id, ComponentState::Absent, Some("unknown hook component")),
    }
}

pub fn zygisk_status() -> ComponentStatus {
    if !device::ksu_module_loaded() {
        return component_status(
            ZYGISK.id,
            ComponentState::Absent,
            Some("KernelSU is not loaded in this boot"),
        );
    }
    match zygisk_status_inner() {
        Ok(state) => state,
        Err(error) => component_status(
            ZYGISK.id,
            ComponentState::Broken,
            Some(&format!("cannot verify NeoZygisk: {error}")),
        ),
    }
}

fn zygisk_status_inner() -> Result<ComponentStatus> {
    let Some(module) = module_info(ZYGISK.module)? else {
        return Ok(component_status(ZYGISK.id, ComponentState::Absent, None));
    };
    if module.version_code != ZYGISK.version_code {
        return Ok(component_status(
            ZYGISK.id,
            ComponentState::Outdated,
            Some(&format!(
                "module versionCode={} expected={}",
                module.version_code, ZYGISK.version_code
            )),
        ));
    }
    if module.update {
        return Ok(component_status(
            ZYGISK.id,
            ComponentState::Ready,
            Some("NeoZygisk is staged; run `xpad2 hooks activate`"),
        ));
    }
    if !module.enabled {
        return Ok(component_status(
            ZYGISK.id,
            ComponentState::Installed,
            Some("NeoZygisk is installed but disabled"),
        ));
    }
    let health = root::root_exec(
        r#"
prop=/dev/neozygisk/module.prop
marker=/data/adb/modules/zygisksu/xpad2-ls12-compat
monitor=bad
zygote=bad
daemon=bad
monitor_count=0
daemon_count=0
map=bad
compat=bad
module_fd=none
enforcing=bad
test "$(getenforce 2>/dev/null)" = Enforcing && enforcing=ok
grep -q 'monitor:.*tracing' "$prop" 2>/dev/null && monitor=ok
grep -q 'zygote64:.*injected' "$prop" 2>/dev/null && zygote=ok
grep -q 'daemon64:.*running' "$prop" 2>/dev/null && daemon=ok
set -- $(pidof zygisk-ptrace64 2>/dev/null)
monitor_count=$#
set -- $(pidof zygiskd64 2>/dev/null)
daemon_count=$#
zygote_pid=$(pidof zygote64 2>/dev/null | awk '{print $1}')
if [ -n "$zygote_pid" ]; then
  grep -q '/dev/neozygisk/lib64/libzygisk.so' "/proc/$zygote_pid/maps" 2>/dev/null && map=ok
fi
if grep -q '^module_memfd_context=u:object_r:ksu_file:s0:c0$' "$marker" 2>/dev/null && \
   grep -q '^ptrace_workdir=/dev/neozygisk$' "$marker" 2>/dev/null; then
  compat=ok
fi
zygiskd_pid=$(pidof zygiskd64 2>/dev/null | awk '{print $1}')
if [ -n "$zygiskd_pid" ]; then
  for fd in /proc/$zygiskd_pid/fd/*; do
    target=$(readlink "$fd" 2>/dev/null)
    case "$target" in
      *memfd:zygisk-module*)
        module_fd=bad
        ls -lZL "$fd" 2>/dev/null | grep -q 'u:object_r:ksu_file:s0:c0' && module_fd=ok
        ;;
    esac
  done
fi
printf 'XPAD2_ZYGISK_HEALTH enforcing=%s monitor=%s zygote=%s daemon=%s monitor_count=%s daemon_count=%s map=%s compat=%s module_fd=%s\n' \
  "$enforcing" "$monitor" "$zygote" "$daemon" "$monitor_count" "$daemon_count" "$map" "$compat" "$module_fd"
[ "$monitor" = ok ] && [ "$zygote" = ok ] && [ "$daemon" = ok ] && \
  [ "$monitor_count" = 1 ] && [ "$daemon_count" = 1 ] && [ "$map" = ok ] && \
  [ "$compat" = ok ] && [ "$module_fd" != bad ] && [ "$enforcing" = ok ]
"#,
    )?;
    if health.status == 0
        && health
            .text
            .contains("XPAD2_ZYGISK_HEALTH enforcing=ok monitor=ok")
    {
        Ok(component_status(
            ZYGISK.id,
            ComponentState::Active,
            Some("NeoZygisk v2.4 injected into zygote64; XPad2 compatibility verified"),
        ))
    } else {
        Ok(component_status(
            ZYGISK.id,
            ComponentState::Broken,
            Some(&format!("strict health check failed: {}", health.text)),
        ))
    }
}

pub fn vector_status() -> ComponentStatus {
    if !device::ksu_module_loaded() {
        return component_status(
            VECTOR.id,
            ComponentState::Absent,
            Some("KernelSU is not loaded in this boot"),
        );
    }
    match vector_status_inner() {
        Ok(state) => state,
        Err(error) => component_status(
            VECTOR.id,
            ComponentState::Broken,
            Some(&format!("cannot verify Vector: {error}")),
        ),
    }
}

fn vector_status_inner() -> Result<ComponentStatus> {
    let Some(module) = module_info(VECTOR.module)? else {
        return Ok(component_status(VECTOR.id, ComponentState::Absent, None));
    };
    if module.version_code != VECTOR.version_code {
        return Ok(component_status(
            VECTOR.id,
            ComponentState::Outdated,
            Some(&format!(
                "module versionCode={} expected={}",
                module.version_code, VECTOR.version_code
            )),
        ));
    }
    if module.update {
        return Ok(component_status(
            VECTOR.id,
            ComponentState::Ready,
            Some("Vector is staged; run `xpad2 hooks activate`"),
        ));
    }
    if !module.enabled {
        return Ok(component_status(
            VECTOR.id,
            ComponentState::Installed,
            Some("Vector is installed but disabled"),
        ));
    }
    let zygisk = zygisk_status_inner()?;
    if zygisk.state != ComponentState::Active {
        return Ok(component_status(
            VECTOR.id,
            if zygisk.state == ComponentState::Ready {
                ComponentState::Ready
            } else {
                ComponentState::Broken
            },
            Some("Vector is enabled but its NeoZygisk dependency is not active"),
        ));
    }
    let health = root::root_exec(&format!(
        r#"
compat=bad
vectord_count=0
registered=bad
database=bad
policy=bad
dex2oat=bad
system_map=bad
bridge=bad
enforcing=bad
test "$(getenforce 2>/dev/null)" = Enforcing && enforcing=ok
marker=/data/adb/modules/zygisk_vector/xpad2-ls12-compat
if grep -q '^system_server=true$' "$marker" 2>/dev/null && \
   grep -q '^dex2oat=true$' "$marker" 2>/dev/null && \
   grep -q '^policy=minimal-live-vector-dex2oat-v1$' "$marker" 2>/dev/null && \
   grep -q -- '--system-server-max-retry=0' /data/adb/modules/zygisk_vector/service.sh 2>/dev/null; then
  compat=ok
fi
set -- $(pidof vectord 2>/dev/null)
vectord_count=$#
grep -q 'zygisk_vector' /dev/neozygisk/module.prop 2>/dev/null && registered=ok
[ -f /data/adb/lspd/config/modules_config.db ] && database=ok
if /data/adb/xpad2/bin/magiskpolicy --print-rules 2>/dev/null | {policy_check}; then
  policy=ok
fi
if [ -f /data/adb/modules/zygisk_vector/bin/dex2oat64 ] && [ -f /apex/com.android.art/bin/dex2oat64 ]; then
  mod_ino=$(stat -c '%d:%i' /data/adb/modules/zygisk_vector/bin/dex2oat64 2>/dev/null)
  apex_ino=$(stat -c '%d:%i' /apex/com.android.art/bin/dex2oat64 2>/dev/null)
  if [ -n "$mod_ino" ] && [ "$mod_ino" = "$apex_ino" ] && \
     ls -Z /apex/com.android.art/bin/dex2oat64 2>/dev/null | grep -q 'u:object_r:dex2oat_exec:s0'; then
    dex2oat=ok
  fi
fi
system_pid=$(pidof system_server 2>/dev/null | awk '{{print $1}}')
if [ -n "$system_pid" ]; then
  grep -q '/memfd:zygisk-module' "/proc/$system_pid/maps" 2>/dev/null && system_map=ok
fi
verbose=$(ls -1t /data/adb/lspd/log/verbose_* 2>/dev/null | head -n 1)
if [ -n "$verbose" ] && [ -n "$system_pid" ]; then
  grep -Eq ": *$system_pid:.*Injected Vector framework into system_server" "$verbose" 2>/dev/null && bridge=ok
fi
printf 'XPAD2_VECTOR_HEALTH enforcing=%s compat=%s vectord_count=%s registered=%s database=%s policy=%s dex2oat=%s system_map=%s bridge=%s\n' \
  "$enforcing" "$compat" "$vectord_count" "$registered" "$database" "$policy" "$dex2oat" "$system_map" "$bridge"
[ "$compat" = ok ] && [ "$vectord_count" = 1 ] && [ "$registered" = ok ] && \
  [ "$database" = ok ] && [ "$policy" = ok ] && [ "$dex2oat" = ok ] && \
  [ "$system_map" = ok ] && [ "$bridge" = ok ] && [ "$enforcing" = ok ]
"#,
        policy_check = VECTOR_POLICY_AWK_CHECK,
    ))?;
    if health.status == 0
        && health
            .text
            .contains("XPAD2_VECTOR_HEALTH enforcing=ok compat=ok")
    {
        Ok(component_status(
            VECTOR.id,
            ComponentState::Active,
            Some(&format!(
                "Vector v2.2 bridge and dex2oat active under Enforcing SELinux; {}",
                health.text
            )),
        ))
    } else {
        Ok(component_status(
            VECTOR.id,
            ComponentState::Broken,
            Some(&format!("strict health check failed: {}", health.text)),
        ))
    }
}

pub fn install_component(
    catalog: &Catalog,
    paths: &Paths,
    id: &str,
    root: &RootSession,
    log: &mut TransactionLog,
) -> Result<bool> {
    let spec = match canonical_id(id) {
        "zygisk" => ZYGISK,
        "vector" => VECTOR,
        _ => return Err(msg(format!("unknown hook component: {id}"))),
    };
    root.check_boot()?;
    let before = status(spec.id);
    if before.state == ComponentState::Active {
        log.event(
            "component",
            "skipped",
            json!({"id": spec.id, "reason": "strict health check passed"}),
        )?;
        println!("✓ {}: 当前启动周期已严格验活，跳过", spec.id);
        return Ok(false);
    }

    let artifact = catalog.artifact(spec.artifact)?;
    let resolved = catalog.resolve(spec.artifact, paths)?;
    let bytes = resolved.load()?;
    if bytes.len() as u64 != artifact.size || sha256_bytes(&bytes) != artifact.sha256 {
        return Err(msg(format!(
            "locked artifact verification failed for {}",
            spec.artifact
        )));
    }
    let archive = paths.work.join(&artifact.filename);
    atomic_write(&archive, &bytes, 0o600)?;
    let archive_text = archive
        .to_str()
        .ok_or_else(|| msg("module archive path is not valid UTF-8"))?;
    let install_command = format!("{} module install {}", KSUD, shell_quote(archive_text));
    let output = root.exec(&install_command)?;
    log.command_result(
        &format!("install {} module", spec.id),
        output.status == 0,
        &output.text,
    )?;
    if output.status != 0 {
        return Err(msg(format!(
            "{} module installer failed with exit {}: {}",
            spec.id, output.status, output.text
        )));
    }

    let stage = format!("{KSU_MODULES_UPDATE}/{}", spec.module);
    match spec.id {
        "zygisk" => patch_zygisk(paths, root, &stage)?,
        "vector" => patch_vector(paths, root, &stage)?,
        _ => unreachable!(),
    }
    let enable = root.exec(&format!("{} module enable {}", KSUD, spec.module))?;
    log.command_result(
        &format!("enable {} module", spec.id),
        enable.status == 0,
        &enable.text,
    )?;
    if enable.status != 0 {
        return Err(msg(format!(
            "cannot enable {} module: {}",
            spec.id, enable.text
        )));
    }
    let after = status(spec.id);
    if after.state != ComponentState::Ready {
        return Err(msg(format!(
            "{} was not staged for controlled activation: {}",
            spec.id,
            after.detail.unwrap_or_default()
        )));
    }
    log.event(
        "component",
        "staged",
        json!({
            "id": spec.id,
            "module_id": spec.module,
            "version_code": spec.version_code,
            "source": resolved.source_description(),
            "activation": "xpad2 hooks activate",
        }),
    )?;
    println!(
        "✓ {}: 模块与 XPad2 兼容补丁已验证并暂存；待 `xpad2 hooks activate`",
        spec.id
    );
    Ok(true)
}

fn patch_zygisk(paths: &Paths, root: &RootSession, stage: &str) -> Result<()> {
    for relative in [
        "post-fs-data.sh",
        "zygisk-ctl.sh",
        "uninstall.sh",
        "action.sh",
        "bin/zygisk-ctl",
    ] {
        let remote = format!("{stage}/{relative}");
        if !remote_exists(root, &remote)? {
            continue;
        }
        let local = paths
            .work
            .join(format!("neo-{}", relative.replace('/', "-")));
        copy_from_root(root, &remote, &local)?;
        let mut text = fs::read_to_string(&local).at(&local)?;
        if !text.contains("/data/adb/neozygisk") && !text.contains("/dev/neozygisk") {
            return Err(msg(format!(
                "unexpected NeoZygisk script without a locked work directory: {relative}"
            )));
        }
        text = text.replace("/data/adb/neozygisk", "/dev/neozygisk");
        if relative == "post-fs-data.sh" {
            text = patch_zygisk_post_fs_data(&text)?;
        }
        atomic_write(&local, text.as_bytes(), 0o700)?;
        copy_to_root(root, &local, &remote, 0o755)?;
    }

    let remote_daemon = format!("{stage}/bin/zygiskd64");
    let local_daemon = paths.work.join("neo-zygiskd64");
    copy_from_root(root, &remote_daemon, &local_daemon)?;
    let mut daemon = fs::read(&local_daemon).at(&local_daemon)?;
    replace_exact_once(
        &mut daemon,
        STOCK_ZYGISK_CONTEXT,
        LS12_ZYGISK_CONTEXT,
        "NeoZygisk socket context",
    )?;
    atomic_write(&local_daemon, &daemon, 0o700)?;
    copy_to_root(root, &local_daemon, &remote_daemon, 0o755)?;

    let remote_ptrace = format!("{stage}/bin/zygisk-ptrace64");
    let local_ptrace = paths.work.join("neo-zygisk-ptrace64");
    copy_from_root(root, &remote_ptrace, &local_ptrace)?;
    let mut ptrace = fs::read(&local_ptrace).at(&local_ptrace)?;
    replace_exact_once(
        &mut ptrace,
        STOCK_ZYGISK_WORKDIR,
        LS12_ZYGISK_WORKDIR,
        "NeoZygisk ptrace workdir",
    )?;
    atomic_write(&local_ptrace, &ptrace, 0o700)?;
    copy_to_root(root, &local_ptrace, &remote_ptrace, 0o755)?;

    disable_module_sepolicy(root, stage)?;
    write_marker(
        paths,
        root,
        stage,
        ZYGISK_MARKER,
        "component=zygisk\nupstream=NeoZygisk-v2.4-289\nworkdir=/dev/neozygisk\nptrace_workdir=/dev/neozygisk\nsocket_context=u:object_r:ksu_file:s0:c0\nmodule_memfd_context=u:object_r:ksu_file:s0:c0\n",
    )
}

fn patch_zygisk_post_fs_data(text: &str) -> Result<String> {
    let mut patched = text.to_string();
    if !patched.contains("# xpad2-kill-stale-v1") {
        let newline = patched
            .find('\n')
            .ok_or_else(|| msg("NeoZygisk post-fs-data.sh has no shebang line"))?;
        patched.insert_str(
            newline + 1,
            "# xpad2-kill-stale-v1\nxpad2_preexisting_zygiskd=$(pidof zygiskd64 2>/dev/null | awk '{print $1}')\npkill -9 zygisk-ptrace64 2>/dev/null || true\npkill -9 zygiskd64 2>/dev/null || true\n",
        );
    }
    if !patched.contains("# xpad2-label-module-memfd-v2") {
        patched.push_str(
            r#"
# xpad2-label-module-memfd-v2
(
  xpad2_old_pid=${xpad2_preexisting_zygiskd:-}
  xpad2_wait=0
  while [ "$xpad2_wait" -lt 600 ]; do
    xpad2_pid=$(pidof zygiskd64 2>/dev/null | awk '{print $1}')
    if [ -n "$xpad2_pid" ] && [ "$xpad2_pid" != "$xpad2_old_pid" ]; then
      for xpad2_fd in /proc/$xpad2_pid/fd/*; do
        xpad2_target=$(readlink "$xpad2_fd" 2>/dev/null)
        case "$xpad2_target" in
          *memfd:zygisk-module*)
            if chcon u:object_r:ksu_file:s0:c0 "$xpad2_fd" 2>/dev/null && \
               ls -lZL "$xpad2_fd" 2>/dev/null | grep -q 'u:object_r:ksu_file:s0:c0'; then
              echo "labeled pid=$xpad2_pid fd=$xpad2_fd target=$xpad2_target"
              exit 0
            fi
            ;;
        esac
      done
    fi
    xpad2_wait=$((xpad2_wait + 1))
    sleep 0.1
  done
  echo 'no NeoZygisk module memfd observed within 60 seconds'
) >/data/local/tmp/xpad2-neo-memfd.log 2>&1 &
"#,
        );
    }
    if !patched.contains("# xpad2-zygisk-watchdog-v1") {
        patched.push_str(
            r#"
# xpad2-zygisk-watchdog-v1
(
  xpad2_wait=0
  while [ "$xpad2_wait" -lt 35 ]; do
    if grep -q 'zygote64:.*injected' /dev/neozygisk/module.prop 2>/dev/null && \
       grep -q 'daemon64:.*running' /dev/neozygisk/module.prop 2>/dev/null; then
      exit 0
    fi
    xpad2_wait=$((xpad2_wait + 1))
    sleep 1
  done
  touch "$MODDIR/disable"
  pkill -9 zygisk-ptrace64 2>/dev/null || true
  pkill -9 zygiskd64 2>/dev/null || true
  log -p e -t xpad2 'NeoZygisk failed strict activation; module disabled'
) &
"#,
        );
    }
    Ok(patched)
}

fn patch_vector(paths: &Paths, root: &RootSession, stage: &str) -> Result<()> {
    let remote = format!("{stage}/service.sh");
    let local = paths.work.join("vector-service.sh");
    copy_from_root(root, &remote, &local)?;
    let mut text = fs::read_to_string(&local).at(&local)?;
    text = patch_vector_service(&text)?;
    if !text.contains("# xpad2-kill-stale-vectord-v2") {
        let newline = text
            .find('\n')
            .ok_or_else(|| msg("Vector service.sh has no header line"))?;
        text.insert_str(
            newline + 1,
            &format!(
                "# xpad2-kill-stale-vectord-v2\npkill -9 vectord 2>/dev/null || true\npkill -9 lspd 2>/dev/null || true\n{UNMOUNT_DEX2OAT_BINDS}"
            ),
        );
    }
    if !text.contains("# xpad2-vector-watchdog-v2") {
        text.push_str(
            r#"
# xpad2-vector-watchdog-v2
(
  sleep 25
  if ! pidof vectord >/dev/null 2>&1; then
    touch "$MODDIR/disable"
    log -p e -t xpad2 'Vector daemon failed activation; module disabled'
  fi
) &
"#,
        );
    }
    atomic_write(&local, text.as_bytes(), 0o700)?;
    copy_to_root(root, &local, &remote, 0o755)?;
    disable_module_sepolicy(root, stage)?;
    write_marker(
        paths,
        root,
        stage,
        VECTOR_MARKER,
        &format!(
            "component=vector\nupstream=Vector-v2.2-3080\nmode=system-server-bridge+dex2oat\nsystem_server=true\ndex2oat=true\npolicy={VECTOR_POLICY_MARKER}\n"
        ),
    )
}

fn patch_vector_service(text: &str) -> Result<String> {
    if text.contains("--system-server-max-retry=0") {
        return Ok(text.to_string());
    }
    if !text.contains("--system-server-max-retry=3") {
        return Err(msg(
            "Vector service.sh has an unexpected system-server retry policy",
        ));
    }
    Ok(text.replace("--system-server-max-retry=3", "--system-server-max-retry=0"))
}

fn disable_module_sepolicy(root: &RootSession, stage: &str) -> Result<()> {
    let command = format!(
        "if [ -f {0}/sepolicy.rule ]; then mv -f {0}/sepolicy.rule {0}/sepolicy.rule.xpad2-disabled; fi",
        shell_quote(stage)
    );
    let output = root.exec(&command)?;
    if output.status != 0 {
        return Err(msg(format!(
            "cannot quarantine unsupported module sepolicy: {}",
            output.text
        )));
    }
    Ok(())
}

fn write_marker(
    paths: &Paths,
    root: &RootSession,
    stage: &str,
    name: &str,
    contents: &str,
) -> Result<()> {
    let local = paths.work.join(format!("{name}.marker"));
    atomic_write(&local, contents.as_bytes(), 0o600)?;
    copy_to_root(root, &local, &format!("{stage}/{name}"), 0o644)
}

fn copy_from_root(root: &RootSession, remote: &str, local: &Path) -> Result<()> {
    let local_text = local
        .to_str()
        .ok_or_else(|| msg("local compatibility path is not valid UTF-8"))?;
    let command = format!(
        "cp {remote} {local} && chown 2000:2000 {local} && chmod 600 {local}",
        remote = shell_quote(remote),
        local = shell_quote(local_text),
    );
    let output = root.exec(&command)?;
    if output.status != 0 {
        return Err(msg(format!(
            "cannot stage root-owned compatibility input {remote}: {}",
            output.text
        )));
    }
    Ok(())
}

fn copy_to_root(root: &RootSession, local: &Path, remote: &str, mode: u32) -> Result<()> {
    let local_text = local
        .to_str()
        .ok_or_else(|| msg("local compatibility path is not valid UTF-8"))?;
    let new = format!("{remote}.xpad2-new");
    let command = format!(
        "cp {local} {new} && chown 0:0 {new} && chmod {mode:o} {new} && chcon u:object_r:system_file:s0 {new} && mv -f {new} {remote}",
        local = shell_quote(local_text),
        new = shell_quote(&new),
        remote = shell_quote(remote),
    );
    let output = root.exec(&command)?;
    if output.status != 0 {
        return Err(msg(format!(
            "cannot commit XPad2 compatibility patch to {remote}: {}",
            output.text
        )));
    }
    Ok(())
}

fn remote_exists(root: &RootSession, remote: &str) -> Result<bool> {
    let output = root.exec(&format!("test -f {}", shell_quote(remote)))?;
    Ok(output.status == 0)
}

fn replace_exact_once(bytes: &mut [u8], old: &[u8], new: &[u8], label: &str) -> Result<()> {
    if old.len() != new.len() {
        return Err(msg(format!("{label} replacement changes binary length")));
    }
    let old_offsets: Vec<_> = bytes
        .windows(old.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == old).then_some(offset))
        .collect();
    let new_count = bytes
        .windows(new.len())
        .filter(|window| *window == new)
        .count();
    match (old_offsets.as_slice(), new_count) {
        ([offset], 0) => {
            bytes[*offset..*offset + new.len()].copy_from_slice(new);
            Ok(())
        }
        ([], 1) => Ok(()),
        _ => Err(msg(format!(
            "{label} anchor mismatch: old_count={} new_count={new_count}",
            old_offsets.len()
        ))),
    }
}

fn prepare_activation(log: &mut TransactionLog) -> Result<Vec<String>> {
    if !device::ksu_module_loaded() {
        return Err(msg(
            "KernelSU is not loaded; install ksu before hook activation",
        ));
    }
    let zygisk = zygisk_status();
    if !matches!(
        zygisk.state,
        ComponentState::Installed | ComponentState::Ready | ComponentState::Active
    ) {
        return Err(msg(format!(
            "NeoZygisk is not activation-ready: {}",
            zygisk.detail.unwrap_or_default()
        )));
    }
    let mut components = vec!["zygisk".to_string()];
    let vector = vector_status();
    if vector.state != ComponentState::Absent {
        if !matches!(
            vector.state,
            ComponentState::Installed | ComponentState::Ready | ComponentState::Active
        ) {
            return Err(msg(format!(
                "Vector is not activation-ready: {}",
                vector.detail.unwrap_or_default()
            )));
        }
        components.push("vector".to_string());
    }
    log.event(
        "hooks",
        "activation-ready",
        json!({"components": components, "restart": "ksud soft-reboot"}),
    )?;
    Ok(components)
}

fn install_policy_tool(
    catalog: &Catalog,
    paths: &Paths,
    root: &RootSession,
    log: &mut TransactionLog,
) -> Result<()> {
    let artifact = catalog.artifact(MAGISKPOLICY_ARTIFACT)?;
    let resolved = catalog.resolve(MAGISKPOLICY_ARTIFACT, paths)?;
    let bytes = resolved.load()?;
    if bytes.len() as u64 != artifact.size || sha256_bytes(&bytes) != artifact.sha256 {
        return Err(msg("locked magiskpolicy verification failed"));
    }
    let local = paths.work.join(&artifact.filename);
    atomic_write(&local, &bytes, 0o700)?;
    let local_text = local
        .to_str()
        .ok_or_else(|| msg("local magiskpolicy path is not valid UTF-8"))?;
    let command = format!(
        "mkdir -p /data/adb/xpad2/bin && \
         chown 0:0 /data/adb/xpad2 /data/adb/xpad2/bin && \
         chmod 700 /data/adb/xpad2 /data/adb/xpad2/bin && \
         chcon u:object_r:ksu_file:s0:c0 /data/adb/xpad2 /data/adb/xpad2/bin && \
         cp {local} {remote}.xpad2-new && chown 0:0 {remote}.xpad2-new && \
         chmod 700 {remote}.xpad2-new && \
         chcon u:object_r:ksu_file:s0:c0 {remote}.xpad2-new && \
         mv -f {remote}.xpad2-new {remote} && \
         test \"$(sha256sum {remote} | awk '{{print $1}}')\" = {sha}",
        local = shell_quote(local_text),
        remote = shell_quote(MAGISKPOLICY),
        sha = shell_quote(&artifact.sha256),
    );
    let output = root.exec(&command)?;
    log.command_result(
        "install locked magiskpolicy",
        output.status == 0,
        &output.text,
    )?;
    if output.status != 0 {
        return Err(msg(format!(
            "cannot install locked magiskpolicy: {}",
            output.text
        )));
    }
    Ok(())
}

fn apply_live_policy(paths: &Paths, root: &RootSession, log: &mut TransactionLog) -> Result<()> {
    let local_rules = paths.work.join("vector-live.rules");
    atomic_write(&local_rules, VECTOR_LIVE_POLICY_RULES.as_bytes(), 0o600)?;
    let local_text = local_rules
        .to_str()
        .ok_or_else(|| msg("local Vector policy path is not valid UTF-8"))?;
    let remote_rules = "/data/adb/xpad2/vector-live.rules";
    let command = format!(
        "cp {local} {remote}.xpad2-new && chown 0:0 {remote}.xpad2-new && \
         chmod 600 {remote}.xpad2-new && chcon u:object_r:ksu_file:s0:c0 {remote}.xpad2-new && \
         mv -f {remote}.xpad2-new {remote} && \
         {tool} --live --apply {remote}; \
         rc=$?; rm -f {remote}; [ \"$rc\" -eq 0 ] || exit \"$rc\"; \
         {tool} --print-rules 2>/dev/null | {policy_check}",
        local = shell_quote(local_text),
        remote = shell_quote(remote_rules),
        tool = shell_quote(MAGISKPOLICY),
        policy_check = VECTOR_POLICY_AWK_CHECK,
    );
    let output = root.exec(&command)?;
    log.command_result(
        "apply minimal Vector live policy",
        output.status == 0,
        &output.text,
    )?;
    if output.status != 0 {
        return Err(msg(format!(
            "cannot apply the minimal Vector live policy: {}",
            output.text
        )));
    }
    Ok(())
}

pub fn activate(
    catalog: &Catalog,
    paths: &Paths,
    root: &RootSession,
    log: &mut TransactionLog,
) -> Result<Vec<String>> {
    root.check_boot()?;
    let components = prepare_activation(log)?;
    install_policy_tool(catalog, paths, root, log)?;
    if components.iter().any(|id| id == VECTOR.id) {
        apply_live_policy(paths, root, log)?;
    }
    if root.owned {
        // Keep the temporary su transport for recovery and verification, but
        // never bootstrap Zygote/Vector in a permissive userspace. The live
        // rule is already resident, so restore Enforcing before soft reboot.
        root.restore_enforcing(log)?;
    }

    let before = root.exec(
        "printf 'system_server=%s zygiskd=%s\\n' \"$(pidof system_server 2>/dev/null)\" \"$(pidof zygiskd64 2>/dev/null)\"",
    )?;
    let enable = root.exec(&format!(
        r#"
/data/adb/ksud module enable zygisksu
if [ -d /data/adb/modules/zygisk_vector ] || [ -d /data/adb/modules_update/zygisk_vector ]; then
  /data/adb/ksud module enable zygisk_vector
fi
pkill -9 vectord 2>/dev/null || true
pkill -9 lspd 2>/dev/null || true
{unmount_dex2oat}rm -f /data/local/tmp/xpad2-neo-memfd.log
"#,
        unmount_dex2oat = UNMOUNT_DEX2OAT_BINDS,
    ))?;
    log.command_result("enable hook modules", enable.status == 0, &enable.text)?;
    if enable.status != 0 {
        return Err(msg(format!("cannot enable hook modules: {}", enable.text)));
    }
    log.event(
        "hooks",
        "soft-reboot-dispatched",
        json!({"components": components, "before": before.text}),
    )?;
    println!(
        "正在重启 Android userspace 并等待 Hook 链路严格验活；Boot ID 和 late-load KSU 保持不变。"
    );
    std::io::stdout()
        .flush()
        .map_err(|error| msg(format!("cannot flush activation status: {error}")))?;
    runtime::dispatch_soft_reboot(root, "/data/local/tmp/xpad2-hooks-soft-reboot.log")?;

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        root.check_boot()?;
        let zygisk = zygisk_status();
        let vector = components
            .iter()
            .any(|id| id == VECTOR.id)
            .then(vector_status);
        let ready = zygisk.state == ComponentState::Active
            && vector
                .as_ref()
                .is_none_or(|status| status.state == ComponentState::Active);
        let package_ready = ready && runtime::package_service_ready();
        let health = match &vector {
            Some(vector) => format!(
                "zygisk={} {}; vector={} {}; package_service={}",
                zygisk.state,
                zygisk.detail.unwrap_or_default(),
                vector.state,
                vector.detail.clone().unwrap_or_default(),
                if package_ready { "ready" } else { "starting" }
            ),
            None => format!(
                "zygisk={} {}; package_service={}",
                zygisk.state,
                zygisk.detail.unwrap_or_default(),
                if package_ready { "ready" } else { "starting" }
            ),
        };
        if package_ready {
            log.event("hooks", "active", json!({"health": health}))?;
            println!("✓ hooks: {health}");
            return Ok(components);
        }
        if Instant::now() >= deadline {
            return Err(msg(format!(
                "Hook activation did not pass strict health checks within 90 seconds: {health}"
            )));
        }
        thread::sleep(Duration::from_millis(500));
    }
}

pub fn dispatch_soft_reboot() -> Result<()> {
    println!(
        "已调度 Android userspace soft-reboot；ADB 会短暂断开，Boot ID 与 KSU 内核模块保持不变。"
    );
    println!("设备恢复后运行：xpad2 verify zygisk；若安装了 Vector，再运行 xpad2 verify vector。");
    std::io::stdout()
        .flush()
        .map_err(|error| msg(format!("cannot flush activation instructions: {error}")))?;
    let output = root::root_exec(&format!(
        "{} soft-reboot >/data/local/tmp/xpad2-hooks-soft-reboot.log 2>&1 &",
        KSUD
    ))?;
    if output.status != 0 {
        return Err(msg(format!(
            "cannot dispatch controlled userspace restart: {}",
            output.text
        )));
    }
    Ok(())
}

pub fn disable(log: &mut TransactionLog) -> Result<Vec<String>> {
    if !device::ksu_module_loaded() {
        return Err(msg(
            "KernelSU is not loaded; hook modules cannot be managed",
        ));
    }
    let output = root::root_exec(&format!(
        r#"
if [ -x /data/adb/xpad2/bin/magiskpolicy ]; then
  rules_file=/data/adb/xpad2/vector-revoke.rules
  mkdir -p /data/adb/xpad2
  cat <<'XPAD2_REVOKE_EOF' >"$rules_file"
{core}XPAD2_REVOKE_EOF
  xposed_types=$(/data/adb/xpad2/bin/magiskpolicy --print-rules 2>/dev/null | awk '/^type (xposed_file|xposed_data) / {{ print $2 }}')
  case "$xposed_types" in
    *xposed_file*)
      cat <<'XPAD2_REVOKE_EOF' >>"$rules_file"
{xposed_file}XPAD2_REVOKE_EOF
      ;;
  esac
  case "$xposed_types" in
    *xposed_data*)
      cat <<'XPAD2_REVOKE_EOF' >>"$rules_file"
{xposed_data}XPAD2_REVOKE_EOF
      ;;
  esac
  /data/adb/xpad2/bin/magiskpolicy --live --apply "$rules_file"
  rc=$?
  rm -f "$rules_file"
  [ "$rc" -eq 0 ] || exit "$rc"
fi
/data/adb/ksud module disable zygisk_vector 2>/dev/null || true
/data/adb/ksud module disable zygisksu 2>/dev/null || true
pkill -9 vectord 2>/dev/null || true
pkill -9 lspd 2>/dev/null || true
{unmount_dex2oat}pkill -9 zygisk-ptrace64 2>/dev/null || true
pkill -9 zygiskd64 2>/dev/null || true
"#,
        core = VECTOR_REVOKE_CORE_RULES,
        xposed_file = VECTOR_REVOKE_XPOSED_FILE_RULES,
        xposed_data = VECTOR_REVOKE_XPOSED_DATA_RULES,
        unmount_dex2oat = UNMOUNT_DEX2OAT_BINDS,
    ))?;
    log.command_result("disable hook modules", output.status == 0, &output.text)?;
    if output.status != 0 {
        return Err(msg(format!("cannot disable hook modules: {}", output.text)));
    }
    Ok(vec!["zygisk".to_string(), "vector".to_string()])
}

fn module_info(id: &str) -> Result<Option<ModuleInfo>> {
    let output = root::root_exec(&format!("{} module list", KSUD))?;
    if output.status != 0 {
        return Err(msg(format!("ksud module list failed: {}", output.text)));
    }
    let start = output
        .text
        .find('[')
        .ok_or_else(|| msg("ksud module list returned no JSON array"))?;
    let end = output
        .text
        .rfind(']')
        .ok_or_else(|| msg("ksud module list returned an incomplete JSON array"))?;
    let modules: Value = serde_json::from_str(&output.text[start..=end])?;
    let Some(module) = modules.as_array().and_then(|entries| {
        entries
            .iter()
            .find(|entry| entry["id"].as_str() == Some(id))
    }) else {
        return Ok(None);
    };
    Ok(Some(ModuleInfo {
        enabled: json_bool(&module["enabled"]),
        update: json_bool(&module["update"]),
        version_code: json_string(&module["versionCode"]),
    }))
}

fn json_bool(value: &Value) -> bool {
    value.as_bool().unwrap_or_else(|| {
        value
            .as_str()
            .is_some_and(|text| text.eq_ignore_ascii_case("true"))
    })
}

fn json_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .or_else(|| value.as_u64().map(|number| number.to_string()))
        .unwrap_or_default()
}

fn component_status(id: &str, state: ComponentState, detail: Option<&str>) -> ComponentStatus {
    ComponentStatus {
        id: id.to_string(),
        state,
        detail: detail.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_lsposed_id_is_a_vector_alias() {
        assert_eq!(canonical_id("vector"), "vector");
        assert_eq!(canonical_id("lsposed"), "vector");
    }

    #[test]
    fn zygisk_context_patch_is_length_preserving_and_idempotent() {
        assert_eq!(STOCK_ZYGISK_CONTEXT.len(), LS12_ZYGISK_CONTEXT.len());
        let mut bytes = [b"head".as_slice(), STOCK_ZYGISK_CONTEXT, b"tail".as_slice()].concat();
        replace_exact_once(
            &mut bytes,
            STOCK_ZYGISK_CONTEXT,
            LS12_ZYGISK_CONTEXT,
            "test",
        )
        .expect("first patch");
        replace_exact_once(
            &mut bytes,
            STOCK_ZYGISK_CONTEXT,
            LS12_ZYGISK_CONTEXT,
            "test",
        )
        .expect("idempotent patch");
        assert!(
            bytes
                .windows(LS12_ZYGISK_CONTEXT.len())
                .any(|window| window == LS12_ZYGISK_CONTEXT)
        );
    }

    #[test]
    fn zygisk_ptrace_workdir_patch_is_length_preserving_and_idempotent() {
        assert_eq!(STOCK_ZYGISK_WORKDIR.len(), LS12_ZYGISK_WORKDIR.len());
        let mut bytes = [b"head\0".as_slice(), STOCK_ZYGISK_WORKDIR, b"tail".as_slice()].concat();
        replace_exact_once(
            &mut bytes,
            STOCK_ZYGISK_WORKDIR,
            LS12_ZYGISK_WORKDIR,
            "test-workdir",
        )
        .expect("first patch");
        replace_exact_once(
            &mut bytes,
            STOCK_ZYGISK_WORKDIR,
            LS12_ZYGISK_WORKDIR,
            "test-workdir",
        )
        .expect("idempotent patch");
        assert!(
            bytes
                .windows(LS12_ZYGISK_WORKDIR.len())
                .any(|window| window == LS12_ZYGISK_WORKDIR)
        );
    }

    #[test]
    fn vector_live_policy_has_no_unscoped_wildcard_allows() {
        assert!(!VECTOR_LIVE_POLICY_RULES.contains("allow *"));
        assert!(!VECTOR_LIVE_POLICY_RULES.contains(" *"));
        assert!(!VECTOR_LIVE_POLICY_RULES.contains("unlabeled"));
        assert!(!VECTOR_LIVE_POLICY_RULES.contains("untrusted_app"));
        assert!(VECTOR_LIVE_POLICY_RULES.contains("allow system_server system_server process execmem"));
        assert!(VECTOR_LIVE_POLICY_RULES.contains("allow dex2oat dex2oat_exec file execute_no_trans"));
        assert!(
            VECTOR_LIVE_POLICY_RULES
                .contains("allow dex2oat system_linker_exec file execute_no_trans")
        );
        assert!(VECTOR_LIVE_POLICY_RULES.contains("type xposed_file file_type"));
        assert!(VECTOR_LIVE_POLICY_RULES.contains("type xposed_data file_type"));
    }

    #[test]
    fn zygisk_post_fs_data_patch_adds_cleanup_and_watchdog_once() {
        let stock = "#!/system/bin/sh\nMODDIR=${0%/*}\nTMP_PATH=/dev/neozygisk\n";
        let once = patch_zygisk_post_fs_data(stock).expect("patch");
        let twice = patch_zygisk_post_fs_data(&once).expect("patch twice");
        assert_eq!(once, twice);
        assert_eq!(once.matches("# xpad2-kill-stale-v1").count(), 1);
        assert_eq!(once.matches("# xpad2-label-module-memfd-v2").count(), 1);
        assert_eq!(once.matches("# xpad2-zygisk-watchdog-v1").count(), 1);
        assert!(once.contains("xpad2_preexisting_zygiskd="));
        assert!(once.contains("chcon u:object_r:ksu_file:s0:c0"));
    }

    #[test]
    fn vector_service_patch_disables_restart_storms_idempotently() {
        let stock = "# Extract the directory path\nMODDIR=\"${0%/*}\"\nunshare --propagation slave -m \"$MODDIR/daemon\" --system-server-max-retry=3 \"$@\" &\n";
        let once = patch_vector_service(stock).expect("patch");
        let twice = patch_vector_service(&once).expect("patch twice");
        assert_eq!(once, twice);
        assert!(once.contains("--system-server-max-retry=0"));
        assert!(!once.contains("--system-server-max-retry=3"));
    }

    #[test]
    fn hook_runtime_has_no_application_specific_targets() {
        let source = include_str!("hooks.rs");
        for encoded in [
            vec![
                99, 111, 109, 46, 116, 97, 108, 46, 112, 97, 100, 46, 97, 105, 99, 111, 114, 101,
            ],
            vec![
                99, 111, 109, 46, 116, 97, 108, 46, 112, 97, 100, 46, 108, 117, 105,
            ],
            vec![97, 105, 99, 111, 114, 101, 61],
            vec![108, 117, 105, 61],
        ] {
            let forbidden = String::from_utf8(encoded).expect("ASCII boundary");
            assert!(
                !source.contains(&forbidden),
                "forbidden target: {forbidden}"
            );
        }
    }
}
