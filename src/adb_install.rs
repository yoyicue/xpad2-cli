use crate::catalog::Catalog;
use crate::device;
use crate::error::{IoContext, Result, msg, needs_reboot};
use crate::install;
use crate::logging::TransactionLog;
use crate::model::{ComponentState, ComponentStatus};
use crate::root::RootSession;
use crate::runtime;
use crate::util::{
    Paths, atomic_write, boot_id, epoch_seconds, getprop, output_text, run, selinux, sha256_bytes,
    shell_quote,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub const ID: &str = "adb-install";
const PROPERTY: &str = "ro.genie.gota.version";
const V_TYPE_ERROR: &str = "ADB install is not allowed on V-type devices";
const STATE_SCHEMA: u32 = 1;
const MAGISK_ARTIFACT: &str = "magisk-resetprop";
const MAGISK: &str = "/data/adb/xpad2/bin/magisk";
const SOFT_REBOOT_LOG: &str = "/data/local/tmp/xpad2-adb-install-soft-reboot.log";
const RESTART_DEADLINE: Duration = Duration::from_secs(90);

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    #[default]
    Disabled,
    Applying,
    PropertyApplied,
    Restarting,
    Verifying,
    Active,
    Reverting,
    Broken,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
struct PolicyState {
    schema: u32,
    policy_enabled: bool,
    phase: Phase,
    original_value: Option<String>,
    replacement_value: Option<String>,
    applied_boot_id: Option<String>,
    verified_boot_id: Option<String>,
    verified_system_server_pid: Option<u32>,
    verified_at: Option<u64>,
    runtime: Option<String>,
    last_error: Option<String>,
}

impl Default for PolicyState {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA,
            policy_enabled: false,
            phase: Phase::Disabled,
            original_value: None,
            replacement_value: None,
            applied_boot_id: None,
            verified_boot_id: None,
            verified_system_server_pid: None,
            verified_at: None,
            runtime: None,
            last_error: None,
        }
    }
}

#[derive(Serialize)]
pub struct AdbInstallReport {
    pub status: ComponentStatus,
    pub policy_enabled: bool,
    pub phase: Phase,
    pub current_value: String,
    pub original_value: Option<String>,
    pub replacement_value: Option<String>,
    pub boot_id: String,
    pub system_server_pid: Option<u32>,
    pub verified_boot_id: Option<String>,
    pub verified_system_server_pid: Option<u32>,
    pub verified_at: Option<u64>,
    pub runtime: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug)]
enum GateProbe {
    Open,
    VBlocked,
}

pub fn status(paths: &Paths) -> ComponentStatus {
    report(paths).status
}

pub fn report(paths: &Paths) -> AdbInstallReport {
    let current_value = getprop(PROPERTY);
    let current_boot = boot_id();
    let current_pid = system_server_pid().ok();
    let (state, load_error) = match load_state(paths) {
        Ok(state) => (state, None),
        Err(error) => (PolicyState::default(), Some(error.to_string())),
    };
    let phase = if load_error.is_some() {
        Phase::Broken
    } else {
        state.phase
    };
    let component = if let Some(error) = &load_error {
        component_status(ComponentState::Broken, error.clone())
    } else if state.phase == Phase::Broken {
        component_status(
            ComponentState::Broken,
            state
                .last_error
                .clone()
                .unwrap_or_else(|| "adb-install policy is in an interrupted state".to_string()),
        )
    } else if !state.policy_enabled {
        component_status(
            ComponentState::Absent,
            format!("stock V-type behavior; property={current_value}"),
        )
    } else if state.applied_boot_id.as_deref() != Some(current_boot.as_str()) {
        component_status(
            ComponentState::Ready,
            "run `xpad2 adb-install enable` or `xpad2 install full` for this boot".to_string(),
        )
    } else if state.phase == Phase::Active
        && state.replacement_value.as_deref() != Some(current_value.as_str())
        && current_value.starts_with('V')
    {
        component_status(
            ComponentState::Broken,
            format!(
                "property changed after verification: expected={}, actual={current_value}",
                state.replacement_value.as_deref().unwrap_or("unknown")
            ),
        )
    } else if state.phase == Phase::Active
        && state.replacement_value.as_deref() != Some(current_value.as_str())
    {
        component_status(
            ComponentState::Ready,
            format!(
                "non-V property changed to {current_value}; run `xpad2 adb-install verify` to refresh evidence"
            ),
        )
    } else if state.phase == Phase::Active
        && state.verified_boot_id.as_deref() == Some(current_boot.as_str())
        && state.verified_system_server_pid == current_pid
    {
        component_status(
            ComponentState::Active,
            format!(
                "shell install-create verified; property={} runtime={}",
                current_value,
                state.runtime.as_deref().unwrap_or("not-required")
            ),
        )
    } else if matches!(state.phase, Phase::Active | Phase::Verifying) {
        component_status(
            ComponentState::Ready,
            "property applied; run `xpad2 adb-install verify` for the current system_server"
                .to_string(),
        )
    } else {
        component_status(
            ComponentState::Broken,
            format!(
                "adb-install policy did not complete: phase={:?} error={}",
                state.phase,
                state.last_error.as_deref().unwrap_or("none")
            ),
        )
    };
    AdbInstallReport {
        status: component,
        policy_enabled: state.policy_enabled,
        phase,
        current_value,
        original_value: state.original_value,
        replacement_value: state.replacement_value,
        boot_id: current_boot,
        system_server_pid: current_pid,
        verified_boot_id: state.verified_boot_id,
        verified_system_server_pid: state.verified_system_server_pid,
        verified_at: state.verified_at,
        runtime: state.runtime,
        last_error: load_error.or(state.last_error),
    }
}

pub fn print_status(paths: &Paths, json_output: bool) -> Result<()> {
    let report = report(paths);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{:<16} {:<13} {}",
            ID,
            report.status.state,
            report.status.detail.as_deref().unwrap_or("")
        );
        println!(
            "property: {} -> {} (current: {})",
            report.original_value.as_deref().unwrap_or("unknown"),
            report.replacement_value.as_deref().unwrap_or("unchanged"),
            report.current_value
        );
        println!("boot-id: {}", report.boot_id);
        println!(
            "system-server-pid: {}",
            report
                .system_server_pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        println!("persistence: current boot only; rerun enable after an ordinary reboot");
    }
    Ok(())
}

pub fn enable(catalog: &Catalog, paths: &Paths, log: &mut TransactionLog) -> Result<bool> {
    device::product_check(catalog)?;
    if matches!(probe_gate()?, GateProbe::Open) {
        let current = getprop(PROPERTY);
        let (original, replacement) = open_policy_values(paths, current.clone())?;
        mark_verified(paths, None, original, replacement)?;
        log.event(
            "adb-install",
            "already-open",
            json!({"property": PROPERTY, "value": current}),
        )?;
        println!("✓ adb-install: 原生 ADB 安装门已开放，无需修改属性或重启 userspace");
        return Ok(false);
    }
    with_runtime(catalog, paths, log, |root, runtime_id, log| {
        enable_with_runtime(catalog, paths, root, runtime_id, log)
    })
}

pub fn enable_with_runtime(
    catalog: &Catalog,
    paths: &Paths,
    root: &RootSession,
    runtime_id: &str,
    log: &mut TransactionLog,
) -> Result<bool> {
    let result = enable_inner(catalog, paths, root, runtime_id, log);
    if let Err(error) = &result {
        mark_failure(paths, true, error.to_string());
    }
    result
}

fn enable_inner(
    catalog: &Catalog,
    paths: &Paths,
    root: &RootSession,
    runtime_id: &str,
    log: &mut TransactionLog,
) -> Result<bool> {
    root.check_boot()?;
    if matches!(probe_gate()?, GateProbe::Open) {
        let current = getprop(PROPERTY);
        let (original, replacement) = open_policy_values(paths, current.clone())?;
        mark_verified(paths, Some(runtime_id), original, replacement)?;
        log.event(
            "adb-install",
            "already-open",
            json!({"property": PROPERTY, "value": current, "runtime": runtime_id}),
        )?;
        println!("✓ adb-install: 原生 ADB 安装门已开放，无需修改属性或重启 userspace");
        return Ok(false);
    }

    let original = getprop(PROPERTY);
    let replacement = replacement_value(&original)?;
    let before_pid = system_server_pid()?;
    let mut state = PolicyState {
        policy_enabled: true,
        phase: Phase::Applying,
        original_value: Some(original.clone()),
        replacement_value: Some(replacement.clone()),
        applied_boot_id: Some(boot_id()),
        runtime: Some(runtime_id.to_string()),
        ..PolicyState::default()
    };
    save_state(paths, &state)?;
    log.event(
        "adb-install",
        "applying",
        json!({"property": PROPERTY, "original": original, "replacement": replacement, "system_server_pid": before_pid}),
    )?;

    let prepared = (|| -> Result<()> {
        install_resetprop(catalog, paths, root, log)?;
        set_property(root, &replacement, log)?;
        let actual = getprop(PROPERTY);
        if actual != replacement {
            return Err(msg(format!(
                "property readback mismatch after resetprop: expected={replacement}, actual={actual}"
            )));
        }
        state.phase = Phase::PropertyApplied;
        save_state(paths, &state)?;
        root.restore_enforcing(log)?;
        Ok(())
    })();
    if let Err(error) = prepared {
        let restore_error = if getprop(PROPERTY) == replacement {
            set_property(root, &original, log).err()
        } else {
            None
        };
        return Err(match restore_error {
            Some(restore) => msg(format!(
                "{error}; additionally, restoring {PROPERTY} failed: {restore}"
            )),
            None => error,
        });
    }

    state.phase = Phase::Restarting;
    save_state(paths, &state)?;
    println!(
        "正在重启 Android userspace 以重新初始化 Build.IS_USER_V；Boot ID 与 late-load runtime 保持不变。ADB 断开后请用 `xpad2 adb-install status` 检查结果。"
    );
    log.detach_output_for_restart()?;
    runtime::dispatch_soft_reboot(root, SOFT_REBOOT_LOG)?;
    log.event(
        "adb-install",
        "soft-reboot-dispatched",
        json!({"before_system_server_pid": before_pid, "runtime": runtime_id}),
    )?;
    let after_pid = wait_userspace(paths, root, runtime_id, before_pid, &replacement, true)?;
    let effective = getprop(PROPERTY);
    if effective != replacement {
        log.event(
            "adb-install",
            "non-v-property-override",
            json!({"requested": replacement, "effective": effective}),
        )?;
    }
    state.phase = Phase::Verifying;
    save_state(paths, &state)?;
    match probe_gate()? {
        GateProbe::Open => {}
        GateProbe::VBlocked => {
            return Err(msg(
                "PackageInstallerService still rejects ADB install after userspace restart",
            ));
        }
    }
    mark_verified(paths, Some(runtime_id), original, effective)?;
    log.event(
        "adb-install",
        "active",
        json!({"system_server_pid": after_pid, "verification": "shell install-create + install-abandon", "selinux": selinux()}),
    )?;
    println!("✓ adb-install: 新 system_server 已通过真实 shell 安装会话验证；当前 boot 有效");
    Ok(true)
}

pub fn verify(paths: &Paths, log: &mut TransactionLog) -> Result<()> {
    match probe_gate()? {
        GateProbe::VBlocked => Err(msg(V_TYPE_ERROR)),
        GateProbe::Open => {
            let state = load_state(paths)?;
            if state.policy_enabled {
                let current = getprop(PROPERTY);
                if state
                    .replacement_value
                    .as_deref()
                    .is_some_and(|value| value != current)
                    && current.starts_with('V')
                {
                    return Err(msg(format!(
                        "property conflicts with the recorded adb-install policy: expected={}, actual={current}",
                        state.replacement_value.unwrap_or_default()
                    )));
                }
                let original = state.original_value.unwrap_or_else(|| current.clone());
                let replacement = current;
                mark_verified(paths, state.runtime.as_deref(), original, replacement)?;
            }
            log.event(
                "adb-install",
                "verified",
                json!({"verification": "shell install-create + install-abandon"}),
            )?;
            println!("✓ adb-install: shell install-create/install-abandon 验证通过");
            Ok(())
        }
    }
}

pub fn disable(catalog: &Catalog, paths: &Paths, log: &mut TransactionLog) -> Result<bool> {
    device::product_check(catalog)?;
    let state = load_state(paths)?;
    if !state.policy_enabled && state.phase != Phase::Broken {
        println!("adb-install: 策略已经停用");
        return Ok(false);
    }
    let Some(original) = state.original_value.clone() else {
        return Err(msg(
            "no trustworthy original property value is recorded; use an ordinary reboot to restore the stock value",
        ));
    };
    let replacement = state.replacement_value.clone().unwrap_or_default();
    if original == replacement
        || state.applied_boot_id.as_deref() != Some(boot_id().as_str())
        || getprop(PROPERTY) == original
    {
        let mut disabled = state;
        disabled.policy_enabled = false;
        disabled.phase = Phase::Disabled;
        disabled.last_error = None;
        disabled.verified_boot_id = None;
        disabled.verified_system_server_pid = None;
        disabled.verified_at = None;
        save_state(paths, &disabled)?;
        println!("adb-install: 已停用；当前无需 userspace 重启");
        return Ok(false);
    }
    with_runtime(catalog, paths, log, |root, runtime_id, log| {
        let result =
            disable_with_runtime(catalog, paths, root, runtime_id, original, replacement, log);
        if let Err(error) = &result {
            mark_failure(paths, false, error.to_string());
        }
        result
    })
}

fn disable_with_runtime(
    catalog: &Catalog,
    paths: &Paths,
    root: &RootSession,
    runtime_id: &str,
    original: String,
    replacement: String,
    log: &mut TransactionLog,
) -> Result<bool> {
    let before_pid = system_server_pid()?;
    let mut state = load_state(paths)?;
    state.policy_enabled = false;
    state.phase = Phase::Reverting;
    state.last_error = None;
    state.verified_boot_id = None;
    state.verified_system_server_pid = None;
    state.verified_at = None;
    save_state(paths, &state)?;
    install_resetprop(catalog, paths, root, log)?;
    set_property(root, &original, log)?;
    if getprop(PROPERTY) != original {
        return Err(msg("failed to restore the original V-type property"));
    }
    root.restore_enforcing(log)?;
    state.phase = Phase::Restarting;
    save_state(paths, &state)?;
    log.detach_output_for_restart()?;
    runtime::dispatch_soft_reboot(root, SOFT_REBOOT_LOG)?;
    wait_userspace(paths, root, runtime_id, before_pid, &original, false)?;
    state.phase = Phase::Disabled;
    state.applied_boot_id = None;
    state.last_error = None;
    save_state(paths, &state)?;
    log.event(
        "adb-install",
        "disabled",
        json!({"property": PROPERTY, "value": original, "previous_value": replacement}),
    )?;
    println!("adb-install: 已恢复原始 V 属性并重启 Android userspace");
    Ok(true)
}

fn with_runtime<T>(
    catalog: &Catalog,
    paths: &Paths,
    log: &mut TransactionLog,
    action: impl FnOnce(&RootSession, &str, &mut TransactionLog) -> Result<T>,
) -> Result<T> {
    device::runtime_profile_check(catalog)?;
    let root = if device::ksu_module_loaded() {
        RootSession {
            owned: false,
            started_boot_id: boot_id(),
        }
    } else {
        RootSession::acquire(catalog, paths, log, false)?
    };
    let runtime_id = selected_runtime(paths);
    let mut result = (|| {
        install::ensure_runtime(catalog, paths, runtime_id, &root, log)?;
        action(&root, runtime_id, log)
    })();
    if let Err(cleanup_error) = root.close(log) {
        result = Err(match result {
            Ok(_) => cleanup_error,
            Err(original) => needs_reboot(format!(
                "{original}; additionally, safe root cleanup failed: {cleanup_error}"
            )),
        });
    }
    result
}

fn selected_runtime(paths: &Paths) -> &'static str {
    if device::ksu_status(paths).state == ComponentState::Active {
        "ksu"
    } else if device::suu_status(paths).state == ComponentState::Active {
        "suu"
    } else {
        "ksu"
    }
}

fn install_resetprop(
    catalog: &Catalog,
    paths: &Paths,
    root: &RootSession,
    log: &mut TransactionLog,
) -> Result<()> {
    let artifact = catalog.artifact(MAGISK_ARTIFACT)?;
    let resolved = catalog.resolve(MAGISK_ARTIFACT, paths)?;
    let bytes = resolved.load()?;
    if bytes.len() as u64 != artifact.size || sha256_bytes(&bytes) != artifact.sha256 {
        return Err(msg("locked Magisk resetprop provider verification failed"));
    }
    let local = paths.work.join(&artifact.filename);
    atomic_write(&local, &bytes, 0o700)?;
    let local_text = local
        .to_str()
        .ok_or_else(|| msg("local Magisk path is not valid UTF-8"))?;
    let command = format!(
        "mkdir -p /data/adb/xpad2/bin && \
         chown 0:0 /data/adb/xpad2 /data/adb/xpad2/bin && \
         chmod 700 /data/adb/xpad2 /data/adb/xpad2/bin && \
         chcon u:object_r:ksu_file:s0:c0 /data/adb/xpad2 /data/adb/xpad2/bin && \
         cp {local} {remote}.xpad2-new && chown 0:0 {remote}.xpad2-new && \
         chmod 700 {remote}.xpad2-new && \
         chcon u:object_r:ksu_file:s0:c0 {remote}.xpad2-new && \
         mv -f {remote}.xpad2-new {remote} && \
         test \"$({remote} resetprop {property})\" = \"$(getprop {property})\" && \
         test \"$(sha256sum {remote} | awk '{{print $1}}')\" = {sha}",
        local = shell_quote(local_text),
        remote = shell_quote(MAGISK),
        property = PROPERTY,
        sha = shell_quote(&artifact.sha256),
    );
    let output = root.exec(&command)?;
    log.command_result(
        "install locked Magisk resetprop provider",
        output.status == 0,
        &output.text,
    )?;
    if output.status != 0 {
        return Err(msg(format!(
            "cannot install locked Magisk resetprop provider: {}",
            output.text
        )));
    }
    Ok(())
}

fn set_property(root: &RootSession, value: &str, log: &mut TransactionLog) -> Result<()> {
    let output = root.exec(&format!(
        "{} resetprop {} {}",
        shell_quote(MAGISK),
        PROPERTY,
        shell_quote(value)
    ))?;
    log.command_result(
        "resetprop ro.genie.gota.version",
        output.status == 0,
        &output.text,
    )?;
    if output.status != 0 {
        return Err(msg(format!("resetprop failed: {}", output.text)));
    }
    Ok(())
}

fn wait_userspace(
    paths: &Paths,
    root: &RootSession,
    runtime_id: &str,
    before_pid: u32,
    expected_property: &str,
    allow_any_non_v: bool,
) -> Result<u32> {
    let spec = device::runtime_spec(runtime_id)
        .ok_or_else(|| msg(format!("unknown runtime: {runtime_id}")))?;
    let deadline = Instant::now() + RESTART_DEADLINE;
    loop {
        root.check_boot()?;
        let pid = system_server_pid().ok();
        let package_ready = runtime::package_service_ready();
        let current_property = getprop(PROPERTY);
        let property_ready = property_ready(expected_property, &current_property, allow_any_non_v);
        let runtime_state = device::runtime_status(paths, spec);
        if package_ready
            && property_ready
            && pid.is_some_and(|pid| pid != before_pid)
            && runtime_state.state == ComponentState::Active
        {
            return Ok(pid.expect("checked system_server pid"));
        }
        if Instant::now() >= deadline {
            return Err(msg(format!(
                "userspace did not become ready within 90 seconds: package_ready={package_ready} property_ready={property_ready} system_server_pid={pid:?} runtime={} {}",
                runtime_state.state,
                runtime_state.detail.unwrap_or_default()
            )));
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn property_ready(expected: &str, current: &str, allow_any_non_v: bool) -> bool {
    current == expected || (allow_any_non_v && !current.starts_with('V'))
}

fn is_transient_probe_error(text: &str) -> bool {
    text.contains("android.os.storage.StorageManager.getVolumes()")
        || text.contains(
            "Cannot access system provider: 'settings' before system providers are installed!",
        )
}

fn probe_gate() -> Result<GateProbe> {
    let deadline = Instant::now() + RESTART_DEADLINE;
    loop {
        match probe_gate_once() {
            Err(error)
                if is_transient_probe_error(&error.to_string()) && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(500));
            }
            result => return result,
        }
    }
}

fn probe_gate_once() -> Result<GateProbe> {
    let output = run_as_shell(&["package", "install-create", "-r"])?;
    let text = output_text(&output);
    if !output.status.success() {
        if text.contains(V_TYPE_ERROR) {
            return Ok(GateProbe::VBlocked);
        }
        return Err(msg(format!("shell install-create failed: {text}")));
    }
    let session = parse_session_id(&text)
        .ok_or_else(|| msg(format!("cannot parse shell install session id: {text}")))?;
    let session_text = session.to_string();
    let abandon = run_as_shell(&["package", "install-abandon", &session_text])?;
    if !abandon.status.success() {
        return Err(msg(format!(
            "install-abandon failed for session {session}: {}",
            output_text(&abandon)
        )));
    }
    Ok(GateProbe::Open)
}

fn run_as_shell(args: &[&str]) -> Result<std::process::Output> {
    if unsafe { libc::geteuid() } == 2000 {
        return run("/system/bin/cmd", args);
    }
    let su = Path::new("/system/bin/su");
    if !su.exists() {
        return Err(msg(
            "ADB-install verification requires shell UID 2000 or an active KSU/SUU su transport",
        ));
    }
    let identity = run("/system/bin/su", &["2000", "id", "-u"])?;
    if !identity.status.success() || output_text(&identity).trim() != "2000" {
        return Err(msg(format!(
            "cannot enter shell UID 2000 for ADB-install verification: {}",
            output_text(&identity)
        )));
    }
    let mut command = vec!["2000", "/system/bin/cmd"];
    command.extend_from_slice(args);
    run("/system/bin/su", &command)
}

fn parse_session_id(text: &str) -> Option<u32> {
    let start = text.rfind('[')? + 1;
    let end = text[start..].find(']')? + start;
    let value = &text[start..end];
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn replacement_value(original: &str) -> Result<String> {
    let suffix = original.strip_prefix('V').ok_or_else(|| {
        msg(format!(
            "unexpected {PROPERTY} value {original:?}; expected canonical V<digits>"
        ))
    })?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(msg(format!(
            "unexpected {PROPERTY} value {original:?}; expected canonical V<digits>"
        )));
    }
    Ok(format!("A{suffix}"))
}

fn system_server_pid() -> Result<u32> {
    let output = run("/system/bin/pidof", &["system_server"])?;
    if !output.status.success() {
        return Err(msg("system_server is not running"));
    }
    output_text(&output)
        .split_whitespace()
        .next()
        .ok_or_else(|| msg("pidof returned no system_server pid"))?
        .parse()
        .map_err(|error| msg(format!("invalid system_server pid: {error}")))
}

fn open_policy_values(paths: &Paths, current: String) -> Result<(String, String)> {
    let state = load_state(paths)?;
    let original = open_original_value(&state, &current);
    Ok((original, current))
}

fn open_original_value(state: &PolicyState, current: &str) -> String {
    if state.policy_enabled {
        state
            .original_value
            .clone()
            .unwrap_or_else(|| current.to_string())
    } else {
        current.to_string()
    }
}

fn mark_verified(
    paths: &Paths,
    runtime: Option<&str>,
    original: String,
    replacement: String,
) -> Result<()> {
    let state = PolicyState {
        policy_enabled: true,
        phase: Phase::Active,
        original_value: Some(original),
        replacement_value: Some(replacement),
        applied_boot_id: Some(boot_id()),
        verified_boot_id: Some(boot_id()),
        verified_system_server_pid: Some(system_server_pid()?),
        verified_at: Some(epoch_seconds()),
        runtime: runtime.map(str::to_string),
        last_error: None,
        ..PolicyState::default()
    };
    save_state(paths, &state)
}

fn mark_failure(paths: &Paths, policy_enabled: bool, error: String) {
    let mut state = load_state(paths).unwrap_or_default();
    state.policy_enabled = policy_enabled;
    state.phase = Phase::Broken;
    state.last_error = Some(error);
    state.verified_boot_id = None;
    state.verified_system_server_pid = None;
    state.verified_at = None;
    let _ = save_state(paths, &state);
}

fn state_path(paths: &Paths) -> PathBuf {
    paths.state.join("adb-install.json")
}

fn load_state(paths: &Paths) -> Result<PolicyState> {
    let path = state_path(paths);
    if !path.exists() {
        return Ok(PolicyState::default());
    }
    let bytes = fs::read(&path).at(&path)?;
    let state: PolicyState = serde_json::from_slice(&bytes)?;
    if state.schema != STATE_SCHEMA {
        return Err(msg(format!(
            "unsupported adb-install state schema: {}",
            state.schema
        )));
    }
    Ok(state)
}

fn save_state(paths: &Paths, state: &PolicyState) -> Result<()> {
    atomic_write(
        &state_path(paths),
        &serde_json::to_vec_pretty(state)?,
        0o600,
    )
}

fn component_status(state: ComponentState, detail: String) -> ComponentStatus {
    ComponentStatus {
        id: ID.to_string(),
        state,
        detail: Some(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_preserves_the_firmware_suffix() {
        assert_eq!(
            replacement_value("V261026").expect("replacement"),
            "A261026"
        );
        assert_eq!(replacement_value("V19").expect("replacement"), "A19");
    }

    #[test]
    fn replacement_rejects_noncanonical_values() {
        for value in ["", "A261026", "v261026", "V", "V-1", "V261026x", "VV261026"] {
            assert!(replacement_value(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn session_id_parser_requires_numeric_brackets() {
        assert_eq!(
            parse_session_id("Success: created install session [12345]"),
            Some(12345)
        );
        assert_eq!(
            parse_session_id("Success: created install session [x]"),
            None
        );
        assert_eq!(parse_session_id("no session"), None);
    }

    #[test]
    fn property_gate_accepts_an_external_non_v_value_only_for_enable() {
        assert!(property_ready("A261026", "261026", true));
        assert!(property_ready("V261026", "V261026", false));
        assert!(!property_ready("A261026", "V261026", true));
        assert!(!property_ready("V261026", "261026", false));
    }

    #[test]
    fn idempotent_enable_preserves_the_original_stock_value() {
        let mut state = PolicyState {
            policy_enabled: true,
            original_value: Some("V261026".to_string()),
            ..PolicyState::default()
        };
        assert_eq!(open_original_value(&state, "261026"), "V261026");
        state.policy_enabled = false;
        assert_eq!(open_original_value(&state, "261026"), "261026");
    }

    #[test]
    fn startup_probe_errors_are_bounded_retry_candidates() {
        assert!(is_transient_probe_error(
            "java.lang.NullPointerException at android.os.storage.StorageManager.getVolumes()"
        ));
        assert!(is_transient_probe_error(
            "Cannot access system provider: 'settings' before system providers are installed!"
        ));
        assert!(!is_transient_probe_error(V_TYPE_ERROR));
        assert!(!is_transient_probe_error("permission denied"));
    }

    #[test]
    fn state_defaults_to_disabled() {
        let state = PolicyState::default();
        assert!(!state.policy_enabled);
        assert_eq!(state.phase, Phase::Disabled);
        assert_eq!(state.schema, STATE_SCHEMA);
    }
}
