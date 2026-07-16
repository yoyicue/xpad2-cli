use crate::apk;
use crate::catalog::{Catalog, ResolvedArtifact};
use crate::device;
use crate::error::{IoContext, Result, msg, needs_reboot};
use crate::logging::TransactionLog;
use crate::model::{ApkIdentity, Artifact, ComponentState};
use crate::root::RootSession;
use crate::util::{
    Paths, atomic_write, copy_atomic, safe_filename, sha256_bytes, sha256_file, shell_quote,
    validate_elf_arm64,
};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const XPAD_INSTALL: &str = "/data/local/tmp/xpad-install";

pub fn install_locked_cli(
    catalog: &Catalog,
    paths: &Paths,
    id: &str,
    log: &mut TransactionLog,
) -> Result<bool> {
    let artifact = catalog.artifact(id)?;
    let target = artifact
        .target
        .as_deref()
        .ok_or_else(|| msg(format!("locked CLI {id} has no target")))?;
    let state = device::cli_status(artifact);
    if state.state == ComponentState::Installed {
        if id == "xpad-installer" {
            ensure_installer_backup(log)?;
        }
        log.event(
            "component",
            "skipped",
            json!({"id": id, "reason": "already verified"}),
        )?;
        println!("✓ {id}: 已是锁定版本，跳过");
        return Ok(false);
    }
    let resolved = catalog.resolve(id, paths)?;
    let bytes = verified_bytes(&resolved)?;
    let staging = paths.work.join(format!("validate-{id}"));
    atomic_write(&staging, &bytes, artifact.mode)?;
    validate_elf_arm64(&staging)?;
    atomic_write(Path::new(target), &bytes, artifact.mode)?;
    validate_elf_arm64(Path::new(target))?;
    let actual = sha256_file(Path::new(target))?;
    if actual != artifact.sha256 {
        return Err(msg(format!("post-install SHA-256 mismatch for {id}")));
    }
    if id == "xpad-installer" {
        let output = log.run_streaming("xpad-install self-test", target, &["self-test"])?;
        if !output.status.success() {
            return Err(classify_installer_error(
                "xpad-install self-test",
                output.status.code(),
                &output.text,
            ));
        }
        if !output.text.contains("XPAD_INSTALL_SELF_TEST status=ok") {
            return Err(msg("xpad-install self-test returned no success marker"));
        }
        ensure_installer_backup(log)?;
    }
    log.event("component", "installed", json!({"id": id, "target": target, "sha256": actual, "source": resolved.source_description()}))?;
    println!("✓ {id}: 已安装并验证");
    Ok(true)
}

pub fn ensure_installer_backup(log: &mut TransactionLog) -> Result<bool> {
    if !Path::new(XPAD_INSTALL).is_file() {
        return Err(msg(
            "xpad-install is not installed; cannot maintain installer-backup",
        ));
    }
    println!("检查 0044 备用安装身份（健康时不创建事务）…");
    let output = log.run_streaming(
        "xpad-install znxrun ensure",
        XPAD_INSTALL,
        &["znxrun", "ensure"],
    )?;
    if !output.status.success() {
        return Err(classify_installer_error(
            "installer-backup repair",
            output.status.code(),
            &output.text,
        ));
    }
    let state = device::installer_backup_status();
    if state.state != ComponentState::Active {
        return Err(msg(format!(
            "installer-backup final verification failed: {}",
            state.detail.unwrap_or_default()
        )));
    }
    let changed = output.text.contains("ZNXRUN_ENSURE result=repaired");
    log.event(
        "component",
        if changed { "repaired" } else { "verified" },
        json!({"id": "installer-backup", "transport": "0044", "uid": 10072}),
    )?;
    println!("✓ installer-backup: 正式 anchor 与 UID 10072 已验证");
    Ok(changed)
}

pub fn install_arbitrary_cli(
    source: &Path,
    name: Option<&str>,
    log: &mut TransactionLog,
) -> Result<PathBuf> {
    validate_elf_arm64(source)?;
    let filename = match name {
        Some(name) => safe_filename(name)?.to_string(),
        None => source
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| msg("CLI source has no valid basename"))
            .and_then(|s| safe_filename(s).map(str::to_string))?,
    };
    let target = PathBuf::from("/data/local/tmp").join(filename);
    let digest = sha256_file(source)?;
    copy_atomic(source, &target, 0o700)?;
    validate_elf_arm64(&target)?;
    if sha256_file(&target)? != digest {
        return Err(msg("post-install CLI SHA-256 mismatch"));
    }
    log.event(
        "cli",
        "installed",
        json!({"source": source, "target": target, "sha256": digest}),
    )?;
    Ok(target)
}

pub fn ensure_runtime(
    catalog: &Catalog,
    paths: &Paths,
    runtime_id: &str,
    root: &RootSession,
    log: &mut TransactionLog,
) -> Result<bool> {
    root.check_boot()?;
    let spec = device::runtime_spec(runtime_id)
        .ok_or_else(|| msg(format!("unknown runtime: {runtime_id}")))?;
    let resolved = catalog.resolve(spec.loader_artifact, paths)?;
    let bytes = verified_bytes(&resolved)?;
    let diagnostic = paths.state.join(spec.diagnostic_filename);
    atomic_write(&diagnostic, &bytes, 0o700)?;
    let before = device::runtime_status(paths, spec);
    if before.state == ComponentState::Active {
        log.event(
            "component",
            "skipped",
            json!({"id": spec.id, "reason": "healthy in current boot"}),
        )?;
        println!("✓ {}: 当前启动周期已健康加载，跳过", spec.id);
        return Ok(false);
    }
    if before.state == ComponentState::NeedsReboot {
        return Err(needs_reboot(
            before
                .detail
                .unwrap_or_else(|| "loaded KernelSU is incompatible".to_string()),
        ));
    }
    if device::ksu_module_loaded() {
        return Err(needs_reboot(before.detail.unwrap_or_else(|| {
            format!(
                "a KernelSU-family module is already loaded; refusing online switch to {}",
                spec.display_name
            )
        })));
    }
    let path = diagnostic
        .to_str()
        .ok_or_else(|| msg("invalid runtime diagnostic path"))?;
    let command = format!(
        "{} late-load --kmi {}",
        shell_quote(path),
        shell_quote(spec.kmi)
    );
    log.event(
        "component",
        "running",
        json!({"id": spec.id, "action": "late-load", "runtime": spec.display_name}),
    )?;
    let output = root.exec(&command)?;
    log.command_result(
        &format!("{} late-load", spec.id),
        output.status == 0,
        &output.text,
    )?;
    if output.status != 0 {
        return Err(msg(format!(
            "{} late-load failed with exit {}: {}",
            spec.display_name, output.status, output.text
        )));
    }
    // `ksud late-load` daemonizes before the child loads the embedded module.
    // Keep the temporary root window open until that child has either exposed
    // the complete locked identity or timed out. Closing root immediately
    // races the child and can restore SELinux before init_module(2).
    log.event(
        "component",
        "waiting",
        json!({"id": spec.id, "deadline_seconds": 30}),
    )?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut after = device::runtime_status(paths, spec);
    while after.state != ComponentState::Active && Instant::now() < deadline {
        root.check_boot()?;
        thread::sleep(Duration::from_millis(250));
        after = device::runtime_status(paths, spec);
    }
    if after.state != ComponentState::Active {
        let detail = after.detail.unwrap_or_default();
        if device::ksu_module_loaded() {
            return Err(needs_reboot(format!(
                "{} is resident but failed locked debug-info verification: {detail}",
                spec.display_name
            )));
        }
        return Err(msg(format!(
            "{} late-load child did not register the module within 30 seconds: {detail}",
            spec.display_name
        )));
    }
    log.event(
        "component",
        "active",
        json!({"id": spec.id, "version": spec.version, "runtime": "late-load"}),
    )?;
    println!(
        "✓ {}: {} / {} / late-load 已验证",
        spec.id, spec.display_name, spec.version
    );
    Ok(true)
}

pub fn install_locked_apk(
    catalog: &Catalog,
    paths: &Paths,
    id: &str,
    log: &mut TransactionLog,
) -> Result<bool> {
    let artifact = catalog.artifact(id)?;
    let mut current = device::apk_status(artifact);
    if id == "boominstaller" && current.state == ComponentState::Ready {
        println!("BoomInstaller 本地 ADB 自启动正在收敛，最多等待 60 秒…");
        for _ in 0..60 {
            thread::sleep(Duration::from_secs(1));
            current = device::apk_status(artifact);
            if current.state == ComponentState::Active {
                break;
            }
        }
    }
    let needs_activation = id == "boominstaller"
        && matches!(
            current.state,
            ComponentState::Broken | ComponentState::Ready | ComponentState::Installed
        );
    if (id == "boominstaller" && current.state == ComponentState::Active)
        || (id != "boominstaller" && current.state == ComponentState::Installed)
    {
        log.event(
            "component",
            "skipped",
            json!({"id": id, "reason": "installed identity verified"}),
        )?;
        println!("✓ {id}: 已是锁定版本，跳过");
        return Ok(false);
    }
    if current.state == ComponentState::Incompatible {
        return Err(msg(format!(
            "{id} has an incompatible installed identity; xpad2 will not uninstall it or erase app data: {}",
            current.detail.unwrap_or_default()
        )));
    }
    install_locked_cli(catalog, paths, "xpad-installer", log)?;
    let resolved = catalog.resolve(id, paths)?;
    let bytes = verified_bytes(&resolved)?;
    let staged = paths.work.join(&artifact.filename);
    atomic_write(&staged, &bytes, 0o600)?;
    let identity = apk::inspect(&staged)?;
    verify_locked_apk_identity(artifact, &identity)?;
    apk::check_arm64_compatible(&identity)?;

    let mut changed = false;
    if !needs_activation {
        install_apk_with_xpad_install(&staged, &identity, log)?;
        changed = true;
        verify_installed(artifact, &identity)?;
    }
    if id == "boominstaller" {
        activate_boom(&identity, log)?;
        changed = true;
        let final_state = device::apk_status(artifact);
        if final_state.state != ComponentState::Active {
            return Err(msg(format!(
                "BoomInstaller activation verification failed: {}",
                final_state.detail.unwrap_or_default()
            )));
        }
    }
    log.event("component", "installed", json!({"id": id, "package": identity.package, "version_code": identity.version_code, "cert_sha256": identity.cert_sha256, "source": resolved.source_description()}))?;
    println!(
        "✓ {id}: 包名、版本、签名{}已验证",
        if id == "boominstaller" {
            "和服务"
        } else {
            ""
        }
    );
    Ok(changed)
}

pub fn install_arbitrary_apk(path: &Path, log: &mut TransactionLog) -> Result<ApkIdentity> {
    let identity = apk::inspect(path)?;
    apk::check_arm64_compatible(&identity)?;
    println!(
        "APK: package={} versionCode={} certSHA256={} ABI={}",
        identity.package,
        identity.version_code,
        identity.cert_sha256,
        if identity.native_abis.is_empty() {
            "none".to_string()
        } else {
            identity.native_abis.join(",")
        }
    );
    if let Some(installed) = device::installed_apk_identity(&identity.package)? {
        if installed.cert_sha256 != identity.cert_sha256 {
            return Err(msg(format!(
                "installed {} uses a different signing certificate; refusing uninstall/data loss",
                identity.package
            )));
        }
        if installed.version_code >= identity.version_code {
            log.event("apk", "skipped", json!({"package": identity.package, "installed_version": installed.version_code, "candidate_version": identity.version_code}))?;
            return Ok(installed);
        }
    }
    if !Path::new(XPAD_INSTALL).exists() {
        return Err(msg(
            "xpad-install is not installed; run `xpad2 install xpad-installer` first",
        ));
    }
    install_apk_with_xpad_install(path, &identity, log)?;
    let installed = device::installed_apk_identity(&identity.package)?.ok_or_else(|| {
        msg(format!(
            "PackageManager cannot find {} after install",
            identity.package
        ))
    })?;
    if installed.version_code != identity.version_code
        || installed.cert_sha256 != identity.cert_sha256
    {
        return Err(msg("independent PackageManager APK verification failed"));
    }
    Ok(installed)
}

fn verified_bytes(resolved: &ResolvedArtifact<'_>) -> Result<Vec<u8>> {
    let bytes = resolved.load()?;
    if bytes.len() as u64 != resolved.artifact.size {
        return Err(msg(format!("size mismatch for {}", resolved.artifact.id)));
    }
    let actual = sha256_bytes(&bytes);
    if actual != resolved.artifact.sha256 {
        return Err(msg(format!(
            "SHA-256 mismatch for {}",
            resolved.artifact.id
        )));
    }
    Ok(bytes)
}

fn verify_locked_apk_identity(artifact: &Artifact, identity: &ApkIdentity) -> Result<()> {
    if identity.size != artifact.size
        || identity.apk_sha256 != artifact.sha256
        || artifact.package.as_deref() != Some(identity.package.as_str())
        || artifact.version_code != Some(identity.version_code)
        || artifact.cert_sha256.as_deref() != Some(identity.cert_sha256.as_str())
    {
        return Err(msg(format!(
            "locked APK identity mismatch for {}: package={} versionCode={} cert={} sha256={} size={}",
            artifact.id,
            identity.package,
            identity.version_code,
            identity.cert_sha256,
            identity.apk_sha256,
            identity.size
        )));
    }
    Ok(())
}

fn install_apk_with_xpad_install(
    path: &Path,
    identity: &ApkIdentity,
    log: &mut TransactionLog,
) -> Result<()> {
    let path_text = path.to_str().ok_or_else(|| msg("invalid APK path"))?;
    let already_installed = device::installed_apk_identity(&identity.package)?.is_some();
    let (verb, backend, action) = apk_install_plan(already_installed);
    println!(
        "{action} {}：只通过受管 0044，通常 10–30 秒；若需要用 31317 补回 0044，总计最多约 60 秒。若 Android 报 process is bad，将停止并要求普通重启。",
        identity.package,
    );
    log.event(
        "apk",
        "installing",
        json!({"package": identity.package, "version_code": identity.version_code, "operation": verb, "backend": backend}),
    )?;
    let command_name = format!("xpad-install {verb} --backend {backend}");
    let output = log.run_streaming(
        &command_name,
        XPAD_INSTALL,
        &[verb, "--backend", backend, path_text],
    )?;
    if !output.status.success() {
        return Err(classify_installer_error(
            if already_installed {
                "APK upgrade"
            } else {
                "APK install"
            },
            output.status.code(),
            &output.text,
        ));
    }
    Ok(())
}

fn apk_install_plan(already_installed: bool) -> (&'static str, &'static str, &'static str) {
    if already_installed {
        // Every target APK stays inside the persistent UID 10072/0044 identity.
        // The auto backend may switch from Provider to PackageInstaller within
        // that identity; guarded 31317 is only allowed to repair 0044 first.
        ("upgrade", "auto", "升级")
    } else {
        ("install", "auto", "安装")
    }
}

fn verify_installed(artifact: &Artifact, expected: &ApkIdentity) -> Result<()> {
    let package = artifact.package.as_deref().unwrap_or(&expected.package);
    let installed = device::installed_apk_identity(package)?.ok_or_else(|| {
        msg(format!(
            "PackageManager cannot find {package} after install"
        ))
    })?;
    if installed.package != expected.package
        || installed.version_code != expected.version_code
        || installed.cert_sha256 != expected.cert_sha256
    {
        return Err(msg(format!(
            "independent PackageManager verification failed for {package}"
        )));
    }
    if device::installer_attribution(package).is_none() {
        return Err(msg(format!(
            "PackageManager did not report installer attribution for {package}"
        )));
    }
    Ok(())
}

fn activate_boom(identity: &ApkIdentity, log: &mut TransactionLog) -> Result<()> {
    let apk_path = device::installed_apk_path(&identity.package)?.ok_or_else(|| {
        msg(format!(
            "PackageManager cannot find {} before activation",
            identity.package
        ))
    })?;
    let starter = boom_starter_path(&apk_path)?;
    if !starter.is_file() {
        return Err(msg(format!(
            "installed BoomInstaller starter is missing: {}",
            starter.display()
        )));
    }
    let starter_text = starter
        .to_str()
        .ok_or_else(|| msg("invalid Boom starter path"))?;
    let apk_text = apk_path
        .to_str()
        .ok_or_else(|| msg("invalid Boom APK path"))?;
    let starter_arg = format!("--starter={starter_text}");
    let apk_arg = format!("--apk={apk_text}");
    log.event(
        "boominstaller",
        "activating",
        json!({"autostart": true, "apk": apk_path, "starter": starter}),
    )?;
    println!("激活 BoomInstaller 并配置普通开机自启动，预计约 20–60 秒…");
    let output = log.run_streaming(
        "xpad-install activate",
        XPAD_INSTALL,
        &["activate", &starter_arg, &apk_arg],
    )?;
    if !output.status.success() {
        return Err(classify_installer_error(
            "BoomInstaller activation",
            output.status.code(),
            &output.text,
        ));
    }
    Ok(())
}

fn boom_starter_path(apk: &Path) -> Result<PathBuf> {
    let base = apk
        .parent()
        .ok_or_else(|| msg("installed BoomInstaller APK has no parent directory"))?;
    Ok(base.join("lib/arm64/libshizuku.so"))
}

fn classify_installer_error(
    context: &str,
    exit_code: Option<i32>,
    text: &str,
) -> crate::error::Error {
    let lower = text.to_ascii_lowercase();
    if exit_code == Some(75) {
        needs_reboot(format!(
            "{context}: xpad-install safety circuit breaker tripped; reboot clears this per-boot state"
        ))
    } else if lower.contains("process is bad")
        || lower.contains("bad process")
        || lower.contains("zygote") && lower.contains("bad")
    {
        needs_reboot(format!(
            "{context}: Android marked the helper process bad; reboot clears this per-boot state"
        ))
    } else {
        msg(format!("{context} failed: {text}"))
    }
}

pub fn cleanup_work(paths: &Paths) -> Result<()> {
    if !paths.work.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&paths.work).at(&paths.work)? {
        let entry = entry.at(&paths.work)?;
        let path = entry.path();
        if entry.file_type().at(&path)?.is_dir() {
            fs::remove_dir_all(&path).at(&path)?;
        } else {
            fs::remove_file(&path).at(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{apk_install_plan, boom_starter_path, classify_installer_error};
    use std::path::Path;

    #[test]
    fn apk_installs_and_updates_use_the_managed_0044_identity() {
        assert_eq!(apk_install_plan(false), ("install", "auto", "安装"));
        assert_eq!(apk_install_plan(true), ("upgrade", "auto", "升级"));
    }

    #[test]
    fn boom_activation_uses_the_verified_installed_native_library() {
        let apk = Path::new("/data/app/example/base.apk");
        assert_eq!(
            boom_starter_path(apk).expect("derive starter"),
            Path::new("/data/app/example/lib/arm64/libshizuku.so")
        );
    }

    #[test]
    fn installer_exit_75_is_always_a_reboot_requirement() {
        let error = classify_installer_error("test", Some(75), "no textual hint");
        assert!(error.requires_reboot());
    }
}
