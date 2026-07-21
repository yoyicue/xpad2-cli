use crate::catalog::Catalog;
use crate::device;
use crate::error::{Error, Result, msg, needs_reboot};
use crate::hooks;
use crate::install;
use crate::logging::TransactionLog;
use crate::model::{ComponentState, Receipt};
use crate::ota;
use crate::root::RootSession;
use crate::util::{OperationLock, Paths, boot_id, selinux};
use serde_json::json;
use std::collections::BTreeSet;

const FULL: &[&str] = &[
    "ksu",
    "xpad-installer",
    "installer-backup",
    "ksu-manager",
    "boominstaller",
];
const SUU_FULL: &[&str] = &[
    "suu",
    "xpad-installer",
    "installer-backup",
    "suu-manager",
    "boominstaller",
];
const COMPONENT_ORDER: &[&str] = &[
    "ksu",
    "suu",
    "zygisk",
    "lsposed",
    "xpad-installer",
    "installer-backup",
    "ksu-manager",
    "suu-manager",
    "boominstaller",
];

pub fn install_components(catalog: &Catalog, paths: &Paths, requested: &[String]) -> Result<()> {
    let components = normalize(requested)?;
    paths.ensure()?;
    let _lock = OperationLock::acquire(&paths.lock)?;
    let operation = format!("install {}", components.join(" "));
    let mut log = TransactionLog::start(paths, &operation)?;
    let started_boot = boot_id();
    let started_selinux = selinux();
    log.event(
        "preflight",
        "running",
        json!({"boot_id": started_boot, "selinux": started_selinux, "components": components}),
    )?;
    let mut root_session: Option<RootSession> = None;
    let mut package_manager_changed = false;

    let mut result = (|| {
        device::product_check(catalog)?;
        let runtime_id = components
            .iter()
            .find(|id| id.as_str() == "ksu" || id.as_str() == "suu")
            .map(String::as_str);
        let early_manager = match runtime_id {
            Some("ksu") if components.iter().any(|id| id == "ksu-manager") => Some("ksu-manager"),
            Some("suu") if components.iter().any(|id| id == "suu-manager") => Some("suu-manager"),
            _ => None,
        };

        if let Some(runtime_id) = runtime_id {
            // A runtime request is the only built-in install path that needs
            // the IonStack fingerprint/kernel gate. Product-family installs
            // below remain available when Root is unsupported.
            device::root_profile_check(catalog)?;
            let ota_status = ota::freeze(&mut log)?;
            println!(
                "✓ ota: {}",
                ota_status.detail.as_deref().unwrap_or("frozen")
            );
            // Install the matching Manager after the mandatory OTA gate but
            // before late-load. SukiSU validates and pins the official Manager
            // identity while the module is registering; doing this first also
            // removes a first-install race for KernelSU.
            if let Some(manager) = early_manager {
                package_manager_changed |=
                    install::install_locked_apk(catalog, paths, manager, &mut log)?;
            }
            if device::ksu_module_loaded() {
                root_session = Some(RootSession {
                    owned: false,
                    started_boot_id: started_boot.clone(),
                });
            } else {
                root_session = Some(RootSession::acquire(catalog, paths, &mut log, false)?);
            }
            install::ensure_runtime(
                catalog,
                paths,
                runtime_id,
                root_session.as_ref().expect("root session initialized"),
                &mut log,
            )?;
        }
        let mut hook_changed = false;
        for hook in ["zygisk", "lsposed"] {
            if components.iter().any(|id| id == hook) {
                hook_changed |= hooks::install_component(
                    catalog,
                    paths,
                    hook,
                    root_session
                        .as_ref()
                        .ok_or_else(|| msg("hook installation has no KernelSU root session"))?,
                    &mut log,
                )?;
            }
        }
        if hook_changed {
            let root = root_session
                .as_ref()
                .ok_or_else(|| msg("hook activation has no root session"))?;
            hooks::activate(catalog, paths, root, &mut log)?;
            if root.owned {
                // activate() restores Enforcing before Zygote starts but keeps
                // the temporary su as a recovery transport until Vector has
                // passed strict health checks. Reassert and verify that state
                // immediately before releasing the temporary su.
                root.restore_enforcing(&mut log)?;
                for hook in ["zygisk", "lsposed"] {
                    if components.iter().any(|id| id == hook) {
                        let state = hooks::status(hook);
                        if state.state != ComponentState::Active {
                            return Err(msg(format!(
                                "{hook} failed after restoring SELinux Enforcing: {}",
                                state.detail.unwrap_or_default()
                            )));
                        }
                    }
                }
            }
        }
        if components
            .iter()
            .any(|id| id == "xpad-installer" || id == "installer-backup")
        {
            install::install_locked_cli(catalog, paths, "xpad-installer", &mut log)?;
        }
        for manager in ["ksu-manager", "suu-manager"] {
            if components.iter().any(|id| id == manager) && early_manager != Some(manager) {
                package_manager_changed |=
                    install::install_locked_apk(catalog, paths, manager, &mut log)?;
            }
        }
        if components.iter().any(|id| id == "boominstaller") {
            package_manager_changed |=
                install::install_locked_apk(catalog, paths, "boominstaller", &mut log)?;
        }
        if package_manager_changed {
            // PackageManager regenerates packages.list after APK commits. The
            // anchor should make that rewrite persistent by itself; this final
            // idempotent pass also repairs and verifies the fallback after all
            // requested APK transactions have completed.
            install::ensure_installer_backup(catalog.artifact("xpad-installer")?, &mut log)?;
        }
        Ok(())
    })();

    if let Some(root) = &root_session
        && let Err(cleanup_error) = root.close(&mut log)
    {
        result = Err(match result {
            Ok(()) => cleanup_error,
            Err(original) => needs_reboot(format!(
                "{original}; additionally, safe root cleanup failed: {cleanup_error}"
            )),
        });
    }

    if result.is_ok() {
        if boot_id() != started_boot {
            result = Err(needs_reboot("Boot ID changed before final verification"));
        } else if let Some(runtime_id) = components
            .iter()
            .find(|id| id.as_str() == "ksu" || id.as_str() == "suu")
            .map(String::as_str)
        {
            let ota_status = ota::status();
            if ota_status.state != ComponentState::Active {
                result = Err(msg(format!(
                    "final OTA freeze verification failed: {}",
                    ota_status.detail.unwrap_or_default()
                )));
            }
            let runtime_status = device::runtime_spec(runtime_id)
                .map(|spec| device::runtime_status(paths, spec))
                .expect("normalized runtime");
            if result.is_ok() && runtime_status.state != ComponentState::Active {
                result = Err(needs_reboot(format!(
                    "final {runtime_id} verification failed: {}",
                    runtime_status.detail.unwrap_or_default()
                )));
            }
        }
    }
    if result.is_ok()
        && (package_manager_changed
            || components
                .iter()
                .any(|id| id == "xpad-installer" || id == "installer-backup"))
    {
        let state = device::cli_status(catalog.artifact("xpad-installer")?);
        if state.state != ComponentState::Installed {
            result = Err(msg(format!(
                "final xpad-installer verification failed: {}",
                state.detail.unwrap_or_default()
            )));
        }
    }
    if result.is_ok()
        && (package_manager_changed
            || components
                .iter()
                .any(|id| id == "xpad-installer" || id == "installer-backup"))
    {
        let state = device::installer_backup_status(catalog.artifact("xpad-installer")?);
        if state.state != ComponentState::Active {
            result = Err(msg(format!(
                "final installer-backup verification failed: {}",
                state.detail.unwrap_or_default()
            )));
        }
    }
    for manager in ["ksu-manager", "suu-manager"] {
        if result.is_ok() && components.iter().any(|id| id == manager) {
            let state = device::apk_status(catalog.artifact(manager)?);
            if state.state != ComponentState::Installed {
                result = Err(msg(format!(
                    "final {manager} verification failed: {}",
                    state.detail.unwrap_or_default()
                )));
            }
        }
    }
    if result.is_ok() && components.iter().any(|id| id == "boominstaller") {
        let state = device::apk_status(catalog.artifact("boominstaller")?);
        if state.state != ComponentState::Active {
            result = Err(msg(format!(
                "final BoomInstaller verification failed: {}",
                state.detail.unwrap_or_default()
            )));
        }
    }
    for hook in ["zygisk", "lsposed"] {
        if result.is_ok() && components.iter().any(|id| id == hook) {
            let state = hooks::status(hook);
            if state.state != ComponentState::Active {
                result = Err(msg(format!(
                    "final {hook} activation verification failed: {}",
                    state.detail.unwrap_or_default()
                )));
            }
        }
    }
    if result.is_ok()
        && root_session.as_ref().is_some_and(|root| root.owned)
        && selinux() != "Enforcing"
    {
        result = Err(needs_reboot("SELinux is not Enforcing after installation"));
    }

    let _ = install::cleanup_work(paths);
    let ended_boot = boot_id();
    let ended_selinux = selinux();
    let error_text = result.as_ref().err().map(ToString::to_string);
    let needs_reboot = result.as_ref().err().is_some_and(Error::requires_reboot);
    let receipt = Receipt {
        transaction_id: log.id.clone(),
        operation,
        success: result.is_ok(),
        started_boot_id: started_boot,
        ended_boot_id: ended_boot,
        started_selinux,
        ended_selinux,
        components,
        error: error_text,
        needs_reboot,
    };
    log.write_receipt(paths, &receipt)?;
    match &result {
        Ok(()) => println!(
            "完成：所有请求组件已通过独立验证，事务日志 {}",
            log.dir.display()
        ),
        Err(error) if error.requires_reboot() => {
            eprintln!("需要普通重启：{error}");
            eprintln!("诊断日志：{}", log.dir.display());
        }
        Err(error) => {
            eprintln!("安装未完成：{error}");
            eprintln!("诊断日志：{}", log.dir.display());
        }
    }
    result
}

fn normalize(requested: &[String]) -> Result<Vec<String>> {
    let mut selected = BTreeSet::new();
    let default = ["full".to_string()];
    for id in if requested.is_empty() {
        &default[..]
    } else {
        requested
    } {
        if id == "full" {
            selected.extend(FULL.iter().map(|id| id.to_string()));
        } else if id == "suu-full" {
            selected.extend(SUU_FULL.iter().map(|id| id.to_string()));
        } else if COMPONENT_ORDER.contains(&id.as_str()) {
            selected.insert(id.clone());
        } else {
            return Err(msg(format!("unknown built-in component: {id}")));
        }
    }
    if selected.contains("lsposed") {
        selected.insert("zygisk".to_string());
    }
    if selected.contains("zygisk") {
        selected.insert("ksu".to_string());
    }
    if selected.contains("ksu") && selected.contains("suu") {
        return Err(msg(
            "ksu and suu are mutually exclusive in one boot; choose full or suu-full",
        ));
    }
    let mut ordered = Vec::new();
    for id in COMPONENT_ORDER {
        if selected.remove(*id) {
            ordered.push((*id).to_string());
        }
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_includes_managed_installer_backup_after_cli() {
        let components = normalize(&["full".to_string()]).expect("normalize full");
        assert_eq!(components, FULL);
        let cli = components
            .iter()
            .position(|id| id == "xpad-installer")
            .expect("xpad-installer");
        let backup = components
            .iter()
            .position(|id| id == "installer-backup")
            .expect("installer-backup");
        assert_eq!(backup, cli + 1);
    }

    #[test]
    fn installer_backup_is_a_valid_standalone_component() {
        assert_eq!(
            normalize(&["installer-backup".to_string()]).expect("normalize backup"),
            vec!["installer-backup"]
        );
    }

    #[test]
    fn empty_selection_defaults_to_full() {
        assert_eq!(normalize(&[]).expect("default full"), FULL);
    }

    #[test]
    fn suu_full_selects_only_the_sukisu_runtime_and_manager() {
        assert_eq!(
            normalize(&["suu-full".to_string()]).expect("suu full"),
            SUU_FULL
        );
    }

    #[test]
    fn runtimes_cannot_be_mixed_in_one_boot() {
        let error =
            normalize(&["ksu".to_string(), "suu".to_string()]).expect_err("runtime mix must fail");
        assert!(error.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn zygisk_adds_the_tested_kernelsu_dependency() {
        assert_eq!(
            normalize(&["zygisk".to_string()]).expect("normalize zygisk"),
            vec!["ksu", "zygisk"]
        );
    }

    #[test]
    fn lsposed_adds_zygisk_and_kernelsu_in_order() {
        assert_eq!(
            normalize(&["lsposed".to_string()]).expect("normalize lsposed"),
            vec!["ksu", "zygisk", "lsposed"]
        );
    }
}
