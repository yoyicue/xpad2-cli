use crate::catalog::Catalog;
use crate::device;
use crate::error::{Error, Result, msg, needs_reboot};
use crate::install;
use crate::logging::TransactionLog;
use crate::model::{ComponentState, Receipt};
use crate::ota;
use crate::root::RootSession;
use crate::util::{OperationLock, Paths, boot_id, selinux};
use serde_json::json;
use std::collections::BTreeSet;

const FULL: &[&str] = &["ksu", "xpad-installer", "ksu-manager", "boominstaller"];

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

    let mut result = (|| {
        device::profile_check(catalog)?;
        if components.iter().any(|id| id == "ksu") {
            let ota_status = ota::freeze(&mut log)?;
            println!(
                "✓ ota: {}",
                ota_status.detail.as_deref().unwrap_or("frozen")
            );
            if device::ksu_module_loaded() {
                root_session = Some(RootSession {
                    owned: false,
                    started_boot_id: started_boot.clone(),
                });
            } else {
                root_session = Some(RootSession::acquire(catalog, paths, &mut log, false)?);
            }
            install::ensure_ksu(
                catalog,
                paths,
                root_session.as_ref().expect("root session initialized"),
                &mut log,
            )?;
        }
        if components.iter().any(|id| id == "xpad-installer") {
            install::install_locked_cli(catalog, paths, "xpad-installer", &mut log)?;
        }
        if components.iter().any(|id| id == "ksu-manager") {
            install::install_locked_apk(catalog, paths, "ksu-manager", &mut log)?;
        }
        if components.iter().any(|id| id == "boominstaller") {
            install::install_locked_apk(catalog, paths, "boominstaller", &mut log)?;
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
        } else if components.iter().any(|id| id == "ksu") {
            let ota_status = ota::status();
            if ota_status.state != ComponentState::Active {
                result = Err(msg(format!(
                    "final OTA freeze verification failed: {}",
                    ota_status.detail.unwrap_or_default()
                )));
            }
            let ksu_status = device::ksu_status(paths);
            if result.is_ok() && ksu_status.state != ComponentState::Active {
                result = Err(needs_reboot(format!(
                    "final KernelSU verification failed: {}",
                    ksu_status.detail.unwrap_or_default()
                )));
            }
        }
    }
    if result.is_ok() && components.iter().any(|id| id == "xpad-installer") {
        let state = device::cli_status(catalog.artifact("xpad-installer")?);
        if state.state != ComponentState::Installed {
            result = Err(msg(format!(
                "final xpad-installer verification failed: {}",
                state.detail.unwrap_or_default()
            )));
        }
    }
    if result.is_ok() && components.iter().any(|id| id == "ksu-manager") {
        let state = device::apk_status(catalog.artifact("ksu-manager")?);
        if state.state != ComponentState::Installed {
            result = Err(msg(format!(
                "final KSU Manager verification failed: {}",
                state.detail.unwrap_or_default()
            )));
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
    if requested.is_empty() {
        return Err(msg("install requires at least one component"));
    }
    let mut selected = BTreeSet::new();
    for id in requested {
        if id == "full" {
            selected.extend(FULL.iter().map(|id| id.to_string()));
        } else if FULL.contains(&id.as_str()) {
            selected.insert(id.clone());
        } else {
            return Err(msg(format!("unknown built-in component: {id}")));
        }
    }
    let mut ordered = Vec::new();
    for id in FULL {
        if selected.remove(*id) {
            ordered.push((*id).to_string());
        }
    }
    Ok(ordered)
}
