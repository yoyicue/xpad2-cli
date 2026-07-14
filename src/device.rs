use crate::apk;
use crate::catalog::Catalog;
use crate::model::{Artifact, ComponentState, ComponentStatus, DeviceStatus};
use crate::util::{
    Paths, boot_id, executable_exists, getprop, kernel_release, output_text, run, selinux,
    sha256_file, validate_elf_arm64,
};
use std::fs;
use std::path::{Path, PathBuf};

const SU: &str = "/data/local/tmp/su";
const KSU_DIAGNOSTIC: &str = "ksud-xpad2";

pub fn root_status() -> ComponentStatus {
    if !executable_exists(Path::new(SU)) {
        return status("temporary-root", ComponentState::Absent, None);
    }
    match run(SU, &["-c", "id"]) {
        Ok(output) if output.status.success() => {
            let text = output_text(&output);
            if text.lines().any(|line| line.contains("uid=0(root)")) {
                status(
                    "temporary-root",
                    ComponentState::Active,
                    Some("independent su -c id verified"),
                )
            } else {
                status(
                    "temporary-root",
                    ComponentState::Broken,
                    Some(&format!("su exists but identity is not root: {text}")),
                )
            }
        }
        Ok(output) => status(
            "temporary-root",
            ComponentState::Broken,
            Some(&format!("su verification failed: {}", output_text(&output))),
        ),
        Err(error) => status(
            "temporary-root",
            ComponentState::Broken,
            Some(&error.to_string()),
        ),
    }
}

pub fn ksu_status(paths: &Paths) -> ComponentStatus {
    if !ksu_module_loaded() {
        return status(
            "ksu",
            ComponentState::Absent,
            Some("not loaded in this boot"),
        );
    }
    let candidates = [
        paths.state.join(KSU_DIAGNOSTIC),
        PathBuf::from("/data/local/tmp/ksud-xpad2"),
    ];
    let Some(ksud) = candidates.iter().find(|p| executable_exists(p)) else {
        return status(
            "ksu",
            ComponentState::Broken,
            Some("kernel module is loaded but the locked diagnostic ksud is unavailable"),
        );
    };
    let Some(ksud_text) = ksud.to_str() else {
        return status("ksu", ComponentState::Broken, Some("invalid ksud path"));
    };
    match run(ksud_text, &["debug", "info"]) {
        Ok(output) => {
            let text = output_text(&output);
            let expected = [
                "version: 32547",
                "uapi_version: 2",
                "lkm: true",
                "late_load: true",
                "runtime_mode: late-load",
            ];
            if output.status.success()
                && expected
                    .iter()
                    .all(|needle| text.lines().any(|line| line.trim() == *needle))
            {
                status(
                    "ksu",
                    ComponentState::Active,
                    Some("version=32547 uapi=2 late-load"),
                )
            } else {
                status(
                    "ksu",
                    ComponentState::NeedsReboot,
                    Some(&format!(
                        "loaded KernelSU does not match the locked runtime: {text}"
                    )),
                )
            }
        }
        Err(error) => status(
            "ksu",
            ComponentState::NeedsReboot,
            Some(&format!("cannot query loaded KernelSU: {error}")),
        ),
    }
}

pub fn ksu_module_loaded() -> bool {
    let modules = fs::read_to_string("/proc/modules").unwrap_or_default();
    modules.lines().any(|line| line.starts_with("kernelsu "))
        || Path::new("/sys/module/kernelsu").exists()
}

pub fn cli_status(artifact: &Artifact) -> ComponentStatus {
    let target = artifact.target.as_deref().unwrap_or("");
    let path = Path::new(target);
    if !path.exists() {
        return status(&artifact.id, ComponentState::Absent, None);
    }
    if validate_elf_arm64(path).is_err() {
        return status(
            &artifact.id,
            ComponentState::Broken,
            Some("target is not a valid AArch64 ELF"),
        );
    }
    match sha256_file(path) {
        Ok(actual) if actual == artifact.sha256 => {
            if artifact.id == "xpad-installer" {
                match run(target, &["doctor"]) {
                    Ok(output) if output.status.success() => status(
                        &artifact.id,
                        ComponentState::Installed,
                        Some("locked hash and doctor verified"),
                    ),
                    Ok(output) => status(
                        &artifact.id,
                        ComponentState::Broken,
                        Some(&format!(
                            "locked hash; doctor failed: {}",
                            output_text(&output)
                        )),
                    ),
                    Err(error) => status(
                        &artifact.id,
                        ComponentState::Broken,
                        Some(&format!("locked hash; doctor unavailable: {error}")),
                    ),
                }
            } else {
                status(
                    &artifact.id,
                    ComponentState::Installed,
                    Some("locked hash verified"),
                )
            }
        }
        Ok(actual) => status(
            &artifact.id,
            ComponentState::Outdated,
            Some(&format!("SHA-256 mismatch: {actual}")),
        ),
        Err(error) => status(
            &artifact.id,
            ComponentState::Broken,
            Some(&error.to_string()),
        ),
    }
}

pub fn apk_status(artifact: &Artifact) -> ComponentStatus {
    let package = artifact.package.as_deref().unwrap_or("");
    let identity = match installed_apk_identity(package) {
        Ok(None) => return status(&artifact.id, ComponentState::Absent, None),
        Ok(Some(identity)) => identity,
        Err(error) => {
            return status(
                &artifact.id,
                ComponentState::Broken,
                Some(&format!("cannot inspect installed APK: {error}")),
            );
        }
    };
    if identity.package != package {
        return status(
            &artifact.id,
            ComponentState::Incompatible,
            Some(&format!(
                "installed package identity is {}",
                identity.package
            )),
        );
    }
    if artifact.cert_sha256.as_deref() != Some(identity.cert_sha256.as_str()) {
        return status(
            &artifact.id,
            ComponentState::Incompatible,
            Some(&format!(
                "signing certificate mismatch: {}",
                identity.cert_sha256
            )),
        );
    }
    let expected_version = artifact.version_code.unwrap_or_default();
    if identity.version_code < expected_version {
        return status(
            &artifact.id,
            ComponentState::Outdated,
            Some(&format!(
                "versionCode {} < {}",
                identity.version_code, expected_version
            )),
        );
    }
    if identity.version_code > expected_version {
        return status(
            &artifact.id,
            ComponentState::Incompatible,
            Some(&format!(
                "unvalidated newer versionCode {} > locked {}",
                identity.version_code, expected_version
            )),
        );
    }
    let attribution = installer_attribution(package);
    let Some(attribution) = attribution else {
        return status(
            &artifact.id,
            ComponentState::Broken,
            Some("APK identity is correct but PackageManager installer attribution is missing"),
        );
    };
    if artifact.id == "boominstaller" {
        let service = run("/system/bin/pidof", &["boominstaller_server"])
            .or_else(|_| run("pidof", &["boominstaller_server"]));
        let autostart = global_setting("adb_enabled").as_deref() == Some("1")
            && global_setting("adb_wifi_enabled").as_deref() == Some("1")
            && global_setting("adb_allowed_connection_time").as_deref() == Some("0");
        let service_active = service
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false);
        if service_active && autostart {
            status(
                &artifact.id,
                ComponentState::Active,
                Some(&format!(
                    "APK identity, installer={}, system service and autostart settings verified",
                    attribution
                )),
            )
        } else if autostart {
            status(
                &artifact.id,
                ComponentState::Ready,
                Some(&format!(
                    "APK identity and autostart are correct; service is not active yet (installer={})",
                    attribution
                )),
            )
        } else {
            status(
                &artifact.id,
                ComponentState::Broken,
                Some(&format!(
                    "APK identity is correct but runtime target is incomplete (service/autostart, installer={})",
                    attribution
                )),
            )
        }
    } else {
        status(
            &artifact.id,
            ComponentState::Installed,
            Some(&format!(
                "package, version, signing certificate and installer={} verified",
                attribution
            )),
        )
    }
}

pub fn installer_attribution(package: &str) -> Option<String> {
    let output = run("/system/bin/dumpsys", &["package", package]).ok()?;
    let text = output_text(&output);
    for line in text.lines() {
        let trimmed = line.trim();
        for key in ["installerPackageName=", "installerPackage="] {
            if let Some(value) = trimmed.strip_prefix(key) {
                let value = value.trim().trim_matches('"');
                if !value.is_empty() && value != "null" {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn global_setting(name: &str) -> Option<String> {
    let output = run("/system/bin/settings", &["get", "global", name]).ok()?;
    if !output.status.success() {
        return None;
    }
    let value = output_text(&output);
    (!value.is_empty() && value != "null").then_some(value)
}

pub fn installed_apk_identity(
    package: &str,
) -> crate::error::Result<Option<crate::model::ApkIdentity>> {
    let Some(path) = installed_apk_path(package)? else {
        return Ok(None);
    };
    Ok(Some(apk::inspect(&path)?))
}

pub fn installed_apk_path(package: &str) -> crate::error::Result<Option<PathBuf>> {
    let output =
        run("/system/bin/pm", &["path", package]).or_else(|_| run("pm", &["path", package]))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = output_text(&output);
    let paths: Vec<_> = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("package:"))
        .map(PathBuf::from)
        .collect();
    let Some(path) = paths
        .iter()
        .find(|path| path.file_name().is_some_and(|name| name == "base.apk"))
        .or_else(|| paths.first())
        .cloned()
    else {
        return Err(crate::error::msg(
            "PackageManager returned no base APK path",
        ));
    };
    Ok(Some(path))
}

pub fn snapshot(catalog: &Catalog, paths: &Paths) -> DeviceStatus {
    let fingerprint = getprop("ro.build.fingerprint");
    let kernel = kernel_release();
    let supported = fingerprint == catalog.lock.profile.build_fingerprint
        && kernel.starts_with(&catalog.lock.profile.kernel_release_prefix);
    let mut components = Vec::new();
    components.push(ksu_status(paths));
    if let Ok(artifact) = catalog.artifact("ksu-manager") {
        components.push(apk_status(artifact));
    }
    if let Ok(artifact) = catalog.artifact("xpad-installer") {
        components.push(cli_status(artifact));
    }
    if let Ok(artifact) = catalog.artifact("boominstaller") {
        components.push(apk_status(artifact));
    }
    let transaction_warnings = crate::logging::transaction_warnings(paths);
    let action_required = components
        .iter()
        .find(|c| c.state == ComponentState::NeedsReboot)
        .map(|c| {
            format!(
                "ordinary reboot required: {}",
                c.detail.as_deref().unwrap_or(&c.id)
            )
        })
        .or_else(|| transaction_warnings.first().cloned());
    DeviceStatus {
        product_version: env!("CARGO_PKG_VERSION").to_string(),
        supported,
        fingerprint,
        kernel_release: kernel,
        boot_id: boot_id(),
        selinux: selinux(),
        temporary_root: root_status(),
        components,
        transaction_warnings,
        action_required,
    }
}

pub fn profile_check(catalog: &Catalog) -> crate::error::Result<()> {
    let fingerprint = getprop("ro.build.fingerprint");
    let kernel = kernel_release();
    if fingerprint != catalog.lock.profile.build_fingerprint {
        return Err(crate::error::msg(format!(
            "unsupported firmware: expected /260 fingerprint {}, got {}",
            catalog.lock.profile.build_fingerprint, fingerprint
        )));
    }
    if !kernel.starts_with(&catalog.lock.profile.kernel_release_prefix) {
        return Err(crate::error::msg(format!(
            "unsupported kernel: expected {}*, got {}",
            catalog.lock.profile.kernel_release_prefix, kernel
        )));
    }
    Ok(())
}

pub fn component<'a>(snapshot: &'a DeviceStatus, id: &str) -> Option<&'a ComponentStatus> {
    if id == "temporary-root" {
        Some(&snapshot.temporary_root)
    } else {
        snapshot
            .components
            .iter()
            .find(|component| component.id == id)
    }
}

fn status(id: &str, state: ComponentState, detail: Option<&str>) -> ComponentStatus {
    ComponentStatus {
        id: id.to_string(),
        state,
        detail: detail.map(str::to_string),
    }
}
