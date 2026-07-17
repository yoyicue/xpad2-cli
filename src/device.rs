use crate::apk;
use crate::catalog::Catalog;
use crate::error::{IoContext, Result, msg};
use crate::model::{Artifact, ComponentState, ComponentStatus, DeviceStatus};
use crate::ota;
use crate::util::{
    Paths, boot_id, executable_exists, getprop, kernel_release, kernel_version, output_text, run,
    selinux, sha256_file, validate_elf_arm64,
};
use std::fs;
use std::path::{Path, PathBuf};

const SU: &str = "/data/local/tmp/su";

pub struct RuntimeSpec {
    pub id: &'static str,
    pub display_name: &'static str,
    pub loader_artifact: &'static str,
    pub diagnostic_filename: &'static str,
    pub diagnostic_fallback: &'static str,
    pub kmi: &'static str,
    pub version: u64,
    pub expected_info: &'static [&'static str],
    pub other_version_marker: &'static str,
}

pub const KSU_RUNTIME: RuntimeSpec = RuntimeSpec {
    id: "ksu",
    display_name: "KernelSU",
    loader_artifact: "ksud",
    diagnostic_filename: "ksud-xpad2",
    diagnostic_fallback: "/data/local/tmp/ksud-xpad2",
    kmi: "xpad2-4.19.191",
    version: 32547,
    expected_info: &[
        "version: 32547",
        "uapi_version: 2",
        "lkm: true",
        "late_load: true",
        "runtime_mode: late-load",
    ],
    other_version_marker: "version: 40796",
};

pub const SUU_RUNTIME: RuntimeSpec = RuntimeSpec {
    id: "suu",
    display_name: "SukiSU Ultra",
    loader_artifact: "suu-ksud",
    diagnostic_filename: "ksud-sukisu-xpad2",
    diagnostic_fallback: "/data/local/tmp/ksud-sukisu-xpad2",
    kmi: "xpad2-sukisu-4.19.191",
    version: 40796,
    expected_info: &[
        "version: 40796",
        "flags: 0x5",
        "features: 0x5",
        "lkm: true",
        "late_load: true",
        "runtime_mode: late-load",
    ],
    other_version_marker: "version: 32547",
};

pub fn runtime_spec(id: &str) -> Option<&'static RuntimeSpec> {
    match id {
        "ksu" => Some(&KSU_RUNTIME),
        "suu" => Some(&SUU_RUNTIME),
        _ => None,
    }
}

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
    runtime_status(paths, &KSU_RUNTIME)
}

pub fn suu_status(paths: &Paths) -> ComponentStatus {
    runtime_status(paths, &SUU_RUNTIME)
}

pub fn runtime_status(paths: &Paths, spec: &RuntimeSpec) -> ComponentStatus {
    if !ksu_module_loaded() {
        return status(
            spec.id,
            ComponentState::Absent,
            Some("not loaded in this boot"),
        );
    }
    let candidates = [
        paths.state.join(spec.diagnostic_filename),
        PathBuf::from(spec.diagnostic_fallback),
    ];
    let Some(ksud) = candidates.iter().find(|p| executable_exists(p)) else {
        let other = if spec.id == "ksu" {
            &SUU_RUNTIME
        } else {
            &KSU_RUNTIME
        };
        let other_candidates = [
            paths.state.join(other.diagnostic_filename),
            PathBuf::from(other.diagnostic_fallback),
        ];
        if let Some(other_ksud) = other_candidates.iter().find(|p| executable_exists(p))
            && let Some(other_text) = other_ksud.to_str()
            && let Ok(output) = run(other_text, &["debug", "info"])
        {
            let text = output_text(&output);
            if output.status.success()
                && other
                    .expected_info
                    .iter()
                    .all(|needle| text.lines().any(|line| line.trim() == *needle))
            {
                return status(
                    spec.id,
                    ComponentState::Ready,
                    Some("another supported runtime is active; ordinary reboot before switching"),
                );
            }
        }
        return status(
            spec.id,
            ComponentState::Broken,
            Some(&format!(
                "kernel module is loaded but the locked {} diagnostic is unavailable",
                spec.display_name
            )),
        );
    };
    let Some(ksud_text) = ksud.to_str() else {
        return status(
            spec.id,
            ComponentState::Broken,
            Some("invalid runtime diagnostic path"),
        );
    };
    match run(ksud_text, &["debug", "info"]) {
        Ok(output) => {
            let text = output_text(&output);
            if output.status.success()
                && spec
                    .expected_info
                    .iter()
                    .all(|needle| text.lines().any(|line| line.trim() == *needle))
            {
                status(
                    spec.id,
                    ComponentState::Active,
                    Some(&format!(
                        "{} version={} late-load",
                        spec.display_name, spec.version
                    )),
                )
            } else if text
                .lines()
                .any(|line| line.trim() == spec.other_version_marker)
            {
                status(
                    spec.id,
                    ComponentState::Ready,
                    Some("another supported runtime is active; ordinary reboot before switching"),
                )
            } else {
                status(
                    spec.id,
                    ComponentState::NeedsReboot,
                    Some(&format!(
                        "loaded KernelSU-family module does not match locked {}: {text}",
                        spec.display_name
                    )),
                )
            }
        }
        Err(error) => status(
            spec.id,
            ComponentState::NeedsReboot,
            Some(&format!(
                "cannot query loaded {} runtime: {error}",
                spec.display_name
            )),
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
                match run(target, &["self-test"]) {
                    Ok(output)
                        if output.status.success()
                            && output_text(&output)
                                .contains("XPAD_INSTALL_SELF_TEST status=ok") =>
                    {
                        status(
                            &artifact.id,
                            ComponentState::Installed,
                            Some("locked hash and read-only self-test verified"),
                        )
                    }
                    Ok(output) => status(
                        &artifact.id,
                        ComponentState::Broken,
                        Some(&format!(
                            "locked hash; read-only self-test failed: {}",
                            output_text(&output)
                        )),
                    ),
                    Err(error) => status(
                        &artifact.id,
                        ComponentState::Broken,
                        Some(&format!(
                            "locked hash; read-only self-test unavailable: {error}"
                        )),
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

pub fn verify_locked_cli_path(artifact: &Artifact) -> Result<&str> {
    let target = artifact
        .target
        .as_deref()
        .ok_or_else(|| msg(format!("locked CLI {} has no target", artifact.id)))?;
    let path = Path::new(target);
    let metadata = fs::symlink_metadata(path).at(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(msg(format!(
            "locked CLI target is not a regular file: {}",
            path.display()
        )));
    }
    validate_elf_arm64(path)?;
    let actual = sha256_file(path)?;
    if actual != artifact.sha256 {
        return Err(msg(format!(
            "locked CLI SHA-256 mismatch for {}: expected {}, got {actual}",
            artifact.id, artifact.sha256
        )));
    }
    Ok(target)
}

pub fn installer_backup_status(xpad_installer: &Artifact) -> ComponentStatus {
    let target = Path::new(
        xpad_installer
            .target
            .as_deref()
            .unwrap_or("/data/local/tmp/xpad-install"),
    );
    if !target.is_file() {
        return status(
            "installer-backup",
            ComponentState::Absent,
            Some("xpad-install is not installed"),
        );
    }
    let verified = match verify_locked_cli_path(xpad_installer) {
        Ok(path) => path,
        Err(error) => {
            return status(
                "installer-backup",
                ComponentState::Broken,
                Some(&format!(
                    "refusing to execute unverified xpad-install: {error}"
                )),
            );
        }
    };
    match run(verified, &["znxrun", "status"]) {
        Ok(output) => parse_installer_backup_status(output.status.success(), &output_text(&output)),
        Err(error) => status(
            "installer-backup",
            ComponentState::Broken,
            Some(&format!("status command failed: {error}")),
        ),
    }
}

fn parse_installer_backup_status(success: bool, text: &str) -> ComponentStatus {
    let detail = text.trim();
    if success && text.contains("status=healthy") {
        status("installer-backup", ComponentState::Active, Some(detail))
    } else if text.contains("status=legacy") {
        status(
            "installer-backup",
            ComponentState::Broken,
            Some("legacy alias is active but managed anchor repair is required"),
        )
    } else if text.contains("status=invalid") {
        status(
            "installer-backup",
            ComponentState::Incompatible,
            Some("znxrun exists with an unexpected identity"),
        )
    } else if text.contains("status=missing") {
        status(
            "installer-backup",
            ComponentState::Absent,
            Some("managed 0044 alias is missing; repair is available"),
        )
    } else {
        status(
            "installer-backup",
            ComponentState::Broken,
            Some(&format!("unrecognized status: {detail}")),
        )
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
        let autostart = global_setting("adb_enabled").as_deref() == Some("1")
            && global_setting("adb_wifi_enabled").as_deref() == Some("1")
            && global_setting("adb_allowed_connection_time").as_deref() == Some("0");
        let service_uids = match named_process_uids("boominstaller_server") {
            Ok(uids) => uids,
            Err(error) => {
                return status(
                    &artifact.id,
                    ComponentState::Broken,
                    Some(&format!(
                        "cannot verify BoomInstaller service identity: {error}"
                    )),
                );
            }
        };
        let service_identity = boom_service_identity(&service_uids);
        if let Err(error) = &service_identity {
            return status(
                &artifact.id,
                ComponentState::Broken,
                Some(&format!(
                    "APK identity is correct but BoomInstaller runtime is unsafe: {error}"
                )),
            );
        }
        if let Ok(Some((uid, mode))) = service_identity
            && autostart
        {
            status(
                &artifact.id,
                ComponentState::Active,
                Some(&format!(
                    "APK identity, installer={}, service uid={} ({}) and autostart settings verified",
                    attribution, uid, mode
                )),
            )
        } else if service_uids.is_empty() && autostart {
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

fn named_process_uids(name: &str) -> std::result::Result<Vec<u32>, String> {
    let output = run("/system/bin/pidof", &[name])
        .or_else(|_| run("pidof", &[name]))
        .map_err(|error| error.to_string())?;
    if !output.status.success() || output.stdout.is_empty() {
        return Ok(Vec::new());
    }
    let mut uids = Vec::new();
    for value in output_text(&output).split_whitespace() {
        let pid = value
            .parse::<u32>()
            .map_err(|_| format!("pidof returned invalid PID {value:?}"))?;
        let path = format!("/proc/{pid}/status");
        let process_status =
            fs::read_to_string(&path).map_err(|error| format!("cannot read {path}: {error}"))?;
        let uid = parse_proc_status_uid(&process_status)
            .ok_or_else(|| format!("{path} has no valid Uid field"))?;
        uids.push(uid);
    }
    uids.sort_unstable();
    Ok(uids)
}

fn parse_proc_status_uid(process_status: &str) -> Option<u32> {
    process_status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn boom_service_identity(uids: &[u32]) -> std::result::Result<Option<(u32, &'static str)>, String> {
    match uids {
        [] => Ok(None),
        [0] => Ok(Some((0, "root"))),
        [2000] => Ok(Some((2000, "adb-shell"))),
        [uid] => Err(format!(
            "unsupported uid={uid}; only root uid=0 or adb-shell uid=2000 is allowed"
        )),
        _ => Err(format!(
            "multiple service identities are present: {:?}",
            uids
        )),
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
    let version = kernel_version();
    let abi = getprop("ro.product.cpu.abi");
    let fingerprint_policy = catalog.lock.profile.fingerprint_policy();
    let supported = catalog
        .lock
        .profile
        .matches_runtime(&fingerprint, &kernel, &version, &abi);
    let mut components = Vec::new();
    components.push(ota::status());
    components.push(ksu_status(paths));
    components.push(suu_status(paths));
    if let Ok(artifact) = catalog.artifact("ksu-manager") {
        components.push(apk_status(artifact));
    }
    if let Ok(artifact) = catalog.artifact("suu-manager") {
        components.push(apk_status(artifact));
    }
    if let Ok(artifact) = catalog.artifact("xpad-installer") {
        components.push(cli_status(artifact));
        components.push(installer_backup_status(artifact));
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
        fingerprint_incremental: fingerprint_policy.incremental(&fingerprint),
        fingerprint,
        kernel_release: kernel,
        kernel_version: version,
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
    let version = kernel_version();
    let abi = getprop("ro.product.cpu.abi");
    let policy = catalog.lock.profile.fingerprint_policy();
    policy.validate()?;
    if !policy.matches(&fingerprint) {
        return Err(crate::error::msg(format!(
            "unsupported firmware fingerprint: expected {}, got {}",
            policy.expectation(),
            fingerprint
        )));
    }
    if !kernel.starts_with(&catalog.lock.profile.kernel_release_prefix) {
        return Err(crate::error::msg(format!(
            "unsupported kernel: expected {}*, got {}",
            catalog.lock.profile.kernel_release_prefix, kernel
        )));
    }
    if !catalog.lock.profile.kernel_version.is_empty()
        && version != catalog.lock.profile.kernel_version
    {
        return Err(crate::error::msg(format!(
            "unsupported kernel build: expected {:?}, got {:?}",
            catalog.lock.profile.kernel_version, version
        )));
    }
    if abi != catalog.lock.profile.abi {
        return Err(crate::error::msg(format!(
            "unsupported ABI: expected {}, got {}",
            catalog.lock.profile.abi, abi
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_managed_installer_backup_states() {
        let healthy = parse_installer_backup_status(
            true,
            "ZNXRUN_STATUS status=healthy alias=healthy uid=10070 expected_uid=10070 anchor=anchored",
        );
        assert_eq!(healthy.state, ComponentState::Active);

        let legacy = parse_installer_backup_status(
            false,
            "ZNXRUN_STATUS status=legacy alias=healthy uid=10070 expected_uid=10070 anchor=missing",
        );
        assert_eq!(legacy.state, ComponentState::Broken);

        let missing = parse_installer_backup_status(
            false,
            "ZNXRUN_STATUS status=missing alias=missing uid=none anchor=missing",
        );
        assert_eq!(missing.state, ComponentState::Absent);

        let invalid = parse_installer_backup_status(
            false,
            "ZNXRUN_STATUS status=invalid alias=invalid uid=none anchor=anchored",
        );
        assert_eq!(invalid.state, ComponentState::Incompatible);
    }

    #[test]
    fn healthy_marker_requires_success_exit_status() {
        let state = parse_installer_backup_status(
            false,
            "ZNXRUN_STATUS status=healthy alias=healthy uid=10070 expected_uid=10070 anchor=anchored",
        );
        assert_eq!(state.state, ComponentState::Broken);
    }

    #[test]
    fn installer_backup_refuses_a_tampered_xpad_installer_before_execution() {
        let catalog = Catalog::load().unwrap();
        let locked = catalog.artifact("xpad-installer").unwrap();
        let mut artifact = locked.clone();
        let root = std::env::temp_dir().join(format!(
            "xpad2-device-integrity-{}",
            crate::util::unique_id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("xpad-install");
        let mut bytes = crate::catalog::verify_embedded_artifact(locked)
            .unwrap()
            .to_vec();
        let last = bytes.last_mut().unwrap();
        *last ^= 0x01;
        fs::write(&target, bytes).unwrap();
        artifact.target = Some(target.display().to_string());

        let state = installer_backup_status(&artifact);
        assert_eq!(state.state, ComponentState::Broken);
        assert!(
            state
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("SHA-256 mismatch"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn boom_service_accepts_only_one_root_or_adb_shell_identity() {
        assert_eq!(boom_service_identity(&[]), Ok(None));
        assert_eq!(boom_service_identity(&[0]), Ok(Some((0, "root"))));
        assert_eq!(
            boom_service_identity(&[2000]),
            Ok(Some((2000, "adb-shell")))
        );
        assert!(boom_service_identity(&[1000]).is_err());
        assert!(boom_service_identity(&[10070]).is_err());
        assert!(boom_service_identity(&[10072]).is_err());
        assert!(boom_service_identity(&[0, 2000]).is_err());
        assert!(boom_service_identity(&[2000, 2000]).is_err());
    }

    #[test]
    fn parses_real_uid_from_proc_status() {
        assert_eq!(
            parse_proc_status_uid("Name:\tboominstaller_server\nUid:\t2000\t2000\t2000\t2000\n"),
            Some(2000)
        );
        assert_eq!(parse_proc_status_uid("Name:\tmissing\n"), None);
    }
}
