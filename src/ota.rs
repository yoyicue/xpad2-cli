use crate::error::{Result, msg};
use crate::logging::TransactionLog;
use crate::model::{ComponentState, ComponentStatus};
use crate::util::{output_text, run};
use serde_json::json;

const PM: &str = "/system/bin/pm";
const DUMPSYS: &str = "/system/bin/dumpsys";

pub const PACKAGES: &[&str] = &["com.tal.pad.ota"];

#[derive(Clone, Debug)]
struct PackageState {
    package: &'static str,
    enabled_state: u32,
}

impl PackageState {
    fn frozen(&self) -> bool {
        is_frozen_state(self.enabled_state)
    }
}

pub fn status() -> ComponentStatus {
    match inspect_all() {
        Ok(states) => status_from_states(&states),
        Err(error) => ComponentStatus {
            id: "ota".to_string(),
            state: ComponentState::Broken,
            detail: Some(error.to_string()),
        },
    }
}

pub fn freeze(log: &mut TransactionLog) -> Result<ComponentStatus> {
    set_frozen(true, log)
}

pub fn unfreeze(log: &mut TransactionLog) -> Result<ComponentStatus> {
    set_frozen(false, log)
}

fn set_frozen(freeze: bool, log: &mut TransactionLog) -> Result<ComponentStatus> {
    // Inspect the complete locked set before changing anything. A renamed or
    // missing package on an unexpected build must not result in a partial,
    // guessed policy change.
    let initial = inspect_all()?;
    for state in initial {
        if state.frozen() == freeze {
            log.event(
                "ota-freeze",
                "skipped",
                json!({
                    "package": state.package,
                    "reason": if freeze { "already-frozen" } else { "already-enabled" },
                    "enabled_state": state.enabled_state
                }),
            )?;
            continue;
        }

        let output = if freeze {
            run(PM, &["disable-user", "--user", "0", state.package])?
        } else {
            run(PM, &["enable", "--user", "0", state.package])?
        };
        let text = output_text(&output);
        let command = if freeze {
            format!("pm disable-user --user 0 {}", state.package)
        } else {
            format!("pm enable --user 0 {}", state.package)
        };
        log.command_result(&command, output.status.success(), &text)?;
        if !output.status.success() {
            return Err(msg(format!(
                "PackageManager could not {} OTA package {}: {}",
                if freeze { "freeze" } else { "unfreeze" },
                state.package,
                text
            )));
        }

        let verified = inspect_package(state.package)?;
        if verified.frozen() != freeze {
            return Err(msg(format!(
                "PackageManager returned success but OTA package {} remained enabled_state={}",
                state.package, verified.enabled_state
            )));
        }
        log.event(
            "ota-freeze",
            "verified",
            json!({
                "package": state.package,
                "frozen": freeze,
                "enabled_state": verified.enabled_state,
                "user": 0
            }),
        )?;
    }

    let final_state = status_from_states(&inspect_all()?);
    let expected = if freeze {
        ComponentState::Active
    } else {
        ComponentState::Ready
    };
    if final_state.state != expected {
        return Err(msg(format!(
            "OTA policy verification failed: {}",
            final_state.detail.as_deref().unwrap_or("unknown state")
        )));
    }
    Ok(final_state)
}

fn inspect_all() -> Result<Vec<PackageState>> {
    PACKAGES
        .iter()
        .map(|package| inspect_package(package))
        .collect()
}

fn inspect_package(package: &'static str) -> Result<PackageState> {
    let path = run(PM, &["path", package])?;
    let path_text = output_text(&path);
    if !path.status.success() || !path_text.lines().any(|line| line.starts_with("package:")) {
        return Err(msg(format!(
            "required /260 OTA package is missing: {package}"
        )));
    }

    let output = run(DUMPSYS, &["package", package])?;
    let text = output_text(&output);
    if !output.status.success() {
        return Err(msg(format!("cannot inspect OTA package {package}: {text}")));
    }
    let enabled_state = parse_user_enabled_state(&text).ok_or_else(|| {
        msg(format!(
            "PackageManager did not report the User 0 enabled state for {package}"
        ))
    })?;
    if enabled_state > 4 {
        return Err(msg(format!(
            "unknown PackageManager enabled state for {package}: {enabled_state}"
        )));
    }
    Ok(PackageState {
        package,
        enabled_state,
    })
}

fn status_from_states(states: &[PackageState]) -> ComponentStatus {
    let frozen = states.iter().all(PackageState::frozen);
    let details = states
        .iter()
        .map(|state| {
            format!(
                "{}={}",
                state.package,
                enabled_state_name(state.enabled_state)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    ComponentStatus {
        id: "ota".to_string(),
        state: if frozen {
            ComponentState::Active
        } else {
            ComponentState::Ready
        },
        detail: Some(if frozen {
            format!("PackageManager user 0 frozen: {details}")
        } else {
            format!("OTA enabled: {details}; Root preflight freezes it automatically")
        }),
    }
}

fn parse_user_enabled_state(text: &str) -> Option<u32> {
    text.lines().find_map(|line| {
        let user = line.trim().strip_prefix("User 0:")?;
        user.split_whitespace()
            .find_map(|field| field.strip_prefix("enabled=")?.parse().ok())
    })
}

fn is_frozen_state(state: u32) -> bool {
    // disabled-until-used (4) can be re-enabled by an explicit launch and is
    // therefore not strong enough for the pre-Root OTA gate.
    matches!(state, 2 | 3)
}

fn enabled_state_name(state: u32) -> &'static str {
    match state {
        0 => "default",
        1 => "enabled",
        2 => "disabled",
        3 => "disabled-user",
        4 => "disabled-until-used",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_zero_package_state() {
        let dumpsys =
            "User 0: ceDataInode=3305 installed=true stopped=false enabled=3 instant=false";
        assert_eq!(parse_user_enabled_state(dumpsys), Some(3));
    }

    #[test]
    fn only_disabled_package_states_are_frozen() {
        assert!(!is_frozen_state(0));
        assert!(!is_frozen_state(1));
        assert!(is_frozen_state(2));
        assert!(is_frozen_state(3));
        assert!(!is_frozen_state(4));
    }

    #[test]
    fn freeze_set_contains_only_the_active_system_ota_daemon() {
        assert_eq!(PACKAGES, &["com.tal.pad.ota"]);
        assert!(!PACKAGES.contains(&"com.tal.init.ota"));
        assert!(!PACKAGES.contains(&"com.tal.pad.app_upgrade"));
    }
}
