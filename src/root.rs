use crate::catalog::Catalog;
use crate::device;
use crate::error::{Result, msg, needs_reboot};
use crate::logging::TransactionLog;
use crate::model::ComponentState;
use crate::ota;
use crate::profile::{IonStackArtifacts, parse_anchor_offset};
use crate::util::{
    Paths, atomic_write, boot_id, kernel_version, output_text, remove_if_exists, run, selinux,
    shell_quote, unique_id,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const RUNNER: &str = "/data/local/tmp/ionstack_reroot_device";
const PERF_TARGET: &str = "/data/local/tmp/ionstack_perf_target";
const PRELOAD: &str = "/data/local/tmp/ionstack_preload.so";
const PROBE: &str = "/data/local/tmp/cve43499_chainwalk_probe_arm32";
pub const SU: &str = "/data/local/tmp/su";
const SOCKET: &str = "/data/local/tmp/temp_su.sock";
const DAEMON_LOG: &str = "/data/local/tmp/su_daemon.log";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileEvidence {
    Exact,
    Compatible,
}

impl ProfileEvidence {
    fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Compatible => "compatible",
        }
    }
}

struct ProfileSelection<'a> {
    artifacts: IonStackArtifacts<'a>,
    evidence: ProfileEvidence,
    anchor_matches: usize,
}

struct ChainFilesGuard;

impl Drop for ChainFilesGuard {
    fn drop(&mut self) {
        cleanup_chain_files();
    }
}

pub struct RootSession {
    pub owned: bool,
    pub started_boot_id: String,
}

pub struct RootCommandOutput {
    pub status: i32,
    pub text: String,
}

impl RootSession {
    pub fn acquire(
        catalog: &Catalog,
        paths: &Paths,
        log: &mut TransactionLog,
        preserve_existing: bool,
    ) -> Result<Self> {
        device::profile_check(catalog)?;
        let started_boot_id = boot_id();
        let ota_status = ota::freeze(log)?;
        println!(
            "✓ ota: {}",
            ota_status.detail.as_deref().unwrap_or("frozen")
        );
        if boot_id() != started_boot_id {
            return Err(needs_reboot(
                "Boot ID changed while applying the mandatory pre-Root OTA freeze",
            ));
        }
        let existing = device::root_status();
        if existing.state == ComponentState::Active {
            log.event(
                "root",
                "reused",
                json!({"boot_id": started_boot_id, "adopted_by_transaction": !preserve_existing}),
            )?;
            return Ok(Self {
                owned: !preserve_existing,
                started_boot_id,
            });
        }

        if let Some(pid) = stale_daemon_pid() {
            return Err(needs_reboot(format!(
                "a stale root daemon (pid {pid}) is alive but its client cannot verify root; refusing to stack another exploit session"
            )));
        }

        cleanup_stale_shell_files();
        let _chain_files = ChainFilesGuard;
        let current_kernel_version = kernel_version();
        let selection = select_ionstack_profile(
            catalog,
            paths,
            log,
            &started_boot_id,
            &current_kernel_version,
        )?;
        let artifacts = selection.artifacts;
        log.event(
            "root",
            "profile-selected",
            json!({
                "profile": artifacts.profile_id,
                "kernel_version": current_kernel_version,
                "evidence": selection.evidence.as_str(),
                "anchor_matches": selection.anchor_matches,
                "runner": artifacts.runner,
                "preload": artifacts.preload,
            }),
        )?;
        println!(
            "✓ IonStack profile: {} ({})",
            artifacts.profile_id,
            selection.evidence.as_str()
        );
        for (id, path) in [
            (artifacts.runner, RUNNER),
            (artifacts.perf_target, PERF_TARGET),
            (artifacts.preload, PRELOAD),
            (artifacts.chainwalk_probe, PROBE),
        ] {
            let resolved = catalog.resolve(id, paths)?;
            let bytes = resolved.load()?;
            atomic_write(Path::new(path), &bytes, 0o700)?;
        }

        if selection.evidence == ProfileEvidence::Compatible {
            println!(
                "兼容内核：已由只读 offset anchors 选型，正在依次执行 preflight 与 validate。"
            );
            let preflight = stream_runner(
                log,
                &started_boot_id,
                &["--preflight-only", "--allow-profile-version-mismatch"],
                "compatible-preflight",
            )?;
            require_complete_state(&preflight, "compatible preflight")?;
            let validation = stream_runner(
                log,
                &started_boot_id,
                &["--validate-only", "--allow-profile-version-mismatch"],
                "compatible-validation",
            )?;
            require_complete_state(&validation, "compatible validation")?;
        }
        log.event(
            "root",
            "running",
            json!({
                "attempt": 1,
                "max_holder_attempts": 6,
                "expectation": "usually several minutes; stops after six holder opportunities"
            }),
        )?;
        println!(
            "临时 Root：最多 6 轮 holder 机会，通常需要数分钟；6 轮仍失败会停止并建议普通重启。 "
        );
        let runner_args: &[&str] = if selection.evidence == ProfileEvidence::Compatible {
            &[
                "--allow-profile-version-mismatch",
                "--accept-compatible-write",
            ]
        } else {
            &[]
        };
        let run_result = stream_runner(log, &started_boot_id, runner_args, "root");
        let text = match run_result {
            Ok(text) => text,
            Err(error) => {
                if device::root_status().state == ComponentState::Active {
                    log.event(
                        "root",
                        "verified-after-runner-error",
                        json!({"runner_error": error.to_string()}),
                    )?;
                    String::new()
                } else {
                    return Err(error);
                }
            }
        };

        if boot_id() != started_boot_id {
            return Err(needs_reboot(
                "Boot ID changed during IonStack root acquisition; old success files were discarded",
            ));
        }
        let verified = device::root_status();
        if verified.state != ComponentState::Active {
            if text.contains("holder attempts exhausted") {
                return Err(needs_reboot(
                    "IonStack exhausted all 6 holder opportunities; further attempts in this boot have low value",
                ));
            }
            return Err(msg(format!(
                "IonStack runner exited without independently verified root: {}",
                verified.detail.unwrap_or_default()
            )));
        }
        log.event(
            "root",
            "active",
            json!({"verification": "su -c id", "boot_id": started_boot_id}),
        )?;
        Ok(Self {
            owned: true,
            started_boot_id,
        })
    }

    pub fn check_boot(&self) -> Result<()> {
        let current = boot_id();
        if current != self.started_boot_id {
            return Err(needs_reboot(format!(
                "Boot ID changed during transaction ({} -> {})",
                self.started_boot_id, current
            )));
        }
        Ok(())
    }

    pub fn exec(&self, command: &str) -> Result<RootCommandOutput> {
        self.check_boot()?;
        root_exec(command)
    }

    pub fn close(&self, log: &mut TransactionLog) -> Result<()> {
        if !self.owned {
            log.event(
                "root-cleanup",
                "skipped",
                json!({"reason": "root existed before this transaction"}),
            )?;
            return Ok(());
        }
        let cleanup = r#"
pid=$(sed -n 's/^su daemon ready pid=\([0-9][0-9]*\).*/\1/p' /data/local/tmp/su_daemon.log 2>/dev/null | head -n 1)
if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
  cmd=$(tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
  case "$cmd" in
    *"/data/local/tmp/su --daemonize"*) kill "$pid" 2>/dev/null || true ;;
  esac
fi
rm -f /data/local/tmp/temp_su.sock /data/local/tmp/su /data/local/tmp/su_daemon.log
rm -f /data/local/tmp/ionstack_modprobe /data/local/tmp/ionstack_badfmt
setenforce 1 >/dev/null 2>&1 || true
"#;
        let result = self.exec(cleanup);
        cleanup_chain_files();
        if let Ok(output) = &result {
            log.command_result("root-cleanup", output.status == 0, &output.text)?;
        }
        result?;
        thread::sleep(Duration::from_millis(250));
        let enforcing = selinux();
        let root = device::root_status();
        let socket_absent = !Path::new(SOCKET).exists();
        if enforcing != "Enforcing" || root.state == ComponentState::Active || !socket_absent {
            return Err(needs_reboot(format!(
                "temporary root cleanup did not reach the safe state (SELinux={enforcing}, root={}, socket_absent={socket_absent})",
                root.state
            )));
        }
        log.event("root-cleanup", "succeeded", json!({"selinux": enforcing, "socket_absent": true, "client_absent": !Path::new(SU).exists()}))?;
        Ok(())
    }
}

pub fn root_exec(command: &str) -> Result<RootCommandOutput> {
    let marker = format!("__XPAD2_RC_{}__=", unique_id().replace('-', "_"));
    let wrapped = format!(
        "{command}\n__xpad2_rc=$?\nprintf '\\n{}%d\\n' \"$__xpad2_rc\"",
        marker
    );
    let output = run(SU, &["-c", &wrapped])?;
    let text = output_text(&output);
    let mut rc = None;
    let mut clean = Vec::new();
    for line in text.lines() {
        if let Some(value) = line.trim().strip_prefix(&marker) {
            rc = value.parse::<i32>().ok();
        } else {
            clean.push(line);
        }
    }
    let status = rc.ok_or_else(|| msg(format!("root RPC returned no status marker: {text}")))?;
    Ok(RootCommandOutput {
        status,
        text: clean.join("\n"),
    })
}

pub fn command_from_argv(argv: &[String]) -> Result<String> {
    if argv.is_empty() {
        return Err(msg("root -- requires a command"));
    }
    Ok(argv
        .iter()
        .map(|value| shell_quote(value))
        .collect::<Vec<_>>()
        .join(" "))
}

fn select_ionstack_profile<'a>(
    catalog: &'a Catalog,
    paths: &Paths,
    log: &mut TransactionLog,
    expected_boot_id: &str,
    current_kernel_version: &str,
) -> Result<ProfileSelection<'a>> {
    if let Some(artifacts) = catalog.lock.ionstack_artifacts(current_kernel_version) {
        return Ok(ProfileSelection {
            artifacts,
            evidence: ProfileEvidence::Exact,
            anchor_matches: 0,
        });
    }

    let discovery_target = catalog
        .lock
        .ionstack_discovery_target()
        .ok_or_else(|| msg("signed catalog has no IonStack discovery target"))?;
    let resolved = catalog.resolve(discovery_target, paths)?;
    atomic_write(Path::new(PERF_TARGET), &resolved.load()?, 0o700)?;
    println!("内核编译标识未精确命中；已进入只读 profile discovery，不会在选型前执行内核写入。");
    log.event(
        "root-profile-discovery",
        "running",
        json!({
            "kernel_version": current_kernel_version,
            "target": discovery_target,
            "policy": "two-independent-offset-anchors",
        }),
    )?;
    let observations = collect_profile_observations(log, expected_boot_id)?;
    let (profile_id, anchor_matches, candidates) =
        compatible_profile(&catalog.lock, &observations)?;
    let artifacts = catalog
        .lock
        .ionstack_artifacts_for_profile(profile_id)
        .ok_or_else(|| {
            msg(format!(
                "selected IonStack profile disappeared: {profile_id}"
            ))
        })?;
    log.event(
        "root-profile-discovery",
        "compatible",
        json!({
            "profile": profile_id,
            "anchor_matches": anchor_matches,
            "observed_offsets": observations.len(),
            "candidates": candidates,
        }),
    )?;
    Ok(ProfileSelection {
        artifacts,
        evidence: ProfileEvidence::Compatible,
        anchor_matches,
    })
}

fn collect_profile_observations(
    log: &mut TransactionLog,
    expected_boot_id: &str,
) -> Result<BTreeMap<u64, u32>> {
    let mut observations = BTreeMap::new();
    let getuid = run_discovery_workload(
        log,
        expected_boot_id,
        "getuid",
        true,
        &[
            "--discover",
            "--sample-ms=2500",
            "--freq=4000",
            "--attempts=8",
            "--workload=getuid",
        ],
    )?;
    parse_discovery_observations(&getuid, &mut observations);
    let base = parse_discovery_base(&getuid)
        .ok_or_else(|| msg("IonStack read-only discovery found no KASLR base"))?;
    let base_arg = format!("--kaslr-base={base}");
    for workload in ["ashmem-open-close", "ashmem-ioctl", "selinux-enforce"] {
        let workload_arg = format!("--workload={workload}");
        let output = run_discovery_workload(
            log,
            expected_boot_id,
            workload,
            false,
            &[
                "--discover",
                "--sample-ms=2500",
                "--freq=4000",
                "--attempts=8",
                &base_arg,
                &workload_arg,
            ],
        )?;
        parse_discovery_observations(&output, &mut observations);
    }
    Ok(observations)
}

fn run_discovery_workload(
    log: &mut TransactionLog,
    expected_boot_id: &str,
    workload: &str,
    required: bool,
    arguments: &[&str],
) -> Result<String> {
    if boot_id() != expected_boot_id {
        return Err(needs_reboot(
            "Boot ID changed before IonStack profile discovery",
        ));
    }
    let name = format!("profile-discovery-{workload}");
    let output = log.run_streaming(&name, PERF_TARGET, arguments)?;
    if boot_id() != expected_boot_id {
        return Err(needs_reboot(
            "Boot ID changed during IonStack profile discovery",
        ));
    }
    if !output.status.success() && required {
        return Err(msg(format!(
            "IonStack profile discovery workload {workload} failed with {}",
            output.status
        )));
    }
    if !output.status.success() {
        log.event(
            "root-profile-discovery",
            "workload-degraded",
            json!({"workload": workload, "exit_code": output.status.code()}),
        )?;
        eprintln!(
            "提示：只读 discovery workload {workload} 不可用；继续使用其余证据，证据不足时会安全停止。"
        );
    }
    Ok(output.text)
}

fn parse_discovery_base(text: &str) -> Option<String> {
    text.lines()
        .filter(|line| line.contains("DISCOVERY workload=getuid "))
        .flat_map(|line| line.split_ascii_whitespace())
        .find_map(|field| field.strip_prefix("base="))
        .filter(|value| {
            value.strip_prefix("0x").is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit())
            })
        })
        .map(str::to_string)
}

fn parse_discovery_observations(text: &str, observations: &mut BTreeMap<u64, u32>) {
    for line in text
        .lines()
        .filter(|line| line.contains("DISCOVERY_IP ") || line.contains("DISCOVERY_IMAGE_REG "))
    {
        let mut offset = None;
        let mut hits = None;
        for field in line.split_ascii_whitespace() {
            if let Some(value) = field.strip_prefix("off=") {
                offset = parse_anchor_offset(value);
            } else if let Some(value) = field.strip_prefix("hits=") {
                hits = value.parse::<u32>().ok();
            }
        }
        if let (Some(offset), Some(hits)) = (offset, hits) {
            observations
                .entry(offset)
                .and_modify(|current| *current = (*current).max(hits))
                .or_insert(hits);
        }
    }
}

fn compatible_profile<'a>(
    lock: &'a crate::model::AssetsLock,
    observations: &BTreeMap<u64, u32>,
) -> Result<(&'a str, usize, Vec<serde_json::Value>)> {
    let mut candidates = Vec::new();
    for profile in &lock.ionstack_discovery_profiles {
        let mut anchor_matches = 0usize;
        let mut hit_score = 0u64;
        for value in profile.offsets.values() {
            let offset = parse_anchor_offset(value).ok_or_else(|| {
                msg(format!(
                    "invalid signed discovery offset for {}: {value}",
                    profile.profile_id
                ))
            })?;
            if let Some(hits) = observations.get(&offset) {
                anchor_matches += 1;
                hit_score += u64::from((*hits).min(20));
            }
        }
        candidates.push((profile.profile_id.as_str(), anchor_matches, hit_score));
    }
    candidates.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| left.0.cmp(right.0))
    });
    let report = candidates
        .iter()
        .map(|(profile, anchor_matches, hit_score)| {
            json!({
                "profile": profile,
                "anchor_matches": anchor_matches,
                "hit_score": hit_score,
            })
        })
        .collect::<Vec<_>>();
    let Some(best) = candidates.first() else {
        return Err(msg("signed catalog has no IonStack discovery profiles"));
    };
    let runner_up_matches = candidates.get(1).map_or(0, |candidate| candidate.1);
    if best.1 < 2 || best.1 <= runner_up_matches {
        return Err(msg(format!(
            "IonStack profile discovery is ambiguous: candidates={report:?}"
        )));
    }
    Ok((best.0, best.1, report))
}

fn stream_runner(
    log: &mut TransactionLog,
    expected_boot_id: &str,
    arguments: &[&str],
    stage: &str,
) -> Result<String> {
    let mut child = Command::new(RUNNER)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| msg(format!("start IonStack runner: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| msg("capture IonStack stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| msg("capture IonStack stderr"))?;
    let (tx, rx) = mpsc::channel::<(&'static str, String)>();
    let streams: [(&'static str, Box<dyn Read + Send>); 2] = [
        ("ionstack", Box::new(stdout)),
        ("ionstack-stderr", Box::new(stderr)),
    ];
    for (source, stream) in streams {
        let sender = tx.clone();
        thread::spawn(move || {
            for line in BufReader::new(stream).lines() {
                match line {
                    Ok(line) => {
                        if sender.send((source, line)).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
    drop(tx);
    let deadline = Instant::now() + Duration::from_secs(20 * 60);
    let mut all = String::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok((source, line)) => {
                all.push_str(&line);
                all.push('\n');
                log.line(source, &line)?;
                if let Some(attempt) = parse_holder_attempt(&line) {
                    log.event(
                        "root-holder",
                        "running",
                        json!({"attempt": attempt, "max": 6}),
                    )?;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if boot_id() != expected_boot_id {
                    let _ = child.kill();
                    return Err(needs_reboot(
                        "Boot ID changed while IonStack runner was active",
                    ));
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    return Err(needs_reboot(
                        "IonStack runner exceeded the 20-minute safety deadline",
                    ));
                }
                if child
                    .try_wait()
                    .map_err(|e| msg(format!("wait IonStack runner: {e}")))?
                    .is_some()
                {
                    while let Ok((source, line)) = rx.try_recv() {
                        all.push_str(&line);
                        all.push('\n');
                        log.line(source, &line)?;
                    }
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = child
        .wait()
        .map_err(|e| msg(format!("wait IonStack runner: {e}")))?;
    log.event(
        "root-runner",
        if status.success() {
            "succeeded"
        } else {
            "failed"
        },
        json!({"stage": stage, "arguments": arguments, "exit_code": status.code()}),
    )?;
    if !status.success() {
        if all.contains("holder attempts exhausted") {
            return Err(needs_reboot(
                "IonStack exhausted all 6 holder opportunities; perform an ordinary reboot before retrying",
            ));
        }
        return Err(msg(format!(
            "IonStack runner stage {stage} failed with {status}"
        )));
    }
    Ok(all)
}

fn require_complete_state(text: &str, stage: &str) -> Result<()> {
    if text
        .lines()
        .any(|line| line.contains("[reroot] STATE ") && line.contains(" to=complete "))
    {
        Ok(())
    } else {
        Err(msg(format!(
            "IonStack {stage} emitted no terminal complete state"
        )))
    }
}

fn parse_holder_attempt(line: &str) -> Option<u32> {
    let value = line.split("HOLDER attempt=").nth(1)?.split('/').next()?;
    value.parse().ok()
}

fn cleanup_stale_shell_files() {
    for path in [RUNNER, PERF_TARGET, PRELOAD, PROBE, SU, SOCKET, DAEMON_LOG] {
        let _ = remove_if_exists(Path::new(path));
    }
}

fn cleanup_chain_files() {
    for path in [RUNNER, PERF_TARGET, PRELOAD, PROBE] {
        let _ = remove_if_exists(Path::new(path));
    }
}

fn stale_daemon_pid() -> Option<u32> {
    let log = fs::read_to_string(DAEMON_LOG).ok()?;
    let pid = log.lines().find_map(|line| {
        line.strip_prefix("su daemon ready pid=")?
            .split_whitespace()
            .next()?
            .parse::<u32>()
            .ok()
    })?;
    let command = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let command = String::from_utf8_lossy(&command).replace('\0', " ");
    command
        .contains("/data/local/tmp/su --daemonize")
        .then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V19_B_DISCOVERY: &str = r#"
[perf-target] DISCOVERY workload=getuid base=0xffffff9e36280000 samples=42 image_ips=42 image_regs=4 direct_regs=20
[perf-target] DISCOVERY_IP rank=1 value=0xffffff9e36e67210 off=0x00be7210 hits=8
[perf-target] DISCOVERY_IP rank=1 value=0xffffff9e36e67e58 off=0x00be7e58 hits=11
[perf-target] DISCOVERY_IP rank=2 value=0xffffff9e36e67ed8 off=0x00be7ed8 hits=9
[perf-target] DISCOVERY_IP rank=1 value=0xffffff9e36e67360 off=0x00be7360 hits=13
[perf-target] DISCOVERY_IP rank=2 value=0xffffff9e36e67ca0 off=0x00be7ca0 hits=7
[perf-target] DISCOVERY_IMAGE_REG rank=1 value=0xffffff9e3837b2b8 off=0x020fb2b8 hits=17
"#;

    #[test]
    fn parses_discovery_base_and_keeps_maximum_hits() {
        assert_eq!(
            parse_discovery_base(V19_B_DISCOVERY).as_deref(),
            Some("0xffffff9e36280000")
        );
        let mut observations = BTreeMap::new();
        parse_discovery_observations(V19_B_DISCOVERY, &mut observations);
        parse_discovery_observations(
            "[perf-target] DISCOVERY_IP rank=9 value=0x0 off=0x00be7360 hits=2",
            &mut observations,
        );
        assert_eq!(observations.get(&0x00be7360), Some(&13));
        assert_eq!(observations.len(), 6);
    }

    #[test]
    fn compatible_discovery_selects_v19_b_from_independent_anchors() {
        let catalog = Catalog::load().unwrap();
        let mut observations = BTreeMap::new();
        parse_discovery_observations(V19_B_DISCOVERY, &mut observations);
        let (profile, matches, _) = compatible_profile(&catalog.lock, &observations).unwrap();
        assert_eq!(profile, "xpad2-v19-b");
        assert_eq!(matches, 6);
    }

    #[test]
    fn common_anchor_alone_is_ambiguous() {
        let catalog = Catalog::load().unwrap();
        let observations = BTreeMap::from([(0x020fb2b8, 17)]);
        assert!(compatible_profile(&catalog.lock, &observations).is_err());
    }

    #[test]
    fn runner_stage_requires_a_terminal_complete_transition() {
        assert!(
            require_complete_state(
                "[reroot] STATE seq=2 from=profile to=complete reason=preflight-only",
                "preflight"
            )
            .is_ok()
        );
        assert!(require_complete_state("[reroot] PREFLIGHT_OK", "preflight").is_err());
    }
}
