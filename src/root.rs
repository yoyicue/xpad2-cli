use crate::catalog::Catalog;
use crate::device;
use crate::error::{Result, msg, needs_reboot};
use crate::logging::TransactionLog;
use crate::model::ComponentState;
use crate::ota;
use crate::util::{
    Paths, atomic_write, boot_id, output_text, remove_if_exists, run, selinux, shell_quote,
    unique_id,
};
use serde_json::json;
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
        for (id, path) in [
            ("ionstack-runner", RUNNER),
            ("ionstack-perf-target", PERF_TARGET),
            ("ionstack-preload", PRELOAD),
            ("ionstack-chainwalk-probe", PROBE),
        ] {
            let resolved = catalog.resolve(id, paths)?;
            let bytes = resolved.load()?;
            atomic_write(Path::new(path), &bytes, 0o700)?;
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
        let run_result = stream_runner(log, &started_boot_id);
        cleanup_chain_files();
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

fn stream_runner(log: &mut TransactionLog, expected_boot_id: &str) -> Result<String> {
    let mut child = Command::new(RUNNER)
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
        json!({"exit_code": status.code()}),
    )?;
    if !status.success() {
        if all.contains("holder attempts exhausted") {
            return Err(needs_reboot(
                "IonStack exhausted all 6 holder opportunities; perform an ordinary reboot before retrying",
            ));
        }
        return Err(msg(format!("IonStack runner failed with {status}")));
    }
    Ok(all)
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
