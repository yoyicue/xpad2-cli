use crate::error::{IoContext, Result, msg};
use crate::model::Receipt;
use crate::util::{
    Paths, atomic_write, boot_id, epoch_seconds, run, selinux, timestamp_filename, unique_id,
};
use serde_json::{Map, Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

pub struct TransactionLog {
    pub id: String,
    pub dir: PathBuf,
    events: File,
    raw: File,
    raw_lines_since_sync: u32,
    active_path: PathBuf,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ActiveTransaction {
    id: String,
    operation: String,
    boot_id: String,
    pid: u32,
    started_at: u64,
}

impl TransactionLog {
    pub fn start(paths: &Paths, operation: &str) -> Result<Self> {
        paths.ensure()?;
        recover_interrupted_transactions(paths)?;
        let id = format!("{}-{}", timestamp_filename(), unique_id());
        let dir = paths.logs.join(&id);
        fs::create_dir_all(&dir).at(&dir)?;
        fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).at(&dir)?;
        let events_path = dir.join("events.jsonl");
        let raw_path = dir.join("raw.log");
        let events = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&events_path)
            .at(&events_path)?;
        let raw = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&raw_path)
            .at(&raw_path)?;
        let mut log = Self {
            id,
            dir,
            events,
            raw,
            raw_lines_since_sync: 0,
            active_path: paths.state.join("active-transaction.json"),
        };
        let active = ActiveTransaction {
            id: log.id.clone(),
            operation: operation.to_string(),
            boot_id: boot_id(),
            pid: std::process::id(),
            started_at: epoch_seconds(),
        };
        atomic_write(
            &log.active_path,
            &serde_json::to_vec_pretty(&active)?,
            0o600,
        )?;
        log.event("transaction", "started", json!({"operation": operation}))?;
        Ok(log)
    }

    pub fn event(&mut self, event: &str, state: &str, fields: Value) -> Result<()> {
        let mut map = Map::new();
        map.insert("ts".to_string(), json!(epoch_seconds()));
        map.insert("event".to_string(), json!(event));
        map.insert("state".to_string(), json!(state));
        if let Value::Object(extra) = fields {
            map.extend(extra);
        }
        serde_json::to_writer(&mut self.events, &Value::Object(map))?;
        self.events
            .write_all(b"\n")
            .at(self.dir.join("events.jsonl"))?;
        self.events.flush().at(self.dir.join("events.jsonl"))?;
        self.events.sync_data().at(self.dir.join("events.jsonl"))?;
        Ok(())
    }

    pub fn line(&mut self, source: &str, line: &str) -> Result<()> {
        let redacted = redact(line);
        writeln!(self.raw, "[{source}] {redacted}").at(self.dir.join("raw.log"))?;
        self.raw.flush().at(self.dir.join("raw.log"))?;
        self.raw_lines_since_sync += 1;
        if self.raw_lines_since_sync >= 16 {
            self.raw.sync_data().at(self.dir.join("raw.log"))?;
            self.raw_lines_since_sync = 0;
        }
        println!("{redacted}");
        Ok(())
    }

    pub fn command_result(&mut self, name: &str, success: bool, output: &str) -> Result<()> {
        for line in output.lines() {
            self.line(name, line)?;
        }
        self.event(
            "command",
            if success { "succeeded" } else { "failed" },
            json!({"name": name}),
        )
    }

    pub fn write_receipt(&mut self, paths: &Paths, receipt: &Receipt) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(receipt)?;
        atomic_write(&self.dir.join("receipt.json"), &bytes, 0o600)?;
        atomic_write(&paths.state.join("last-transaction.json"), &bytes, 0o600)?;
        if receipt.success {
            atomic_write(&paths.state.join("last-success.json"), &bytes, 0o600)?;
        }
        self.event(
            "transaction",
            if receipt.success {
                "succeeded"
            } else {
                "failed"
            },
            json!({"needs_reboot": receipt.needs_reboot, "error": receipt.error}),
        )?;
        self.raw.sync_data().at(self.dir.join("raw.log"))?;
        if let Ok(raw) = fs::read(&self.active_path)
            && let Ok(active) = serde_json::from_slice::<ActiveTransaction>(&raw)
            && active.id == self.id
        {
            fs::remove_file(&self.active_path).at(&self.active_path)?;
            if let Some(parent) = self.active_path.parent() {
                File::open(parent).at(parent)?.sync_all().at(parent)?;
            }
        }
        Ok(())
    }
}

pub fn transaction_warnings(paths: &Paths) -> Vec<String> {
    let current_boot = boot_id();
    let mut warnings = Vec::new();
    let active_path = paths.state.join("active-transaction.json");
    if let Ok(raw) = fs::read(&active_path)
        && let Ok(active) = serde_json::from_slice::<ActiveTransaction>(&raw)
    {
        if active.boot_id == current_boot && Path::new(&format!("/proc/{}", active.pid)).exists() {
            warnings.push(format!(
                "transaction {} ({}) is currently active",
                active.id, active.operation
            ));
        } else {
            warnings.push(format!(
                "transaction {} ({}) was interrupted; boot {} -> {}",
                active.id, active.operation, active.boot_id, current_boot
            ));
        }
    }
    if let Ok(entries) = fs::read_dir(&paths.logs) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !path.join("receipt.json").exists() {
                let id = entry.file_name().to_string_lossy().to_string();
                if !warnings.iter().any(|warning| warning.contains(&id)) {
                    warnings.push(format!("transaction {id} has no final receipt (process terminated or device rebooted)"));
                }
            }
        }
    }
    warnings.sort();
    warnings
}

fn recover_interrupted_transactions(paths: &Paths) -> Result<()> {
    let current_boot = boot_id();
    let active_path = paths.state.join("active-transaction.json");
    let active = fs::read(&active_path)
        .ok()
        .and_then(|raw| serde_json::from_slice::<ActiveTransaction>(&raw).ok());
    if let Some(active) = &active {
        let receipt_path = paths.logs.join(&active.id).join("receipt.json");
        if !receipt_path.exists() {
            let receipt = Receipt {
                transaction_id: active.id.clone(),
                operation: active.operation.clone(),
                success: false,
                started_boot_id: active.boot_id.clone(),
                ended_boot_id: current_boot.clone(),
                started_selinux: "unknown".to_string(),
                ended_selinux: selinux(),
                components: vec![],
                error: Some("transaction interrupted before final receipt; device reboot or process termination detected".to_string()),
                needs_reboot: active.boot_id == current_boot,
            };
            atomic_write(&receipt_path, &serde_json::to_vec_pretty(&receipt)?, 0o600)?;
        }
    }
    if active_path.exists() {
        fs::remove_file(&active_path).at(&active_path)?;
    }
    if let Ok(entries) = fs::read_dir(&paths.logs) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() || dir.join("receipt.json").exists() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            let receipt = Receipt {
                transaction_id: id,
                operation: "unknown interrupted transaction".to_string(),
                success: false,
                started_boot_id: "unknown".to_string(),
                ended_boot_id: current_boot.clone(),
                started_selinux: "unknown".to_string(),
                ended_selinux: selinux(),
                components: vec![],
                error: Some(
                    "no final receipt was found; recovered on the next modifying operation"
                        .to_string(),
                ),
                needs_reboot: false,
            };
            atomic_write(
                &dir.join("receipt.json"),
                &serde_json::to_vec_pretty(&receipt)?,
                0o600,
            )?;
        }
    }
    Ok(())
}

pub fn redact(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let sensitive = [
        "serialno",
        "persist.sys.adb",
        "adb_keys",
        "adbkey",
        "private key",
        "private_key",
        "password=",
        "token=",
        "client_secret",
        "authorization: bearer",
        "bearer ",
        "pairing_code",
        "pairing code",
    ];
    if sensitive.iter().any(|needle| lower.contains(needle)) {
        "[REDACTED sensitive diagnostic line]".to_string()
    } else {
        let mut output = input.to_string();
        for identifier in device_identifiers() {
            output = output.replace(identifier, "[REDACTED_SERIAL]");
        }
        output
    }
}

fn device_identifiers() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    VALUES.get_or_init(|| {
        [
            "ro.serialno",
            "ro.boot.serialno",
            "ro.boot.genie.serialno",
            "ro.genie.serialno",
        ]
        .into_iter()
        .map(crate::util::getprop)
        .filter(|value| value.len() >= 6 && value != "unknown")
        .collect()
    })
}

pub fn export_logs(paths: &Paths, destination: &Path) -> Result<PathBuf> {
    paths.ensure()?;
    if !destination.is_dir() {
        return Err(msg(format!(
            "log export destination is not a directory: {}",
            destination.display()
        )));
    }
    let staging = paths.work.join(format!("log-export-{}", unique_id()));
    fs::create_dir_all(&staging).at(&staging)?;
    let result = (|| {
        atomic_write(
            &staging.join("assets.lock.json"),
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets.lock.json")),
            0o600,
        )?;
        atomic_write(
            &staging.join("sources.lock.json"),
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/sources.lock.json")),
            0o600,
        )?;
        let summary = json!({
            "product_version": env!("CARGO_PKG_VERSION"),
            "boot_id": boot_id(),
            "selinux": selinux(),
            "exported_at": epoch_seconds()
        });
        atomic_write(
            &staging.join("summary.json"),
            &serde_json::to_vec_pretty(&summary)?,
            0o600,
        )?;

        capture(&staging.join("getprop.txt"), "/system/bin/getprop", &[])?;
        capture(&staging.join("uname.txt"), "/system/bin/uname", &["-a"])?;
        capture(
            &staging.join("logcat-current.txt"),
            "/system/bin/logcat",
            &["-b", "all", "-d", "-t", "3000"],
        )?;
        capture(
            &staging.join("logcat-previous-boot.txt"),
            "/system/bin/logcat",
            &["-L", "-b", "all", "-d"],
        )?;
        capture(
            &staging.join("last-kmsg-dropbox.txt"),
            "/system/bin/dumpsys",
            &["dropbox", "--print", "SYSTEM_LAST_KMSG"],
        )?;
        capture(&staging.join("dmesg.txt"), "/system/bin/dmesg", &[])?;
        capture(
            &staging.join("ksu-package.txt"),
            "/system/bin/dumpsys",
            &["package", "me.weishu.kernelsu"],
        )?;
        capture(
            &staging.join("boom-package.txt"),
            "/system/bin/dumpsys",
            &["package", "com.yoyicue.boominstaller"],
        )?;

        let output = destination.join(format!("xpad2log-{}.zip", timestamp_filename()));
        let file = File::create(&output).at(&output)?;
        let mut zip = ZipWriter::new(file);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        add_tree(&mut zip, &staging, "diagnostics", options)?;
        if paths.logs.exists() {
            add_tree(&mut zip, &paths.logs, "transactions", options)?;
        }
        if Path::new("/sys/fs/pstore").is_dir() {
            let _ = add_tree(&mut zip, Path::new("/sys/fs/pstore"), "pstore", options);
        }
        zip.finish()?;
        Ok(output)
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

fn capture(path: &Path, program: &str, args: &[&str]) -> Result<()> {
    let text = match run(program, args) {
        Ok(output) => {
            let mut combined = String::new();
            combined.push_str(&String::from_utf8_lossy(&output.stdout));
            if !output.stderr.is_empty() {
                combined.push_str("\n[stderr]\n");
                combined.push_str(&String::from_utf8_lossy(&output.stderr));
            }
            combined
        }
        Err(error) => format!("capture unavailable: {error}\n"),
    };
    let redacted = text.lines().map(redact).collect::<Vec<_>>().join("\n");
    atomic_write(path, redacted.as_bytes(), 0o600)
}

fn add_tree(
    zip: &mut ZipWriter<File>,
    root: &Path,
    prefix: &str,
    options: SimpleFileOptions,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(root)
        .at(root)?
        .collect::<std::io::Result<Vec<_>>>()
        .at(root)?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let name = format!("{prefix}/{}", entry.file_name().to_string_lossy());
        let kind = entry.file_type().at(&path)?;
        if kind.is_dir() {
            add_tree(zip, &path, &name, options)?;
        } else if kind.is_file() {
            zip.start_file(name, options)?;
            let mut file = File::open(&path).at(&path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data).at(&path)?;
            zip.write_all(&data)
                .map_err(|e| msg(format!("write diagnostic ZIP: {e}")))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_redaction_covers_serials_and_credentials() {
        for line in [
            "[ro.boot.serialno]: [ABC123456]",
            "Authorization: Bearer secret",
            "token=secret",
            "-----BEGIN PRIVATE KEY-----",
            "adb pairing_code=123456",
        ] {
            assert!(
                redact(line).starts_with("[REDACTED"),
                "not redacted: {line}"
            );
        }
    }

    #[test]
    fn interrupted_transaction_is_recovered_with_a_receipt() {
        let root = std::env::temp_dir().join(format!("xpad2-log-test-{}", unique_id()));
        let paths = Paths {
            root: root.clone(),
            cache: root.join("cache"),
            cache_is_explicit: false,
            work: root.join("work"),
            state: root.join("state"),
            logs: root.join("logs"),
            lock: root.join("operation.lock"),
        };
        let interrupted =
            TransactionLog::start(&paths, "install full").expect("start interrupted transaction");
        let interrupted_id = interrupted.id.clone();
        drop(interrupted);
        assert!(!transaction_warnings(&paths).is_empty());

        let mut next =
            TransactionLog::start(&paths, "cleanup").expect("start recovery transaction");
        assert!(
            paths
                .logs
                .join(interrupted_id)
                .join("receipt.json")
                .is_file()
        );
        let receipt = Receipt {
            transaction_id: next.id.clone(),
            operation: "cleanup".to_string(),
            success: true,
            started_boot_id: boot_id(),
            ended_boot_id: boot_id(),
            started_selinux: selinux(),
            ended_selinux: selinux(),
            components: vec![],
            error: None,
            needs_reboot: false,
        };
        next.write_receipt(&paths, &receipt)
            .expect("finish recovery transaction");
        assert!(!paths.state.join("active-transaction.json").exists());
        let _ = fs::remove_dir_all(root);
    }
}
