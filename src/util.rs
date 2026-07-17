use crate::error::{IoContext, Result, msg};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_ROOT: &str = "/data/local/tmp/.xpad2";

#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
    pub cache: PathBuf,
    pub cache_is_explicit: bool,
    pub managed_blob_root: PathBuf,
    pub managed_cache_root: PathBuf,
    pub work: PathBuf,
    pub state: PathBuf,
    pub logs: PathBuf,
    pub lock: PathBuf,
}

impl Paths {
    pub fn new(
        cache_override: Option<&Path>,
        product_version: &str,
        catalog_version: &str,
    ) -> Result<Self> {
        let cache_override = cache_override
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os("XPAD2_CACHE_DIR").map(PathBuf::from));
        let cache_is_explicit = cache_override.is_some();
        let state_root = PathBuf::from(DEFAULT_ROOT);
        let managed_blob_root = state_root.join("cache").join("blobs");
        let managed_cache_root = state_root.join("cache").join("releases");
        let cache = match cache_override {
            Some(path) => path,
            None => managed_cache_path_at(&managed_cache_root, product_version, catalog_version)?,
        };
        Ok(Self {
            cache,
            cache_is_explicit,
            managed_blob_root,
            managed_cache_root,
            work: state_root.join("work"),
            state: state_root.join("state"),
            logs: state_root.join("logs"),
            lock: state_root.join("operation.lock"),
            root: state_root,
        })
    }

    pub fn managed_cache_path(
        &self,
        product_version: &str,
        catalog_version: &str,
    ) -> Result<PathBuf> {
        managed_cache_path_at(&self.managed_cache_root, product_version, catalog_version)
    }

    pub fn ensure(&self) -> Result<()> {
        for path in [
            &self.root,
            &self.managed_blob_root,
            &self.managed_cache_root,
            &self.cache,
            &self.work,
            &self.state,
            &self.logs,
        ] {
            fs::create_dir_all(path).at(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).at(path)?;
        }
        // Older development builds created transaction directories with the
        // caller's umask. Normalize existing diagnostics without following
        // symlinks so exported root-chain data is never left world-readable.
        for entry in fs::read_dir(&self.logs).at(&self.logs)? {
            let entry = entry.at(&self.logs)?;
            if !entry.file_type().at(entry.path())?.is_dir() {
                continue;
            }
            let dir = entry.path();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).at(&dir)?;
            for child in fs::read_dir(&dir).at(&dir)? {
                let child = child.at(&dir)?;
                if child.file_type().at(child.path())?.is_file() {
                    let path = child.path();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).at(&path)?;
                }
            }
        }
        Ok(())
    }
}

fn managed_cache_path_at(
    root: &Path,
    product_version: &str,
    catalog_version: &str,
) -> Result<PathBuf> {
    for (name, value) in [
        ("product version", product_version),
        ("catalog version", catalog_version),
    ] {
        if value.is_empty()
            || value.len() > 96
            || value.starts_with('.')
            || value.contains("..")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(msg(format!("unsafe {name} for managed cache: {value:?}")));
        }
    }
    Ok(root.join(format!("{product_version}--{catalog_version}")))
}

pub struct OperationLock {
    file: File,
}

impl OperationLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).at(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .at(path)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return Err(msg(format!(
                "another xpad2 operation is active (lock: {})",
                path.display()
            )));
        }
        Ok(Self { file })
    }
}

impl Drop for OperationLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).at(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 128];
    loop {
        let n = file.read(&mut buf).at(path)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| msg("target has no parent directory"))?;
    fs::create_dir_all(parent).at(parent)?;
    let partial = parent.join(format!(
        ".{}.{}.partial",
        path.file_name().and_then(OsStr::to_str).unwrap_or("xpad2"),
        unique_id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&partial)
            .at(&partial)?;
        file.write_all(bytes).at(&partial)?;
        file.sync_all().at(&partial)?;
        fs::set_permissions(&partial, fs::Permissions::from_mode(mode)).at(&partial)?;
        fs::rename(&partial, path).at(path)?;
        File::open(parent).at(parent)?.sync_all().at(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

pub fn copy_atomic(source: &Path, target: &Path, mode: u32) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| msg("target has no parent directory"))?;
    fs::create_dir_all(parent).at(parent)?;
    let partial = parent.join(format!(
        ".{}.{}.partial",
        target
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("xpad2"),
        unique_id()
    ));
    let result = (|| {
        let source_file = File::open(source).at(source)?;
        let expected = source_file.metadata().at(source)?.len();
        let mut input = BufReader::with_capacity(128 * 1024, source_file);
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&partial)
            .at(&partial)?;
        let copied = std::io::copy(&mut input, &mut output).at(&partial)?;
        if copied != expected {
            return Err(msg(format!(
                "source size changed while copying {}: expected {expected}, copied {copied}",
                source.display()
            )));
        }
        output.sync_all().at(&partial)?;
        fs::set_permissions(&partial, fs::Permissions::from_mode(mode)).at(&partial)?;
        fs::rename(&partial, target).at(target)?;
        File::open(parent).at(parent)?.sync_all().at(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

pub fn validate_elf_arm64(path: &Path) -> Result<()> {
    let mut header = [0u8; 64];
    File::open(path)
        .at(path)?
        .read_exact(&mut header)
        .at(path)?;
    if &header[..4] != b"\x7fELF" {
        return Err(msg(format!("{} is not ELF", path.display())));
    }
    if header[4] != 2 || header[5] != 1 {
        return Err(msg(format!(
            "{} is not ELF64 little-endian",
            path.display()
        )));
    }
    let machine = u16::from_le_bytes([header[18], header[19]]);
    if machine != 183 {
        return Err(msg(format!(
            "{} is not AArch64 ELF (e_machine={machine})",
            path.display()
        )));
    }
    Ok(())
}

pub fn safe_filename(value: &str) -> Result<&str> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains("..")
        || value.chars().any(char::is_control)
    {
        return Err(msg(format!("unsafe target filename: {value:?}")));
    }
    Ok(value)
}

pub fn run(program: &str, args: &[&str]) -> Result<Output> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| msg(format!("failed to execute {program}: {e}")))
}

pub fn output_text(output: &Output) -> String {
    let stdout_lossy = String::from_utf8_lossy(&output.stdout);
    let stderr_lossy = String::from_utf8_lossy(&output.stderr);
    let stdout = stdout_lossy.trim();
    let stderr = stderr_lossy.trim();
    match (stdout.is_empty(), stderr.is_empty()) {
        (false, false) => format!("{stdout}\n{stderr}"),
        (false, true) => stdout.to_string(),
        (true, false) => stderr.to_string(),
        (true, true) => String::new(),
    }
}

pub fn getprop(name: &str) -> String {
    run("/system/bin/getprop", &[name])
        .or_else(|_| run("getprop", &[name]))
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn read_trimmed(path: &Path) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn boot_id() -> String {
    read_trimmed(Path::new("/proc/sys/kernel/random/boot_id"))
}

pub fn selinux() -> String {
    run("/system/bin/getenforce", &[])
        .or_else(|_| run("getenforce", &[]))
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "Unknown".to_string())
}

pub fn kernel_release() -> String {
    run("/system/bin/uname", &["-r"])
        .or_else(|_| run("uname", &["-r"]))
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn unique_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
}

pub fn timestamp_filename() -> String {
    match run("/system/bin/date", &["+%Y%m%d-%H%M%S"])
        .or_else(|_| run("date", &["+%Y%m%d-%H%M%S"]))
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    {
        Ok(value) if !value.is_empty() => value,
        _ => unique_id(),
    }
}

pub fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn executable_exists(path: &Path) -> bool {
    path.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

pub fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(crate::error::Error::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_are_single_safe_segments() {
        assert_eq!(safe_filename("tool-1.0").unwrap(), "tool-1.0");
        for bad in ["", ".", "..", "../tool", "a/b", "a..b", "bad\nname"] {
            assert!(safe_filename(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn shell_quote_handles_single_quotes() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn managed_cache_paths_are_version_scoped_and_safe() {
        let root = Path::new("/cache/releases");
        assert_eq!(
            managed_cache_path_at(root, "0.2.0", "2026-07-15.9").unwrap(),
            root.join("0.2.0--2026-07-15.9")
        );
        for bad in ["", "../0.2.0", "0/2/0", ".hidden", "0..2"] {
            assert!(managed_cache_path_at(root, bad, "catalog").is_err());
        }
    }

    #[test]
    fn operation_lock_is_process_wide_exclusive() {
        let root = std::env::temp_dir().join(format!("xpad2-lock-{}", unique_id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("operation.lock");
        let first = OperationLock::acquire(&path).unwrap();
        assert!(OperationLock::acquire(&path).is_err());
        drop(first);
        OperationLock::acquire(&path).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_copy_streams_and_replaces_the_target() {
        let root = std::env::temp_dir().join(format!("xpad2-copy-{}", unique_id()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        let target = root.join("target");
        let bytes = (0..4 * 1024 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&source, &bytes).unwrap();
        fs::write(&target, b"old").unwrap();
        copy_atomic(&source, &target, 0o700).unwrap();
        assert_eq!(sha256_file(&target).unwrap(), sha256_bytes(&bytes));
        assert_eq!(
            target.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::read_dir(&root)
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("partial"))
                .count(),
            0
        );
        fs::remove_dir_all(root).unwrap();
    }
}
