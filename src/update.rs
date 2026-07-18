use crate::catalog::{self, Catalog};
use crate::device;
use crate::error::{IoContext, Result, msg};
use crate::logging::TransactionLog;
use crate::model::AssetsLock;
#[cfg(test)]
use crate::model::DeviceProfile;
use crate::util::{
    Paths, atomic_write, copy_atomic, getprop, kernel_release, safe_filename, sha256_bytes,
    sha256_file, unique_id, validate_elf_arm64,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zip::ZipArchive;

const UPDATE_SCHEMA: u32 = 1;
const UPDATE_KIND: &str = "xpad2-update";
const UPDATE_CHANNEL: &str = "stable";
const UPDATE_REPOSITORY: &str = "https://github.com/yoyicue/xpad2-cli";
const GITHUB_API_REPOSITORY: &str = "https://api.github.com/repos/yoyicue/xpad2-cli";
const MANIFEST_FILENAME: &str = "xpad2-update.json";
const SIGNATURE_FILENAME: &str = "xpad2-update.json.sig";
const CATALOG_SIGNATURE_FILENAME: &str = "catalog.sig";
const DELTA_INDEX_FILENAME: &str = "xpad2-deltas.json";
const DELTA_SIGNATURE_FILENAME: &str = "xpad2-deltas.json.sig";
const DELTA_SCHEMA: u32 = 1;
const DELTA_KIND: &str = "xpad2-deltas";
const MAX_MANIFEST_SIZE: usize = 256 * 1024;
const MAX_SIGNATURE_SIZE: usize = 64 * 1024;
const MAX_RELEASE_METADATA_SIZE: usize = 2 * 1024 * 1024;
const MAX_BINARY_SIZE: u64 = 128 * 1024 * 1024;
const MAX_DELTA_SIZE: u64 = 64 * 1024 * 1024;
const MAX_CACHE_ARCHIVE_SIZE: u64 = 512 * 1024 * 1024;
const MAX_EXTRACTED_SIZE: u64 = 768 * 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = 4096;
const DOWNLOAD_ATTEMPTS: u32 = 3;
const MAX_AUTOMATIC_RETRY_DELAY: Duration = Duration::from_secs(60);

#[derive(Debug)]
enum HttpFailure {
    Fatal(String),
    Retryable {
        message: String,
        retry_after: Option<Duration>,
    },
}

impl HttpFailure {
    fn message(&self) -> &str {
        match self {
            Self::Fatal(message) | Self::Retryable { message, .. } => message,
        }
    }
}

type HttpResult<T> = std::result::Result<T, HttpFailure>;

#[derive(Clone, Debug)]
pub struct UpdateRequest {
    pub check: bool,
    pub json: bool,
    pub version: Option<String>,
    pub offline: Option<PathBuf>,
    pub manifest_url: Option<String>,
    pub reinstall: bool,
    pub allow_downgrade: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateManifest {
    schema: u32,
    kind: String,
    channel: String,
    repository: String,
    version: String,
    catalog_version: String,
    profile: UpdateProfile,
    binary: UpdateAsset,
    cache: UpdateAsset,
    catalog: CatalogIdentity,
    release_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateProfile {
    build_fingerprint: String,
    kernel_release_prefix: String,
    abi: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct UpdateAsset {
    filename: String,
    url: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeltaIndex {
    schema: u32,
    kind: String,
    repository: String,
    target_version: String,
    target_binary: UpdateAsset,
    deltas: Vec<DeltaEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeltaEntry {
    from_version: String,
    from_size: u64,
    from_sha256: String,
    patch: UpdateAsset,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogIdentity {
    filename: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    url: String,
    size: u64,
    state: String,
    digest: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VersionState {
    Available,
    Current,
    Ahead,
}

impl VersionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Current => "current",
            Self::Ahead => "ahead",
        }
    }
}

struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn create(paths: &Paths) -> Result<Self> {
        paths.ensure()?;
        let path = paths.work.join(format!("self-update-{}", unique_id()));
        fs::create_dir(&path).at(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).at(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct VerifiedManifest {
    manifest: UpdateManifest,
    raw: Vec<u8>,
    signature: Vec<u8>,
    offline_root: Option<PathBuf>,
    github_release: Option<GitHubRelease>,
    source: String,
}

struct CacheSwap {
    target: PathBuf,
    previous: Option<PathBuf>,
}

impl CacheSwap {
    fn rollback(&self) -> Result<()> {
        if self.target.exists() {
            fs::remove_dir_all(&self.target).at(&self.target)?;
        }
        if let Some(previous) = &self.previous
            && previous.exists()
        {
            fs::rename(previous, &self.target).at(&self.target)?;
        }
        sync_parent(&self.target)
    }

    fn commit(&self) -> Result<()> {
        if let Some(previous) = &self.previous
            && previous.exists()
        {
            fs::remove_dir_all(previous).at(previous)?;
        }
        Ok(())
    }
}

struct BinarySwap {
    target: PathBuf,
    backup: PathBuf,
    rollback_staged: PathBuf,
    expected_sha256: String,
}

struct CandidateAcquisition {
    path: PathBuf,
    mode: &'static str,
    transferred_bytes: u64,
}

impl BinarySwap {
    fn rollback(&self) -> Result<()> {
        if self.rollback_staged.exists() {
            if let Err(rename_error) = fs::rename(&self.rollback_staged, &self.target) {
                copy_atomic(&self.backup, &self.target, 0o700).map_err(|copy_error| {
                    msg(format!(
                        "atomic rollback rename failed ({rename_error}); backup copy also failed: {copy_error}"
                    ))
                })?;
            }
        } else {
            copy_atomic(&self.backup, &self.target, 0o700)?;
        }
        sync_parent(&self.target)?;
        let actual = sha256_file(&self.target)?;
        if actual != self.expected_sha256 {
            return Err(msg(format!(
                "rolled-back xpad2 identity mismatch: expected {}, got {actual}",
                self.expected_sha256
            )));
        }
        Ok(())
    }

    fn commit(&self) -> Result<()> {
        if self.rollback_staged.exists() {
            fs::remove_file(&self.rollback_staged).at(&self.rollback_staged)?;
            sync_parent(&self.rollback_staged)?;
        }
        Ok(())
    }
}

pub fn parse_args(args: &[String]) -> Result<UpdateRequest> {
    let mut request = UpdateRequest {
        check: false,
        json: false,
        version: None,
        offline: None,
        manifest_url: None,
        reinstall: false,
        allow_downgrade: false,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--check" => request.check = true,
            "--json" => request.json = true,
            "--reinstall" => request.reinstall = true,
            "--allow-downgrade" => request.allow_downgrade = true,
            "--version" => {
                index += 1;
                request.version = Some(
                    args.get(index)
                        .ok_or_else(|| msg("--version requires a semantic version"))?
                        .clone(),
                );
            }
            "--offline" => {
                index += 1;
                request.offline =
                    Some(PathBuf::from(args.get(index).ok_or_else(|| {
                        msg("--offline requires a directory or update ZIP")
                    })?));
            }
            "--manifest-url" => {
                index += 1;
                request.manifest_url = Some(
                    args.get(index)
                        .ok_or_else(|| msg("--manifest-url requires an HTTPS URL"))?
                        .clone(),
                );
            }
            other if other.starts_with("--version=") => {
                request.version = Some(other["--version=".len()..].to_string());
            }
            other if other.starts_with("--offline=") => {
                request.offline = Some(PathBuf::from(&other["--offline=".len()..]));
            }
            other if other.starts_with("--manifest-url=") => {
                request.manifest_url = Some(other["--manifest-url=".len()..].to_string());
            }
            _ => return Err(msg(update_usage())),
        }
        index += 1;
    }

    if let Some(version) = &request.version {
        parse_canonical_version(version)?;
    }
    if request.offline.is_some() && request.manifest_url.is_some() {
        return Err(msg("--offline and --manifest-url are mutually exclusive"));
    }
    if request.json && !request.check {
        return Err(msg("--json is only valid with --check"));
    }
    if request.check && (request.reinstall || request.allow_downgrade) {
        return Err(msg(
            "--check cannot be combined with --reinstall or --allow-downgrade",
        ));
    }
    if request.allow_downgrade && request.version.is_none() && request.offline.is_none() {
        return Err(msg(
            "--allow-downgrade requires an explicit --version or --offline bundle",
        ));
    }
    Ok(request)
}

pub fn check(catalog: &Catalog, paths: &Paths, request: &UpdateRequest) -> Result<()> {
    device::profile_check(catalog)?;
    let workspace = Workspace::create(paths)?;
    let verified = acquire_manifest(request, &workspace)?;
    validate_target_profile(&verified.manifest, catalog)?;
    let current = parse_canonical_version(env!("CARGO_PKG_VERSION"))?;
    let target = parse_canonical_version(&verified.manifest.version)?;
    let state = version_state(&current, &target);

    if request.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "current_version": current.to_string(),
                "target_version": target.to_string(),
                "catalog_version": verified.manifest.catalog_version,
                "state": state.as_str(),
                "source": verified.source,
                "release_url": verified.manifest.release_url,
            }))?
        );
    } else {
        match state {
            VersionState::Available => println!(
                "可更新：xpad2 {} -> {}（catalog {}）\n{}",
                current, target, verified.manifest.catalog_version, verified.manifest.release_url
            ),
            VersionState::Current => println!(
                "已是当前稳定版：xpad2 {}（catalog {}）",
                current, verified.manifest.catalog_version
            ),
            VersionState::Ahead => {
                println!("当前版本 {} 高于所选发布 {}；不会自动降级", current, target)
            }
        }
    }
    Ok(())
}

pub fn apply(
    catalog: &Catalog,
    paths: &Paths,
    request: &UpdateRequest,
    log: &mut TransactionLog,
) -> Result<bool> {
    if paths.cache_is_explicit {
        return Err(msg(
            "self-update refuses --cache-dir/XPAD2_CACHE_DIR; use the managed versioned cache",
        ));
    }
    device::profile_check(catalog)?;
    let workspace = Workspace::create(paths)?;
    let verified = acquire_manifest(request, &workspace)?;
    validate_target_profile(&verified.manifest, catalog)?;
    let current = parse_canonical_version(env!("CARGO_PKG_VERSION"))?;
    let target = parse_canonical_version(&verified.manifest.version)?;
    let state = version_state(&current, &target);

    match state {
        VersionState::Current if !request.reinstall => {
            println!("xpad2 {current} 已是所选版本，无需更新");
            return Ok(false);
        }
        VersionState::Ahead if !request.allow_downgrade => {
            return Err(msg(format!(
                "refusing downgrade {} -> {}; repeat with an explicit version/bundle and --allow-downgrade",
                current, target
            )));
        }
        _ => {}
    }

    log.event(
        "self-update",
        "manifest-verified",
        json!({
            "source": verified.source,
            "current_version": current.to_string(),
            "target_version": target.to_string(),
            "catalog_version": verified.manifest.catalog_version,
            "reinstall": request.reinstall,
            "downgrade": state == VersionState::Ahead,
        }),
    )?;
    println!(
        "准备更新 xpad2 {} -> {}；下载、签名校验、内嵌缓存导出和候选自检通常需要 1–3 分钟…",
        current, target
    );

    let manifest_path = workspace.path.join(MANIFEST_FILENAME);
    let signature_path = workspace.path.join(SIGNATURE_FILENAME);
    atomic_write(&manifest_path, &verified.raw, 0o600)?;
    atomic_write(&signature_path, &verified.signature, 0o600)?;

    let candidate_acquisition =
        acquire_candidate_binary(&verified, &current, &workspace.path, log)?;
    let candidate = candidate_acquisition.path;
    validate_elf_arm64(&candidate)?;
    let catalog_signature = acquire_catalog_signature(&verified, &workspace.path)?;
    let (cache_source, target_lock, cache_mode) = if let Some(catalog_signature) = catalog_signature
    {
        let exported = workspace.path.join("embedded-cache");
        export_candidate_cache(
            &candidate,
            &manifest_path,
            &signature_path,
            &catalog_signature,
            &exported,
            log,
        )?;
        let lock = load_cache_catalog_against_manifest(&exported, &verified.manifest)?;
        (exported, lock, "candidate-export")
    } else {
        eprintln!("提示：所选旧发布没有独立 catalog.sig，兼容模式将下载完整离线 cache。");
        let cache_archive = acquire_asset(
            &verified.manifest.cache,
            verified.offline_root.as_deref(),
            verified.github_release.as_ref(),
            &workspace.path,
            0o600,
            "离线 cache",
        )?;
        let unpacked = workspace.path.join("cache-unpacked");
        extract_zip_safely(&cache_archive, &unpacked, MAX_EXTRACTED_SIZE)?;
        let cache_source = locate_named_root(&unpacked, "xpad2-cache")?;
        let target_lock = verify_cache_against_manifest(&cache_source, &verified.manifest, None)?;
        verify_candidate(
            &candidate,
            &manifest_path,
            &signature_path,
            &cache_source,
            log,
        )?;
        (cache_source, target_lock, "legacy-cache-download")
    };

    let target_cache = paths.managed_cache_path(
        &verified.manifest.version,
        &verified.manifest.catalog_version,
    )?;
    let cache_swap = install_version_cache(&cache_source, &target_lock, &target_cache, paths)?;
    let binary_swap = match install_candidate_binary(&candidate, &current, paths) {
        Ok(swap) => swap,
        Err(error) => {
            let _ = cache_swap.rollback();
            return Err(error);
        }
    };

    let postcheck = verify_candidate(
        &binary_swap.target,
        &manifest_path,
        &signature_path,
        &target_cache,
        log,
    );
    if let Err(error) = postcheck {
        let binary_rollback = binary_swap.rollback();
        let cache_rollback = cache_swap.rollback();
        log.event(
            "self-update",
            "rolled-back",
            json!({
                "target_version": target.to_string(),
                "candidate_error": error.to_string(),
                "binary_rollback": binary_rollback.as_ref().err().map(ToString::to_string),
                "cache_rollback": cache_rollback.as_ref().err().map(ToString::to_string),
            }),
        )?;
        binary_rollback?;
        cache_rollback?;
        return Err(msg(format!(
            "installed candidate failed self-check and was rolled back: {error}"
        )));
    }

    cache_swap.commit()?;
    if let Err(error) = binary_swap.commit() {
        log.event(
            "self-update",
            "maintenance-warning",
            json!({"cleanup": "rollback-staging", "error": error.to_string()}),
        )?;
        eprintln!("提示：更新已安装，但临时回滚副本清理失败：{error}");
    }
    let cache_files_removed = match catalog::retain_managed_cache_releases(
        paths,
        &[target_cache.clone(), paths.cache.clone()],
    ) {
        Ok(removed) => removed,
        Err(error) => {
            log.event(
                "cache",
                "maintenance-warning",
                json!({"error": error.to_string()}),
            )?;
            eprintln!("提示：更新已安装，但历史缓存回收失败：{error}");
            0
        }
    };
    let record = json!({
        "from_version": current.to_string(),
        "to_version": target.to_string(),
        "catalog_version": verified.manifest.catalog_version,
        "binary_sha256": verified.manifest.binary.sha256,
        "binary_mode": candidate_acquisition.mode,
        "binary_transferred_bytes": candidate_acquisition.transferred_bytes,
        "cache_sha256": verified.manifest.cache.sha256,
        "cache_mode": cache_mode,
        "cache_files_removed": cache_files_removed,
        "manifest_sha256": sha256_bytes(&verified.raw),
        "source": verified.source,
        "rollback_binary": binary_swap.backup.clone(),
    });
    atomic_write(
        &paths.state.join("last-self-update.json"),
        &serde_json::to_vec_pretty(&record)?,
        0o600,
    )?;
    if let Err(error) = prune_binary_backups(paths, 2, &binary_swap.backup) {
        log.event(
            "self-update",
            "maintenance-warning",
            json!({"cleanup": "binary-backups", "error": error.to_string()}),
        )?;
        eprintln!("提示：更新已安装，但历史 ELF 备份回收失败：{error}");
    }
    log.event("self-update", "installed", record)?;
    println!(
        "更新完成：xpad2 {}（catalog {}）；旧 ELF 已保留用于失败恢复",
        target, verified.manifest.catalog_version
    );
    Ok(true)
}

fn verify_candidate_identity(
    catalog: &Catalog,
    manifest_path: &Path,
    signature_path: &Path,
) -> Result<UpdateManifest> {
    let raw = read_limited(manifest_path, MAX_MANIFEST_SIZE)?;
    let signature = read_limited(signature_path, MAX_SIGNATURE_SIZE)?;
    catalog::verify_catalog_signature(&raw, &signature)?;
    let manifest: UpdateManifest = serde_json::from_slice(&raw)?;
    validate_manifest(&manifest)?;
    if manifest.version != env!("CARGO_PKG_VERSION")
        || manifest.catalog_version != catalog.lock.catalog_version
        || manifest.profile.build_fingerprint != catalog.lock.profile.build_fingerprint
        || manifest.profile.kernel_release_prefix != catalog.lock.profile.kernel_release_prefix
        || manifest.profile.abi != catalog.lock.profile.abi
    {
        return Err(msg(
            "candidate embedded release identity does not match update manifest",
        ));
    }
    catalog.lock.profile.fingerprint_policy().validate()?;
    device::profile_check(catalog)?;
    let current_exe = std::env::current_exe()
        .map_err(|error| msg(format!("cannot resolve candidate executable: {error}")))?;
    verify_file_identity(&current_exe, &manifest.binary, "candidate ELF")?;
    validate_elf_arm64(&current_exe)?;
    Ok(manifest)
}

pub fn verify_candidate_command(catalog: &Catalog, args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err(msg("internal candidate verification usage error"));
    }
    let manifest = verify_candidate_identity(catalog, Path::new(&args[0]), Path::new(&args[1]))?;
    let cache = Path::new(&args[2]);
    let managed_paths = Paths::new(None, &manifest.version, &manifest.catalog_version)?;
    let managed_paths = (cache == managed_paths.cache).then_some(&managed_paths);
    let lock = verify_cache_against_manifest(cache, &manifest, managed_paths)?;
    let verified = lock
        .artifacts
        .iter()
        .filter(|artifact| artifact.embedded)
        .count();
    println!(
        "XPAD2_UPDATE_CANDIDATE_OK version={} catalog={} blobs={}",
        manifest.version, manifest.catalog_version, verified
    );
    Ok(())
}

pub fn export_candidate_cache_command(catalog: &Catalog, args: &[String]) -> Result<()> {
    if args.len() != 4 {
        return Err(msg("internal candidate cache export usage error"));
    }
    let manifest = verify_candidate_identity(catalog, Path::new(&args[0]), Path::new(&args[1]))?;
    let catalog_signature = read_regular_limited(Path::new(&args[2]), MAX_SIGNATURE_SIZE)?;
    let embedded_catalog = catalog::embedded_catalog_raw();
    if embedded_catalog.len() as u64 != manifest.catalog.size
        || sha256_bytes(embedded_catalog) != manifest.catalog.sha256
    {
        return Err(msg(
            "candidate embedded catalog identity does not match update manifest",
        ));
    }
    catalog::verify_catalog_signature(embedded_catalog, &catalog_signature)?;
    let exported =
        catalog::export_embedded_cache(catalog, &catalog_signature, Path::new(&args[3]))?;
    println!(
        "XPAD2_UPDATE_CACHE_EXPORT_OK version={} catalog={} blobs={}",
        manifest.version, manifest.catalog_version, exported
    );
    Ok(())
}

pub fn update_usage() -> &'static str {
    "usage: xpad2 update [--check] [--json] [--version VERSION] [--offline DIRECTORY_OR_ZIP] [--reinstall] [--allow-downgrade] [--manifest-url HTTPS_URL]"
}

fn acquire_manifest(request: &UpdateRequest, workspace: &Workspace) -> Result<VerifiedManifest> {
    let (raw, signature, offline_root, github_release, source) =
        if let Some(path) = &request.offline {
            let root = prepare_offline_root(path, &workspace.path)?;
            let manifest_path = root.join(MANIFEST_FILENAME);
            let signature_path = root.join(SIGNATURE_FILENAME);
            (
                read_regular_limited(&manifest_path, MAX_MANIFEST_SIZE)?,
                read_regular_limited(&signature_path, MAX_SIGNATURE_SIZE)?,
                Some(root.clone()),
                None,
                format!("offline:{}", path.display()),
            )
        } else if let Some(url) = configured_manifest_url(request) {
            validate_https_url(&url, "manifest URL")?;
            let signature_url = format!("{url}.sig");
            let agent = http_agent();
            println!("检查签名更新清单…");
            (
                fetch_small(&agent, &url, MAX_MANIFEST_SIZE, "update manifest")?,
                fetch_small(
                    &agent,
                    &signature_url,
                    MAX_SIGNATURE_SIZE,
                    "update manifest signature",
                )?,
                None,
                None,
                url,
            )
        } else {
            let agent = http_agent();
            let api_url = github_release_api_url(request);
            println!("通过 GitHub Releases API 检查签名更新清单…");
            let metadata = fetch_small_with_accept(
                &agent,
                &api_url,
                MAX_RELEASE_METADATA_SIZE,
                "GitHub release metadata",
                "application/vnd.github+json",
            )?;
            let release: GitHubRelease = serde_json::from_slice(&metadata)?;
            validate_github_release(&release, request.version.as_deref())?;
            let manifest_asset = github_asset(&release, MANIFEST_FILENAME)?;
            let signature_asset = github_asset(&release, SIGNATURE_FILENAME)?;
            if manifest_asset.size == 0 || manifest_asset.size > MAX_MANIFEST_SIZE as u64 {
                return Err(msg("GitHub update manifest asset has an invalid size"));
            }
            if signature_asset.size == 0 || signature_asset.size > MAX_SIGNATURE_SIZE as u64 {
                return Err(msg("GitHub update signature asset has an invalid size"));
            }
            (
                fetch_small_with_accept(
                    &agent,
                    &manifest_asset.url,
                    MAX_MANIFEST_SIZE,
                    "update manifest",
                    "application/octet-stream",
                )?,
                fetch_small_with_accept(
                    &agent,
                    &signature_asset.url,
                    MAX_SIGNATURE_SIZE,
                    "update manifest signature",
                    "application/octet-stream",
                )?,
                None,
                Some(release),
                api_url,
            )
        };
    catalog::verify_catalog_signature(&raw, &signature)?;
    let manifest: UpdateManifest = serde_json::from_slice(&raw)?;
    validate_manifest(&manifest)?;
    if let Some(requested) = &request.version
        && manifest.version != *requested
    {
        return Err(msg(format!(
            "selected manifest version {} != requested {}",
            manifest.version, requested
        )));
    }
    if let Some(release) = &github_release {
        validate_github_release_manifest(release, &manifest)?;
    }
    Ok(VerifiedManifest {
        manifest,
        raw,
        signature,
        offline_root,
        github_release,
        source,
    })
}

fn configured_manifest_url(request: &UpdateRequest) -> Option<String> {
    if let Some(url) = &request.manifest_url {
        return Some(url.clone());
    }
    if request.version.is_none()
        && let Some(url) = std::env::var_os("XPAD2_UPDATE_MANIFEST_URL")
    {
        return Some(url.to_string_lossy().into_owned());
    }
    None
}

fn github_release_api_url(request: &UpdateRequest) -> String {
    if let Some(version) = &request.version {
        return format!("{GITHUB_API_REPOSITORY}/releases/tags/v{version}");
    }
    format!("{GITHUB_API_REPOSITORY}/releases/latest")
}

fn validate_github_release(release: &GitHubRelease, requested: Option<&str>) -> Result<()> {
    if release.draft || release.prerelease {
        return Err(msg("GitHub update release is draft or prerelease"));
    }
    let version = release
        .tag_name
        .strip_prefix('v')
        .ok_or_else(|| msg("GitHub update release tag is not v-prefixed semver"))?;
    let parsed = parse_canonical_version(version)?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        return Err(msg(
            "GitHub stable release tag is not a stable semantic version",
        ));
    }
    if let Some(requested) = requested
        && version != requested
    {
        return Err(msg(format!(
            "GitHub release tag {} != requested v{}",
            release.tag_name, requested
        )));
    }
    let expected_page = format!("{UPDATE_REPOSITORY}/releases/tag/{}", release.tag_name);
    if release.html_url != expected_page {
        return Err(msg(
            "GitHub release page does not belong to the canonical repository",
        ));
    }
    Ok(())
}

fn github_asset<'a>(release: &'a GitHubRelease, name: &str) -> Result<&'a GitHubAsset> {
    github_asset_optional(release, name)?
        .ok_or_else(|| msg(format!("GitHub release asset missing: {name}")))
}

fn github_asset_optional<'a>(
    release: &'a GitHubRelease,
    name: &str,
) -> Result<Option<&'a GitHubAsset>> {
    let mut matches = release.assets.iter().filter(|asset| asset.name == name);
    let Some(asset) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(msg(format!(
            "GitHub release contains duplicate asset: {name}"
        )));
    }
    if asset.state != "uploaded" {
        return Err(msg(format!("GitHub release asset is not uploaded: {name}")));
    }
    validate_https_url(&asset.url, "GitHub asset API URL")?;
    let parsed = url::Url::parse(&asset.url)
        .map_err(|error| msg(format!("invalid GitHub asset API URL: {error}")))?;
    let expected_prefix = format!("{GITHUB_API_REPOSITORY}/releases/assets/");
    if parsed.host_str() != Some("api.github.com") || !asset.url.starts_with(&expected_prefix) {
        return Err(msg(format!("untrusted GitHub asset API URL for {name}")));
    }
    Ok(Some(asset))
}

fn validate_github_release_manifest(
    release: &GitHubRelease,
    manifest: &UpdateManifest,
) -> Result<()> {
    if release.tag_name != format!("v{}", manifest.version)
        || release.html_url != manifest.release_url
    {
        return Err(msg(
            "GitHub release identity does not match signed update manifest",
        ));
    }
    for (locked, label) in [(&manifest.binary, "binary"), (&manifest.cache, "cache")] {
        let asset = github_asset(release, &locked.filename)?;
        if asset.size != locked.size {
            return Err(msg(format!(
                "GitHub {label} asset size does not match signed manifest"
            )));
        }
        if let Some(digest) = &asset.digest
            && digest != &format!("sha256:{}", locked.sha256)
        {
            return Err(msg(format!(
                "GitHub {label} asset digest does not match signed manifest"
            )));
        }
    }
    Ok(())
}

fn prepare_offline_root(source: &Path, workspace: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(source).at(source)?;
    let root = if metadata.file_type().is_symlink() {
        return Err(msg(format!(
            "offline update source must not be a symlink: {}",
            source.display()
        )));
    } else if metadata.is_dir() {
        source.to_path_buf()
    } else if metadata.is_file() {
        let extracted = workspace.join("offline-bundle");
        extract_zip_safely(source, &extracted, MAX_EXTRACTED_SIZE)?;
        locate_named_root(&extracted, "xpad2-update")?
    } else {
        return Err(msg(format!(
            "offline update source is neither a directory nor a ZIP: {}",
            source.display()
        )));
    };
    if root.join(MANIFEST_FILENAME).is_file() && root.join(SIGNATURE_FILENAME).is_file() {
        return Ok(root);
    }
    let nested = root.join("xpad2-update");
    if nested.join(MANIFEST_FILENAME).is_file() && nested.join(SIGNATURE_FILENAME).is_file() {
        return Ok(nested);
    }
    Err(msg(format!(
        "offline bundle is missing {MANIFEST_FILENAME} and {SIGNATURE_FILENAME}"
    )))
}

fn validate_manifest(manifest: &UpdateManifest) -> Result<()> {
    if manifest.schema != UPDATE_SCHEMA
        || manifest.kind != UPDATE_KIND
        || manifest.channel != UPDATE_CHANNEL
        || manifest.repository != UPDATE_REPOSITORY
    {
        return Err(msg(
            "unsupported or untrusted xpad2 update manifest identity",
        ));
    }
    let version = parse_canonical_version(&manifest.version)?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        return Err(msg(
            "stable update manifest must use a release semantic version",
        ));
    }
    let expected_binary = format!("xpad2-v{}-android-arm64", manifest.version);
    let expected_cache = format!("xpad2-cache-v{}.zip", manifest.version);
    if manifest.binary.filename != expected_binary || manifest.cache.filename != expected_cache {
        return Err(msg("update asset filenames do not match manifest version"));
    }
    safe_filename(&manifest.binary.filename)?;
    safe_filename(&manifest.cache.filename)?;
    if manifest.catalog.filename != "catalog.json" {
        return Err(msg("update catalog filename must be catalog.json"));
    }
    validate_asset(&manifest.binary, MAX_BINARY_SIZE, "binary")?;
    validate_asset(&manifest.cache, MAX_CACHE_ARCHIVE_SIZE, "cache")?;
    if manifest.catalog.size == 0 || manifest.catalog.size > MAX_MANIFEST_SIZE as u64 {
        return Err(msg("update catalog size is outside the safe range"));
    }
    validate_sha256(&manifest.catalog.sha256, "catalog SHA-256")?;
    validate_https_url(&manifest.release_url, "release URL")?;
    if manifest.profile.build_fingerprint.is_empty()
        || manifest.profile.kernel_release_prefix.is_empty()
        || manifest.profile.abi != "arm64-v8a"
    {
        return Err(msg("invalid target device profile in update manifest"));
    }
    Ok(())
}

fn validate_asset(asset: &UpdateAsset, max_size: u64, name: &str) -> Result<()> {
    if asset.size == 0 || asset.size > max_size {
        return Err(msg(format!("{name} asset size is outside the safe range")));
    }
    validate_sha256(&asset.sha256, &format!("{name} SHA-256"))?;
    validate_https_url(&asset.url, &format!("{name} URL"))?;
    if !asset.url.ends_with(&format!("/{}", asset.filename)) {
        return Err(msg(format!(
            "{name} URL does not end with its locked filename"
        )));
    }
    Ok(())
}

fn validate_target_profile(manifest: &UpdateManifest, catalog: &Catalog) -> Result<()> {
    let profile = &catalog.lock.profile;
    if manifest.profile.build_fingerprint != profile.build_fingerprint
        || manifest.profile.kernel_release_prefix != profile.kernel_release_prefix
        || manifest.profile.abi != profile.abi
    {
        return Err(msg("update release targets a different device profile"));
    }
    let fingerprint_policy = profile.fingerprint_policy();
    fingerprint_policy.validate()?;
    let fingerprint = getprop("ro.build.fingerprint");
    let abi = getprop("ro.product.cpu.abi");
    let kernel = kernel_release();
    if !catalog
        .lock
        .matches_technical_runtime(&fingerprint, &kernel, &abi)
    {
        return Err(msg(
            "current device does not match the signed update profile",
        ));
    }
    Ok(())
}

fn parse_canonical_version(raw: &str) -> Result<Version> {
    let version = Version::parse(raw)
        .map_err(|error| msg(format!("invalid semantic version {raw:?}: {error}")))?;
    if version.to_string() != raw {
        return Err(msg(format!("non-canonical semantic version: {raw:?}")));
    }
    Ok(version)
}

fn version_state(current: &Version, target: &Version) -> VersionState {
    use std::cmp::Ordering;
    match current.cmp(target) {
        Ordering::Less => VersionState::Available,
        Ordering::Equal => VersionState::Current,
        Ordering::Greater => VersionState::Ahead,
    }
}

fn validate_sha256(value: &str, name: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(msg(format!("invalid lowercase {name}: {value:?}")));
    }
    Ok(())
}

fn validate_https_url(value: &str, name: &str) -> Result<()> {
    let parsed = url::Url::parse(value)
        .map_err(|error| msg(format!("invalid {name} {value:?}: {error}")))?;
    if value.len() > 4096
        || parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(msg(format!("invalid {name}: {value:?}")));
    }
    Ok(())
}

fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .user_agent(&format!("xpad2/{}", env!("CARGO_PKG_VERSION")))
        .timeout_connect(Duration::from_secs(30))
        .timeout_read(Duration::from_secs(120))
        .timeout_write(Duration::from_secs(120))
        .redirects(8)
        .build()
}

fn request(agent: &ureq::Agent, url: &str, accept: Option<&str>) -> ureq::Request {
    let mut request = agent.get(url);
    if let Some(accept) = accept {
        request = request.set("Accept", accept);
    }
    if url.starts_with("https://api.github.com/") {
        request = request.set("X-GitHub-Api-Version", "2022-11-28");
    }
    request
}

fn response_retry_after(response: &ureq::Response) -> Option<Duration> {
    if let Some(seconds) = response
        .header("Retry-After")
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        return Some(Duration::from_secs(seconds));
    }
    let reset = response
        .header("X-RateLimit-Reset")?
        .trim()
        .parse::<u64>()
        .ok()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Some(Duration::from_secs(reset.saturating_sub(now).max(1)))
}

fn classify_ureq_error(error: ureq::Error, label: &str) -> HttpFailure {
    match error {
        ureq::Error::Status(status, response) => {
            let rate_limited = status == 429
                || (status == 403
                    && response
                        .header("X-RateLimit-Remaining")
                        .is_some_and(|value| value.trim() == "0"));
            let message = if rate_limited {
                format!("HTTPS {label} rate limited (HTTP {status})")
            } else {
                format!("HTTPS {label} failed with HTTP {status}")
            };
            if rate_limited || status == 408 || status == 425 || (500..=599).contains(&status) {
                HttpFailure::Retryable {
                    message,
                    retry_after: response_retry_after(&response),
                }
            } else {
                HttpFailure::Fatal(message)
            }
        }
        ureq::Error::Transport(error) => HttpFailure::Retryable {
            message: format!("HTTPS {label} transport failed: {error}"),
            retry_after: None,
        },
    }
}

fn retry_delay(failure: &HttpFailure, attempt: u32) -> Result<Duration> {
    match failure {
        HttpFailure::Fatal(message) => Err(msg(message.clone())),
        HttpFailure::Retryable {
            message,
            retry_after,
        } => {
            let delay = retry_after.unwrap_or_else(|| Duration::from_secs(attempt as u64));
            if delay > MAX_AUTOMATIC_RETRY_DELAY {
                return Err(msg(format!(
                    "{message}; server requires waiting about {} seconds, retry later",
                    delay.as_secs()
                )));
            }
            Ok(delay)
        }
    }
}

fn fetch_small(agent: &ureq::Agent, url: &str, max: usize, label: &str) -> Result<Vec<u8>> {
    fetch_small_with_optional_accept(agent, url, max, label, None)
}

fn fetch_small_with_accept(
    agent: &ureq::Agent,
    url: &str,
    max: usize,
    label: &str,
    accept: &str,
) -> Result<Vec<u8>> {
    fetch_small_with_optional_accept(agent, url, max, label, Some(accept))
}

fn fetch_small_with_optional_accept(
    agent: &ureq::Agent,
    url: &str,
    max: usize,
    label: &str,
    accept: Option<&str>,
) -> Result<Vec<u8>> {
    let mut last_error = None::<String>;
    for attempt in 1..=DOWNLOAD_ATTEMPTS {
        match fetch_small_once(agent, url, max, label, accept) {
            Ok(bytes) => return Ok(bytes),
            Err(failure) => {
                let message = failure.message().to_string();
                if attempt == DOWNLOAD_ATTEMPTS {
                    return Err(msg(message));
                }
                let delay = retry_delay(&failure, attempt)?;
                eprintln!(
                    "{label} 网络请求失败（{attempt}/{DOWNLOAD_ATTEMPTS}）：{message}；{} 秒后重试…",
                    delay.as_secs()
                );
                std::thread::sleep(delay);
                last_error = Some(message);
            }
        }
    }
    Err(msg(
        last_error.unwrap_or_else(|| format!("{label} download failed"))
    ))
}

fn fetch_small_once(
    agent: &ureq::Agent,
    url: &str,
    max: usize,
    label: &str,
    accept: Option<&str>,
) -> HttpResult<Vec<u8>> {
    let response = request(agent, url, accept)
        .call()
        .map_err(|error| classify_ureq_error(error, label))?;
    if let Some(length) = response.header("Content-Length")
        && length
            .parse::<u64>()
            .ok()
            .is_some_and(|length| length > max as u64)
    {
        return Err(HttpFailure::Fatal(format!(
            "{label} exceeds the safe size limit"
        )));
    }
    let mut reader = response.into_reader().take(max as u64 + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| HttpFailure::Retryable {
            message: format!("HTTPS {label} read failed: {error}"),
            retry_after: None,
        })?;
    if bytes.len() > max {
        return Err(HttpFailure::Fatal(format!(
            "{label} exceeds the safe size limit"
        )));
    }
    Ok(bytes)
}

fn acquire_catalog_signature(
    verified: &VerifiedManifest,
    workspace: &Path,
) -> Result<Option<PathBuf>> {
    let bytes = if let Some(root) = &verified.offline_root {
        let source = root.join(CATALOG_SIGNATURE_FILENAME);
        if !source.is_file() {
            return Ok(None);
        }
        read_regular_limited(&source, MAX_SIGNATURE_SIZE)?
    } else if let Some(release) = &verified.github_release {
        let Some(asset) = github_asset_optional(release, CATALOG_SIGNATURE_FILENAME)? else {
            return Ok(None);
        };
        if asset.size == 0 || asset.size > MAX_SIGNATURE_SIZE as u64 {
            return Err(msg("GitHub catalog signature asset has an invalid size"));
        }
        let agent = http_agent();
        fetch_small_with_accept(
            &agent,
            &asset.url,
            MAX_SIGNATURE_SIZE,
            "catalog signature",
            "application/octet-stream",
        )?
    } else {
        return Ok(None);
    };
    if bytes.is_empty() {
        return Err(msg("catalog signature is empty"));
    }
    let target = workspace.join(CATALOG_SIGNATURE_FILENAME);
    atomic_write(&target, &bytes, 0o600)?;
    Ok(Some(target))
}

fn acquire_delta_index(
    verified: &VerifiedManifest,
    workspace: &Path,
) -> Result<Option<DeltaIndex>> {
    let pair = if let Some(root) = &verified.offline_root {
        let index = root.join(DELTA_INDEX_FILENAME);
        let signature = root.join(DELTA_SIGNATURE_FILENAME);
        match (index.exists(), signature.exists()) {
            (false, false) => None,
            (true, true) => Some((
                read_regular_limited(&index, MAX_MANIFEST_SIZE)?,
                read_regular_limited(&signature, MAX_SIGNATURE_SIZE)?,
            )),
            _ => {
                return Err(msg(
                    "offline update contains only one delta index/signature sidecar",
                ));
            }
        }
    } else if let Some(release) = &verified.github_release {
        let index_asset = github_asset_optional(release, DELTA_INDEX_FILENAME)?;
        let signature_asset = github_asset_optional(release, DELTA_SIGNATURE_FILENAME)?;
        match (index_asset, signature_asset) {
            (None, None) => None,
            (Some(index_asset), Some(signature_asset)) => {
                if index_asset.size == 0 || index_asset.size > MAX_MANIFEST_SIZE as u64 {
                    return Err(msg("GitHub delta index asset has an invalid size"));
                }
                if signature_asset.size == 0 || signature_asset.size > MAX_SIGNATURE_SIZE as u64 {
                    return Err(msg("GitHub delta signature asset has an invalid size"));
                }
                let agent = http_agent();
                Some((
                    fetch_small_with_accept(
                        &agent,
                        &index_asset.url,
                        MAX_MANIFEST_SIZE,
                        "delta index",
                        "application/octet-stream",
                    )?,
                    fetch_small_with_accept(
                        &agent,
                        &signature_asset.url,
                        MAX_SIGNATURE_SIZE,
                        "delta index signature",
                        "application/octet-stream",
                    )?,
                ))
            }
            _ => {
                return Err(msg(
                    "GitHub release contains only one delta index/signature sidecar",
                ));
            }
        }
    } else {
        None
    };
    let Some((raw, signature)) = pair else {
        return Ok(None);
    };
    catalog::verify_catalog_signature(&raw, &signature)?;
    let index: DeltaIndex = serde_json::from_slice(&raw)?;
    validate_delta_index(&index, &verified.manifest)?;
    atomic_write(&workspace.join(DELTA_INDEX_FILENAME), &raw, 0o600)?;
    atomic_write(&workspace.join(DELTA_SIGNATURE_FILENAME), &signature, 0o600)?;
    Ok(Some(index))
}

fn validate_delta_index(index: &DeltaIndex, manifest: &UpdateManifest) -> Result<()> {
    if index.schema != DELTA_SCHEMA
        || index.kind != DELTA_KIND
        || index.repository != UPDATE_REPOSITORY
        || index.target_version != manifest.version
        || index.target_binary != manifest.binary
    {
        return Err(msg(
            "signed delta index does not match the target update manifest",
        ));
    }
    if index.deltas.is_empty() || index.deltas.len() > 16 {
        return Err(msg("signed delta index has an invalid entry count"));
    }
    let target = parse_canonical_version(&manifest.version)?;
    let mut versions = BTreeSet::new();
    for entry in &index.deltas {
        let from = parse_canonical_version(&entry.from_version)?;
        if !from.pre.is_empty()
            || !from.build.is_empty()
            || from >= target
            || !versions.insert(entry.from_version.as_str())
        {
            return Err(msg(format!(
                "invalid or duplicate delta base version: {}",
                entry.from_version
            )));
        }
        if entry.from_size == 0 || entry.from_size > MAX_BINARY_SIZE {
            return Err(msg(format!(
                "delta base size is outside the safe range: {}",
                entry.from_version
            )));
        }
        validate_sha256(&entry.from_sha256, "delta base SHA-256")?;
        validate_asset(&entry.patch, MAX_DELTA_SIZE, "delta patch")?;
        let expected_filename = format!(
            "xpad2-delta-v{}-to-v{}-android-arm64.zst",
            entry.from_version, manifest.version
        );
        let expected_url = format!(
            "{UPDATE_REPOSITORY}/releases/download/v{}/{}",
            manifest.version, expected_filename
        );
        if entry.patch.filename != expected_filename
            || entry.patch.url != expected_url
            || entry.patch.size >= manifest.binary.size
        {
            return Err(msg(format!(
                "delta patch identity is invalid for base {}",
                entry.from_version
            )));
        }
    }
    Ok(())
}

fn acquire_candidate_binary(
    verified: &VerifiedManifest,
    current: &Version,
    workspace: &Path,
    log: &mut TransactionLog,
) -> Result<CandidateAcquisition> {
    let current_version = current.to_string();
    if let Some(index) = acquire_delta_index(verified, workspace)?
        && let Some(entry) = index
            .deltas
            .iter()
            .find(|entry| entry.from_version == current_version)
    {
        let current_exe = std::env::current_exe()
            .map_err(|error| msg(format!("cannot resolve current executable: {error}")))?;
        verify_regular_file(&current_exe)?;
        let metadata = fs::metadata(&current_exe).at(&current_exe)?;
        let actual_sha = if metadata.len() == entry.from_size {
            Some(sha256_file(&current_exe)?)
        } else {
            None
        };
        if actual_sha.as_deref() == Some(entry.from_sha256.as_str()) {
            println!(
                "命中增量更新：{} -> {}，仅下载 {:.1} KiB…",
                entry.from_version,
                verified.manifest.version,
                entry.patch.size as f64 / 1024.0
            );
            let delta_result: Result<PathBuf> = (|| {
                let patch = acquire_asset(
                    &entry.patch,
                    verified.offline_root.as_deref(),
                    verified.github_release.as_ref(),
                    workspace,
                    0o600,
                    "xpad2 delta",
                )?;
                let candidate = workspace.join(&verified.manifest.binary.filename);
                reconstruct_candidate_from_delta(
                    &current_exe,
                    &patch,
                    &candidate,
                    &verified.manifest.binary,
                )?;
                validate_elf_arm64(&candidate)?;
                Ok(candidate)
            })();
            match delta_result {
                Ok(candidate) => {
                    log.event(
                        "self-update",
                        "delta-reconstructed",
                        json!({
                            "from_version": entry.from_version,
                            "from_sha256": entry.from_sha256,
                            "patch_filename": entry.patch.filename,
                            "patch_size": entry.patch.size,
                            "target_sha256": verified.manifest.binary.sha256,
                        }),
                    )?;
                    return Ok(CandidateAcquisition {
                        path: candidate,
                        mode: "delta",
                        transferred_bytes: entry.patch.size,
                    });
                }
                Err(error) => {
                    log.event(
                        "self-update",
                        "delta-fallback",
                        json!({
                            "from_version": entry.from_version,
                            "error": error.to_string(),
                        }),
                    )?;
                    eprintln!("提示：增量更新失败，安全回退完整 ELF：{error}");
                }
            }
        } else {
            log.event(
                "self-update",
                "delta-base-mismatch",
                json!({
                    "from_version": entry.from_version,
                    "expected_size": entry.from_size,
                    "actual_size": metadata.len(),
                    "expected_sha256": entry.from_sha256,
                    "actual_sha256": actual_sha,
                }),
            )?;
            eprintln!("提示：当前 ELF 不是发布版精确基线，跳过 delta 并下载完整 ELF。");
        }
    }

    let candidate = acquire_asset(
        &verified.manifest.binary,
        verified.offline_root.as_deref(),
        verified.github_release.as_ref(),
        workspace,
        0o700,
        "xpad2 ELF",
    )?;
    Ok(CandidateAcquisition {
        path: candidate,
        mode: "full",
        transferred_bytes: verified.manifest.binary.size,
    })
}

fn reconstruct_candidate_from_delta(
    base: &Path,
    patch: &Path,
    target: &Path,
    identity: &UpdateAsset,
) -> Result<()> {
    verify_regular_file(base)?;
    verify_regular_file(patch)?;
    if target.exists() {
        return Err(msg(format!(
            "delta reconstruction target already exists: {}",
            target.display()
        )));
    }
    let dictionary = read_limited(base, MAX_BINARY_SIZE as usize)?;
    let patch_file = BufReader::new(File::open(patch).at(patch)?);
    let mut decoder = zstd::stream::read::Decoder::with_dictionary(patch_file, &dictionary)
        .map_err(|error| msg(format!("cannot initialize zstd delta decoder: {error}")))?;
    let parent = target
        .parent()
        .ok_or_else(|| msg("delta reconstruction target has no parent"))?;
    fs::create_dir_all(parent).at(parent)?;
    let partial = parent.join(format!(".{}.delta.partial", identity.filename));
    if fs::symlink_metadata(&partial).is_ok() {
        fs::remove_file(&partial).at(&partial)?;
    }
    let result = (|| {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&partial)
            .at(&partial)?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 128 * 1024];
        loop {
            let count = decoder
                .read(&mut buffer)
                .map_err(|error| msg(format!("zstd delta decode failed: {error}")))?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| msg("delta output size overflow"))?;
            if total > identity.size {
                return Err(msg("delta output exceeds signed target size"));
            }
            output.write_all(&buffer[..count]).at(&partial)?;
            hasher.update(&buffer[..count]);
        }
        output.sync_all().at(&partial)?;
        let digest = format!("{:x}", hasher.finalize());
        if total != identity.size || digest != identity.sha256 {
            return Err(msg(format!(
                "delta output identity mismatch: size {total}/{} sha256 {digest}/{}",
                identity.size, identity.sha256
            )));
        }
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o700)).at(&partial)?;
        fs::rename(&partial, target).at(target)?;
        sync_parent(target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
        let _ = fs::remove_file(target);
    }
    result
}

fn acquire_asset(
    asset: &UpdateAsset,
    offline_root: Option<&Path>,
    github_release: Option<&GitHubRelease>,
    workspace: &Path,
    mode: u32,
    label: &str,
) -> Result<PathBuf> {
    let target = workspace.join(&asset.filename);
    let downloaded;
    if let Some(root) = offline_root {
        downloaded = false;
        let source = root.join(&asset.filename);
        verify_regular_file(&source)?;
        verify_file_identity(&source, asset, label)?;
        copy_atomic(&source, &target, mode)?;
    } else {
        downloaded = true;
        println!(
            "下载 {label}：{}（{:.1} MiB）…",
            asset.filename,
            asset.size as f64 / 1024.0 / 1024.0
        );
        let (url, accept) = if let Some(release) = github_release {
            let transport = github_asset(release, &asset.filename)?;
            if transport.size != asset.size
                || transport
                    .digest
                    .as_ref()
                    .is_some_and(|digest| digest != &format!("sha256:{}", asset.sha256))
            {
                return Err(msg(format!(
                    "GitHub asset identity does not match signed metadata: {}",
                    asset.filename
                )));
            }
            (transport.url.as_str(), Some("application/octet-stream"))
        } else {
            (asset.url.as_str(), None)
        };
        download_file(url, &target, asset, mode, label, accept)?;
    }
    if !downloaded {
        verify_file_identity(&target, asset, label)?;
    }
    Ok(target)
}

fn download_file(
    url: &str,
    target: &Path,
    asset: &UpdateAsset,
    mode: u32,
    label: &str,
    accept: Option<&str>,
) -> Result<()> {
    let agent = http_agent();
    let mut last_error = None::<String>;
    for attempt in 1..=DOWNLOAD_ATTEMPTS {
        match download_file_once(&agent, url, target, asset, mode, label, accept) {
            Ok(()) => return Ok(()),
            Err(failure) => {
                let message = failure.message().to_string();
                if attempt == DOWNLOAD_ATTEMPTS {
                    return Err(msg(message));
                }
                let delay = retry_delay(&failure, attempt)?;
                eprintln!(
                    "{label} 下载失败（{attempt}/{DOWNLOAD_ATTEMPTS}）：{message}；保留 partial，{} 秒后续传…",
                    delay.as_secs()
                );
                std::thread::sleep(delay);
                last_error = Some(message);
            }
        }
    }
    Err(msg(
        last_error.unwrap_or_else(|| format!("{label} download failed"))
    ))
}

fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let value = value.trim().strip_prefix("bytes ")?;
    let (range, total) = value.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    let total = total.parse::<u64>().ok()?;
    (start <= end && end < total).then_some((start, end, total))
}

fn hash_existing_partial(path: &Path) -> HttpResult<(Sha256, u64)> {
    let mut file = File::open(path).map_err(|error| {
        HttpFailure::Fatal(format!("cannot open partial {}: {error}", path.display()))
    })?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            HttpFailure::Fatal(format!("cannot read partial {}: {error}", path.display()))
        })?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        hasher.update(&buffer[..count]);
    }
    Ok((hasher, total))
}

fn download_file_once(
    agent: &ureq::Agent,
    url: &str,
    target: &Path,
    asset: &UpdateAsset,
    mode: u32,
    label: &str,
    accept: Option<&str>,
) -> HttpResult<()> {
    let parent = target
        .parent()
        .ok_or_else(|| HttpFailure::Fatal("download target has no parent directory".to_string()))?;
    fs::create_dir_all(parent).map_err(|error| {
        HttpFailure::Fatal(format!("cannot create download directory: {error}"))
    })?;
    let partial = parent.join(format!(".{}.partial", asset.filename));
    if partial.exists() {
        let metadata = fs::symlink_metadata(&partial).map_err(|error| {
            HttpFailure::Fatal(format!(
                "cannot inspect partial {}: {error}",
                partial.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HttpFailure::Fatal(format!(
                "download partial is not a regular file: {}",
                partial.display()
            )));
        }
        if metadata.len() > asset.size {
            fs::remove_file(&partial).map_err(|error| {
                HttpFailure::Fatal(format!("cannot remove oversized partial: {error}"))
            })?;
        } else if metadata.len() == asset.size {
            let actual =
                sha256_file(&partial).map_err(|error| HttpFailure::Fatal(error.to_string()))?;
            if actual == asset.sha256 {
                fs::set_permissions(&partial, fs::Permissions::from_mode(mode))
                    .map_err(|error| HttpFailure::Fatal(error.to_string()))?;
                fs::rename(&partial, target)
                    .map_err(|error| HttpFailure::Fatal(error.to_string()))?;
                return sync_parent(target).map_err(|error| HttpFailure::Fatal(error.to_string()));
            }
            fs::remove_file(&partial).map_err(|error| {
                HttpFailure::Fatal(format!("cannot remove corrupt partial: {error}"))
            })?;
        }
    }

    let mut offset = fs::metadata(&partial)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let mut download_request = request(agent, url, accept);
    if offset > 0 {
        download_request = download_request.set("Range", &format!("bytes={offset}-"));
    }
    let response = download_request
        .call()
        .map_err(|error| classify_ureq_error(error, label))?;
    let append = if offset > 0 && response.status() == 206 {
        let Some((start, _end, total)) = response
            .header("Content-Range")
            .and_then(parse_content_range)
        else {
            return Err(HttpFailure::Fatal(format!(
                "{label} resume response has no valid Content-Range"
            )));
        };
        if start != offset || total != asset.size {
            return Err(HttpFailure::Fatal(format!(
                "{label} resume Content-Range does not match signed size"
            )));
        }
        true
    } else if response.status() == 200 {
        offset = 0;
        false
    } else if offset == 0 && response.status() == 206 {
        let valid = response
            .header("Content-Range")
            .and_then(parse_content_range)
            .is_some_and(|(start, _, total)| start == 0 && total == asset.size);
        if !valid {
            return Err(HttpFailure::Fatal(format!(
                "{label} partial response does not match signed size"
            )));
        }
        false
    } else {
        return Err(HttpFailure::Fatal(format!(
            "{label} returned unexpected HTTP status {}",
            response.status()
        )));
    };
    if let Some(length) = response
        .header("Content-Length")
        .and_then(|length| length.parse::<u64>().ok())
    {
        let expected = asset.size.saturating_sub(offset);
        if length != expected {
            return Err(HttpFailure::Fatal(format!(
                "{label} HTTP Content-Length does not match signed remaining size"
            )));
        }
    }

    let (mut hasher, existing) = if append {
        hash_existing_partial(&partial)?
    } else {
        (Sha256::new(), 0)
    };
    if existing != offset {
        return Err(HttpFailure::Fatal(format!(
            "{label} partial changed while preparing resume"
        )));
    }
    let mut options = OpenOptions::new();
    options.create(true).write(true).mode(0o600);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    let mut output = options
        .open(&partial)
        .map_err(|error| HttpFailure::Fatal(format!("cannot open download partial: {error}")))?;
    let mut reader = response.into_reader();
    let mut total = offset;
    let mut last_progress = Instant::now();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| HttpFailure::Retryable {
                message: format!("HTTPS {label} read failed after {total} bytes: {error}"),
                retry_after: None,
            })?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| HttpFailure::Fatal(format!("{label} size overflow")))?;
        if total > asset.size {
            return Err(HttpFailure::Fatal(format!("{label} exceeds signed size")));
        }
        output.write_all(&buffer[..count]).map_err(|error| {
            HttpFailure::Fatal(format!("cannot write download partial: {error}"))
        })?;
        hasher.update(&buffer[..count]);
        if last_progress.elapsed() >= Duration::from_secs(15) {
            eprintln!(
                "{label} 下载进度：{:.1}/{:.1} MiB（{:.0}%）",
                total as f64 / 1024.0 / 1024.0,
                asset.size as f64 / 1024.0 / 1024.0,
                total as f64 * 100.0 / asset.size as f64
            );
            last_progress = Instant::now();
        }
    }
    if total != asset.size {
        return Err(HttpFailure::Retryable {
            message: format!("HTTPS {label} ended early at {total}/{} bytes", asset.size),
            retry_after: None,
        });
    }
    output
        .sync_all()
        .map_err(|error| HttpFailure::Fatal(format!("cannot sync download partial: {error}")))?;
    let digest = format!("{:x}", hasher.finalize());
    if digest != asset.sha256 {
        let _ = fs::remove_file(&partial);
        return Err(HttpFailure::Retryable {
            message: format!(
                "{label} SHA-256 mismatch: expected {}, got {digest}",
                asset.sha256
            ),
            retry_after: None,
        });
    }
    fs::set_permissions(&partial, fs::Permissions::from_mode(mode))
        .map_err(|error| HttpFailure::Fatal(error.to_string()))?;
    fs::rename(&partial, target).map_err(|error| HttpFailure::Fatal(error.to_string()))?;
    println!(
        "{label} 下载完成：{:.1} MiB",
        total as f64 / 1024.0 / 1024.0
    );
    sync_parent(target).map_err(|error| HttpFailure::Fatal(error.to_string()))
}

fn verify_file_identity(path: &Path, asset: &UpdateAsset, label: &str) -> Result<()> {
    let metadata = fs::metadata(path).at(path)?;
    if !metadata.is_file() || metadata.len() != asset.size {
        return Err(msg(format!(
            "{label} size mismatch: expected {}, got {}",
            asset.size,
            metadata.len()
        )));
    }
    let actual = sha256_file(path)?;
    if actual != asset.sha256 {
        return Err(msg(format!(
            "{label} SHA-256 mismatch: expected {}, got {actual}",
            asset.sha256
        )));
    }
    Ok(())
}

fn verify_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).at(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(msg(format!("not a regular file: {}", path.display())));
    }
    Ok(())
}

fn load_cache_catalog_against_manifest(
    cache: &Path,
    manifest: &UpdateManifest,
) -> Result<AssetsLock> {
    let catalog_path = cache.join("catalog.json");
    verify_regular_file(&catalog_path)?;
    let raw = read_limited(&catalog_path, MAX_MANIFEST_SIZE)?;
    if raw.len() as u64 != manifest.catalog.size || sha256_bytes(&raw) != manifest.catalog.sha256 {
        return Err(msg("cache catalog identity does not match update manifest"));
    }
    let lock = catalog::load_signed_external_catalog(cache)?;
    lock.profile.fingerprint_policy().validate()?;
    if lock.schema != 1
        || lock.product_version != manifest.version
        || lock.catalog_version != manifest.catalog_version
        || lock.profile.build_fingerprint != manifest.profile.build_fingerprint
        || lock.profile.kernel_release_prefix != manifest.profile.kernel_release_prefix
        || lock.profile.abi != manifest.profile.abi
    {
        return Err(msg(
            "signed cache catalog does not match update release identity",
        ));
    }
    let mut ids = BTreeSet::new();
    for artifact in &lock.artifacts {
        if !ids.insert(artifact.id.as_str()) {
            return Err(msg(format!(
                "duplicate artifact in update catalog: {}",
                artifact.id
            )));
        }
    }
    if ids.is_empty() {
        return Err(msg("update catalog contains no artifacts"));
    }
    Ok(lock)
}

fn verify_cache_against_manifest(
    cache: &Path,
    manifest: &UpdateManifest,
    managed_paths: Option<&Paths>,
) -> Result<AssetsLock> {
    let lock = load_cache_catalog_against_manifest(cache, manifest)?;
    for artifact in lock.artifacts.iter().filter(|artifact| artifact.embedded) {
        let blob = cache.join("blobs").join(&artifact.sha256);
        if let Some(paths) = managed_paths {
            catalog::verify_cache_blob_reference(&blob, artifact, paths)?;
        } else {
            verify_regular_file(&blob)?;
            catalog::verify_blob(&blob, artifact)?;
        }
    }
    Ok(lock)
}

fn verify_candidate(
    binary: &Path,
    manifest: &Path,
    signature: &Path,
    cache: &Path,
    log: &mut TransactionLog,
) -> Result<()> {
    let output = Command::new(binary)
        .arg("_update-verify-candidate")
        .arg(manifest)
        .arg(signature)
        .arg(cache)
        .env_remove("XPAD2_CACHE_DIR")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| msg(format!("failed to execute candidate self-check: {error}")))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(stderr.trim());
    }
    log.command_result("candidate-self-check", output.status.success(), &text)?;
    if !output.status.success() || !text.contains("XPAD2_UPDATE_CANDIDATE_OK") {
        return Err(msg(format!("candidate self-check failed: {text}")));
    }
    Ok(())
}

fn export_candidate_cache(
    binary: &Path,
    manifest: &Path,
    signature: &Path,
    catalog_signature: &Path,
    destination: &Path,
    log: &mut TransactionLog,
) -> Result<()> {
    let output = Command::new(binary)
        .arg("_update-export-cache")
        .arg(manifest)
        .arg(signature)
        .arg(catalog_signature)
        .arg(destination)
        .env_remove("XPAD2_CACHE_DIR")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| msg(format!("failed to execute candidate cache export: {error}")))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(stderr.trim());
    }
    log.command_result("candidate-cache-export", output.status.success(), &text)?;
    if !output.status.success() || !text.contains("XPAD2_UPDATE_CACHE_EXPORT_OK") {
        return Err(msg(format!("candidate cache export failed: {text}")));
    }
    Ok(())
}

fn install_version_cache(
    source: &Path,
    lock: &AssetsLock,
    target: &Path,
    paths: &Paths,
) -> Result<CacheSwap> {
    let parent = target
        .parent()
        .ok_or_else(|| msg("managed cache target has no parent"))?;
    fs::create_dir_all(parent).at(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).at(parent)?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| msg("managed cache target has an invalid name"))?;
    let staging = parent.join(format!(".{name}.{}.partial", unique_id()));
    let previous = parent.join(format!(".{name}.{}.previous", unique_id()));
    fs::create_dir(&staging).at(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).at(&staging)?;
    fs::create_dir(staging.join("blobs")).at(staging.join("blobs"))?;
    fs::set_permissions(staging.join("blobs"), fs::Permissions::from_mode(0o700))
        .at(staging.join("blobs"))?;
    let result = (|| {
        copy_atomic(
            &source.join("catalog.json"),
            &staging.join("catalog.json"),
            0o600,
        )?;
        copy_atomic(
            &source.join("catalog.sig"),
            &staging.join("catalog.sig"),
            0o600,
        )?;
        catalog::populate_deduplicated_blobs(source, &staging, paths, lock)?;
        if target.exists() {
            fs::rename(target, &previous).at(target)?;
        }
        if let Err(error) = fs::rename(&staging, target).at(target) {
            if previous.exists() {
                let _ = fs::rename(&previous, target);
            }
            return Err(error);
        }
        sync_parent(target)?;
        Ok(CacheSwap {
            target: target.to_path_buf(),
            previous: previous.exists().then_some(previous.clone()),
        })
    })();
    if result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn install_candidate_binary(
    candidate: &Path,
    current: &Version,
    paths: &Paths,
) -> Result<BinarySwap> {
    let target = std::env::current_exe()
        .map_err(|error| msg(format!("cannot resolve current xpad2 executable: {error}")))?;
    verify_regular_file(&target)?;
    let current_sha = sha256_file(&target)?;
    let backup_dir = paths.state.join("update-backups");
    fs::create_dir_all(&backup_dir).at(&backup_dir)?;
    fs::set_permissions(&backup_dir, fs::Permissions::from_mode(0o700)).at(&backup_dir)?;
    let backup = backup_dir.join(format!("xpad2-v{}-{}", current, &current_sha[..12]));
    if !backup.exists() {
        copy_atomic(&target, &backup, 0o700)?;
    }
    if sha256_file(&backup)? != current_sha {
        return Err(msg("self-update rollback backup identity mismatch"));
    }
    let target_parent = target
        .parent()
        .ok_or_else(|| msg("current xpad2 executable has no parent directory"))?;
    let target_name = target
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("xpad2");
    let rollback_staged = target_parent.join(format!(".{target_name}.{}.rollback", unique_id()));
    copy_atomic(&backup, &rollback_staged, 0o700)?;
    let swap = BinarySwap {
        target: target.clone(),
        backup,
        rollback_staged,
        expected_sha256: current_sha,
    };
    if let Err(error) = copy_atomic(candidate, &target, 0o700) {
        let rollback = swap.rollback();
        return Err(match rollback {
            Ok(()) => error,
            Err(rollback_error) => msg(format!(
                "candidate installation failed ({error}); rollback also failed: {rollback_error}"
            )),
        });
    }
    let installed_identity =
        (|| -> Result<bool> { Ok(sha256_file(&target)? == sha256_file(candidate)?) })();
    if !matches!(installed_identity, Ok(true)) {
        let identity_error = match installed_identity {
            Ok(false) => "post-write SHA-256 mismatch".to_string(),
            Ok(true) => unreachable!(),
            Err(error) => format!("post-write identity check failed: {error}"),
        };
        let rollback = swap.rollback();
        return Err(match rollback {
            Ok(()) => msg(format!("installed xpad2 ELF {identity_error}")),
            Err(rollback_error) => msg(format!(
                "installed xpad2 ELF {identity_error}; rollback also failed: {rollback_error}"
            )),
        });
    }
    Ok(swap)
}

fn prune_binary_backups(paths: &Paths, keep: usize, protected: &Path) -> Result<usize> {
    let dir = paths.state.join("update-backups");
    if !dir.exists() {
        return Ok(0);
    }
    let mut entries = fs::read_dir(&dir)
        .at(&dir)?
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
                && entry.file_name().to_string_lossy().starts_with("xpad2-v")
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    let remove_count = entries.len().saturating_sub(keep.max(2));
    let mut removed = 0usize;
    for entry in entries {
        if removed >= remove_count {
            break;
        }
        if entry.path() == protected {
            continue;
        }
        fs::remove_file(entry.path()).at(entry.path())?;
        removed += 1;
    }
    Ok(removed)
}

fn extract_zip_safely(source: &Path, destination: &Path, max_total: u64) -> Result<()> {
    verify_regular_file(source)?;
    if destination.exists() {
        fs::remove_dir_all(destination).at(destination)?;
    }
    fs::create_dir_all(destination).at(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).at(destination)?;
    let file = File::open(source).at(source)?;
    let mut archive = ZipArchive::new(file)?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(msg("update ZIP contains too many entries"));
    }
    let mut total = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let relative = entry
            .enclosed_name()
            .ok_or_else(|| msg("update ZIP contains an unsafe path"))?
            .to_path_buf();
        if relative.as_os_str().is_empty() {
            continue;
        }
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170000;
            if kind != 0 && kind != 0o040000 && kind != 0o100000 {
                return Err(msg("update ZIP contains a non-regular filesystem entry"));
            }
        }
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| msg("update ZIP expanded size overflow"))?;
        if total > max_total {
            return Err(msg("update ZIP exceeds the safe expanded size limit"));
        }
        let output = destination.join(relative);
        if entry.is_dir() {
            fs::create_dir_all(&output).at(&output)?;
            fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).at(&output)?;
            continue;
        }
        let parent = output
            .parent()
            .ok_or_else(|| msg("update ZIP entry has no parent"))?;
        fs::create_dir_all(parent).at(parent)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&output)
            .at(&output)?;
        let copied = std::io::copy(&mut entry, &mut file).at(&output)?;
        if copied != entry.size() {
            return Err(msg("update ZIP entry size changed during extraction"));
        }
        file.sync_all().at(&output)?;
    }
    Ok(())
}

fn locate_named_root(parent: &Path, expected: &str) -> Result<PathBuf> {
    if parent.file_name().is_some_and(|name| name == expected) {
        return Ok(parent.to_path_buf());
    }
    let direct = parent.join(expected);
    if direct.is_dir() {
        return Ok(direct);
    }
    Err(msg(format!(
        "archive does not contain the expected {expected}/ root"
    )))
}

fn read_regular_limited(path: &Path, max: usize) -> Result<Vec<u8>> {
    verify_regular_file(path)?;
    read_limited(path, max)
}

fn read_limited(path: &Path, max: usize) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path).at(path)?;
    if metadata.len() > max as u64 {
        return Err(msg(format!(
            "{} exceeds the safe size limit",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .at(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .at(path)?;
    if bytes.len() > max {
        return Err(msg(format!(
            "{} exceeds the safe size limit",
            path.display()
        )));
    }
    Ok(bytes)
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent).at(parent)?.sync_all().at(parent)?;
    }
    Ok(())
}

#[cfg(test)]
fn profile_from_catalog(profile: &DeviceProfile) -> UpdateProfile {
    UpdateProfile {
        build_fingerprint: profile.build_fingerprint.clone(),
        kernel_release_prefix: profile.kernel_release_prefix.clone(),
        abi: profile.abi.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("xpad2-update-{label}-{}", unique_id()))
    }

    fn manifest() -> UpdateManifest {
        UpdateManifest {
            schema: 1,
            kind: UPDATE_KIND.to_string(),
            channel: UPDATE_CHANNEL.to_string(),
            repository: UPDATE_REPOSITORY.to_string(),
            version: "0.2.0".to_string(),
            catalog_version: "2026-07-15.9".to_string(),
            profile: UpdateProfile {
                build_fingerprint: "vendor/device:13/build/260:user/release-keys".to_string(),
                kernel_release_prefix: "4.19.191".to_string(),
                abi: "arm64-v8a".to_string(),
            },
            binary: UpdateAsset {
                filename: "xpad2-v0.2.0-android-arm64".to_string(),
                url: "https://github.com/yoyicue/xpad2-cli/releases/download/v0.2.0/xpad2-v0.2.0-android-arm64".to_string(),
                size: 1,
                sha256: "a".repeat(64),
            },
            cache: UpdateAsset {
                filename: "xpad2-cache-v0.2.0.zip".to_string(),
                url: "https://github.com/yoyicue/xpad2-cli/releases/download/v0.2.0/xpad2-cache-v0.2.0.zip".to_string(),
                size: 1,
                sha256: "b".repeat(64),
            },
            catalog: CatalogIdentity {
                filename: "catalog.json".to_string(),
                size: 1,
                sha256: "c".repeat(64),
            },
            release_url: "https://github.com/yoyicue/xpad2-cli/releases/tag/v0.2.0".to_string(),
        }
    }

    fn read_http_headers(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut one = [0u8; 1];
        while bytes.len() < 32 * 1024 {
            let count = stream.read(&mut one).unwrap();
            if count == 0 {
                break;
            }
            bytes.push(one[0]);
            if bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    }

    fn github_release() -> GitHubRelease {
        let asset = |name: &str, size: u64, digest: Option<String>, id: u64| GitHubAsset {
            name: name.to_string(),
            url: format!("https://api.github.com/repos/yoyicue/xpad2-cli/releases/assets/{id}"),
            size,
            state: "uploaded".to_string(),
            digest,
        };
        GitHubRelease {
            tag_name: "v0.2.0".to_string(),
            html_url: "https://github.com/yoyicue/xpad2-cli/releases/tag/v0.2.0".to_string(),
            draft: false,
            prerelease: false,
            assets: vec![
                asset(MANIFEST_FILENAME, 1024, None, 1),
                asset(SIGNATURE_FILENAME, 512, None, 2),
                asset(
                    "xpad2-v0.2.0-android-arm64",
                    1,
                    Some(format!("sha256:{}", "a".repeat(64))),
                    3,
                ),
                asset(
                    "xpad2-cache-v0.2.0.zip",
                    1,
                    Some(format!("sha256:{}", "b".repeat(64))),
                    4,
                ),
            ],
        }
    }

    #[test]
    fn strict_manifest_accepts_the_release_shape() {
        validate_manifest(&manifest()).unwrap();
    }

    fn delta_index_for(manifest: &UpdateManifest) -> DeltaIndex {
        let from_version = "0.1.9";
        let filename = format!(
            "xpad2-delta-v{from_version}-to-v{}-android-arm64.zst",
            manifest.version
        );
        DeltaIndex {
            schema: DELTA_SCHEMA,
            kind: DELTA_KIND.to_string(),
            repository: UPDATE_REPOSITORY.to_string(),
            target_version: manifest.version.clone(),
            target_binary: manifest.binary.clone(),
            deltas: vec![DeltaEntry {
                from_version: from_version.to_string(),
                from_size: 900,
                from_sha256: "d".repeat(64),
                patch: UpdateAsset {
                    filename: filename.clone(),
                    url: format!(
                        "{UPDATE_REPOSITORY}/releases/download/v{}/{filename}",
                        manifest.version
                    ),
                    size: 100,
                    sha256: "e".repeat(64),
                },
            }],
        }
    }

    #[test]
    fn signed_delta_index_is_strictly_bound_to_target_and_base() {
        let mut manifest = manifest();
        manifest.binary.size = 1024;
        let index = delta_index_for(&manifest);
        validate_delta_index(&index, &manifest).unwrap();

        let mut wrong_target = delta_index_for(&manifest);
        wrong_target.target_binary.sha256 = "f".repeat(64);
        assert!(validate_delta_index(&wrong_target, &manifest).is_err());

        let mut duplicate = delta_index_for(&manifest);
        duplicate.deltas.push(DeltaEntry {
            from_version: duplicate.deltas[0].from_version.clone(),
            from_size: duplicate.deltas[0].from_size,
            from_sha256: duplicate.deltas[0].from_sha256.clone(),
            patch: duplicate.deltas[0].patch.clone(),
        });
        assert!(validate_delta_index(&duplicate, &manifest).is_err());

        let mut wrong_transport = delta_index_for(&manifest);
        wrong_transport.deltas[0].patch.url = "https://example.invalid/delta.zst".to_string();
        assert!(validate_delta_index(&wrong_transport, &manifest).is_err());
    }

    #[test]
    fn zstd_delta_reconstruction_is_bounded_and_exact() {
        let root = test_dir("delta-reconstruct");
        fs::create_dir_all(&root).unwrap();
        let base = (0..512 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut target_bytes = base.clone();
        target_bytes[1000..2000].fill(0x5a);
        target_bytes.extend_from_slice(b"new signed tail");
        let mut encoder = zstd::stream::Encoder::with_dictionary(Vec::new(), 3, &base).unwrap();
        encoder.write_all(&target_bytes).unwrap();
        let patch_bytes = encoder.finish().unwrap();
        let base_path = root.join("base");
        let patch_path = root.join("patch.zst");
        fs::write(&base_path, &base).unwrap();
        fs::write(&patch_path, patch_bytes).unwrap();
        let identity = UpdateAsset {
            filename: "candidate".to_string(),
            url: "https://example.invalid/candidate".to_string(),
            size: target_bytes.len() as u64,
            sha256: sha256_bytes(&target_bytes),
        };
        let target = root.join("candidate");
        reconstruct_candidate_from_delta(&base_path, &patch_path, &target, &identity).unwrap();
        assert_eq!(fs::read(&target).unwrap(), target_bytes);

        fs::remove_file(&target).unwrap();
        let mut undersized = identity;
        undersized.size -= 1;
        assert!(
            reconstruct_candidate_from_delta(&base_path, &patch_path, &target, &undersized)
                .is_err()
        );
        assert!(!target.exists());
        assert!(!root.join(".candidate.delta.partial").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn content_range_parser_is_strict() {
        assert_eq!(parse_content_range("bytes 10-19/20"), Some((10, 19, 20)));
        for invalid in ["10-19/20", "bytes 20-19/20", "bytes 0-20/20", "bytes */20"] {
            assert_eq!(parse_content_range(invalid), None);
        }
    }

    #[test]
    fn long_server_retry_delay_is_not_spun_on() {
        let failure = HttpFailure::Retryable {
            message: "rate limited".to_string(),
            retry_after: Some(Duration::from_secs(600)),
        };
        assert!(retry_delay(&failure, 1).is_err());
    }

    #[test]
    fn interrupted_download_resumes_with_http_range() {
        let body = (0..256 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let split = body.len() / 2;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_body = body.clone();
        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let first_headers = read_http_headers(&mut first);
            assert!(!first_headers.to_ascii_lowercase().contains("\r\nrange:"));
            write!(
                first,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                server_body.len()
            )
            .unwrap();
            first.write_all(&server_body[..split]).unwrap();
            drop(first);

            let (mut second, _) = listener.accept().unwrap();
            let second_headers = read_http_headers(&mut second);
            assert!(
                second_headers
                    .to_ascii_lowercase()
                    .contains(&format!("\r\nrange: bytes={split}-"))
            );
            write!(
                second,
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                server_body.len() - split,
                split,
                server_body.len() - 1,
                server_body.len()
            )
            .unwrap();
            second.write_all(&server_body[split..]).unwrap();
        });

        let root = test_dir("range-resume");
        fs::create_dir_all(&root).unwrap();
        let target = root.join("asset.bin");
        let asset = UpdateAsset {
            filename: "asset.bin".to_string(),
            url: format!("http://{address}/asset.bin"),
            size: body.len() as u64,
            sha256: sha256_bytes(&body),
        };
        download_file(&asset.url, &target, &asset, 0o600, "range-test", None).unwrap();
        server.join().unwrap();
        assert_eq!(fs::read(&target).unwrap(), body);
        assert!(!root.join(".asset.bin.partial").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_unsafe_or_mismatched_assets() {
        let mut value = manifest();
        value.binary.filename = "../xpad2".to_string();
        assert!(validate_manifest(&value).is_err());
        let mut value = manifest();
        value.cache.url = "http://example.invalid/cache.zip".to_string();
        assert!(validate_manifest(&value).is_err());
        let mut value = manifest();
        value.binary.sha256 = "A".repeat(64);
        assert!(validate_manifest(&value).is_err());
    }

    #[test]
    fn version_policy_distinguishes_update_current_and_downgrade() {
        let current = Version::parse("0.2.0").unwrap();
        assert_eq!(
            version_state(&current, &Version::parse("0.2.1").unwrap()),
            VersionState::Available
        );
        assert_eq!(version_state(&current, &current), VersionState::Current);
        assert_eq!(
            version_state(&current, &Version::parse("0.1.9").unwrap()),
            VersionState::Ahead
        );
    }

    #[test]
    fn update_arguments_require_explicit_downgrade_authority() {
        let args = vec!["--allow-downgrade".to_string()];
        assert!(parse_args(&args).is_err());
        let args = vec![
            "--version".to_string(),
            "0.1.9".to_string(),
            "--allow-downgrade".to_string(),
        ];
        assert!(parse_args(&args).is_ok());
    }

    #[test]
    fn github_api_transport_is_bound_to_the_signed_release() {
        let release = github_release();
        validate_github_release(&release, Some("0.2.0")).unwrap();
        validate_github_release_manifest(&release, &manifest()).unwrap();

        let mut wrong_host = github_release();
        wrong_host.assets[0].url =
            "https://example.invalid/repos/yoyicue/xpad2-cli/releases/assets/1".to_string();
        assert!(github_asset(&wrong_host, MANIFEST_FILENAME).is_err());

        let mut wrong_digest = github_release();
        wrong_digest.assets[2].digest = Some(format!("sha256:{}", "f".repeat(64)));
        assert!(validate_github_release_manifest(&wrong_digest, &manifest()).is_err());
    }

    #[test]
    fn catalog_profile_projection_stays_legacy_updater_compatible() {
        let source = DeviceProfile {
            build_fingerprint: "prefix/260:suffix".to_string(),
            build_fingerprint_prefix: "prefix/".to_string(),
            build_fingerprint_suffix: ":suffix".to_string(),
            fingerprint_incremental_min: 19,
            fingerprint_incremental_max: 260,
            kernel_release_prefix: "4.19".to_string(),
            kernel_version: "exact kernel build".to_string(),
            abi: "arm64-v8a".to_string(),
        };
        let converted = profile_from_catalog(&source);
        assert_eq!(converted.build_fingerprint, source.build_fingerprint);
        assert_eq!(
            converted.kernel_release_prefix,
            source.kernel_release_prefix
        );
        assert_eq!(converted.abi, source.abi);
        assert_eq!(
            serde_json::to_value(&converted)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["abi", "build_fingerprint", "kernel_release_prefix"])
        );
    }

    #[test]
    fn rollback_primitives_restore_the_previous_binary_and_cache() {
        let root = test_dir("rollback");
        fs::create_dir_all(&root).unwrap();
        let binary = root.join("xpad2");
        let backup = root.join("xpad2.backup");
        let rollback_staged = root.join(".xpad2.rollback");
        atomic_write(&binary, b"new", 0o700).unwrap();
        atomic_write(&backup, b"old", 0o700).unwrap();
        atomic_write(&rollback_staged, b"old", 0o700).unwrap();
        BinarySwap {
            target: binary.clone(),
            backup,
            rollback_staged: rollback_staged.clone(),
            expected_sha256: sha256_bytes(b"old"),
        }
        .rollback()
        .unwrap();
        assert_eq!(fs::read(&binary).unwrap(), b"old");
        assert!(!rollback_staged.exists());

        let cache = root.join("cache");
        let previous = root.join("cache.previous");
        fs::create_dir(&cache).unwrap();
        fs::create_dir(&previous).unwrap();
        fs::write(cache.join("marker"), b"new").unwrap();
        fs::write(previous.join("marker"), b"old").unwrap();
        CacheSwap {
            target: cache.clone(),
            previous: Some(previous),
        }
        .rollback()
        .unwrap();
        assert_eq!(fs::read(cache.join("marker")).unwrap(), b"old");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn binary_backup_pruning_keeps_two_and_never_removes_the_recorded_target() {
        let root = test_dir("backup-prune");
        let paths = Paths {
            cache: root.join("cache/releases/current"),
            cache_is_explicit: false,
            managed_blob_root: root.join("cache/blobs"),
            managed_cache_root: root.join("cache/releases"),
            work: root.join("work"),
            state: root.join("state"),
            logs: root.join("logs"),
            lock: root.join("operation.lock"),
            root: root.clone(),
        };
        paths.ensure().unwrap();
        let backup_dir = paths.state.join("update-backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let protected = backup_dir.join("xpad2-v0.4.1-protected");
        for name in [
            "xpad2-v0.4.1-protected",
            "xpad2-v0.4.2-old",
            "xpad2-v0.4.3-old",
            "xpad2-v0.4.4-new",
        ] {
            fs::write(backup_dir.join(name), name.as_bytes()).unwrap();
        }
        assert_eq!(prune_binary_backups(&paths, 2, &protected).unwrap(), 2);
        assert!(protected.exists());
        assert_eq!(fs::read_dir(&backup_dir).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn zip_extraction_rejects_parent_traversal() {
        let root = test_dir("zip-slip");
        fs::create_dir_all(&root).unwrap();
        let archive_path = root.join("malicious.zip");
        let file = File::create(&archive_path).unwrap();
        let mut archive = ZipWriter::new(file);
        archive
            .start_file("../escaped", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"bad").unwrap();
        archive.finish().unwrap();
        let output = root.join("output");
        assert!(extract_zip_safely(&archive_path, &output, 1024).is_err());
        assert!(!root.join("escaped").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
