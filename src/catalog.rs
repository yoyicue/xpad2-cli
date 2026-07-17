use crate::embedded;
use crate::error::{Error, IoContext, Result, msg};
use crate::model::{Artifact, AssetsLock};
use crate::util::{Paths, atomic_write, copy_atomic, sha256_file};
use base64::Engine;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const LOCK_JSON: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets.lock.json"));
const PUBLIC_KEY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/keys/catalog-release-public.pem"
));
static STALE_MANAGED_CACHE_WARNED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct Catalog {
    pub lock: AssetsLock,
}

pub enum ResolvedSource {
    Cache(PathBuf),
    Embedded(&'static [u8]),
}

pub struct ResolvedArtifact<'a> {
    pub artifact: &'a Artifact,
    pub source: ResolvedSource,
}

impl ResolvedArtifact<'_> {
    pub fn load(&self) -> Result<Vec<u8>> {
        match &self.source {
            ResolvedSource::Cache(path) => fs::read(path).at(path),
            ResolvedSource::Embedded(bytes) => Ok(bytes.to_vec()),
        }
    }

    pub fn source_description(&self) -> String {
        match &self.source {
            ResolvedSource::Cache(path) => format!("cache:{}", path.display()),
            ResolvedSource::Embedded(_) => "embedded".to_string(),
        }
    }
}

impl Catalog {
    pub fn load() -> Result<Self> {
        let lock: AssetsLock = serde_json::from_str(LOCK_JSON)?;
        if lock.product_version != env!("CARGO_PKG_VERSION") {
            return Err(msg(format!(
                "assets.lock product version {} != binary version {}",
                lock.product_version,
                env!("CARGO_PKG_VERSION")
            )));
        }
        let mut seen = BTreeSet::new();
        for artifact in lock.artifacts.iter().filter(|a| a.embedded) {
            if !seen.insert(artifact.id.as_str()) {
                return Err(msg(format!(
                    "duplicate embedded artifact identity: {}",
                    artifact.id
                )));
            }
            let embedded = embedded::get(&artifact.id)
                .ok_or_else(|| msg(format!("embedded artifact missing: {}", artifact.id)))?;
            if embedded.filename != artifact.filename
                || embedded.bytes.len() as u64 != artifact.size
            {
                return Err(msg(format!(
                    "embedded artifact identity mismatch: {}",
                    artifact.id
                )));
            }
        }
        Ok(Self { lock })
    }

    pub fn artifact(&self, id: &str) -> Result<&Artifact> {
        self.lock
            .artifacts
            .iter()
            .find(|a| a.id == id)
            .ok_or_else(|| msg(format!("unknown component/artifact: {id}")))
    }

    pub fn resolve<'a>(&'a self, id: &str, paths: &Paths) -> Result<ResolvedArtifact<'a>> {
        let artifact = self.artifact(id)?;
        let catalog_path = paths.cache.join("catalog.json");
        let sig_path = paths.cache.join("catalog.sig");
        if catalog_path.exists() || sig_path.exists() {
            let cached = (|| -> Result<Option<PathBuf>> {
                let external = verify_external_catalog(&paths.cache, self)?;
                if let Some(entry) = external.artifacts.iter().find(|a| a.id == id) {
                    let blob = paths.cache.join("blobs").join(&entry.sha256);
                    if fs::symlink_metadata(&blob).is_ok() {
                        verify_cache_blob_reference(&blob, entry, paths)?;
                        return Ok(Some(blob));
                    }
                }
                Ok(None)
            })();
            match cached {
                Ok(Some(blob)) => {
                    return Ok(ResolvedArtifact {
                        artifact,
                        source: ResolvedSource::Cache(blob),
                    });
                }
                Ok(None) => {}
                Err(error) if managed_cache_may_fall_back(paths.cache_is_explicit) => {
                    if !STALE_MANAGED_CACHE_WARNED.swap(true, Ordering::Relaxed) {
                        eprintln!(
                            "提示：默认托管缓存校验失败，已忽略并改用当前 ELF 的内嵌锁定制品：{error}；可执行 `xpad2 cache clear`。"
                        );
                    }
                }
                Err(error) => return Err(error),
            }
        }
        let bytes = verify_embedded_artifact(artifact)?;
        Ok(ResolvedArtifact {
            artifact,
            source: ResolvedSource::Embedded(bytes),
        })
    }
}

pub fn embedded_catalog_raw() -> &'static [u8] {
    LOCK_JSON.as_bytes()
}

pub fn verify_embedded_artifact(artifact: &Artifact) -> Result<&'static [u8]> {
    let embedded = embedded::get(&artifact.id)
        .ok_or_else(|| msg(format!("embedded artifact missing: {}", artifact.id)))?;
    if embedded.filename != artifact.filename || embedded.bytes.len() as u64 != artifact.size {
        return Err(msg(format!(
            "embedded artifact metadata mismatch: {}",
            artifact.id
        )));
    }
    let actual = crate::util::sha256_bytes(embedded.bytes);
    if actual != artifact.sha256 {
        return Err(msg(format!(
            "embedded artifact SHA-256 mismatch for {}: expected {}, got {actual}",
            artifact.id, artifact.sha256
        )));
    }
    Ok(embedded.bytes)
}

pub fn export_embedded_cache(
    catalog: &Catalog,
    catalog_signature: &[u8],
    destination: &Path,
) -> Result<usize> {
    if destination.exists() {
        return Err(msg(format!(
            "embedded cache export destination already exists: {}",
            destination.display()
        )));
    }
    verify_catalog_signature(embedded_catalog_raw(), catalog_signature)?;
    fs::create_dir_all(destination.join("blobs")).at(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).at(destination)?;
    fs::set_permissions(destination.join("blobs"), fs::Permissions::from_mode(0o700))
        .at(destination.join("blobs"))?;
    atomic_write(
        &destination.join("catalog.json"),
        embedded_catalog_raw(),
        0o600,
    )?;
    atomic_write(&destination.join("catalog.sig"), catalog_signature, 0o600)?;
    let mut exported = 0;
    for artifact in catalog.lock.artifacts.iter().filter(|a| a.embedded) {
        let bytes = verify_embedded_artifact(artifact)?;
        atomic_write(
            &destination.join("blobs").join(&artifact.sha256),
            bytes,
            0o600,
        )?;
        exported += 1;
    }
    Ok(exported)
}

fn managed_cache_may_fall_back(cache_is_explicit: bool) -> bool {
    !cache_is_explicit
}

fn signature_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.starts_with(b"-----") {
        return Err(msg(
            "catalog.sig must be a raw or base64 RSA signature, not PEM",
        ));
    }
    if raw.iter().all(|b| {
        b.is_ascii_whitespace()
            || b.is_ascii_alphanumeric()
            || *b == b'+'
            || *b == b'/'
            || *b == b'='
    }) {
        let compact: Vec<u8> = raw
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(compact)
            && !decoded.is_empty()
        {
            return Ok(decoded);
        }
    }
    Ok(raw.to_vec())
}

pub fn verify_catalog_signature(catalog: &[u8], signature: &[u8]) -> Result<()> {
    let key = catalog_public_key()?;
    let signature = signature_bytes(signature)?;
    let digest = Sha256::digest(catalog);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
        .map_err(|_| msg("catalog signature verification failed"))
}

fn catalog_public_key() -> Result<RsaPublicKey> {
    let body = PUBLIC_KEY
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| msg(format!("invalid embedded catalog public-key base64: {e}")))?;
    RsaPublicKey::from_public_key_der(&der)
        .map_err(|e| msg(format!("invalid embedded catalog public key: {e}")))
}

pub fn verify_external_catalog(cache: &Path, baseline: &Catalog) -> Result<AssetsLock> {
    let external = load_signed_external_catalog(cache)?;
    if external.schema != baseline.lock.schema
        || external.product_version != baseline.lock.product_version
        || external.catalog_version != baseline.lock.catalog_version
        || external.profile != baseline.lock.profile
    {
        return Err(Error::CatalogReleaseMismatch);
    }
    let expected: BTreeMap<_, _> = baseline
        .lock
        .artifacts
        .iter()
        .map(|a| (a.id.as_str(), a))
        .collect();
    if external.artifacts.len() != expected.len() {
        return Err(msg(format!(
            "external catalog artifact count mismatch: expected {}, got {}",
            expected.len(),
            external.artifacts.len()
        )));
    }
    let mut seen = BTreeSet::new();
    for entry in &external.artifacts {
        if !seen.insert(entry.id.as_str()) {
            return Err(msg(format!(
                "external catalog contains duplicate artifact {}",
                entry.id
            )));
        }
        let Some(locked) = expected.get(entry.id.as_str()) else {
            return Err(msg(format!(
                "external catalog contains unlocked artifact {}",
                entry.id
            )));
        };
        if entry != *locked {
            return Err(msg(format!(
                "external catalog changes locked identity for {}",
                entry.id
            )));
        }
    }
    Ok(external)
}

pub fn load_signed_external_catalog(cache: &Path) -> Result<AssetsLock> {
    let catalog_path = cache.join("catalog.json");
    let signature_path = cache.join("catalog.sig");
    let raw = fs::read(&catalog_path).at(&catalog_path)?;
    let sig = fs::read(&signature_path).at(&signature_path)?;
    verify_catalog_signature(&raw, &sig)?;
    Ok(serde_json::from_slice(&raw)?)
}

pub fn verify_blob(path: &Path, artifact: &Artifact) -> Result<()> {
    let size = path.metadata().at(path)?.len();
    if size != artifact.size {
        return Err(msg(format!(
            "cache blob size mismatch for {}: expected {}, got {}",
            artifact.id, artifact.size, size
        )));
    }
    let actual = sha256_file(path)?;
    if actual != artifact.sha256 {
        return Err(msg(format!(
            "cache blob SHA-256 mismatch for {}: expected {}, got {}",
            artifact.id, artifact.sha256, actual
        )));
    }
    Ok(())
}

fn same_file(left: &Path, right: &Path) -> bool {
    let Ok(left) = left.metadata() else {
        return false;
    };
    let Ok(right) = right.metadata() else {
        return false;
    };
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn link_or_reference(source: &Path, target: &Path) -> Result<()> {
    if same_file(source, target) {
        return Ok(());
    }
    if fs::symlink_metadata(target).is_ok() {
        fs::remove_file(target).at(target)?;
    }
    match fs::hard_link(source, target) {
        Ok(()) => Ok(()),
        // Android's shell SELinux policy rejects hard-link creation even when
        // source and target are both shell-owned under /data/local/tmp. A
        // content-addressed, exact-target symlink keeps one physical copy and
        // is validated before every use.
        Err(_) => symlink(source, target).at(target),
    }
}

pub(crate) fn verify_cache_blob_reference(
    path: &Path,
    artifact: &Artifact,
    paths: &Paths,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path).at(path)?;
    if metadata.file_type().is_symlink() {
        if paths.cache_is_explicit {
            return Err(msg(format!(
                "explicit cache blob must not be a symlink: {}",
                artifact.id
            )));
        }
        let expected = paths.managed_blob_root.join(&artifact.sha256);
        let target = fs::read_link(path).at(path)?;
        if target != expected {
            return Err(msg(format!(
                "managed cache blob reference escapes the content store: {}",
                artifact.id
            )));
        }
        let global_metadata = fs::symlink_metadata(&expected).at(&expected)?;
        if !global_metadata.is_file() || global_metadata.file_type().is_symlink() {
            return Err(msg(format!(
                "managed content-store blob is not a regular file: {}",
                artifact.id
            )));
        }
    } else if !metadata.is_file() {
        return Err(msg(format!("cache blob is not a file: {}", artifact.id)));
    }
    verify_blob(path, artifact)
}

pub fn populate_deduplicated_blobs(
    source_cache: &Path,
    destination_cache: &Path,
    paths: &Paths,
    lock: &AssetsLock,
) -> Result<usize> {
    fs::create_dir_all(&paths.managed_blob_root).at(&paths.managed_blob_root)?;
    fs::set_permissions(&paths.managed_blob_root, fs::Permissions::from_mode(0o700))
        .at(&paths.managed_blob_root)?;
    let destination_blobs = destination_cache.join("blobs");
    fs::create_dir_all(&destination_blobs).at(&destination_blobs)?;
    fs::set_permissions(&destination_blobs, fs::Permissions::from_mode(0o700))
        .at(&destination_blobs)?;

    let mut linked = 0;
    for artifact in lock.artifacts.iter().filter(|artifact| artifact.embedded) {
        let source = source_cache.join("blobs").join(&artifact.sha256);
        let global = paths.managed_blob_root.join(&artifact.sha256);
        let global_is_regular = fs::symlink_metadata(&global)
            .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
            .unwrap_or(false);
        if global_is_regular {
            if verify_blob(&global, artifact).is_err() {
                fs::remove_file(&global).at(&global)?;
                if !source.is_file() {
                    return Err(msg(format!(
                        "global cache blob is corrupt and no trusted source exists: {}",
                        artifact.id
                    )));
                }
                verify_blob(&source, artifact)?;
                copy_atomic(&source, &global, 0o600)?;
            }
        } else {
            if fs::symlink_metadata(&global).is_ok() {
                fs::remove_file(&global).at(&global)?;
            }
            if !source.is_file() {
                return Err(msg(format!(
                    "cache blob missing from release and global store: {}",
                    artifact.id
                )));
            }
            verify_blob(&source, artifact)?;
            copy_atomic(&source, &global, 0o600)?;
        }
        link_or_reference(&global, &destination_blobs.join(&artifact.sha256))?;
        linked += 1;
    }
    Ok(linked)
}

fn count_tree_files(path: &Path) -> usize {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return 0;
    };
    if metadata.is_file() {
        return 1;
    }
    if !metadata.is_dir() {
        return 0;
    }
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(std::result::Result::ok)
        .map(|entry| count_tree_files(&entry.path()))
        .sum()
}

pub fn retain_managed_cache_releases(paths: &Paths, requested: &[PathBuf]) -> Result<usize> {
    if paths.cache_is_explicit {
        return Ok(0);
    }
    paths.ensure()?;
    let mut keep_names = BTreeSet::new();
    let mut referenced = BTreeSet::new();
    for release in requested {
        if !release.exists() {
            continue;
        }
        if release.parent() != Some(paths.managed_cache_root.as_path()) {
            return Err(msg(format!(
                "managed cache retention path is outside release root: {}",
                release.display()
            )));
        }
        let Some(name) = release.file_name().and_then(|name| name.to_str()) else {
            return Err(msg("managed cache release has an invalid name"));
        };
        if !release.join("catalog.json").is_file() {
            continue;
        }
        let lock = load_signed_external_catalog(release)?;
        populate_deduplicated_blobs(release, release, paths, &lock)?;
        for artifact in lock.artifacts.iter().filter(|artifact| artifact.embedded) {
            referenced.insert(artifact.sha256.clone());
        }
        keep_names.insert(name.to_string());
    }

    let mut removed = 0;
    for entry in fs::read_dir(&paths.managed_cache_root).at(&paths.managed_cache_root)? {
        let entry = entry.at(&paths.managed_cache_root)?;
        if !entry.file_type().at(entry.path())?.is_dir() {
            continue;
        }
        if !keep_names.contains(entry.file_name().to_string_lossy().as_ref()) {
            removed += count_tree_files(&entry.path());
            fs::remove_dir_all(entry.path()).at(entry.path())?;
        }
    }
    for entry in fs::read_dir(&paths.managed_blob_root).at(&paths.managed_blob_root)? {
        let entry = entry.at(&paths.managed_blob_root)?;
        if entry.file_type().at(entry.path())?.is_file()
            && !referenced.contains(entry.file_name().to_string_lossy().as_ref())
        {
            fs::remove_file(entry.path()).at(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn import_cache(source: &Path, paths: &Paths, baseline: &Catalog) -> Result<usize> {
    let external = verify_external_catalog(source, baseline)?;
    paths.ensure()?;
    let blobs = paths.cache.join("blobs");
    fs::create_dir_all(&blobs).at(&blobs)?;
    let imported = if paths.cache_is_explicit {
        let mut imported = 0;
        for artifact in external.artifacts.iter().filter(|a| a.embedded) {
            let source_blob = source.join("blobs").join(&artifact.sha256);
            verify_blob(&source_blob, artifact)?;
            let target_blob = blobs.join(&artifact.sha256);
            if !target_blob.exists() || sha256_file(&target_blob)? != artifact.sha256 {
                copy_atomic(&source_blob, &target_blob, 0o600)?;
                imported += 1;
            }
        }
        imported
    } else {
        populate_deduplicated_blobs(source, &paths.cache, paths, &external)?
    };
    let catalog_raw = fs::read(source.join("catalog.json")).at(source.join("catalog.json"))?;
    let signature_raw = fs::read(source.join("catalog.sig")).at(source.join("catalog.sig"))?;
    atomic_write(&paths.cache.join("catalog.json"), &catalog_raw, 0o600)?;
    atomic_write(&paths.cache.join("catalog.sig"), &signature_raw, 0o600)?;
    Ok(imported)
}

pub fn verify_cache(paths: &Paths, baseline: &Catalog) -> Result<Vec<String>> {
    if paths.cache_is_explicit {
        return verify_complete_external_cache(&paths.cache, baseline);
    }
    let external = verify_external_catalog(&paths.cache, baseline)?;
    let mut verified = Vec::new();
    for artifact in external.artifacts.iter().filter(|a| a.embedded) {
        let blob = paths.cache.join("blobs").join(&artifact.sha256);
        verify_cache_blob_reference(&blob, artifact, paths)?;
        verified.push(artifact.id.clone());
    }
    Ok(verified)
}

pub fn verify_complete_external_cache(cache: &Path, baseline: &Catalog) -> Result<Vec<String>> {
    let external = verify_external_catalog(cache, baseline)?;
    let mut verified = Vec::new();
    for artifact in external.artifacts.iter().filter(|a| a.embedded) {
        let blob = cache.join("blobs").join(&artifact.sha256);
        if !blob.is_file() {
            return Err(msg(format!("cache blob missing: {}", artifact.id)));
        }
        verify_blob(&blob, artifact)?;
        verified.push(artifact.id.clone());
    }
    Ok(verified)
}

pub fn prune_cache(paths: &Paths, baseline: &Catalog) -> Result<usize> {
    if !paths.cache_is_explicit {
        let mut candidates = fs::read_dir(&paths.managed_cache_root)
            .at(&paths.managed_cache_root)?
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry.path() != paths.cache
                    && entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
                    && entry.path().join("catalog.json").is_file()
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|entry| {
            entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok()
        });
        let mut keep = vec![paths.cache.clone()];
        if let Some(previous) = candidates.pop() {
            keep.push(previous.path());
        }
        return retain_managed_cache_releases(paths, &keep);
    }
    let keep: BTreeSet<_> = baseline
        .lock
        .artifacts
        .iter()
        .map(|a| a.sha256.as_str())
        .collect();
    let dir = paths.cache.join("blobs");
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in fs::read_dir(&dir).at(&dir)? {
        let entry = entry.at(&dir)?;
        if entry.file_type().at(entry.path())?.is_file() {
            let name = entry.file_name();
            if !keep.contains(name.to_string_lossy().as_ref()) {
                fs::remove_file(entry.path()).at(entry.path())?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

pub fn clear_cache(paths: &Paths) -> Result<usize> {
    if !paths.cache_is_explicit {
        let count = count_tree_files(&paths.managed_cache_root)
            + count_tree_files(&paths.managed_blob_root);
        if paths.managed_cache_root.exists() {
            fs::remove_dir_all(&paths.managed_cache_root).at(&paths.managed_cache_root)?;
        }
        if paths.managed_blob_root.exists() {
            fs::remove_dir_all(&paths.managed_blob_root).at(&paths.managed_blob_root)?;
        }
        paths.ensure()?;
        return Ok(count);
    }
    if !paths.cache.exists() {
        return Ok(0);
    }
    let mut count = 0;
    for name in ["catalog.json", "catalog.sig"] {
        let path = paths.cache.join(name);
        if path.exists() {
            fs::remove_file(&path).at(&path)?;
            count += 1;
        }
    }
    let blobs = paths.cache.join("blobs");
    if blobs.exists() {
        for entry in fs::read_dir(&blobs).at(&blobs)? {
            let entry = entry.at(&blobs)?;
            if entry.file_type().at(entry.path())?.is_file() {
                fs::remove_file(entry.path()).at(entry.path())?;
                count += 1;
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ArtifactKind, DeviceProfile};

    fn test_paths(label: &str) -> Paths {
        let root = std::env::temp_dir().join(format!(
            "xpad2-catalog-{label}-{}",
            crate::util::unique_id()
        ));
        Paths {
            cache: root.join("cache/releases/current"),
            cache_is_explicit: false,
            managed_blob_root: root.join("cache/blobs"),
            managed_cache_root: root.join("cache/releases"),
            work: root.join("work"),
            state: root.join("state"),
            logs: root.join("logs"),
            lock: root.join("operation.lock"),
            root,
        }
    }

    #[test]
    fn embedded_catalog_public_key_is_valid() {
        catalog_public_key().expect("catalog public key parses");
    }

    #[test]
    fn invalid_catalog_signature_is_rejected() {
        assert!(verify_catalog_signature(b"catalog", &[0u8; 512]).is_err());
    }

    #[test]
    fn embedded_artifacts_verify_on_demand() {
        let catalog = Catalog::load().unwrap();
        for artifact in catalog
            .lock
            .artifacts
            .iter()
            .filter(|artifact| artifact.embedded)
        {
            assert_eq!(
                verify_embedded_artifact(artifact).unwrap().len() as u64,
                artifact.size
            );
        }
    }

    #[test]
    fn release_cache_blobs_share_the_global_store() {
        let paths = test_paths("dedupe");
        paths.ensure().unwrap();
        let bytes = b"shared-content-addressed-blob";
        let sha = crate::util::sha256_bytes(bytes);
        let artifact = Artifact {
            id: "test".to_string(),
            filename: "test.bin".to_string(),
            kind: ArtifactKind::Internal,
            version: "1".to_string(),
            size: bytes.len() as u64,
            sha256: sha.clone(),
            embedded: true,
            mode: 0o600,
            target: None,
            package: None,
            version_code: None,
            cert_sha256: None,
        };
        let lock = AssetsLock {
            schema: 1,
            product_version: "test".to_string(),
            catalog_version: "test".to_string(),
            profile: DeviceProfile {
                build_fingerprint: "fp".to_string(),
                kernel_release_prefix: "kernel".to_string(),
                abi: "arm64-v8a".to_string(),
            },
            artifacts: vec![artifact],
        };
        let source = paths.root.join("source");
        let destination = paths.root.join("destination");
        fs::create_dir_all(source.join("blobs")).unwrap();
        fs::write(source.join("blobs").join(&sha), bytes).unwrap();
        populate_deduplicated_blobs(&source, &destination, &paths, &lock).unwrap();
        let global = paths.managed_blob_root.join(&sha);
        let linked = destination.join("blobs").join(&sha);
        assert_eq!(fs::read(&global).unwrap(), bytes);
        assert!(
            same_file(&global, &linked)
                || fs::read_link(&linked).is_ok_and(|target| target == global)
        );
        fs::remove_file(&linked).unwrap();
        symlink(&global, &linked).unwrap();
        verify_cache_blob_reference(&linked, &lock.artifacts[0], &paths).unwrap();
        fs::remove_file(&linked).unwrap();
        let escaped = paths.root.join("escaped");
        fs::write(&escaped, bytes).unwrap();
        symlink(&escaped, &linked).unwrap();
        assert!(verify_cache_blob_reference(&linked, &lock.artifacts[0], &paths).is_err());
        fs::remove_dir_all(&paths.root).unwrap();
    }

    #[test]
    fn default_cache_validation_failure_falls_back_but_explicit_cache_is_strict() {
        assert!(managed_cache_may_fall_back(false));
        assert!(!managed_cache_may_fall_back(true));

        let catalog = Catalog::load().unwrap();
        let paths = test_paths("invalid-default-signature");
        paths.ensure().unwrap();
        fs::write(paths.cache.join("catalog.json"), LOCK_JSON).unwrap();
        fs::write(paths.cache.join("catalog.sig"), b"invalid-signature").unwrap();
        let resolved = catalog.resolve("xpad-installer", &paths).unwrap();
        assert!(matches!(resolved.source, ResolvedSource::Embedded(_)));

        let mut explicit = test_paths("invalid-explicit-signature");
        explicit.cache_is_explicit = true;
        explicit.ensure().unwrap();
        fs::write(explicit.cache.join("catalog.json"), LOCK_JSON).unwrap();
        fs::write(explicit.cache.join("catalog.sig"), b"invalid-signature").unwrap();
        assert!(catalog.resolve("xpad-installer", &explicit).is_err());

        fs::remove_dir_all(paths.root).unwrap();
        fs::remove_dir_all(explicit.root).unwrap();
    }
}
