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
        for artifact in lock.artifacts.iter().filter(|a| a.embedded) {
            let embedded = embedded::get(&artifact.id)
                .ok_or_else(|| msg(format!("embedded artifact missing: {}", artifact.id)))?;
            if embedded.filename != artifact.filename
                || embedded.bytes.len() as u64 != artifact.size
                || crate::util::sha256_bytes(embedded.bytes) != artifact.sha256
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
            match verify_external_catalog(&paths.cache, self) {
                Ok(external) => {
                    if let Some(entry) = external.artifacts.iter().find(|a| a.id == id) {
                        let blob = paths.cache.join("blobs").join(&entry.sha256);
                        if blob.exists() {
                            verify_blob(&blob, entry)?;
                            return Ok(ResolvedArtifact {
                                artifact,
                                source: ResolvedSource::Cache(blob),
                            });
                        }
                    }
                }
                Err(error) if may_ignore_managed_cache_error(&error, paths.cache_is_explicit) => {
                    if !STALE_MANAGED_CACHE_WARNED.swap(true, Ordering::Relaxed) {
                        eprintln!(
                            "提示：默认缓存属于其他 xpad2 版本，已忽略并改用当前 ELF 的内嵌锁定制品；可执行 `xpad2 cache clear` 或导入同版本缓存。"
                        );
                    }
                }
                Err(error) => return Err(error),
            }
        }
        let embedded = embedded::get(id)
            .ok_or_else(|| msg(format!("artifact {id} is neither cached nor embedded")))?;
        Ok(ResolvedArtifact {
            artifact,
            source: ResolvedSource::Embedded(embedded.bytes),
        })
    }
}

fn may_ignore_managed_cache_error(error: &Error, cache_is_explicit: bool) -> bool {
    !cache_is_explicit && matches!(error, Error::CatalogReleaseMismatch)
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
    let catalog_path = cache.join("catalog.json");
    let signature_path = cache.join("catalog.sig");
    let raw = fs::read(&catalog_path).at(&catalog_path)?;
    let sig = fs::read(&signature_path).at(&signature_path)?;
    verify_catalog_signature(&raw, &sig)?;
    let external: AssetsLock = serde_json::from_slice(&raw)?;
    if external.schema != baseline.lock.schema
        || external.product_version != baseline.lock.product_version
        || external.catalog_version != baseline.lock.catalog_version
    {
        return Err(Error::CatalogReleaseMismatch);
    }
    let expected: BTreeMap<_, _> = baseline
        .lock
        .artifacts
        .iter()
        .map(|a| (a.id.as_str(), a))
        .collect();
    for entry in &external.artifacts {
        let Some(locked) = expected.get(entry.id.as_str()) else {
            return Err(msg(format!(
                "external catalog contains unlocked artifact {}",
                entry.id
            )));
        };
        if entry.sha256 != locked.sha256
            || entry.size != locked.size
            || entry.kind != locked.kind
            || entry.version != locked.version
        {
            return Err(msg(format!(
                "external catalog changes locked identity for {}",
                entry.id
            )));
        }
    }
    Ok(external)
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

pub fn import_cache(source: &Path, paths: &Paths, baseline: &Catalog) -> Result<usize> {
    let external = verify_external_catalog(source, baseline)?;
    paths.ensure()?;
    let blobs = paths.cache.join("blobs");
    fs::create_dir_all(&blobs).at(&blobs)?;
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
    let catalog_raw = fs::read(source.join("catalog.json")).at(source.join("catalog.json"))?;
    let signature_raw = fs::read(source.join("catalog.sig")).at(source.join("catalog.sig"))?;
    atomic_write(&paths.cache.join("catalog.json"), &catalog_raw, 0o600)?;
    atomic_write(&paths.cache.join("catalog.sig"), &signature_raw, 0o600)?;
    Ok(imported)
}

pub fn verify_cache(paths: &Paths, baseline: &Catalog) -> Result<Vec<String>> {
    let external = verify_external_catalog(&paths.cache, baseline)?;
    let mut verified = Vec::new();
    for artifact in external.artifacts.iter().filter(|a| a.embedded) {
        let blob = paths.cache.join("blobs").join(&artifact.sha256);
        if blob.exists() {
            verify_blob(&blob, artifact)?;
            verified.push(artifact.id.clone());
        }
    }
    Ok(verified)
}

pub fn prune_cache(paths: &Paths, baseline: &Catalog) -> Result<usize> {
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

    #[test]
    fn embedded_catalog_public_key_is_valid() {
        catalog_public_key().expect("catalog public key parses");
    }

    #[test]
    fn invalid_catalog_signature_is_rejected() {
        assert!(verify_catalog_signature(b"catalog", &[0u8; 512]).is_err());
    }

    #[test]
    fn only_default_cache_may_fall_back_from_a_signed_other_release() {
        let mismatch = Error::CatalogReleaseMismatch;
        assert!(may_ignore_managed_cache_error(&mismatch, false));
        assert!(!may_ignore_managed_cache_error(&mismatch, true));
        assert!(!may_ignore_managed_cache_error(
            &msg("bad signature"),
            false
        ));
    }
}
