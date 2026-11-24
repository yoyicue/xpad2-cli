use crate::error::{IoContext, Result, msg};
use crate::model::{ApkIdentity, ApksBundleIdentity};
use crate::util::sha256_file;
use apk_info_axml::AXML;
use apksig::ValueSigningBlock;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const MAX_APKS_MEMBERS: usize = 128;
const MAX_APKS_UNCOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

pub fn inspect(path: &Path) -> Result<ApkIdentity> {
    let metadata = path.metadata().at(path)?;
    if !metadata.is_file() {
        return Err(msg(format!("{} is not a regular APK file", path.display())));
    }

    let file = File::open(path).at(path)?;
    let mut zip = ZipArchive::new(file)?;
    let mut manifest = Vec::new();
    zip.by_name("AndroidManifest.xml")?
        .read_to_end(&mut manifest)
        .at(path)?;
    if manifest.is_empty() {
        return Err(msg("APK has an empty AndroidManifest.xml"));
    }
    let axml = AXML::new(&mut &manifest[..], None)
        .map_err(|e| msg(format!("parse AndroidManifest.xml: {e}")))?;
    let package = axml
        .get_attribute_value("manifest", "package", None)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| msg("APK manifest has no package name"))?;
    let version_code_text = axml
        .get_attribute_value("manifest", "versionCode", None)
        .ok_or_else(|| msg("APK manifest has no versionCode"))?;
    let version_code = version_code_text
        .parse::<u64>()
        .map_err(|_| msg(format!("invalid APK versionCode: {version_code_text}")))?;
    let version_name = axml.get_attribute_value("manifest", "versionName", None);
    let split = axml
        .get_attribute_value("manifest", "split", None)
        .filter(|s| !s.is_empty());

    let mut abis = BTreeSet::new();
    for index in 0..zip.len() {
        let name = zip.by_index(index)?.name().to_string();
        if let Some(rest) = name.strip_prefix("lib/")
            && let Some((abi, library)) = rest.split_once('/')
            && library.ends_with(".so")
            && !abi.is_empty()
        {
            abis.insert(abi.to_string());
        }
    }

    let signed_apk = apksig::Apk::new(path.to_path_buf()).at(path)?;
    let signing_block = signed_apk.get_signing_block().at(path)?;
    let mut primary_cert = None;
    let mut verified_signers = 0usize;
    for block in signing_block.content {
        match block {
            ValueSigningBlock::SignatureSchemeV2Block(v2) => {
                for signer in v2.signers.signers_data {
                    verify_signer(
                        &signed_apk,
                        &signer.pub_key.data,
                        &signer.signed_data.to_u8(),
                        &signer.signed_data.digests.digests_data,
                        &signer.signatures.signatures_data,
                    )?;
                    verified_signers += 1;
                    if primary_cert.is_none() {
                        primary_cert = signer
                            .signed_data
                            .certificates
                            .certificates_data
                            .first()
                            .map(|cert| cert.certificate.clone());
                    }
                }
            }
            ValueSigningBlock::SignatureSchemeV3Block(v3) => {
                for signer in v3.signers.signers_data {
                    verify_signer(
                        &signed_apk,
                        &signer.pub_key.data,
                        &signer.signed_data.to_u8(),
                        &signer.signed_data.digests.digests_data,
                        &signer.signatures.signatures_data,
                    )?;
                    verified_signers += 1;
                    primary_cert = signer
                        .signed_data
                        .certificates
                        .certificates_data
                        .first()
                        .map(|cert| cert.certificate.clone());
                }
            }
            ValueSigningBlock::BaseSigningBlock(_) => {}
        }
    }
    if verified_signers == 0 {
        return Err(msg("APK has no verified v2/v3 signer"));
    }
    let cert = primary_cert
        .as_ref()
        .ok_or_else(|| msg("APK has no v2/v3 signing certificate"))?;
    let cert_sha256 = format!("{:x}", Sha256::digest(cert));

    Ok(ApkIdentity {
        path: path.display().to_string(),
        package,
        split,
        version_code,
        version_name,
        cert_sha256,
        native_abis: abis.into_iter().collect(),
        apk_sha256: sha256_file(path)?,
        size: metadata.len(),
    })
}

fn verify_signer(
    apk: &apksig::Apk,
    public_key: &[u8],
    encoded_signed_data: &[u8],
    digests: &[apksig::common::Digest],
    signatures: &[apksig::common::Signature],
) -> Result<()> {
    let raw_signed_data = encoded_signed_data
        .get(4..)
        .ok_or_else(|| msg("APK signer has invalid signed-data encoding"))?;
    if digests.is_empty() || signatures.is_empty() || digests.len() != signatures.len() {
        return Err(msg("APK signer has inconsistent digest/signature records"));
    }
    for (digest, signature) in digests.iter().zip(signatures) {
        if digest.signature_algorithm_id != signature.signature_algorithm_id {
            return Err(msg("APK signer algorithm IDs do not match"));
        }
        digest
            .signature_algorithm_id
            .verify(public_key, raw_signed_data, &signature.signature)
            .map_err(|e| msg(format!("APK signer verification failed: {e}")))?;
        let actual = apk
            .digest(&digest.signature_algorithm_id)
            .map_err(|e| msg(format!("calculate APK content digest: {e}")))?;
        if actual != digest.digest {
            return Err(msg("APK content digest does not match the signed digest"));
        }
    }
    Ok(())
}

pub fn check_arm64_compatible(identity: &ApkIdentity) -> Result<()> {
    if identity.native_abis.is_empty() || identity.native_abis.iter().any(|abi| abi == "arm64-v8a")
    {
        return Ok(());
    }
    Err(msg(format!(
        "APK {} has native code but no arm64-v8a ABI ({})",
        identity.package,
        identity.native_abis.join(", ")
    )))
}

fn is_candidate_apk_entry(name: &str, is_dir: bool) -> bool {
    if is_dir || name.is_empty() || name.contains("..") || name.starts_with("__MACOSX/") {
        return false;
    }
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    !base.is_empty() && !base.starts_with('.') && base.to_ascii_lowercase().ends_with(".apk")
}

fn is_foreign_abi_split_name(split: &str) -> bool {
    let lower = split.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "config.armeabi_v7a"
            | "config.armeabi"
            | "config.x86_64"
            | "config.x86"
            | "config.mips64"
            | "config.mips"
    )
}

fn sanitize_split_entry(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "split".to_string()
    } else {
        out
    }
}

pub fn is_apks_archive(path: &Path) -> Result<bool> {
    let metadata = path.metadata().at(path)?;
    if !metadata.is_file() {
        return Err(msg(format!("{} is not a regular file", path.display())));
    }
    let file = File::open(path).at(path)?;
    let mut zip = ZipArchive::new(file)?;
    if zip.by_name("AndroidManifest.xml").is_ok() {
        return Ok(false);
    }
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        if is_candidate_apk_entry(entry.name(), entry.is_dir()) {
            return Ok(true);
        }
    }
    Err(msg(format!(
        "{} is neither a valid .apk nor a .apks split archive",
        path.display()
    )))
}

struct ExtractedMember {
    path: PathBuf,
    identity: ApkIdentity,
}

struct WorkCleanup(PathBuf);

impl Drop for WorkCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn prepare_apks_bundle(path: &Path, work_dir: &Path) -> Result<(ApksBundleIdentity, PathBuf)> {
    let metadata = path.metadata().at(path)?;
    if !metadata.is_file() {
        return Err(msg(format!("{} is not a regular .apks file", path.display())));
    }
    let bundle_sha256 = sha256_file(path)?;
    let file = File::open(path).at(path)?;
    let mut zip = ZipArchive::new(file)?;
    if zip.by_name("AndroidManifest.xml").is_ok() {
        return Err(msg(format!(
            "{} is a single .apk package, not an .apks split archive",
            path.display()
        )));
    }

    let mut raw_indices = Vec::new();
    let mut has_splits_dir = false;
    let mut has_standalones_dir = false;
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        let name = entry.name().to_string();
        if !is_candidate_apk_entry(&name, entry.is_dir()) {
            continue;
        }
        if name.starts_with("splits/") {
            has_splits_dir = true;
        }
        if name.starts_with("standalones/") {
            has_standalones_dir = true;
        }
        raw_indices.push((index, name));
    }

    let selected_indices: Vec<(usize, String)> = raw_indices
        .into_iter()
        .filter(|(_, name)| !(has_splits_dir && has_standalones_dir && !name.starts_with("splits/")))
        .collect();
    if selected_indices.is_empty() {
        return Err(msg(format!(
            "{} contains no installable .apk entries",
            path.display()
        )));
    }
    if selected_indices.len() > MAX_APKS_MEMBERS {
        return Err(msg(format!(
            "{} contains {} APK entries (maximum {})",
            path.display(),
            selected_indices.len(),
            MAX_APKS_MEMBERS
        )));
    }

    fs::create_dir_all(work_dir).at(work_dir)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_dir = work_dir.join(format!("apks-inspect-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&temp_dir).at(&temp_dir)?;
    let _cleanup = WorkCleanup(temp_dir.clone());

    let mut total_uncompressed = 0u64;
    let mut base_members = Vec::new();
    let mut split_members = Vec::new();

    for (seq, (zip_idx, entry_name)) in selected_indices.iter().enumerate() {
        let mut entry = zip.by_index(*zip_idx)?;
        let member_path = temp_dir.join(format!("member-{seq:03}.apk"));
        let mut out = File::create(&member_path).at(&member_path)?;
        let mut buf = [0u8; 32768];
        let mut written = 0u64;
        loop {
            let count = entry.read(&mut buf).at(path)?;
            if count == 0 {
                break;
            }
            written = written.saturating_add(count as u64);
            total_uncompressed = total_uncompressed.saturating_add(count as u64);
            if total_uncompressed > MAX_APKS_UNCOMPRESSED_BYTES {
                return Err(msg("APKS bundle exceeds maximum allowed uncompressed size"));
            }
            out.write_all(&buf[..count]).at(&member_path)?;
        }
        out.flush().at(&member_path)?;
        drop(out);
        if written == 0 {
            return Err(msg(format!("APKS entry {entry_name} is empty")));
        }
        let identity = inspect(&member_path)
            .map_err(|e| msg(format!("invalid APK entry {entry_name} in {}: {e}", path.display())))?;
        let member = ExtractedMember {
            path: member_path,
            identity,
        };
        if member.identity.split.is_some() {
            split_members.push(member);
        } else {
            base_members.push(member);
        }
    }

    if base_members.is_empty() {
        return Err(msg("APKS archive contains no base APK"));
    }
    if base_members.len() > 1 {
        return Err(msg(format!(
            "APKS archive contains {} base APKs; expected exactly 1",
            base_members.len()
        )));
    }
    let base = base_members.pop().expect("single base APK");

    let has_arm64 = base.identity.native_abis.iter().any(|abi| abi == "arm64-v8a")
        || split_members.iter().any(|member| {
            member.identity.native_abis.iter().any(|abi| abi == "arm64-v8a")
                || member
                    .identity
                    .split
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case("config.arm64_v8a"))
        });

    let mut kept_splits = Vec::new();
    let mut seen_splits = BTreeSet::new();
    let mut combined_abis: BTreeSet<String> = base.identity.native_abis.iter().cloned().collect();

    for member in split_members {
        let split_name = member
            .identity
            .split
            .clone()
            .expect("split member has split attribute");
        if member.identity.package != base.identity.package {
            return Err(msg(format!(
                "APKS split {split_name} package {} != base package {}",
                member.identity.package, base.identity.package
            )));
        }
        if member.identity.version_code != base.identity.version_code {
            return Err(msg(format!(
                "APKS split {split_name} versionCode {} != base versionCode {}",
                member.identity.version_code, base.identity.version_code
            )));
        }
        if member.identity.cert_sha256 != base.identity.cert_sha256 {
            return Err(msg(format!(
                "APKS split {split_name} signing certificate differs from base APK"
            )));
        }
        let foreign_abi_only = !member.identity.native_abis.is_empty()
            && !member.identity.native_abis.iter().any(|abi| abi == "arm64-v8a");
        if has_arm64 && (is_foreign_abi_split_name(&split_name) || foreign_abi_only) {
            continue;
        }
        if !seen_splits.insert(split_name.clone()) {
            return Err(msg(format!("duplicate split APK in archive: {split_name}")));
        }
        for abi in &member.identity.native_abis {
            combined_abis.insert(abi.clone());
        }
        kept_splits.push(member);
    }

    let native_abis: Vec<String> = combined_abis.into_iter().collect();
    if !native_abis.is_empty() && !native_abis.iter().any(|abi| abi == "arm64-v8a") {
        return Err(msg(format!(
            "APKS {} has native code but no arm64-v8a ABI ({})",
            base.identity.package,
            native_abis.join(", ")
        )));
    }

    kept_splits.sort_by(|a, b| a.identity.split.cmp(&b.identity.split));
    let split_names: Vec<String> = kept_splits
        .iter()
        .filter_map(|m| m.identity.split.clone())
        .collect();
    let apk_count = 1 + kept_splits.len();

    let staged_bundle = work_dir.join(format!(
        "verified-{}-{}-{nonce}.apks",
        sanitize_split_entry(&base.identity.package),
        std::process::id()
    ));
    let bundle_file = File::create(&staged_bundle).at(&staged_bundle)?;
    let mut writer = ZipWriter::new(bundle_file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    writer.start_file("000_base.apk", options)?;
    let mut base_in = File::open(&base.path).at(&base.path)?;
    std::io::copy(&mut base_in, &mut writer).at(&staged_bundle)?;

    for (idx, split_member) in kept_splits.iter().enumerate() {
        let split_label = split_member.identity.split.as_deref().unwrap_or("split");
        let member_name = format!(
            "{:03}_split_{}.apk",
            idx + 1,
            sanitize_split_entry(split_label)
        );
        writer.start_file(member_name, options)?;
        let mut split_in = File::open(&split_member.path).at(&split_member.path)?;
        std::io::copy(&mut split_in, &mut writer).at(&staged_bundle)?;
    }
    let finished = writer.finish()?;
    finished.sync_all().at(&staged_bundle)?;

    Ok((
        ApksBundleIdentity {
            path: path.display().to_string(),
            package: base.identity.package,
            version_code: base.identity.version_code,
            version_name: base.identity.version_name,
            cert_sha256: base.identity.cert_sha256,
            native_abis,
            split_names,
            apk_count,
            bundle_sha256,
            size: metadata.len(),
        },
        staged_bundle,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded;

    #[test]
    fn locked_apks_have_expected_verified_identity() {
        for (id, package, version, cert) in [
            (
                "ksu-manager",
                "me.weishu.kernelsu",
                32547,
                "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6",
            ),
            (
                "suu-manager",
                "com.sukisu.ultra",
                40796,
                "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef",
            ),
            (
                "boominstaller",
                "com.yoyicue.boominstaller",
                24,
                "3cb5b69579d23197ced8100818a85a46b821383a504b394a44cfe3e98ade78a2",
            ),
        ] {
            let asset = embedded::get(id).expect("test asset is embedded");
            let path = std::env::temp_dir().join(format!(
                "xpad2-test-{}-{}",
                std::process::id(),
                asset.filename
            ));
            std::fs::write(&path, asset.bytes).expect("write test APK");
            let identity = inspect(&path).expect("inspect and verify APK");
            let _ = std::fs::remove_file(path);
            assert_eq!(identity.package, package);
            assert_eq!(identity.version_code, version);
            assert_eq!(identity.cert_sha256, cert);
            assert!(identity.split.is_none());
        }
    }

    #[test]
    fn apks_detection_and_bundle_verification_enforce_identity_rules() {
        let boom = embedded::get("boominstaller").expect("boominstaller embedded");
        let ksu = embedded::get("ksu-manager").expect("ksu-manager embedded");
        let root = std::env::temp_dir().join(format!("xpad2-apks-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create test dir");

        let single_apk = root.join("single.apk");
        fs::write(&single_apk, boom.bytes).expect("write single APK");
        assert!(!is_apks_archive(&single_apk).expect("single APK detected"));

        let valid_apks = root.join("valid.apks");
        {
            let f = File::create(&valid_apks).expect("create valid apks");
            let mut zip = ZipWriter::new(f);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zip.start_file("splits/base-master.apk", opts).unwrap();
            zip.write_all(boom.bytes).unwrap();
            zip.start_file("standalones/standalone-x86.apk", opts).unwrap();
            zip.write_all(ksu.bytes).unwrap();
            zip.finish().unwrap();
        }
        assert!(is_apks_archive(&valid_apks).expect("apks archive detected"));
        let (bundle, staged) =
            prepare_apks_bundle(&valid_apks, &root).expect("prepare valid bundle");
        assert_eq!(bundle.package, "com.yoyicue.boominstaller");
        assert_eq!(bundle.version_code, 24);
        assert_eq!(bundle.apk_count, 1);
        assert!(staged.is_file());
        let _ = fs::remove_file(&staged);

        let two_bases = root.join("two-bases.apks");
        {
            let f = File::create(&two_bases).expect("create two-bases apks");
            let mut zip = ZipWriter::new(f);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zip.start_file("base.apk", opts).unwrap();
            zip.write_all(boom.bytes).unwrap();
            zip.start_file("second.apk", opts).unwrap();
            zip.write_all(ksu.bytes).unwrap();
            zip.finish().unwrap();
        }
        let err = prepare_apks_bundle(&two_bases, &root)
            .expect_err("multiple base APKs must fail")
            .to_string();
        assert!(err.contains("base APKs"));

        assert!(is_foreign_abi_split_name("config.x86_64"));
        assert!(is_foreign_abi_split_name("config.armeabi_v7a"));
        assert!(!is_foreign_abi_split_name("config.arm64_v8a"));
        assert!(!is_foreign_abi_split_name("config.zh"));

        let _ = fs::remove_dir_all(&root);
    }
}
