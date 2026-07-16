use crate::error::{IoContext, Result, msg};
use crate::model::ApkIdentity;
use crate::util::sha256_file;
use apk_info_axml::AXML;
use apksig::ValueSigningBlock;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

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
                18,
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
        }
    }
}
