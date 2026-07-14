use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct Lock {
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize)]
struct Artifact {
    id: String,
    filename: String,
    sha256: String,
    size: u64,
    embedded: bool,
}

fn candidate_paths(manifest: &Path, artifact_dir: Option<&Path>, a: &Artifact) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(dir) = artifact_dir {
        paths.push(dir.join(&a.filename));
        paths.push(dir.join(&a.id));
    }
    let parent = manifest.parent().unwrap_or(manifest);
    let mapped = match a.id.as_str() {
        "ionstack-runner" => Some(parent.join("xpad2-ionstack-poc/build/ionstack_reroot_device")),
        "ionstack-perf-target" => {
            Some(parent.join("xpad2-ionstack-poc/build/ionstack_perf_target"))
        }
        "ionstack-preload" => Some(parent.join("xpad2-ionstack-poc/build/ionstack_preload.so")),
        "ionstack-chainwalk-probe" => {
            Some(parent.join("xpad2-ionstack-poc/build/cve_2026_43499_chainwalk_probe_arm32"))
        }
        "ksud" => Some(parent.join("xpad2-ksu-lateload/artifacts/ksud-xpad2")),
        "ksu-manager" => {
            Some(parent.join(
                "xpad2-reroot-android/app/src/main/res/raw/kernelsu_manager_v3_2_4_32457.apk",
            ))
        }
        "xpad-installer" => Some(parent.join("xpad-installer/dist/xpad-install")),
        "boominstaller" => Some(
            parent.join("BoomInstaller/out/apk/BoomInstaller-v13.6.0.r9.2f1ac6f-production.apk"),
        ),
        _ => None,
    };
    if let Some(path) = mapped {
        paths.push(path);
    }
    paths
}

fn main() {
    println!("cargo:rerun-if-changed=assets.lock.json");
    println!("cargo:rerun-if-env-changed=XPAD2_ARTIFACT_DIR");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let lock_path = manifest.join("assets.lock.json");
    let raw = fs::read(&lock_path).expect("read assets.lock.json");
    let lock: Lock = serde_json::from_slice(&raw).expect("parse assets.lock.json");
    let artifact_dir = env::var_os("XPAD2_ARTIFACT_DIR").map(PathBuf::from);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("embedded");
    fs::create_dir_all(&out_dir).expect("create embedded output directory");
    let mut generated = String::from("pub static EMBEDDED: &[EmbeddedAsset] = &[\n");

    for a in lock.artifacts.iter().filter(|a| a.embedded) {
        let candidates = candidate_paths(&manifest, artifact_dir.as_deref(), a);
        let source = candidates.iter().find(|p| p.is_file()).unwrap_or_else(|| {
            panic!(
                "missing locked artifact {} ({}); set XPAD2_ARTIFACT_DIR; tried: {:?}",
                a.id, a.filename, candidates
            )
        });
        println!("cargo:rerun-if-changed={}", source.display());
        let bytes = fs::read(source).unwrap_or_else(|e| panic!("read {}: {e}", source.display()));
        assert_eq!(bytes.len() as u64, a.size, "size mismatch for {}", a.id);
        let actual = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(actual, a.sha256, "SHA-256 mismatch for {}", a.id);
        let dest = out_dir.join(&a.filename);
        fs::write(&dest, bytes).unwrap_or_else(|e| panic!("write {}: {e}", dest.display()));
        generated.push_str(&format!(
            "    EmbeddedAsset {{ id: {:?}, filename: {:?}, bytes: include_bytes!({:?}) }},\n",
            a.id,
            a.filename,
            dest.display().to_string()
        ));
    }
    generated.push_str("];\n");
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("embedded_assets.rs"),
        generated,
    )
    .expect("write embedded asset table");
}
