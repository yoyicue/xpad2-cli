use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AssetsLock {
    pub schema: u32,
    pub product_version: String,
    pub catalog_version: String,
    pub profile: DeviceProfile,
    pub artifacts: Vec<Artifact>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeviceProfile {
    pub build_fingerprint: String,
    pub kernel_release_prefix: String,
    pub abi: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Artifact {
    pub id: String,
    pub filename: String,
    pub kind: ArtifactKind,
    pub version: String,
    pub size: u64,
    pub sha256: String,
    pub embedded: bool,
    pub mode: u32,
    pub target: Option<String>,
    pub package: Option<String>,
    pub version_code: Option<u64>,
    pub cert_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    Internal,
    Metadata,
    Cli,
    Apk,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentState {
    Absent,
    Ready,
    Active,
    Installed,
    Outdated,
    Incompatible,
    Broken,
    NeedsReboot,
}

impl std::fmt::Display for ComponentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Absent => "absent",
            Self::Ready => "ready",
            Self::Active => "active",
            Self::Installed => "installed",
            Self::Outdated => "outdated",
            Self::Incompatible => "incompatible",
            Self::Broken => "broken",
            Self::NeedsReboot => "needs-reboot",
        };
        f.write_str(s)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ComponentStatus {
    pub id: String,
    pub state: ComponentState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceStatus {
    pub product_version: String,
    pub supported: bool,
    pub fingerprint: String,
    pub kernel_release: String,
    pub boot_id: String,
    pub selinux: String,
    pub temporary_root: ComponentStatus,
    pub components: Vec<ComponentStatus>,
    pub transaction_warnings: Vec<String>,
    pub action_required: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApkIdentity {
    pub path: String,
    pub package: String,
    pub version_code: u64,
    pub version_name: Option<String>,
    pub cert_sha256: String,
    pub native_abis: Vec<String>,
    pub apk_sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub transaction_id: String,
    pub operation: String,
    pub success: bool,
    pub started_boot_id: String,
    pub ended_boot_id: String,
    pub started_selinux: String,
    pub ended_selinux: String,
    pub components: Vec<String>,
    pub error: Option<String>,
    pub needs_reboot: bool,
}
