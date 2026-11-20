use crate::error::{Result, msg};
#[cfg(test)]
use crate::model::IonStackDiscoveryProfile;
use crate::model::{AssetsLock, DeviceProfile, IonStackProfile};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IonStackArtifacts<'a> {
    pub profile_id: &'a str,
    pub runner: &'a str,
    pub perf_target: &'a str,
    pub preload: &'a str,
    pub chainwalk_probe: &'a str,
}

#[derive(Clone, Copy)]
pub struct FingerprintPolicy<'a> {
    exact_anchor: &'a str,
    prefix: &'a str,
    suffix: &'a str,
    incremental_min: u32,
    incremental_max: u32,
}

impl DeviceProfile {
    pub fn profile_id(&self) -> &str {
        if self.id.is_empty() {
            "legacy"
        } else {
            &self.id
        }
    }

    pub fn fingerprint_policy(&self) -> FingerprintPolicy<'_> {
        FingerprintPolicy {
            exact_anchor: &self.build_fingerprint,
            prefix: &self.build_fingerprint_prefix,
            suffix: &self.build_fingerprint_suffix,
            incremental_min: self.fingerprint_incremental_min,
            incremental_max: self.fingerprint_incremental_max,
        }
    }

    fn matches_product(&self, fingerprint: &str, product_device: &str, abi: &str) -> bool {
        (self.product_device.is_empty() || self.product_device == product_device)
            && self
                .fingerprint_policy()
                .matches_product_family(fingerprint)
            && self.abi == abi
    }

    fn matches_technical(
        &self,
        fingerprint: &str,
        product_device: &str,
        kernel_release: &str,
        abi: &str,
    ) -> bool {
        self.matches_product(fingerprint, product_device, abi)
            && self.fingerprint_policy().matches(fingerprint)
            && kernel_release.starts_with(&self.kernel_release_prefix)
    }
}

impl IonStackProfile {
    fn belongs_to(&self, device_profile_id: &str) -> bool {
        if self.device_profile_id.is_empty() {
            device_profile_id == "legacy"
        } else {
            self.device_profile_id == device_profile_id
        }
    }

    fn matches_exact(&self, kernel_version: &str, fingerprint_incremental: Option<u32>) -> bool {
        if !self.exact_tuples.is_empty() {
            return fingerprint_incremental.is_some_and(|incremental| {
                self.exact_tuples.iter().any(|tuple| {
                    tuple.fingerprint_incremental == incremental
                        && tuple.kernel_version == kernel_version
                })
            });
        }
        self.kernel_version == kernel_version
            || self
                .kernel_version_alternates
                .iter()
                .any(|alternate| alternate == kernel_version)
    }
}

impl AssetsLock {
    fn configured_device_profiles(&self) -> Vec<&DeviceProfile> {
        if self.device_profiles.is_empty() {
            vec![&self.profile]
        } else {
            self.device_profiles.iter().collect()
        }
    }

    pub(crate) fn configured_ionstack_profiles(&self) -> &[IonStackProfile] {
        if self.ionstack_profiles_v2.is_empty() {
            &self.ionstack_profiles
        } else {
            &self.ionstack_profiles_v2
        }
    }

    pub(crate) fn configured_ionstack_discovery_profiles(
        &self,
    ) -> &[crate::model::IonStackDiscoveryProfile] {
        if self.ionstack_discovery_profiles_v2.is_empty() {
            &self.ionstack_discovery_profiles
        } else {
            &self.ionstack_discovery_profiles_v2
        }
    }

    pub fn selected_product_profile(
        &self,
        fingerprint: &str,
        product_device: &str,
        abi: &str,
    ) -> Option<&DeviceProfile> {
        self.configured_device_profiles()
            .into_iter()
            .find(|profile| profile.matches_product(fingerprint, product_device, abi))
    }

    pub fn selected_technical_profile(
        &self,
        fingerprint: &str,
        product_device: &str,
        kernel_release: &str,
        abi: &str,
    ) -> Option<&DeviceProfile> {
        self.configured_device_profiles()
            .into_iter()
            .find(|profile| {
                profile.matches_technical(fingerprint, product_device, kernel_release, abi)
            })
    }

    pub fn validate_device_profiles(&self) -> Result<()> {
        self.profile.fingerprint_policy().validate()?;
        if self.device_profiles.is_empty() {
            return Ok(());
        }

        let mut ids = BTreeSet::new();
        let mut product_devices = BTreeSet::new();
        for profile in &self.device_profiles {
            profile.fingerprint_policy().validate()?;
            if profile.id.is_empty() || profile.product_device.is_empty() {
                return Err(msg(
                    "device-family profile has an empty id or ro.product.device",
                ));
            }
            if !ids.insert(profile.id.as_str()) {
                return Err(msg(format!(
                    "duplicate device-family profile id: {}",
                    profile.id
                )));
            }
            if !product_devices.insert(profile.product_device.as_str()) {
                return Err(msg(format!(
                    "duplicate device-family ro.product.device: {}",
                    profile.product_device
                )));
            }
        }
        if !self.device_profiles.iter().any(|profile| {
            profile.build_fingerprint_prefix == self.profile.build_fingerprint_prefix
                && profile.build_fingerprint_suffix == self.profile.build_fingerprint_suffix
                && profile.fingerprint_incremental_min == self.profile.fingerprint_incremental_min
                && profile.fingerprint_incremental_max >= self.profile.fingerprint_incremental_max
                && profile
                    .fingerprint_policy()
                    .matches(&self.profile.build_fingerprint)
                && profile.kernel_release_prefix == self.profile.kernel_release_prefix
                && profile.abi == self.profile.abi
        }) {
            return Err(msg(
                "legacy compatibility profile must be contained by one device-family identity",
            ));
        }
        Ok(())
    }

    pub fn validate_ionstack_profiles(&self) -> Result<()> {
        self.validate_device_profiles()?;
        let profiles = self.configured_ionstack_profiles();
        let discovery_profiles = self.configured_ionstack_discovery_profiles();
        if profiles.is_empty() {
            if self.profile.kernel_version.is_empty() {
                return Err(msg("legacy device profile has an empty kernel build"));
            }
            if !discovery_profiles.is_empty() {
                return Err(msg(
                    "legacy device profile unexpectedly has discovery profiles",
                ));
            }
            return Ok(());
        }

        let mut ids = BTreeSet::new();
        let mut kernel_versions = BTreeSet::new();
        let mut perf_targets = BTreeMap::new();
        let device_ids = self
            .configured_device_profiles()
            .into_iter()
            .map(DeviceProfile::profile_id)
            .collect::<BTreeSet<_>>();
        for profile in profiles {
            if profile.id.is_empty()
                || profile.kernel_version.is_empty()
                || profile.runner_artifact.is_empty()
                || profile.perf_target_artifact.is_empty()
                || profile.preload_artifact.is_empty()
                || profile.chainwalk_probe_artifact.is_empty()
            {
                return Err(msg(
                    "IonStack profile has an empty identity or artifact mapping",
                ));
            }
            if !ids.insert(profile.id.as_str()) {
                return Err(msg(format!(
                    "duplicate IonStack profile id: {}",
                    profile.id
                )));
            }
            let device_profile_id = if profile.device_profile_id.is_empty() {
                "legacy"
            } else {
                profile.device_profile_id.as_str()
            };
            if !device_ids.contains(device_profile_id) {
                return Err(msg(format!(
                    "IonStack profile {} references unknown device profile {}",
                    profile.id, device_profile_id
                )));
            }
            for kernel_version in std::iter::once(profile.kernel_version.as_str())
                .chain(profile.kernel_version_alternates.iter().map(String::as_str))
            {
                if kernel_version.is_empty()
                    || !kernel_versions.insert((device_profile_id, kernel_version))
                {
                    return Err(msg(format!(
                        "duplicate or empty IonStack kernel build for {}: {:?}",
                        device_profile_id, kernel_version
                    )));
                }
            }
            match perf_targets.get(device_profile_id) {
                None => {
                    perf_targets.insert(device_profile_id, profile.perf_target_artifact.as_str());
                }
                Some(id) if *id == profile.perf_target_artifact => {}
                Some(_) => {
                    return Err(msg(
                        "IonStack profiles in one device family must share one read-only discovery target",
                    ));
                }
            }
            let device_profile = self
                .configured_device_profiles()
                .into_iter()
                .find(|candidate| candidate.profile_id() == device_profile_id)
                .expect("validated device profile");
            let known_kernel_versions = std::iter::once(profile.kernel_version.as_str())
                .chain(profile.kernel_version_alternates.iter().map(String::as_str))
                .collect::<BTreeSet<_>>();
            let mut exact_incrementals = BTreeSet::new();
            for tuple in &profile.exact_tuples {
                if tuple.fingerprint_incremental < device_profile.fingerprint_incremental_min
                    || tuple.fingerprint_incremental > device_profile.fingerprint_incremental_max
                    || !known_kernel_versions.contains(tuple.kernel_version.as_str())
                    || !exact_incrementals.insert(tuple.fingerprint_incremental)
                {
                    return Err(msg(format!(
                        "invalid or duplicate exact tuple in IonStack profile {}",
                        profile.id
                    )));
                }
            }
        }

        if discovery_profiles.len() != profiles.len() {
            return Err(msg(
                "IonStack discovery catalog must cover every artifact profile",
            ));
        }
        let mut discovery_ids = BTreeSet::new();
        for discovery in discovery_profiles {
            if !ids.contains(discovery.profile_id.as_str()) {
                return Err(msg(format!(
                    "IonStack discovery references unknown profile {}",
                    discovery.profile_id
                )));
            }
            if !discovery_ids.insert(discovery.profile_id.as_str()) {
                return Err(msg(format!(
                    "duplicate IonStack discovery profile: {}",
                    discovery.profile_id
                )));
            }
            let mut offsets = BTreeSet::new();
            for (name, value) in &discovery.offsets {
                let offset = parse_anchor_offset(value).ok_or_else(|| {
                    msg(format!(
                        "invalid IonStack discovery offset {}:{}={value:?}",
                        discovery.profile_id, name
                    ))
                })?;
                if name.is_empty() || !offsets.insert(offset) {
                    return Err(msg(format!(
                        "IonStack discovery profile {} has an empty or duplicate anchor",
                        discovery.profile_id
                    )));
                }
            }
            if offsets.len() < 2 {
                return Err(msg(format!(
                    "IonStack discovery profile {} needs at least two independent anchors",
                    discovery.profile_id
                )));
            }
        }
        Ok(())
    }

    pub fn ionstack_profile(&self, profile_id: &str) -> Option<&IonStackProfile> {
        self.configured_ionstack_profiles()
            .iter()
            .find(|profile| profile.id == profile_id)
    }

    pub fn ionstack_artifacts_for_profile(
        &self,
        profile_id: &str,
    ) -> Option<IonStackArtifacts<'_>> {
        let profile = self.ionstack_profile(profile_id)?;
        Some(IonStackArtifacts {
            profile_id: &profile.id,
            runner: &profile.runner_artifact,
            perf_target: &profile.perf_target_artifact,
            preload: &profile.preload_artifact,
            chainwalk_probe: &profile.chainwalk_probe_artifact,
        })
    }

    pub fn ionstack_discovery_target(&self, device_profile_id: &str) -> Option<&str> {
        self.configured_ionstack_profiles()
            .iter()
            .find(|profile| profile.belongs_to(device_profile_id))
            .map(|profile| profile.perf_target_artifact.as_str())
    }

    pub fn ionstack_artifacts(
        &self,
        device_profile_id: &str,
        kernel_version: &str,
        fingerprint_incremental: Option<u32>,
    ) -> Option<IonStackArtifacts<'_>> {
        let profiles = self.configured_ionstack_profiles();
        if profiles.is_empty() {
            return (device_profile_id == "legacy"
                && (self.profile.kernel_version.is_empty()
                    || self.profile.kernel_version == kernel_version))
                .then_some(IonStackArtifacts {
                    profile_id: "legacy",
                    runner: "ionstack-runner",
                    perf_target: "ionstack-perf-target",
                    preload: "ionstack-preload",
                    chainwalk_probe: "ionstack-chainwalk-probe",
                });
        }
        let profile = profiles.iter().find(|profile| {
            profile.belongs_to(device_profile_id)
                && profile.matches_exact(kernel_version, fingerprint_incremental)
        })?;
        self.ionstack_artifacts_for_profile(&profile.id)
    }

    pub fn ionstack_profile_belongs_to_device(
        &self,
        profile_id: &str,
        device_profile_id: &str,
    ) -> bool {
        self.ionstack_profile(profile_id)
            .is_some_and(|profile| profile.belongs_to(device_profile_id))
    }

    #[cfg(test)]
    pub fn matches_runtime(
        &self,
        fingerprint: &str,
        product_device: &str,
        kernel_release: &str,
        kernel_version: &str,
        abi: &str,
    ) -> bool {
        self.selected_technical_profile(fingerprint, product_device, kernel_release, abi)
            .is_some_and(|device_profile| {
                self.ionstack_artifacts(
                    device_profile.profile_id(),
                    kernel_version,
                    device_profile.fingerprint_policy().incremental(fingerprint),
                )
                .is_some()
            })
    }
}

pub fn parse_anchor_offset(value: &str) -> Option<u64> {
    let digits = value.strip_prefix("0x")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

impl FingerprintPolicy<'_> {
    pub fn validate(self) -> Result<()> {
        if self.exact_anchor.is_empty() {
            return Err(msg("device profile has an empty fingerprint anchor"));
        }
        if self.is_legacy_exact() {
            return Ok(());
        }
        if self.prefix.is_empty()
            || self.suffix.is_empty()
            || self.incremental_min > self.incremental_max
        {
            return Err(msg("device profile has an incomplete fingerprint range"));
        }
        let expected_anchor = format!("{}{}{}", self.prefix, self.incremental_max, self.suffix);
        if self.exact_anchor != expected_anchor {
            return Err(msg(format!(
                "fingerprint compatibility anchor must equal the range upper bound: expected {expected_anchor}, got {}",
                self.exact_anchor
            )));
        }
        Ok(())
    }

    pub fn matches(self, fingerprint: &str) -> bool {
        if self.is_legacy_exact() {
            return fingerprint == self.exact_anchor;
        }
        self.incremental(fingerprint).is_some_and(|incremental| {
            incremental >= self.incremental_min && incremental <= self.incremental_max
        })
    }

    pub fn matches_product_family(self, fingerprint: &str) -> bool {
        if self.is_legacy_exact() {
            fingerprint == self.exact_anchor
        } else {
            self.incremental(fingerprint).is_some()
        }
    }

    pub fn incremental(self, fingerprint: &str) -> Option<u32> {
        if self.is_legacy_exact() {
            return None;
        }
        let numeric = fingerprint
            .strip_prefix(self.prefix)?
            .strip_suffix(self.suffix)?;
        if numeric.is_empty()
            || !numeric.bytes().all(|byte| byte.is_ascii_digit())
            || (numeric.len() > 1 && numeric.starts_with('0'))
        {
            return None;
        }
        numeric.bytes().try_fold(0u32, |value, byte| {
            value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
        })
    }

    fn is_legacy_exact(self) -> bool {
        self.prefix.is_empty()
            && self.suffix.is_empty()
            && self.incremental_min == 0
            && self.incremental_max == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/TP1A.220624.014/";
    const PLUS_PREFIX: &str =
        "alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/TP1A.220624.014/";
    const SUFFIX: &str = ":user/release-keys";

    fn ranged_profile() -> DeviceProfile {
        DeviceProfile {
            id: String::new(),
            product_device: String::new(),
            build_fingerprint: format!("{PREFIX}260{SUFFIX}"),
            build_fingerprint_prefix: PREFIX.to_string(),
            build_fingerprint_suffix: SUFFIX.to_string(),
            fingerprint_incremental_min: 19,
            fingerprint_incremental_max: 260,
            kernel_release_prefix: "4.19.191".to_string(),
            kernel_version: "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026".to_string(),
            abi: "arm64-v8a".to_string(),
            late_load_supported: true,
            hooks_supported: true,
        }
    }

    fn ranged_lock() -> AssetsLock {
        AssetsLock {
            schema: 1,
            product_version: "test".to_string(),
            catalog_version: "test".to_string(),
            profile: ranged_profile(),
            device_profiles: Vec::new(),
            ionstack_profiles: vec![
                ionstack_profile(
                    "xpad2-v19-a",
                    "#1 SMP PREEMPT Tue Aug 13 02:06:24 CST 2024",
                    "a",
                ),
                ionstack_profile(
                    "xpad2-v19-b",
                    "#1 SMP PREEMPT Mon Dec 16 23:29:13 CST 2024",
                    "b",
                ),
                ionstack_profile(
                    "xpad2-v260",
                    "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
                    "260",
                ),
            ],
            ionstack_discovery_profiles: vec![
                discovery_profile("xpad2-v19-a", "0x00be6de8"),
                discovery_profile("xpad2-v19-b", "0x00be7210"),
                discovery_profile("xpad2-v260", "0x00be4c48"),
            ],
            ionstack_profiles_v2: Vec::new(),
            ionstack_discovery_profiles_v2: Vec::new(),
            artifacts: Vec::new(),
        }
    }

    fn unified_lock() -> AssetsLock {
        let mut xpad2 = ranged_profile();
        xpad2.id = "xpad2".to_string();
        xpad2.product_device = "ls12_mt8797_wifi_64".to_string();
        xpad2.build_fingerprint = format!("{PREFIX}308{SUFFIX}");
        xpad2.fingerprint_incremental_max = 308;
        xpad2.kernel_version = "#1 SMP PREEMPT Mon Oct 26 15:08:53 CST 2026".to_string();

        let xpad2p = DeviceProfile {
            id: "xpad2p".to_string(),
            product_device: "ls14_mt8797_wifi_64".to_string(),
            build_fingerprint: format!("{PLUS_PREFIX}272{SUFFIX}"),
            build_fingerprint_prefix: PLUS_PREFIX.to_string(),
            build_fingerprint_suffix: SUFFIX.to_string(),
            fingerprint_incremental_min: 19,
            fingerprint_incremental_max: 272,
            kernel_release_prefix: "4.19.191".to_string(),
            kernel_version: "#1 SMP PREEMPT Thu Jul 23 20:38:25 CST 2026".to_string(),
            abi: "arm64-v8a".to_string(),
            late_load_supported: true,
            hooks_supported: true,
        };
        let xpad2_profile = IonStackProfile {
            id: "xpad2-v260-v308".to_string(),
            device_profile_id: "xpad2".to_string(),
            kernel_version: "#1 SMP PREEMPT Mon Oct 26 15:08:53 CST 2026".to_string(),
            kernel_version_alternates: vec![
                "#1 SMP PREEMPT Thu Jul 23 20:40:43 CST 2026".to_string(),
                "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026".to_string(),
            ],
            exact_tuples: vec![
                crate::model::IonStackExactTuple {
                    fingerprint_incremental: 260,
                    kernel_version: "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026".to_string(),
                },
                crate::model::IonStackExactTuple {
                    fingerprint_incremental: 272,
                    kernel_version: "#1 SMP PREEMPT Thu Jul 23 20:40:43 CST 2026".to_string(),
                },
                crate::model::IonStackExactTuple {
                    fingerprint_incremental: 308,
                    kernel_version: "#1 SMP PREEMPT Mon Oct 26 15:08:53 CST 2026".to_string(),
                },
            ],
            runner_artifact: "runner-xpad2".to_string(),
            perf_target_artifact: "perf-xpad2".to_string(),
            preload_artifact: "preload-xpad2".to_string(),
            chainwalk_probe_artifact: "probe-xpad2".to_string(),
        };
        let xpad2p_profile = IonStackProfile {
            id: "xpad2p-v262-v272".to_string(),
            device_profile_id: "xpad2p".to_string(),
            kernel_version: "#1 SMP PREEMPT Thu Jul 23 20:38:25 CST 2026".to_string(),
            kernel_version_alternates: vec![
                "#1 SMP PREEMPT Mon Jun 29 05:28:07 CST 2026".to_string(),
            ],
            exact_tuples: vec![
                crate::model::IonStackExactTuple {
                    fingerprint_incremental: 262,
                    kernel_version: "#1 SMP PREEMPT Mon Jun 29 05:28:07 CST 2026".to_string(),
                },
                crate::model::IonStackExactTuple {
                    fingerprint_incremental: 272,
                    kernel_version: "#1 SMP PREEMPT Thu Jul 23 20:38:25 CST 2026".to_string(),
                },
            ],
            runner_artifact: "runner-xpad2p".to_string(),
            perf_target_artifact: "perf-xpad2p".to_string(),
            preload_artifact: "preload-xpad2p".to_string(),
            chainwalk_probe_artifact: "probe-xpad2p".to_string(),
        };
        AssetsLock {
            schema: 1,
            product_version: "test".to_string(),
            catalog_version: "test".to_string(),
            profile: xpad2.clone(),
            device_profiles: vec![xpad2, xpad2p],
            ionstack_profiles: Vec::new(),
            ionstack_discovery_profiles: Vec::new(),
            ionstack_profiles_v2: vec![xpad2_profile, xpad2p_profile],
            ionstack_discovery_profiles_v2: vec![
                discovery_profile("xpad2-v260-v308", "0x00be4c48"),
                discovery_profile("xpad2p-v262-v272", "0x00be0b18"),
            ],
            artifacts: Vec::new(),
        }
    }

    fn discovery_profile(id: &str, distinct: &str) -> IonStackDiscoveryProfile {
        IonStackDiscoveryProfile {
            profile_id: id.to_string(),
            offsets: [
                ("distinct".to_string(), distinct.to_string()),
                ("shared".to_string(), "0x020fb2b8".to_string()),
            ]
            .into_iter()
            .collect(),
        }
    }

    fn ionstack_profile(id: &str, kernel_version: &str, suffix: &str) -> IonStackProfile {
        IonStackProfile {
            id: id.to_string(),
            device_profile_id: String::new(),
            kernel_version: kernel_version.to_string(),
            kernel_version_alternates: Vec::new(),
            exact_tuples: Vec::new(),
            runner_artifact: format!("runner-{suffix}"),
            perf_target_artifact: "perf".to_string(),
            preload_artifact: format!("preload-{suffix}"),
            chainwalk_probe_artifact: "probe".to_string(),
        }
    }

    #[test]
    fn accepts_every_canonical_incremental_from_19_through_260() {
        let profile = ranged_profile();
        let policy = profile.fingerprint_policy();
        policy.validate().unwrap();
        assert!(!policy.matches(&format!("{PREFIX}18{SUFFIX}")));
        for incremental in 19..=260 {
            let fingerprint = format!("{PREFIX}{incremental}{SUFFIX}");
            assert!(policy.matches(&fingerprint), "rejected {incremental}");
            assert_eq!(policy.incremental(&fingerprint), Some(incremental));
        }
        assert!(!policy.matches(&format!("{PREFIX}261{SUFFIX}")));
    }

    #[test]
    fn product_family_gate_does_not_inherit_the_root_incremental_range() {
        let lock = ranged_lock();
        for incremental in [18, 19, 260, 261, 1_703_659_196] {
            let fingerprint = format!("{PREFIX}{incremental}{SUFFIX}");
            assert!(
                lock.selected_product_profile(&fingerprint, "", "arm64-v8a")
                    .is_some(),
                "product gate rejected {incremental}"
            );
        }
        let timestamp = format!("{PREFIX}1703659196{SUFFIX}");
        assert!(
            lock.selected_technical_profile(&timestamp, "", "4.19.191+", "arm64-v8a")
                .is_none()
        );
        assert!(
            lock.selected_product_profile(&timestamp, "", "armeabi-v7a")
                .is_none()
        );
        assert!(
            lock.selected_product_profile(&format!("{PREFIX}01703659196{SUFFIX}"), "", "arm64-v8a")
                .is_none()
        );
        assert!(
            lock.selected_product_profile(
                "alps/vnd_other/device:13/TP1A.220624.014/260:user/release-keys",
                "",
                "arm64-v8a"
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_noncanonical_or_different_fingerprints() {
        let profile = ranged_profile();
        let policy = profile.fingerprint_policy();
        for fingerprint in [
            format!("{PREFIX}019{SUFFIX}"),
            format!("{PREFIX}+19{SUFFIX}"),
            format!("{PREFIX}{SUFFIX}"),
            format!("{PREFIX}19x{SUFFIX}"),
            format!("{PREFIX}42949672960{SUFFIX}"),
            format!("{PREFIX}19:user/debug-keys"),
            "alps/vnd_other/ls12_mt8797_wifi_64:13/TP1A.220624.014/19:user/release-keys"
                .to_string(),
        ] {
            assert!(!policy.matches(&fingerprint), "accepted {fingerprint}");
        }
    }

    #[test]
    fn range_requires_an_upper_bound_compatibility_anchor() {
        let mut profile = ranged_profile();
        profile.build_fingerprint = format!("{PREFIX}19{SUFFIX}");
        assert!(profile.fingerprint_policy().validate().is_err());
        profile.build_fingerprint = format!("{PREFIX}260{SUFFIX}");
        profile.build_fingerprint_suffix.clear();
        assert!(profile.fingerprint_policy().validate().is_err());
    }

    #[test]
    fn legacy_profile_remains_exact_only() {
        let profile = DeviceProfile {
            id: String::new(),
            product_device: String::new(),
            build_fingerprint: "legacy/exact".to_string(),
            build_fingerprint_prefix: String::new(),
            build_fingerprint_suffix: String::new(),
            fingerprint_incremental_min: 0,
            fingerprint_incremental_max: 0,
            kernel_release_prefix: "4.19".to_string(),
            kernel_version: String::new(),
            abi: "arm64-v8a".to_string(),
            late_load_supported: true,
            hooks_supported: true,
        };
        let policy = profile.fingerprint_policy();
        policy.validate().unwrap();
        assert!(policy.matches("legacy/exact"));
        assert!(!policy.matches("legacy/other"));
    }

    #[test]
    fn fingerprint_range_never_weakens_kernel_or_abi_identity() {
        let profile = ranged_lock();
        let fingerprint = format!("{PREFIX}19{SUFFIX}");
        assert!(profile.matches_runtime(
            &fingerprint,
            "",
            "4.19.191+",
            "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
            "arm64-v8a"
        ));
        assert!(!profile.matches_runtime(
            &fingerprint,
            "",
            "4.19.191+",
            "#1 SMP PREEMPT Wed Dec 27 15:45:11 CST 2023",
            "arm64-v8a"
        ));
        assert!(!profile.matches_runtime(
            &fingerprint,
            "",
            "5.10.198",
            "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
            "arm64-v8a"
        ));
        assert!(!profile.matches_runtime(
            &fingerprint,
            "",
            "4.19.191+",
            "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
            "armeabi-v7a"
        ));
        assert!(!profile.matches_runtime(
            &format!("{PREFIX}1703659196{SUFFIX}"),
            "",
            "4.19.191+",
            "#1 SMP PREEMPT Wed Dec 27 15:45:11 CST 2023",
            "arm64-v8a"
        ));
    }

    #[test]
    fn exact_kernel_build_selects_each_release_artifact_set() {
        let lock = ranged_lock();
        lock.validate_ionstack_profiles().unwrap();
        for (kernel, id, runner, preload) in [
            (
                "#1 SMP PREEMPT Tue Aug 13 02:06:24 CST 2024",
                "xpad2-v19-a",
                "runner-a",
                "preload-a",
            ),
            (
                "#1 SMP PREEMPT Mon Dec 16 23:29:13 CST 2024",
                "xpad2-v19-b",
                "runner-b",
                "preload-b",
            ),
            (
                "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
                "xpad2-v260",
                "runner-260",
                "preload-260",
            ),
        ] {
            let selected = lock.ionstack_artifacts("legacy", kernel, None).unwrap();
            assert_eq!(selected.profile_id, id);
            assert_eq!(selected.runner, runner);
            assert_eq!(selected.preload, preload);
            assert_eq!(selected.perf_target, "perf");
            assert_eq!(selected.chainwalk_probe, "probe");
        }
    }

    #[test]
    fn unknown_kernel_build_enters_discovery_without_becoming_exact() {
        let lock = ranged_lock();
        let fingerprint = format!("{PREFIX}19{SUFFIX}");
        assert!(!lock.matches_runtime(
            &fingerprint,
            "",
            "4.19.191+",
            "#1 SMP PREEMPT unknown",
            "arm64-v8a"
        ));
        assert!(
            lock.selected_technical_profile(&fingerprint, "", "4.19.191+", "arm64-v8a")
                .is_some()
        );
        assert!(
            lock.ionstack_artifacts("legacy", "#1 SMP PREEMPT unknown", None)
                .is_none()
        );
        assert_eq!(lock.ionstack_discovery_profiles.len(), 3);
    }

    #[test]
    fn duplicate_kernel_profiles_are_rejected() {
        let mut lock = ranged_lock();
        lock.ionstack_profiles[1].kernel_version = lock.ionstack_profiles[0].kernel_version.clone();
        assert!(lock.validate_ionstack_profiles().is_err());
    }

    #[test]
    fn unified_launcher_selects_ls12_and_ls14_without_cross_family_fallback() {
        let lock = unified_lock();
        lock.validate_ionstack_profiles().unwrap();

        let ls12_fingerprint = format!("{PREFIX}260{SUFFIX}");
        let ls12 = lock
            .selected_technical_profile(
                &ls12_fingerprint,
                "ls12_mt8797_wifi_64",
                "4.19.191+",
                "arm64-v8a",
            )
            .unwrap();
        assert_eq!(ls12.profile_id(), "xpad2");
        assert!(ls12.late_load_supported);
        let ls12_272_fingerprint = format!("{PREFIX}272{SUFFIX}");
        let ls12_272 = lock
            .ionstack_artifacts(
                "xpad2",
                "#1 SMP PREEMPT Thu Jul 23 20:40:43 CST 2026",
                Some(272),
            )
            .unwrap();
        assert_eq!(ls12_272.profile_id, "xpad2-v260-v308");
        assert_eq!(ls12_272.runner, "runner-xpad2");
        assert!(
            lock.selected_technical_profile(
                &ls12_272_fingerprint,
                "ls12_mt8797_wifi_64",
                "4.19.191+",
                "arm64-v8a",
            )
            .is_some()
        );

        let ls14_fingerprint = format!("{PLUS_PREFIX}272{SUFFIX}");
        let ls14 = lock
            .selected_technical_profile(
                &ls14_fingerprint,
                "ls14_mt8797_wifi_64",
                "4.19.191+",
                "arm64-v8a",
            )
            .unwrap();
        assert_eq!(ls14.profile_id(), "xpad2p");
        assert!(ls14.late_load_supported);
        assert!(ls14.hooks_supported);

        assert!(
            lock.selected_technical_profile(
                &ls14_fingerprint,
                "ls12_mt8797_wifi_64",
                "4.19.191+",
                "arm64-v8a",
            )
            .is_none()
        );
        assert!(
            lock.ionstack_artifacts(
                "xpad2",
                "#1 SMP PREEMPT Thu Jul 23 20:38:25 CST 2026",
                Some(272),
            )
            .is_none()
        );
    }

    #[test]
    fn xpad2_260_through_308_share_one_isolated_artifact_profile() {
        let lock = unified_lock();
        for (incremental, kernel_version) in [
            (260, "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026"),
            (272, "#1 SMP PREEMPT Thu Jul 23 20:40:43 CST 2026"),
            (308, "#1 SMP PREEMPT Mon Oct 26 15:08:53 CST 2026"),
        ] {
            let artifacts = lock
                .ionstack_artifacts("xpad2", kernel_version, Some(incremental))
                .unwrap();
            assert_eq!(artifacts.profile_id, "xpad2-v260-v308");
            assert_eq!(artifacts.runner, "runner-xpad2");
        }
        assert!(
            lock.ionstack_artifacts(
                "xpad2",
                "#1 SMP PREEMPT Thu Jul 23 20:40:43 CST 2026",
                Some(260),
            )
            .is_none()
        );
        assert!(
            lock.ionstack_artifacts(
                "xpad2",
                "#1 SMP PREEMPT Mon Oct 26 15:08:53 CST 2026",
                Some(272),
            )
            .is_none()
        );
        assert_eq!(lock.ionstack_discovery_target("xpad2"), Some("perf-xpad2"));
    }

    #[test]
    fn xpad2_root_range_is_19_through_308_only() {
        let lock = unified_lock();
        for incremental in [19, 260, 272, 308] {
            let fingerprint = format!("{PREFIX}{incremental}{SUFFIX}");
            assert!(
                lock.selected_technical_profile(
                    &fingerprint,
                    "ls12_mt8797_wifi_64",
                    "4.19.191",
                    "arm64-v8a",
                )
                .is_some()
            );
        }
        for incremental in [18, 309] {
            let fingerprint = format!("{PREFIX}{incremental}{SUFFIX}");
            assert!(
                lock.selected_technical_profile(
                    &fingerprint,
                    "ls12_mt8797_wifi_64",
                    "4.19.191",
                    "arm64-v8a",
                )
                .is_none()
            );
        }
    }

    #[test]
    fn xpad2p_262_and_272_share_one_isolated_artifact_profile() {
        let lock = unified_lock();
        for (incremental, kernel_version) in [
            (262, "#1 SMP PREEMPT Mon Jun 29 05:28:07 CST 2026"),
            (272, "#1 SMP PREEMPT Thu Jul 23 20:38:25 CST 2026"),
        ] {
            let artifacts = lock
                .ionstack_artifacts("xpad2p", kernel_version, Some(incremental))
                .unwrap();
            assert_eq!(artifacts.profile_id, "xpad2p-v262-v272");
            assert_eq!(artifacts.runner, "runner-xpad2p");
        }
        assert!(
            lock.ionstack_artifacts(
                "xpad2p",
                "#1 SMP PREEMPT Thu Jul 23 20:38:25 CST 2026",
                Some(262),
            )
            .is_none()
        );
        assert_eq!(
            lock.ionstack_discovery_target("xpad2p"),
            Some("perf-xpad2p")
        );
        assert_eq!(lock.ionstack_discovery_target("xpad2"), Some("perf-xpad2"));
    }

    #[test]
    fn xpad2p_root_range_is_19_through_272_only() {
        let lock = unified_lock();
        for incremental in [19, 262, 272] {
            let fingerprint = format!("{PLUS_PREFIX}{incremental}{SUFFIX}");
            assert!(
                lock.selected_technical_profile(
                    &fingerprint,
                    "ls14_mt8797_wifi_64",
                    "4.19.191",
                    "arm64-v8a",
                )
                .is_some()
            );
        }
        for incremental in [18, 273] {
            let fingerprint = format!("{PLUS_PREFIX}{incremental}{SUFFIX}");
            assert!(
                lock.selected_technical_profile(
                    &fingerprint,
                    "ls14_mt8797_wifi_64",
                    "4.19.191",
                    "arm64-v8a",
                )
                .is_none()
            );
        }
    }

    #[test]
    fn release_catalog_remains_readable_by_the_v0_4_14_shape() {
        #[allow(dead_code)]
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyProfile {
            build_fingerprint: String,
            build_fingerprint_prefix: String,
            build_fingerprint_suffix: String,
            fingerprint_incremental_min: u32,
            fingerprint_incremental_max: u32,
            kernel_release_prefix: String,
            kernel_version: String,
            abi: String,
        }
        #[allow(dead_code)]
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyIonStackProfile {
            id: String,
            kernel_version: String,
            runner_artifact: String,
            perf_target_artifact: String,
            preload_artifact: String,
            chainwalk_probe_artifact: String,
        }
        #[allow(dead_code)]
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyDiscoveryProfile {
            profile_id: String,
            offsets: BTreeMap<String, String>,
        }
        #[derive(serde::Deserialize)]
        struct LegacyAssetsLock {
            schema: u32,
            product_version: String,
            catalog_version: String,
            profile: LegacyProfile,
            ionstack_profiles: Vec<LegacyIonStackProfile>,
            ionstack_discovery_profiles: Vec<LegacyDiscoveryProfile>,
            artifacts: Vec<serde_json::Value>,
        }

        let legacy: LegacyAssetsLock = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/assets.lock.json"
        )))
        .unwrap();
        assert_eq!(legacy.schema, 1);
        assert_eq!(legacy.product_version, "0.7.6");
        assert_eq!(legacy.catalog_version, "2026-11-20.1");
        assert!(legacy.profile.build_fingerprint.contains("/260:"));
        assert_eq!(legacy.profile.kernel_release_prefix, "4.19.191");
        assert_eq!(legacy.profile.abi, "arm64-v8a");
        assert_eq!(legacy.ionstack_profiles.len(), 3);
        assert_eq!(legacy.ionstack_discovery_profiles.len(), 3);
        assert!(
            legacy
                .ionstack_profiles
                .iter()
                .all(|profile| profile.id.starts_with("xpad2-v"))
        );
        assert!(
            legacy
                .ionstack_discovery_profiles
                .iter()
                .all(|profile| profile.profile_id.starts_with("xpad2-v"))
        );
        assert!(!legacy.artifacts.is_empty());
    }
}
