use crate::error::{Result, msg};
use crate::model::DeviceProfile;

#[derive(Clone, Copy)]
pub struct FingerprintPolicy<'a> {
    exact_anchor: &'a str,
    prefix: &'a str,
    suffix: &'a str,
    incremental_min: u32,
    incremental_max: u32,
}

impl DeviceProfile {
    pub fn fingerprint_policy(&self) -> FingerprintPolicy<'_> {
        FingerprintPolicy {
            exact_anchor: &self.build_fingerprint,
            prefix: &self.build_fingerprint_prefix,
            suffix: &self.build_fingerprint_suffix,
            incremental_min: self.fingerprint_incremental_min,
            incremental_max: self.fingerprint_incremental_max,
        }
    }

    pub fn matches_runtime(
        &self,
        fingerprint: &str,
        kernel_release: &str,
        kernel_version: &str,
        abi: &str,
    ) -> bool {
        self.fingerprint_policy().matches(fingerprint)
            && kernel_release.starts_with(&self.kernel_release_prefix)
            && (self.kernel_version.is_empty() || kernel_version == self.kernel_version)
            && abi == self.abi
    }
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

    pub fn expectation(self) -> String {
        if self.is_legacy_exact() {
            self.exact_anchor.to_string()
        } else {
            format!(
                "{}<canonical {}..={}>{}",
                self.prefix, self.incremental_min, self.incremental_max, self.suffix
            )
        }
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
    const SUFFIX: &str = ":user/release-keys";

    fn ranged_profile() -> DeviceProfile {
        DeviceProfile {
            build_fingerprint: format!("{PREFIX}260{SUFFIX}"),
            build_fingerprint_prefix: PREFIX.to_string(),
            build_fingerprint_suffix: SUFFIX.to_string(),
            fingerprint_incremental_min: 19,
            fingerprint_incremental_max: 260,
            kernel_release_prefix: "4.19.191".to_string(),
            kernel_version: "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026".to_string(),
            abi: "arm64-v8a".to_string(),
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
            build_fingerprint: "legacy/exact".to_string(),
            build_fingerprint_prefix: String::new(),
            build_fingerprint_suffix: String::new(),
            fingerprint_incremental_min: 0,
            fingerprint_incremental_max: 0,
            kernel_release_prefix: "4.19".to_string(),
            kernel_version: String::new(),
            abi: "arm64-v8a".to_string(),
        };
        let policy = profile.fingerprint_policy();
        policy.validate().unwrap();
        assert!(policy.matches("legacy/exact"));
        assert!(!policy.matches("legacy/other"));
    }

    #[test]
    fn fingerprint_range_never_weakens_kernel_or_abi_identity() {
        let profile = ranged_profile();
        let fingerprint = format!("{PREFIX}19{SUFFIX}");
        assert!(profile.matches_runtime(
            &fingerprint,
            "4.19.191+",
            "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
            "arm64-v8a"
        ));
        assert!(!profile.matches_runtime(
            &fingerprint,
            "4.19.191+",
            "#1 SMP PREEMPT Wed Dec 27 15:45:11 CST 2023",
            "arm64-v8a"
        ));
        assert!(!profile.matches_runtime(
            &fingerprint,
            "5.10.198",
            "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
            "arm64-v8a"
        ));
        assert!(!profile.matches_runtime(
            &fingerprint,
            "4.19.191+",
            "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
            "armeabi-v7a"
        ));
        assert!(!profile.matches_runtime(
            &format!("{PREFIX}1703659196{SUFFIX}"),
            "4.19.191+",
            "#1 SMP PREEMPT Wed Dec 27 15:45:11 CST 2023",
            "arm64-v8a"
        ));
    }
}
