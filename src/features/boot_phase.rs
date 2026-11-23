// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::BootPhaseConfig;

/// Boot phase classification for transfer policy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BootPhase {
    /// Firmware PXE ROM bootstrap files.
    PxeRom,
    /// iPXE scripts or executables.
    Ipxe,
    /// Operating-system kernel image.
    Kernel,
    /// Initial RAM filesystem.
    Initrd,
    /// Large operating-system or installer image.
    OsImage,
    /// Bootloader, cloud-init, or other configuration artifact.
    Config,
    /// Artifact unmatched by configured rules.
    Unknown,
}

impl BootPhase {
    /// Number of stable boot-phase variants.
    pub const COUNT: usize = 7;

    /// Stable phase order used by fixed-cardinality metrics.
    pub const ALL: [Self; Self::COUNT] = [
        Self::PxeRom,
        Self::Ipxe,
        Self::Kernel,
        Self::Initrd,
        Self::OsImage,
        Self::Config,
        Self::Unknown,
    ];

    /// Returns the fixed-cardinality metrics index for this phase.
    pub const fn index(self) -> usize {
        match self {
            Self::PxeRom => 0,
            Self::Ipxe => 1,
            Self::Kernel => 2,
            Self::Initrd => 3,
            Self::OsImage => 4,
            Self::Config => 5,
            Self::Unknown => 6,
        }
    }

    /// Returns the stable uppercase label used in metrics and configuration.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PxeRom => "PXE_ROM",
            Self::Ipxe => "IPXE",
            Self::Kernel => "KERNEL",
            Self::Initrd => "INITRD",
            Self::OsImage => "OS_IMAGE",
            Self::Config => "CONFIG",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Parses a case-insensitive configuration name, returning `Unknown` on mismatch.
    pub fn from_name(name: &str) -> Self {
        match name.to_uppercase().as_str() {
            "PXE_ROM" => Self::PxeRom,
            "IPXE" => Self::Ipxe,
            "KERNEL" => Self::Kernel,
            "INITRD" => Self::Initrd,
            "OS_IMAGE" => Self::OsImage,
            "CONFIG" => Self::Config,
            _ => Self::Unknown,
        }
    }
}

/// Return the default relative priority assigned to a boot phase.
///
/// The core uses this value for generic admission and HTTP bandwidth accounting.
/// Optional schedulers may reuse it or supply another policy.
pub fn boot_phase_weight(phase: BootPhase) -> f64 {
    match phase {
        BootPhase::PxeRom => 10.0,
        BootPhase::Ipxe => 8.0,
        BootPhase::Kernel => 6.0,
        BootPhase::Initrd => 5.0,
        BootPhase::OsImage => 3.0,
        BootPhase::Config => 8.0,
        BootPhase::Unknown => 1.0,
    }
}

/// Transfer parameters selected for one boot phase.
#[derive(Debug, Clone)]
pub struct TransferProfile {
    /// Classified boot stage.
    pub phase: BootPhase,
    /// Preferred DATA payload size in bytes.
    pub block_size: u16,
    /// Maximum number of unacknowledged blocks accepted from the client.
    pub max_window_size: u16,
    /// Initial internal retransmission interval in milliseconds.
    pub retransmit_interval_ms: u64,
    /// Adaptive internal retransmission floor in milliseconds.
    pub min_retransmit_interval_ms: u64,
    /// Adaptive internal retransmission ceiling in milliseconds.
    pub max_retransmit_interval_ms: u64,
    /// Maximum retransmissions before aborting.
    pub max_retries: u8,
}

/// Classifies artifact paths with one precompiled set of configured expressions.
pub struct PhaseClassifier {
    /// Combined expression set used to identify matching rules.
    regex_set: RegexSet,
    /// Rule profiles indexed in the same order as `regex_set`.
    rules: Vec<(Regex, TransferProfile)>,
}

impl PhaseClassifier {
    /// Warns on invalid regex patterns so operators are notified of misconfiguration.
    pub fn new(configs: &[BootPhaseConfig]) -> Self {
        let patterns: Vec<&str> = configs
            .iter()
            .filter(|cfg| {
                if Regex::new(&cfg.pattern).is_err() {
                    warn!(
                        phase = %cfg.name,
                        pattern = %cfg.pattern,
                        "Invalid boot phase regex; phase will not match any files"
                    );
                    false
                } else {
                    true
                }
            })
            .map(|cfg| cfg.pattern.as_str())
            .collect();

        let regex_set = RegexSet::new(&patterns).unwrap_or_else(|_| RegexSet::empty());

        let rules = configs
            .iter()
            .filter_map(|cfg| {
                Regex::new(&cfg.pattern).ok().map(|re| {
                    let phase = BootPhase::from_name(&cfg.name);
                    let profile = TransferProfile {
                        phase,
                        block_size: cfg.block_size,
                        max_window_size: cfg.max_window_size,
                        retransmit_interval_ms: cfg.retransmit_interval_ms,
                        min_retransmit_interval_ms: cfg.min_retransmit_interval_ms,
                        max_retransmit_interval_ms: cfg.max_retransmit_interval_ms,
                        max_retries: cfg.max_retries,
                    };
                    (re, profile)
                })
            })
            .collect();

        Self { regex_set, rules }
    }

    /// Return the phase of the first matching configured expression.
    pub fn classify(&self, path: &str) -> BootPhase {
        if let Some(idx) = self.regex_set.matches(path).iter().next() {
            return self.rules[idx].1.phase;
        }
        BootPhase::Unknown
    }

    /// Return the transfer profile of the first matching expression.
    pub fn profile(&self, path: &str) -> Option<&TransferProfile> {
        if let Some(idx) = self.regex_set.matches(path).iter().next() {
            return Some(&self.rules[idx].1);
        }
        None
    }

    /// Classify and return the matching profile from one expression-set scan.
    pub fn classify_and_profile(&self, path: &str) -> (BootPhase, Option<&TransferProfile>) {
        if let Some(idx) = self.regex_set.matches(path).iter().next() {
            let profile = &self.rules[idx].1;
            return (profile.phase, Some(profile));
        }
        (BootPhase::Unknown, None)
    }

    /// Return the first configured profile for `phase`.
    pub fn profile_for_phase(&self, phase: BootPhase) -> Option<&TransferProfile> {
        self.rules
            .iter()
            .find(|(_, p)| p.phase == phase)
            .map(|(_, p)| p)
    }

    /// Return the number of successfully compiled patterns.
    pub fn pattern_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BootPhaseConfig;

    #[test]
    fn test_classify_kernel() {
        let configs = vec![BootPhaseConfig {
            name: "KERNEL".into(),
            pattern: r"(?i)(vmlinuz|bzImage|kernel)".into(),
            block_size: 8192,
            max_window_size: 32,
            retransmit_interval_ms: 1000,
            min_retransmit_interval_ms: 250,
            max_retransmit_interval_ms: 4000,
            max_retries: 5,
        }];
        let classifier = PhaseClassifier::new(&configs);
        assert_eq!(classifier.classify("boot/vmlinuz-5.15"), BootPhase::Kernel);
        assert_eq!(classifier.classify("random.txt"), BootPhase::Unknown);
    }
}
