//! Versions of the external tools we drive and the features they support.

use crate::cmd;
use crate::t;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Version {
            major,
            minor,
            patch,
        }
    }

    /// Parse the first `N[.N[.N]]` found in `text`.
    pub fn find_in(text: &str) -> Option<Version> {
        let start = text.find(|c: char| c.is_ascii_digit())?;
        let rest = &text[start..];
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let mut parts = rest[..end].split('.').filter(|s| !s.is_empty());
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        Some(Version {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.minor == 0 && self.patch == 0 && self.major > 100 {
            // systemd versions are a single number
            write!(f, "{}", self.major)
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tools {
    pub cryptsetup: Option<Version>,
    /// Version reported by `systemd-cryptenroll --version`.
    pub systemd: Option<Version>,
    pub has_cryptenroll: bool,
    pub has_tpm2_tools: bool,
    pub has_lsblk: bool,
    /// `cryptsetup luksAddKey --new-key-slot` exists (newer releases warn
    /// that `--key-slot` is ambiguous there).
    pub cryptsetup_new_key_slot: bool,
}

impl Tools {
    pub fn detect() -> Self {
        let cryptsetup = cmd::run("cryptsetup", &["--version"])
            .filter(|o| o.success)
            .and_then(|o| Version::find_in(o.stdout.trim_start_matches("cryptsetup")));
        let systemd = cmd::run("systemd-cryptenroll", &["--version"])
            .filter(|o| o.success)
            .and_then(|o| o.stdout.lines().next().and_then(Version::find_in));
        Tools {
            cryptsetup,
            has_cryptenroll: systemd.is_some(),
            systemd,
            has_tpm2_tools: cmd::which("tpm2_pcrread").is_some(),
            has_lsblk: cmd::which("lsblk").is_some(),
            cryptsetup_new_key_slot: cryptsetup.is_some()
                && cmd::run("cryptsetup", &["--help"])
                    .is_some_and(|o| o.stdout.contains("--new-key-slot")),
        }
    }
}

/// Feature switches derived from tool versions. Features are gated on
/// versions rather than distribution names.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Caps {
    /// `cryptsetup luksDump --dump-json-metadata` (cryptsetup 2.4+).
    pub json_dump: bool,
    /// `cryptsetup token import --token-replace` (cryptsetup 2.6+).
    pub token_replace: bool,
    /// `luksAddKey --new-key-slot`.
    pub new_key_slot: bool,
    /// systemd-cryptenroll exists (systemd 248+): TPM2, FIDO2, PKCS#11, recovery keys.
    pub cryptenroll: bool,
    /// `--fido2-with-client-pin=` / `--fido2-with-user-presence=` / `--fido2-with-user-verification=` (249+).
    pub fido2_options: bool,
    /// `--tpm2-with-pin=` (251+).
    pub tpm2_pin: bool,
    /// `--unlock-key-file=` (252+).
    pub unlock_key_file: bool,
    /// `--tpm2-public-key=` signed PCR policies (252+).
    pub tpm2_public_key: bool,
    /// `--tpm2-pcrlock=` (255+).
    pub tpm2_pcrlock: bool,
    /// `--unlock-fido2-device=` (253+).
    pub unlock_fido2: bool,
    /// `--unlock-tpm2-device=` (256+).
    pub unlock_tpm2: bool,
}

impl Caps {
    pub fn from_tools(t: &Tools) -> Self {
        let cs = t.cryptsetup.unwrap_or(Version::new(0, 0, 0));
        let sd = t.systemd.map(|v| v.major).unwrap_or(0);
        Caps {
            json_dump: cs >= Version::new(2, 4, 0),
            token_replace: cs >= Version::new(2, 6, 0),
            new_key_slot: t.cryptsetup_new_key_slot,
            cryptenroll: t.has_cryptenroll && sd >= 248,
            fido2_options: sd >= 249,
            tpm2_pin: sd >= 251,
            unlock_key_file: sd >= 252,
            tpm2_public_key: sd >= 252,
            tpm2_pcrlock: sd >= 255,
            unlock_fido2: sd >= 253,
            unlock_tpm2: sd >= 256,
        }
    }

    /// Human readable list of (feature, available).
    pub fn describe(&self) -> Vec<(&'static str, bool)> {
        vec![
            (t!("JSON 头部导出 (cryptsetup ≥ 2.4)"), self.json_dump),
            ("systemd-cryptenroll (systemd ≥ 248)", self.cryptenroll),
            (t!("FIDO2 PIN/触摸/验证选项 (≥ 249)"), self.fido2_options),
            ("TPM2 + PIN (≥ 251)", self.tpm2_pin),
            (
                t!("用密钥文件验证 --unlock-key-file (≥ 252)"),
                self.unlock_key_file,
            ),
            (t!("TPM2 签名 PCR 策略 (≥ 252)"), self.tpm2_public_key),
            ("TPM2 pcrlock (≥ 255)", self.tpm2_pcrlock),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions() {
        assert_eq!(
            Version::find_in("cryptsetup 2.7.0 flags: UDEV BLKID"),
            Some(Version::new(2, 7, 0))
        );
        assert_eq!(
            Version::find_in("systemd 255 (255.4-1ubuntu8.18)"),
            Some(Version::new(255, 0, 0))
        );
        assert_eq!(Version::new(255, 0, 0).to_string(), "255");
        assert_eq!(Version::new(2, 4, 3).to_string(), "2.4.3");
    }

    #[test]
    fn caps_follow_versions() {
        let t = Tools {
            cryptsetup: Some(Version::new(2, 4, 3)),
            systemd: Some(Version::new(249, 0, 0)),
            has_cryptenroll: true,
            has_tpm2_tools: false,
            has_lsblk: true,
            cryptsetup_new_key_slot: false,
        };
        let c = Caps::from_tools(&t);
        assert!(c.json_dump && c.cryptenroll && c.fido2_options);
        assert!(!c.tpm2_pin && !c.token_replace && !c.unlock_key_file);
    }
}
