//! TPM2 device detection and PCR reading.

use crate::cmd;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SYSFS_TPM: &str = "/sys/class/tpm/tpm0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmInfo {
    pub present: bool,
    /// Major TPM version reported by the kernel (2 for TPM 2.0).
    pub version_major: Option<u32>,
    /// Kernel device node used for TPM access (normally /dev/tpmrm0).
    pub dev_node: Option<PathBuf>,
    /// Firmware description of the device, e.g. "TPM 2.0 Device" or the ACPI HID.
    pub description: Option<String>,
    /// Kernel driver bound to the device (tpm_crb, tpm_tis, ...).
    pub driver: Option<String>,
    /// PCR banks exposed through sysfs, e.g. ["sha1", "sha256"].
    pub banks: Vec<String>,
}

impl TpmInfo {
    pub fn detect() -> Self {
        let root = Path::new(SYSFS_TPM);
        if !root.exists() {
            return TpmInfo {
                present: false,
                version_major: None,
                dev_node: None,
                description: None,
                driver: None,
                banks: Vec::new(),
            };
        }
        let version_major = read_trim(&root.join("tpm_version_major")).and_then(|s| s.parse().ok());
        let dev_node = ["/dev/tpmrm0", "/dev/tpm0"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists());
        let description = read_trim(&root.join("device/description"))
            .or_else(|| read_trim(&root.join("device/firmware_node/hid")))
            .or_else(|| read_trim(&root.join("device/modalias")));
        let driver = std::fs::read_link(root.join("device/driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        let mut banks: Vec<String> = std::fs::read_dir(root)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        n.strip_prefix("pcr-").map(str::to_owned)
                    })
                    .collect()
            })
            .unwrap_or_default();
        banks.sort();
        TpmInfo {
            present: true,
            version_major,
            dev_node,
            description,
            driver,
            banks,
        }
    }

    pub fn is_tpm2(&self) -> bool {
        self.present && self.version_major == Some(2)
    }
}

fn read_trim(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// PCR index → raw digest bytes for one bank.
pub type PcrValues = BTreeMap<u8, Vec<u8>>;

/// Read all PCRs of `bank` ("sha256", "sha1", ...).
///
/// `device` follows the systemd-cryptenroll `--tpm2-device=` syntax: `auto`
/// or a `/dev/...` node reads the kernel's sysfs files (kernel ≥ 5.12), a
/// TCTI string such as `swtpm:host=127.0.0.1,port=2321` is read through
/// `tpm2_pcrread` (useful with a software TPM during development).
pub fn read_pcrs(bank: &str, device: &str) -> Result<PcrValues, String> {
    if device == "auto" || device.starts_with('/') {
        match read_pcrs_sysfs(bank) {
            Ok(v) => return Ok(v),
            Err(e) if cmd::which("tpm2_pcrread").is_none() => return Err(e),
            Err(_) => {}
        }
        read_pcrs_tpm2_tools(bank, None)
    } else {
        read_pcrs_tpm2_tools(bank, Some(device))
    }
}

fn read_pcrs_sysfs(bank: &str) -> Result<PcrValues, String> {
    let dir = Path::new(SYSFS_TPM).join(format!("pcr-{bank}"));
    if !dir.is_dir() {
        return Err(format!(
            "{} 不存在（没有 TPM，或内核早于 5.12 不提供 PCR sysfs 接口）",
            dir.display()
        ));
    }
    let mut out = PcrValues::new();
    for i in 0u8..24 {
        let path = dir.join(i.to_string());
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        out.insert(
            i,
            decode_hex(text.trim()).ok_or_else(|| format!("{}: 无法解析", path.display()))?,
        );
    }
    Ok(out)
}

fn read_pcrs_tpm2_tools(bank: &str, tcti: Option<&str>) -> Result<PcrValues, String> {
    let sel = format!("{bank}:all");
    let mut args: Vec<&str> = Vec::new();
    if let Some(t) = tcti {
        args.extend(["-T", t]);
    }
    args.push(&sel);
    let out = cmd::run("tpm2_pcrread", &args).ok_or("未安装 tpm2-tools (tpm2_pcrread)")?;
    if !out.success {
        return Err(format!("tpm2_pcrread 失败: {}", out.stderr.trim()));
    }
    parse_tpm2_pcrread(&out.stdout, bank)
}

/// Parse the YAML-like output of `tpm2_pcrread`.
pub fn parse_tpm2_pcrread(text: &str, bank: &str) -> Result<PcrValues, String> {
    let mut in_bank = false;
    let mut out = PcrValues::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_suffix(':') {
            in_bank = name == bank;
            continue;
        }
        if !in_bank {
            continue;
        }
        if let Some((idx, val)) = t.split_once(':') {
            let idx: u8 = match idx.trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let val = val.trim().trim_start_matches("0x");
            if let Some(bytes) = decode_hex(val) {
                out.insert(idx, bytes);
            }
        }
    }
    if out.is_empty() {
        Err(format!("tpm2_pcrread 输出中没有 {bank} bank"))
    } else {
        Ok(out)
    }
}

/// TPM2 devices as listed by `systemd-cryptenroll --tpm2-device=list`.
pub fn list_tpm2_devices() -> Vec<String> {
    list_devices("--tpm2-device=list")
}

pub(crate) fn list_devices(flag: &str) -> Vec<String> {
    match cmd::run("systemd-cryptenroll", &[flag]) {
        Some(o) if o.success => parse_device_table(&o.stdout),
        _ => Vec::new(),
    }
}

/// Parse the table printed by `--tpm2-device=list` / `--fido2-device=list`:
/// a header line followed by one row per device.
pub fn parse_device_table(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| l.starts_with('/'))
        .collect()
}

pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pcrread() {
        let text = "  sha1:\n    0 : 0x0000000000000000000000000000000000000000\n  sha256:\n    0 : 0x0000000000000000000000000000000000000000000000000000000000000000\n    7 : 0x90F4B39548DF55AD6187A1D20D731ECEE78C545B94AFD16F42EF7592D99CD365\n";
        let v = parse_tpm2_pcrread(text, "sha256").unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(encode_hex(&v[&7])[..8].to_string(), "90f4b395");
        assert_eq!(parse_tpm2_pcrread(text, "sha1").unwrap()[&0].len(), 20);
        assert!(parse_tpm2_pcrread(text, "sha384").is_err());
    }

    #[test]
    fn parses_device_table() {
        let t = "PATH        DEVICE      DRIVER\n/dev/tpmrm0 MSFT0101:00 tpm_crb\n";
        assert_eq!(
            parse_device_table(t),
            vec!["/dev/tpmrm0 MSFT0101:00 tpm_crb"]
        );
        assert!(parse_device_table("No FIDO2 devices found.\n").is_empty());
    }
}
