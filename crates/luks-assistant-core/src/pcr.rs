//! TPM2 PCR knowledge: descriptions, risk hints, and local evaluation of
//! systemd-tpm2 token policies against the current PCR values.
//!
//! systemd-cryptenroll seals the volume key to a policy whose digest it
//! stores as `tpm2-policy-hash`. For plain PCR policies (optionally with a
//! PIN) that digest is fully determined by the selected PCR values, so we
//! can recompute it from the live PCRs and tell — without touching the
//! TPM's sealed object — whether the slot would unlock right now.

use crate::ctx::Paths;
use crate::error::{Error, Result};
use crate::header::Token;
use luks_assistant_sysinfo::tpm::{PcrValues, decode_hex, encode_hex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct PcrInfo {
    pub index: u8,
    pub name: &'static str,
    pub measures: &'static str,
    pub changes: &'static str,
}

const fn p(
    index: u8,
    name: &'static str,
    measures: &'static str,
    changes: &'static str,
) -> PcrInfo {
    PcrInfo {
        index,
        name,
        measures,
        changes,
    }
}

pub const PCRS: [PcrInfo; 24] = [
    p(
        0,
        "SRTM / 固件代码",
        "主板 UEFI 固件核心代码",
        "更新 BIOS/UEFI、CPU 微码",
    ),
    p(
        1,
        "固件配置",
        "主板固件的配置和策略",
        "修改固件设置、更换硬件",
    ),
    p(
        2,
        "Option ROM 代码",
        "显卡、网卡等外部设备固件",
        "更换或更新外部设备固件",
    ),
    p(
        3,
        "Option ROM 配置",
        "外部设备固件的配置数据",
        "更换或更新外部设备固件",
    ),
    p(
        4,
        "引导程序代码",
        "启动管理器 / 引导的 EFI 程序本身",
        "更新引导程序、UKI 或内核 EFI 文件",
    ),
    p(
        5,
        "引导配置",
        "启动项配置与 GPT 分区表",
        "修改 UEFI 启动顺序、分区表",
    ),
    p(6, "电源事件", "平台电源状态", "睡眠、唤醒等事件"),
    p(
        7,
        "安全启动策略",
        "安全启动开关与证书数据库",
        "开关安全启动、更新 db/dbx/KEK",
    ),
    p(
        8,
        "GRUB 命令",
        "GRUB 执行的命令和参数",
        "修改 grub.cfg、更换主题",
    ),
    p(
        9,
        "GRUB 读取的文件",
        "GRUB 读取的内核、initramfs 等文件",
        "更新内核或 initramfs",
    ),
    p(10, "IMA", "运行时加载的程序和库", "运行期间持续变化"),
    p(11, "UKI 内容", "统一内核镜像的各个段", "更新 UKI"),
    p(
        12,
        "UKI 参数 / 凭据",
        "传给 UKI 的内核参数和系统凭据",
        "修改内核参数",
    ),
    p(13, "系统扩展", "systemd-sysext 镜像", "更改扩展镜像"),
    p(14, "MOK", "shim 的 Machine Owner Key", "注册/删除 MOK"),
    p(
        15,
        "machine-id / 系统身份",
        "machine-id 等身份信息",
        "修改 /etc/machine-id，解锁后可能被 systemd 扩展",
    ),
    p(16, "调试", "调试用途", "root 可随意扩展"),
    p(
        17,
        "DRTM",
        "动态度量 (Intel TXT / AMD SKINIT)",
        "通常未使用",
    ),
    p(18, "DRTM", "动态度量", "通常未使用"),
    p(19, "DRTM", "动态度量", "通常未使用"),
    p(20, "DRTM", "动态度量", "通常未使用"),
    p(21, "DRTM", "动态度量", "通常未使用"),
    p(22, "DRTM", "动态度量", "通常未使用"),
    p(
        23,
        "应用专用",
        "用户/应用写入（systemd、fwupd 等）",
        "可被重置为全零",
    ),
];

/// Hints for a PCR selection. Returned strings are warnings to show before
/// enrolling; none of them blocks the operation.
pub fn selection_warnings(pcrs: &[u8], secure_boot: Option<bool>) -> Vec<String> {
    let mut w = Vec::new();
    if pcrs.is_empty() {
        w.push("未选择 PCR：任何能访问这颗 TPM 的系统都能解锁".into());
        return w;
    }
    for &i in pcrs {
        let msg = match i {
            0 => "PCR 0：BIOS/微码更新后失效",
            2 | 3 => "PCR 2/3：外部设备固件变化后失效",
            4 => "PCR 4：引导程序/UKI 更新后失效",
            8 | 9 => "PCR 8/9：GRUB 配置、内核或 initramfs 更新后失效",
            10 => "PCR 10 (IMA) 运行期间持续变化，不可用",
            11 => "PCR 11：UKI 更新后失效",
            12 => "PCR 12：内核参数变化后失效",
            15 => "PCR 15：systemd 可能在解锁后扩展它",
            16 | 23 => "PCR 16/23 可被用户态改写，无安全性",
            17..=22 => "PCR 17-22 仅用于 DRTM",
            _ => continue,
        };
        let msg = msg.to_owned();
        if !w.contains(&msg) {
            w.push(msg);
        }
    }
    if pcrs.contains(&7) && secure_boot == Some(false) {
        w.push("安全启动未开启，PCR 7 保护有限".into());
    }
    if !pcrs.contains(&7) {
        w.push("建议包含 PCR 7".into());
    }
    w
}

pub fn parse_list(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for part in s.split(['+', ',', ' ']).filter(|p| !p.is_empty()) {
        let n: u8 = part
            .parse()
            .map_err(|_| Error::Invalid(format!("无效的 PCR 编号: {part}")))?;
        if n > 23 {
            return Err(Error::Invalid(format!("PCR 编号超出范围: {n}")));
        }
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out.sort();
    Ok(out)
}

pub fn format_list(pcrs: &[u8]) -> String {
    pcrs.iter().map(u8::to_string).collect::<Vec<_>>().join("+")
}

/// Parsed `systemd-tpm2` token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tpm2Token {
    pub pcrs: Vec<u8>,
    pub bank: String,
    pub primary_alg: Option<String>,
    pub policy_hash: Option<String>,
    pub pin: bool,
    pub pcrlock: bool,
    /// Signed PCR policy (`--tpm2-public-key`): PCRs covered by the signature.
    pub pubkey_pcrs: Vec<u8>,
    pub has_pubkey: bool,
}

impl Tpm2Token {
    pub fn from_token(t: &Token) -> Option<Self> {
        if t.kind != "systemd-tpm2" {
            return None;
        }
        let r = &t.raw;
        // Older systemd uses dashes, newer fields use underscores.
        let get = |a: &str, b: &str| r.get(a).or_else(|| r.get(b));
        let list = |v: Option<&serde_json::Value>| -> Vec<u8> {
            v.and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|n| n.as_u64().map(|n| n as u8))
                        .collect()
                })
                .unwrap_or_default()
        };
        Some(Tpm2Token {
            pcrs: list(get("tpm2-pcrs", "tpm2_pcrs")),
            bank: get("tpm2-pcr-bank", "tpm2_pcr_bank")
                .and_then(|v| v.as_str())
                .unwrap_or("sha256")
                .to_owned(),
            primary_alg: get("tpm2-primary-alg", "tpm2_primary_alg")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            policy_hash: get("tpm2-policy-hash", "tpm2_policy_hash")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            pin: get("tpm2-pin", "tpm2_pin")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            pcrlock: get("tpm2_pcrlock", "tpm2-pcrlock")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            pubkey_pcrs: list(get("tpm2_pubkey_pcrs", "tpm2-pubkey-pcrs")),
            has_pubkey: get("tpm2_pubkey", "tpm2-pubkey").is_some(),
        })
    }

    pub fn describe(&self) -> String {
        let mut s = format!(
            "PCR {} ({})",
            if self.pcrs.is_empty() {
                "无".into()
            } else {
                format_list(&self.pcrs)
            },
            self.bank
        );
        if self.pin {
            s.push_str(" + PIN");
        }
        if self.has_pubkey {
            s.push_str(&format!(
                " + 签名策略(PCR {})",
                format_list(&self.pubkey_pcrs)
            ));
        }
        if self.pcrlock {
            s.push_str(" + pcrlock");
        }
        s
    }
}

fn alg_id(bank: &str) -> Option<u16> {
    Some(match bank {
        "sha1" => 0x0004,
        "sha256" => 0x000B,
        "sha384" => 0x000C,
        "sha512" => 0x000D,
        "sm3_256" => 0x0012,
        _ => return None,
    })
}

const TPM_CC_POLICY_PCR: u32 = 0x0000_017F;
const TPM_CC_POLICY_AUTH_VALUE: u32 = 0x0000_016B;

/// Policy digest systemd computes for a PCR (+ optional PIN) policy.
///
/// policy₀ = 0³²
/// PolicyPCR:       policy = H(policy ‖ TPM_CC_PolicyPCR ‖ TPML_PCR_SELECTION ‖ H(PCR values))
/// PolicyAuthValue: policy = H(policy ‖ TPM_CC_PolicyAuthValue)
pub fn policy_hash(bank: &str, pcrs: &[u8], values: &PcrValues, pin: bool) -> Result<[u8; 32]> {
    let mut policy = [0u8; 32];
    if !pcrs.is_empty() {
        let alg = alg_id(bank).ok_or_else(|| Error::Unsupported(format!("PCR bank {bank}")))?;
        let mut sorted = pcrs.to_vec();
        sorted.sort();
        let mut select = [0u8; 3];
        let mut values_hash = Sha256::new();
        for &i in &sorted {
            select[usize::from(i / 8)] |= 1 << (i % 8);
            let v = values
                .get(&i)
                .ok_or_else(|| Error::Invalid(format!("缺少 PCR {i} 的当前值")))?;
            values_hash.update(v);
        }
        let mut h = Sha256::new();
        h.update(policy);
        h.update(TPM_CC_POLICY_PCR.to_be_bytes());
        h.update(1u32.to_be_bytes()); // TPML_PCR_SELECTION.count
        h.update(alg.to_be_bytes());
        h.update([3u8]); // sizeofSelect
        h.update(select);
        h.update(values_hash.finalize());
        policy = h.finalize().into();
    }
    if pin {
        let mut h = Sha256::new();
        h.update(policy);
        h.update(TPM_CC_POLICY_AUTH_VALUE.to_be_bytes());
        policy = h.finalize().into();
    }
    Ok(policy)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TpmStatus {
    /// The current PCR values satisfy the policy.
    Match,
    /// The PCR values changed since enrollment. `changed` lists the PCRs
    /// that differ from a saved snapshot, when one exists.
    Mismatch { changed: Option<Vec<u8>> },
    /// Cannot be decided locally (signed policy, pcrlock, no PCR access...).
    Unknown(String),
}

impl TpmStatus {
    pub fn label(&self) -> String {
        match self {
            TpmStatus::Match => "PCR 匹配".into(),
            TpmStatus::Mismatch { changed: Some(c) } if !c.is_empty() => {
                format!("PCR {} 已变化", format_list(c))
            }
            TpmStatus::Mismatch { .. } => "PCR 已变化".into(),
            TpmStatus::Unknown(why) => format!("无法判断: {why}"),
        }
    }
}

/// PCR values recorded at a time when a token's policy matched, keyed by
/// policy hash. Lets us name the PCRs that changed later.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshots {
    #[serde(default)]
    pub policies: BTreeMap<String, Snapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub bank: String,
    pub values: BTreeMap<u8, String>,
    pub saved: u64,
}

impl Snapshots {
    pub fn load(paths: &Paths, uuid: &str) -> Self {
        std::fs::read(paths.pcr_snapshots(uuid))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, paths: &Paths, uuid: &str) -> Result<()> {
        let path = paths.pcr_snapshots(uuid);
        crate::util::ensure_private_dir(path.parent().expect("dir"), 0o700)?;
        crate::util::write_atomic(
            &path,
            &serde_json::to_vec_pretty(self).expect("serializable"),
            0o600,
        )?;
        Ok(())
    }

    /// Remember the values of `tok`'s PCRs. Returns true if something new was stored.
    pub fn remember(&mut self, tok: &Tpm2Token, values: &PcrValues) -> bool {
        let Some(hash) = &tok.policy_hash else {
            return false;
        };
        if self.policies.contains_key(hash) {
            return false;
        }
        let vals = tok
            .pcrs
            .iter()
            .filter_map(|i| values.get(i).map(|v| (*i, encode_hex(v))))
            .collect();
        self.policies.insert(
            hash.clone(),
            Snapshot {
                bank: tok.bank.clone(),
                values: vals,
                saved: crate::util::now_unix(),
            },
        );
        true
    }

    /// Drop snapshots of policies no longer present in the header.
    pub fn retain(&mut self, live: &[String]) {
        self.policies.retain(|k, _| live.contains(k));
    }
}

/// Evaluate `tok` against `values` (the current PCRs of `tok.bank`).
pub fn evaluate(tok: &Tpm2Token, values: Option<&PcrValues>, snapshots: &Snapshots) -> TpmStatus {
    if tok.pcrlock {
        return TpmStatus::Unknown("使用 pcrlock 策略".into());
    }
    if tok.has_pubkey {
        return TpmStatus::Unknown("使用签名 PCR 策略".into());
    }
    let Some(expected) = tok.policy_hash.as_deref() else {
        return TpmStatus::Unknown("令牌中没有 tpm2-policy-hash".into());
    };
    let Some(values) = values else {
        return TpmStatus::Unknown(format!("无法读取 {} PCR", tok.bank));
    };
    match policy_hash(&tok.bank, &tok.pcrs, values, tok.pin) {
        Ok(h) if encode_hex(&h).eq_ignore_ascii_case(expected) => TpmStatus::Match,
        Ok(_) => {
            let changed = snapshots.policies.get(expected).map(|snap| {
                snap.values
                    .iter()
                    .filter(|(i, v)| {
                        values
                            .get(i)
                            .map(|cur| encode_hex(cur) != **v)
                            .unwrap_or(true)
                    })
                    .map(|(i, _)| *i)
                    .collect()
            });
            TpmStatus::Mismatch { changed }
        }
        Err(e) => TpmStatus::Unknown(e.to_string()),
    }
}

/// Helper for tests and callers holding hex strings.
pub fn values_from_hex(pairs: &[(u8, &str)]) -> PcrValues {
    pairs
        .iter()
        .map(|(i, h)| (*i, decode_hex(h).expect("hex")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PCR7: &str = "90f4b39548df55ad6187a1d20d731ecee78c545b94afd16f42ef7592d99cd365";
    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    // Vectors captured from systemd 255 systemd-cryptenroll against swtpm.
    #[test]
    fn matches_systemd_policy_hashes() {
        let v = values_from_hex(&[(0, ZERO), (7, PCR7)]);
        assert_eq!(
            encode_hex(&policy_hash("sha256", &[0, 7], &v, false).unwrap()),
            "44f59fc517b8e3f33c65335139f041a99aab7dd77be06f4f912508e6a8f2166c"
        );
        assert_eq!(
            encode_hex(&policy_hash("sha256", &[7], &v, true).unwrap()),
            "32903f7b827c0ac2dbaa6832bee210e3b2364d7f37fcac27cc164c28a97f0d4a"
        );
    }

    #[test]
    fn evaluation_and_snapshots() {
        let tok = Tpm2Token {
            pcrs: vec![0, 7],
            bank: "sha256".into(),
            primary_alg: None,
            policy_hash: Some(
                "44f59fc517b8e3f33c65335139f041a99aab7dd77be06f4f912508e6a8f2166c".into(),
            ),
            pin: false,
            pcrlock: false,
            pubkey_pcrs: vec![],
            has_pubkey: false,
        };
        let good = values_from_hex(&[(0, ZERO), (7, PCR7)]);
        let mut snaps = Snapshots::default();
        assert_eq!(evaluate(&tok, Some(&good), &snaps), TpmStatus::Match);
        assert!(snaps.remember(&tok, &good));
        assert!(!snaps.remember(&tok, &good));

        let mut bad = good.clone();
        bad.insert(0, vec![1; 32]);
        assert_eq!(
            evaluate(&tok, Some(&bad), &snaps),
            TpmStatus::Mismatch {
                changed: Some(vec![0])
            }
        );
        assert_eq!(
            evaluate(&tok, Some(&bad), &Snapshots::default()),
            TpmStatus::Mismatch { changed: None }
        );
        assert!(matches!(
            evaluate(&tok, None, &snaps),
            TpmStatus::Unknown(_)
        ));
    }

    #[test]
    fn lists_and_warnings() {
        assert_eq!(parse_list("7+0").unwrap(), vec![0, 7]);
        assert_eq!(parse_list("").unwrap(), Vec::<u8>::new());
        assert!(parse_list("24").is_err());
        assert_eq!(format_list(&[0, 7]), "0+7");
        assert!(selection_warnings(&[], None)[0].contains("未选择"));
        assert!(selection_warnings(&[7], Some(true)).is_empty());
        let w = selection_warnings(&[4, 9], Some(true));
        assert!(w.iter().any(|m| m.contains("PCR 4")) && w.iter().any(|m| m.contains("PCR 7")));
    }

    #[test]
    fn parses_token() {
        let h = crate::header::tests::sample();
        let t = Tpm2Token::from_token(&h.tokens[&1]).unwrap();
        assert_eq!(t.pcrs, vec![0, 7]);
        assert_eq!(t.describe(), "PCR 0+7 (sha256)");
        assert!(Tpm2Token::from_token(&h.tokens[&0]).is_none());
    }
}
