//! Display-ready data for the graphical frontend. Everything here is already
//! formatted, so the GUI only lays it out.

use crate::backup;
use crate::ctx::Ctx;
use crate::device::{self, LuksDevice};
use crate::forms::{self, FormKind};
use crate::health::{Issue, Severity};
use crate::ops::Request;
use crate::pcr::{self, TpmStatus};
use crate::slots::{Overview, Slot, SlotKind};
use crate::util::format_time;
use luks_assistant_sysinfo::SystemInfo;
use luks_assistant_sysinfo::tools::Version;
use luks_assistant_sysinfo::tpm::{PcrValues, encode_hex};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A label/value pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub key: String,
    pub value: String,
}

fn row(k: &str, v: impl Into<String>) -> Row {
    Row {
        key: k.to_owned(),
        value: v.into(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskRow {
    pub depth: usize,
    pub path: String,
    pub name: String,
    pub size: String,
    pub kind: String,
    pub fstype: String,
    pub encryption: String,
    pub trim: Option<bool>,
    pub mount: String,
    pub model: String,
    pub luks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrRow {
    pub index: u8,
    pub value: String,
    pub name: String,
    pub measures: String,
    pub changes: String,
}

/// An entry of the disk picker. Image files given on the command line come
/// first, then the lsblk tree; only LUKS entries are selectable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PickEntry {
    pub depth: usize,
    pub path: String,
    pub text: String,
    pub selectable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemView {
    /// One-line summary for the window header.
    pub summary: String,
    pub system: Vec<Row>,
    pub tpm: Vec<Row>,
    pub fido2: Vec<String>,
    pub pkcs11: Vec<String>,
    pub caps: Vec<(String, bool)>,
    pub disks: Vec<DiskRow>,
    pub luks_volumes: usize,
    pub total_volumes: usize,
    pub pcrs: Vec<PcrRow>,
    pub pcr_error: Option<String>,
    pub picker: Vec<PickEntry>,
    pub backup_root: String,
    pub default_backup_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionView {
    pub label: String,
    pub form: FormKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotView {
    pub id: u32,
    /// Machine-readable kind: empty, passphrase, keyfile, secret, recovery,
    /// tpm2, fido2, pkcs11, token, reencrypt, luks1.
    pub kind: String,
    pub kind_label: String,
    pub subtitle: String,
    /// "ok", "bad" (TPM policy no longer matches), "unknown" or "".
    pub state: String,
    pub details: Vec<Row>,
    pub actions: Vec<ActionView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueView {
    /// "critical", "warning", "info"
    pub level: String,
    pub level_label: String,
    pub title: String,
    pub detail: String,
    pub fix: Option<Request>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceView {
    pub path: String,
    pub title: String,
    pub uuid: String,
    pub header: String,
    pub volume: String,
    pub slots: Vec<SlotView>,
    pub trim_header: bool,
    pub trim_device: Option<bool>,
    pub unlocked: bool,
    pub read_only: Option<String>,
    pub issues: Vec<IssueView>,
    pub bound_pcrs: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRow {
    pub path: String,
    pub title: String,
    pub uuid: String,
    pub last: String,
    pub file: String,
    pub count: usize,
}

fn ver(v: Option<Version>) -> String {
    v.map(|v| v.to_string()).unwrap_or_else(|| "未安装".into())
}

pub fn system_view(ctx: &Ctx, extra: &[PathBuf]) -> SystemView {
    let sys = SystemInfo::probe();
    let tree = device::block_tree(ctx).unwrap_or_default();
    let tpm_label = if ctx.tpm2_device != "auto" {
        format!("TPM2 → {}", ctx.tpm2_device)
    } else if sys.tpm.is_tpm2() {
        format!("TPM2 ✓ {}", sys.tpm.banks.join("/"))
    } else {
        "无 TPM".into()
    };
    let summary = format!(
        "{} · 内核 {} · systemd {} · cryptsetup {} · {} · 安全启动 {}",
        sys.os.pretty_name,
        sys.os.kernel,
        ver(sys.tools.systemd),
        ver(sys.tools.cryptsetup),
        tpm_label,
        sys.firmware.secure_boot_label()
    );
    let system = vec![
        row("发行版", sys.os.pretty_name.clone()),
        row("系列", sys.os.family.label()),
        row("内核", sys.os.kernel.clone()),
        row("主机名", sys.os.hostname.clone()),
        row("cryptsetup", ver(sys.tools.cryptsetup)),
        row("systemd", ver(sys.tools.systemd)),
        row("固件", if sys.firmware.uefi { "UEFI" } else { "BIOS" }),
        row("安全启动", sys.firmware.secure_boot_label()),
    ];
    let mut tpm = Vec::new();
    if sys.tpm.present {
        tpm.push(row(
            "版本",
            format!("TPM {}.0", sys.tpm.version_major.unwrap_or(0)),
        ));
        tpm.push(row(
            "设备",
            sys.tpm
                .dev_node
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        ));
        tpm.push(row("驱动", sys.tpm.driver.clone().unwrap_or_default()));
        tpm.push(row("描述", sys.tpm.description.clone().unwrap_or_default()));
        tpm.push(row("PCR bank", sys.tpm.banks.join(", ")));
    } else {
        tpm.push(row("状态", "未检测到"));
    }
    if ctx.tpm2_device != "auto" {
        tpm.push(row("覆盖", ctx.tpm2_device.clone()));
    }
    let disks = tree
        .flatten()
        .into_iter()
        .map(|(depth, n)| DiskRow {
            depth,
            path: n.path.clone(),
            name: n.path.rsplit('/').next().unwrap_or(&n.path).to_owned(),
            size: n.size.clone().unwrap_or_default(),
            kind: n.kind.clone(),
            fstype: n.fstype.clone().unwrap_or_default(),
            encryption: n.encryption(),
            trim: n.trim(),
            mount: n.mountpoints.join(" "),
            model: n.model.clone().unwrap_or_default(),
            luks: n.is_luks(),
        })
        .collect();
    let (luks, total) = tree.volume_counts();
    let (pcrs, pcr_error) = match luks_assistant_sysinfo::tpm::read_pcrs("sha256", &ctx.tpm2_device)
    {
        Ok(v) => (pcr_rows(Some(&v)), None),
        Err(e) => (pcr_rows(None), Some(e)),
    };
    let mut picker: Vec<PickEntry> = extra
        .iter()
        .map(|p| PickEntry {
            depth: 0,
            path: p.to_string_lossy().into_owned(),
            text: format!("{}  镜像文件", p.display()),
            selectable: true,
        })
        .collect();
    for (depth, n) in tree.flatten() {
        let mut text = format!(
            "{}  {}  {}",
            n.path,
            n.size.clone().unwrap_or_default(),
            n.kind
        );
        for extra in [
            n.fstype.clone(),
            n.label.clone().map(|l| format!("[{l}]")),
            n.model.clone(),
            n.mountpoints.first().cloned(),
        ]
        .into_iter()
        .flatten()
        {
            text.push_str("  ");
            text.push_str(&extra);
        }
        picker.push(PickEntry {
            depth,
            path: n.path.clone(),
            text,
            selectable: n.is_luks(),
        });
    }
    SystemView {
        summary,
        system,
        tpm,
        fido2: luks_assistant_sysinfo::fido2::list_devices(),
        pkcs11: luks_assistant_sysinfo::fido2::list_pkcs11(),
        caps: sys
            .caps
            .describe()
            .into_iter()
            .map(|(n, ok)| (n.to_owned(), ok))
            .collect(),
        disks,
        luks_volumes: luks + extra.len(),
        total_volumes: total + extra.len(),
        pcrs,
        pcr_error,
        picker,
        backup_root: ctx.paths.backup_root.to_string_lossy().into_owned(),
        default_backup_root: ctx
            .paths
            .default_backup_root()
            .to_string_lossy()
            .into_owned(),
    }
}

pub fn pcr_rows(values: Option<&PcrValues>) -> Vec<PcrRow> {
    pcr::PCRS
        .iter()
        .map(|info| PcrRow {
            index: info.index,
            value: values
                .and_then(|m| m.get(&info.index))
                .map(|b| encode_hex(b))
                .unwrap_or_default(),
            name: info.name.to_owned(),
            measures: info.measures.to_owned(),
            changes: info.changes.to_owned(),
        })
        .collect()
}

/// Selected PCRs with their meaning, followed by warnings.
pub fn pcr_notes(selected: &[u8], secure_boot: Option<bool>) -> Vec<String> {
    let mut v = vec![format!(
        "已选 PCR {}",
        if selected.is_empty() {
            "无".into()
        } else {
            pcr::format_list(selected)
        }
    )];
    for &p in selected.iter().filter(|p| **p < 24) {
        let info = &pcr::PCRS[p as usize];
        v.push(format!(
            "PCR {p} {}：{}；改变：{}",
            info.name, info.measures, info.changes
        ));
    }
    v.extend(
        pcr::selection_warnings(selected, secure_boot)
            .into_iter()
            .map(|w| format!("⚠ {w}")),
    );
    v
}

fn kind_id(k: &SlotKind) -> &'static str {
    match k {
        SlotKind::Empty => "empty",
        SlotKind::Passphrase => "passphrase",
        SlotKind::Keyfile => "keyfile",
        SlotKind::Secret => "secret",
        SlotKind::Recovery => "recovery",
        SlotKind::Tpm2 => "tpm2",
        SlotKind::Fido2 => "fido2",
        SlotKind::Pkcs11 => "pkcs11",
        SlotKind::OtherToken(_) => "token",
        SlotKind::Reencrypt => "reencrypt",
        SlotKind::Luks1 => "luks1",
    }
}

fn slot_view(s: &Slot, caps: &luks_assistant_sysinfo::tools::Caps) -> SlotView {
    let subtitle = match (&s.note, &s.tpm2_status) {
        (_, Some(TpmStatus::Mismatch { .. })) => "⚠ PCR 已变化".to_owned(),
        (Some(n), _) if !n.note.text.is_empty() => n.note.text.clone(),
        (_, Some(TpmStatus::Match)) => {
            format!("PCR {}", pcr::format_list(&s.tpm2.as_ref().unwrap().pcrs))
        }
        _ if s.is_empty() => String::new(),
        _ => s.summary(),
    };
    let state = match &s.tpm2_status {
        Some(TpmStatus::Match) => "ok",
        Some(TpmStatus::Mismatch { .. }) => "bad",
        Some(TpmStatus::Unknown(_)) => "unknown",
        None => "",
    };
    let mut details = Vec::new();
    if !s.is_empty() {
        details.push(row("类型", s.kind.label()));
        if let Some(ks) = &s.keyslot {
            details.push(row("KDF", ks.kdf.summary()));
            details.push(row("优先级", ks.priority.label()));
            if let Some(e) = &ks.area_encryption {
                details.push(row("槽位加密", format!("{e}  {} 位", ks.key_size * 8)));
            }
        }
        if !s.tokens.is_empty() {
            details.push(row(
                "令牌",
                s.tokens
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }
        details.push(row(
            "备注",
            match &s.note {
                Some(n) => format!(
                    "{}（{}{}）",
                    if n.note.text.is_empty() {
                        "—"
                    } else {
                        &n.note.text
                    },
                    n.location.label(),
                    n.note
                        .kind
                        .map(|k| format!("，{}", k.label()))
                        .unwrap_or_default()
                ),
                None => "—".into(),
            },
        ));
        if let Some(t) = &s.tpm2 {
            details.push(row("TPM2", t.describe()));
            if let Some(st) = &s.tpm2_status {
                details.push(row("状态", st.label()));
            }
            if let Some(h) = &t.policy_hash {
                details.push(row("策略哈希", h.clone()));
            }
        }
        if let Some(f) = &s.fido2 {
            details.push(row("FIDO2", f.describe()));
            if let Some(rp) = &f.rp {
                details.push(row("RP", rp.clone()));
            }
        }
        if let Some(u) = &s.pkcs11_uri {
            details.push(row("PKCS#11", u.clone()));
        }
    }
    SlotView {
        id: s.id,
        kind: kind_id(&s.kind).to_owned(),
        kind_label: if s.is_empty() {
            String::new()
        } else {
            s.kind.label()
        },
        subtitle,
        state: state.to_owned(),
        details,
        actions: forms::slot_actions(s, caps)
            .into_iter()
            .map(|(label, form)| ActionView { label, form })
            .collect(),
    }
}

fn issue_view(i: &Issue) -> IssueView {
    IssueView {
        level: match i.severity {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
        .into(),
        level_label: i.severity.label().into(),
        title: i.title.clone(),
        detail: i.detail.clone(),
        fix: i.fix.clone(),
    }
}

pub fn device_view(ctx: &Ctx, ov: &Overview, issues: &[Issue]) -> DeviceView {
    let tree = device::block_tree(ctx).unwrap_or_default();
    let node = tree.find(&ov.device.path.to_string_lossy());
    let seg = ov.header.segments.first();
    DeviceView {
        path: ov.device.path.to_string_lossy().into_owned(),
        title: ov.device.display_name(),
        uuid: ov.header.uuid.clone(),
        header: format!(
            "LUKS{} · {} · 已用 {}/32",
            ov.header.version,
            ov.header.uuid,
            ov.used().count()
        ),
        volume: format!(
            "{} · 扇区 {} · JSON {}/{} 字节",
            seg.and_then(|s| s.encryption.clone()).unwrap_or_default(),
            seg.and_then(|s| s.sector_size).unwrap_or(0),
            ov.header.json_used,
            ov.header.config.json_size
        ),
        slots: ov.slots.iter().map(|s| slot_view(s, &ctx.caps)).collect(),
        trim_header: ov.header.allows_discards(),
        trim_device: node.and_then(|n| n.mapping().and_then(|m| m.trim()).or(n.trim())),
        unlocked: ov.device.mapping.is_some(),
        read_only: ov.read_only_reason(),
        issues: issues.iter().map(issue_view).collect(),
        bound_pcrs: ov
            .slots
            .iter()
            .filter_map(|s| s.tpm2.as_ref())
            .flat_map(|t| t.pcrs.clone())
            .collect(),
    }
}

/// Backup status of each device in `paths`.
pub fn backup_rows(ctx: &Ctx, paths: &[PathBuf]) -> Vec<BackupRow> {
    let known = device::discover(ctx).unwrap_or_default();
    paths
        .iter()
        .map(|p| {
            let dev = known
                .iter()
                .find(|d| &d.path == p)
                .cloned()
                .unwrap_or_else(|| LuksDevice::from_path(p));
            let uuid = dev
                .uuid
                .clone()
                .or_else(|| crate::header::read(ctx, p).ok().map(|h| h.uuid))
                .unwrap_or_default();
            let files = if uuid.is_empty() {
                Vec::new()
            } else {
                backup::list(&ctx.paths, &uuid)
            };
            BackupRow {
                path: p.to_string_lossy().into_owned(),
                title: format!(
                    "{}  {}",
                    dev.display_name(),
                    dev.size.clone().unwrap_or_default()
                ),
                uuid,
                last: files
                    .first()
                    .map(|b| format_time(b.modified))
                    .unwrap_or_default(),
                file: files
                    .first()
                    .map(|b| b.path.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                count: files.len(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slots::tests::{sample_overview, test_ctx};

    #[test]
    fn device_view_formats_slots() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let ov = sample_overview();
        let v = device_view(&ctx, &ov, &crate::health::check(&ov));
        assert_eq!(v.slots.len(), 32);
        assert_eq!(v.slots[0].kind, "passphrase");
        assert_eq!(v.slots[0].subtitle, "主密码");
        assert_eq!(v.slots[2].kind, "tpm2");
        assert_eq!(v.slots[2].state, "unknown");
        assert_eq!(v.slots[4].kind, "empty");
        assert!(!v.slots[4].actions.is_empty());
        assert!(v.issues.iter().any(|i| i.fix.is_some()));
        // round-trips through JSON for the GUI
        let s = serde_json::to_string(&v).unwrap();
        let back: DeviceView = serde_json::from_str(&s).unwrap();
        assert_eq!(back.slots[2].kind_label, "TPM2");
    }

    #[test]
    fn notes_list_selection() {
        let n = pcr_notes(&[0, 7], Some(true));
        assert_eq!(n[0], "已选 PCR 0+7");
        assert!(n.iter().any(|l| l.starts_with("⚠ PCR 0")));
    }
}
