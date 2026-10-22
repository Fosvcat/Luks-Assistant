//! Conversion of core data into Slint view models.

use crate::{FieldItem, IssueItem, LineItem, SlotCard};
use luks_assistant_core::device::BlockTree;
use luks_assistant_core::forms::{Field, Value};
use luks_assistant_core::health::{Issue, Severity};
use luks_assistant_core::pcr::{self, TpmStatus};
use luks_assistant_core::proto::PlanView;
use luks_assistant_core::slots::{Overview, Slot, SlotKind};
use luks_assistant_sysinfo::SystemInfo;
use luks_assistant_sysinfo::bootcheck::{Item, Status};
use luks_assistant_sysinfo::tpm::{PcrValues, encode_hex};
use slint::{Color, ModelRc, SharedString, VecModel};

pub fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

pub const NONE: Color = Color::from_argb_u8(0, 0, 0, 0);
pub const GRAY: Color = Color::from_rgb_u8(0x88, 0x88, 0x88);
pub const RED: Color = Color::from_rgb_u8(0xe7, 0x4c, 0x3c);
pub const ORANGE: Color = Color::from_rgb_u8(0xe6, 0x7e, 0x22);
pub const GREEN: Color = Color::from_rgb_u8(0x27, 0xae, 0x60);
pub const BLUE: Color = Color::from_rgb_u8(0x34, 0x98, 0xdb);
pub const PURPLE: Color = Color::from_rgb_u8(0x8e, 0x44, 0xad);
pub const CYAN: Color = Color::from_rgb_u8(0x16, 0xa0, 0x85);
pub const YELLOW: Color = Color::from_rgb_u8(0xd4, 0xac, 0x0d);

pub fn line(text: impl Into<SharedString>) -> LineItem {
    LineItem {
        text: text.into(),
        color: NONE,
        bold: false,
    }
}

pub fn colored(text: impl Into<SharedString>, color: Color) -> LineItem {
    LineItem {
        text: text.into(),
        color,
        bold: false,
    }
}

pub fn bold(text: impl Into<SharedString>) -> LineItem {
    LineItem {
        text: text.into(),
        color: NONE,
        bold: true,
    }
}

pub fn kv(k: &str, v: impl std::fmt::Display) -> LineItem {
    line(format!("{k}：{v}"))
}

pub fn slot_color(s: &Slot) -> Color {
    match &s.kind {
        SlotKind::Empty => GRAY,
        SlotKind::Passphrase | SlotKind::Keyfile | SlotKind::Secret | SlotKind::Luks1 => GREEN,
        SlotKind::Recovery => CYAN,
        SlotKind::Tpm2 => match s.tpm2_status {
            Some(TpmStatus::Mismatch { .. }) => RED,
            _ => PURPLE,
        },
        SlotKind::Fido2 => YELLOW,
        SlotKind::Pkcs11 => BLUE,
        SlotKind::OtherToken(_) | SlotKind::Reencrypt => GRAY,
    }
}

pub fn slot_cards(ov: &Overview) -> Vec<SlotCard> {
    ov.slots
        .iter()
        .map(|s| {
            let subtitle = match (&s.note, &s.tpm2_status) {
                (_, Some(TpmStatus::Mismatch { .. })) => "⚠ PCR 已变化".to_owned(),
                (Some(n), _) if !n.note.text.is_empty() => n.note.text.clone(),
                (_, Some(TpmStatus::Match)) => {
                    format!("✓ PCR {}", pcr::format_list(&s.tpm2.as_ref().unwrap().pcrs))
                }
                _ if s.is_empty() => String::new(),
                _ => s.summary(),
            };
            SlotCard {
                title: if s.is_empty() {
                    format!("{:02}", s.id)
                } else {
                    format!("{:02}  {}", s.id, s.kind.label())
                }
                .into(),
                subtitle: subtitle.into(),
                color: slot_color(s),
                empty: s.is_empty(),
            }
        })
        .collect()
}

pub fn slot_detail(ov: &Overview, id: u32) -> Vec<LineItem> {
    let mut v = Vec::new();
    let Some(s) = ov.slot(id) else { return v };
    if s.is_empty() {
        v.push(colored("空闲", GRAY));
    } else {
        v.push(kv("类型", s.kind.label()));
        if let Some(ks) = &s.keyslot {
            v.push(kv("KDF", ks.kdf.summary()));
            v.push(kv("优先级", ks.priority.label()));
            if let Some(e) = &ks.area_encryption {
                v.push(kv("槽位加密", format!("{e}  {} 位", ks.key_size * 8)));
            }
        }
        if !s.tokens.is_empty() {
            v.push(kv("令牌", format!("{:?}", s.tokens)));
        }
        v.push(kv(
            "备注",
            match &s.note {
                Some(n) => format!(
                    "{}  [{}{}]",
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
            v.push(kv("TPM2", t.describe()));
            if let Some(st) = &s.tpm2_status {
                let c = match st {
                    TpmStatus::Match => GREEN,
                    TpmStatus::Mismatch { .. } => RED,
                    TpmStatus::Unknown(_) => ORANGE,
                };
                v.push(LineItem {
                    text: format!("状态：{}", st.label()).into(),
                    color: c,
                    bold: true,
                });
            }
            if let Some(h) = &t.policy_hash {
                v.push(kv("策略哈希", h));
            }
        }
        if let Some(f) = &s.fido2 {
            v.push(kv(
                "FIDO2",
                format!("{}  RP: {}", f.describe(), f.rp.clone().unwrap_or_default()),
            ));
        }
        if let Some(u) = &s.pkcs11_uri {
            v.push(kv("PKCS#11", u));
        }
    }
    let seg = ov.header.segments.first();
    v.push(line(""));
    v.push(colored(
        format!(
            "卷：{} · 扇区 {} · JSON {}/{} 字节",
            seg.and_then(|s| s.encryption.clone()).unwrap_or_default(),
            seg.and_then(|s| s.sector_size).unwrap_or(0),
            ov.header.json_used,
            ov.header.config.json_size
        ),
        GRAY,
    ));
    if let Some(r) = ov.read_only_reason() {
        v.push(colored(r, ORANGE));
    }
    v
}

pub fn system_lines(
    sys: &SystemInfo,
    tpm2_device: &str,
    fido2: &[String],
    pkcs11: &[String],
) -> Vec<LineItem> {
    let ver = |v: Option<luks_assistant_sysinfo::tools::Version>| {
        v.map(|v| v.to_string()).unwrap_or_else(|| "未安装".into())
    };
    let mut v = vec![
        kv("发行版", &sys.os.pretty_name),
        kv("系列", sys.os.family.label()),
        kv("内核", &sys.os.kernel),
        kv("主机名", &sys.os.hostname),
        kv("cryptsetup", ver(sys.tools.cryptsetup)),
        kv("systemd", ver(sys.tools.systemd)),
        kv("固件", if sys.firmware.uefi { "UEFI" } else { "BIOS" }),
        kv("安全启动", sys.firmware.secure_boot_label()),
        line(""),
        bold("TPM"),
    ];
    if sys.tpm.present {
        v.push(kv(
            "版本",
            format!("TPM {}.0", sys.tpm.version_major.unwrap_or(0)),
        ));
        v.push(kv(
            "设备",
            sys.tpm
                .dev_node
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        ));
        v.push(kv("驱动", sys.tpm.driver.clone().unwrap_or_default()));
        v.push(kv("描述", sys.tpm.description.clone().unwrap_or_default()));
        v.push(kv("PCR bank", sys.tpm.banks.join(", ")));
    } else {
        v.push(colored("未检测到", GRAY));
    }
    if tpm2_device != "auto" {
        v.push(kv("覆盖", tpm2_device));
    }
    for (title, list) in [("FIDO2 安全密钥", fido2), ("PKCS#11 智能卡", pkcs11)] {
        v.push(line(""));
        v.push(bold(title));
        if list.is_empty() {
            v.push(colored("未检测到", GRAY));
        }
        v.extend(list.iter().map(|x| line(x.clone())));
    }
    v.push(line(""));
    v.push(bold("功能"));
    for (name, ok) in sys.caps.describe() {
        v.push(colored(
            format!("{} {name}", if ok { "✓" } else { "✗" }),
            if ok { GREEN } else { RED },
        ));
    }
    v
}

pub fn disk_lines(tree: &BlockTree) -> Vec<LineItem> {
    let (luks, total) = tree.volume_counts();
    let mut v = vec![colored(format!("LUKS 卷 {luks}/{total}"), GRAY)];
    for (depth, n) in tree.flatten() {
        let name = n.path.rsplit('/').next().unwrap_or(&n.path);
        let trim = match n.trim() {
            Some(true) => "TRIM ✓",
            Some(false) => "TRIM ✗",
            None => "",
        };
        let mp = n
            .mountpoints
            .first()
            .map(|m| format!(" {m}"))
            .unwrap_or_default();
        let text = format!(
            "{}{name}  {}  {}  {trim}{mp}",
            "    ".repeat(depth),
            n.size.clone().unwrap_or_default(),
            n.encryption()
        );
        let color = if n.is_luks() {
            GREEN
        } else if n.kind == "crypt" {
            CYAN
        } else {
            NONE
        };
        v.push(colored(text, color));
    }
    v
}

pub fn pcr_lines(values: Option<&Result<PcrValues, String>>, bound: &[u8]) -> Vec<LineItem> {
    let mut v = Vec::new();
    if let Some(Err(e)) = values {
        v.push(colored(e.clone(), ORANGE));
    }
    for info in pcr::PCRS.iter() {
        let val = values
            .and_then(|r| r.as_ref().ok())
            .and_then(|m| m.get(&info.index))
            .map(|b| encode_hex(b))
            .unwrap_or_default();
        let short = if val.is_empty() {
            "—".to_owned()
        } else {
            format!("{}…", &val[..12.min(val.len())])
        };
        let used = bound.contains(&info.index);
        v.push(LineItem {
            text: format!(
                "{:>2}{}  {short}  {}",
                info.index,
                if used { "*" } else { " " },
                info.name
            )
            .into(),
            color: if used { PURPLE } else { NONE },
            bold: used,
        });
    }
    v.push(colored("* 已被 TPM2 槽位使用", GRAY));
    v
}

pub fn issue_items(issues: &[Issue]) -> Vec<IssueItem> {
    issues
        .iter()
        .map(|i| IssueItem {
            severity: i.severity.label().into(),
            color: match i.severity {
                Severity::Critical => RED,
                Severity::Warning => ORANGE,
                Severity::Info => BLUE,
            },
            title: i.title.clone().into(),
            detail: i.detail.clone().into(),
            fixable: i.fix.is_some(),
        })
        .collect()
}

pub fn boot_lines(items: &[Item]) -> Vec<LineItem> {
    items
        .iter()
        .map(|i| {
            let c = match i.status {
                Status::Ok => GREEN,
                Status::Info => BLUE,
                Status::Warn => ORANGE,
                Status::Fail => RED,
                Status::Unknown => GRAY,
            };
            colored(
                format!(
                    "{}  {}：{}",
                    i.status.symbol(),
                    i.title,
                    i.detail.replace('\n', " ")
                ),
                c,
            )
        })
        .collect()
}

pub fn field_items(fields: &[Field]) -> Vec<FieldItem> {
    fields
        .iter()
        .map(|f| {
            let mut item = FieldItem {
                kind: 0,
                label: f.label.clone().into(),
                hint: f.hint.clone().unwrap_or_default().into(),
                text: SharedString::new(),
                checked: false,
                options: model(Vec::<SharedString>::new()),
                index: 0,
                pcrs: model(Vec::<bool>::new()),
            };
            match &f.value {
                Value::Text(t) => item.text = t.clone().into(),
                Value::Secret(t) => {
                    item.kind = 1;
                    item.text = t.clone().into();
                }
                Value::Toggle(b) => {
                    item.kind = 2;
                    item.checked = *b;
                }
                Value::Choice { options, index } => {
                    item.kind = 3;
                    item.options = model(
                        options
                            .iter()
                            .map(|o| SharedString::from(o.as_str()))
                            .collect(),
                    );
                    item.index = *index as i32;
                }
                Value::Pcrs(set) => {
                    item.kind = 4;
                    item.pcrs = model(set.to_vec());
                }
                Value::Label => item.kind = 5,
            }
            item
        })
        .collect()
}

pub fn pcr_notes(selected: &[u8], secure_boot: Option<bool>) -> Vec<LineItem> {
    let mut v = vec![bold(format!(
        "已选 PCR {}",
        if selected.is_empty() {
            "无".into()
        } else {
            pcr::format_list(selected)
        }
    ))];
    for &p in selected {
        let info = &pcr::PCRS[p as usize];
        v.push(colored(
            format!(
                "PCR {p} {}：{}；改变：{}",
                info.name, info.measures, info.changes
            ),
            GRAY,
        ));
    }
    for w in pcr::selection_warnings(selected, secure_boot) {
        v.push(colored(format!("! {w}"), ORANGE));
    }
    v
}

pub fn plan_lines(plans: &[PlanView]) -> Vec<LineItem> {
    let mut v = Vec::new();
    for p in plans {
        v.push(bold(format!("{} — {}", p.title, p.device.display())));
        for w in &p.warnings {
            v.push(colored(format!("  ! {w}"), ORANGE));
        }
        for (i, s) in p.steps.iter().enumerate() {
            v.push(line(format!("{:>2}. {}", i + 1, s.desc)));
            if let Some(c) = &s.command {
                v.push(colored(format!("      $ {c}"), GRAY));
            }
        }
        v.push(line(""));
    }
    v
}
