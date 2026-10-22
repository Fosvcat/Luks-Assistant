//! Header health check ("元数据体检").

use crate::notes::{self, Location};
use crate::ops::Request;
use crate::pcr::TpmStatus;
use crate::slots::{Overview, SlotKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "严重",
            Severity::Warning => "警告",
            Severity::Info => "提示",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// A request that fixes the issue without further input, if any.
    pub fix: Option<Request>,
}

fn issue(
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
    fix: Option<Request>,
) -> Issue {
    Issue {
        severity,
        title: title.into(),
        detail: detail.into(),
        fix,
    }
}

pub fn check(ov: &Overview) -> Vec<Issue> {
    let mut out = Vec::new();
    if let Some(r) = ov.read_only_reason() {
        out.push(issue(Severity::Warning, "只读设备", r, None));
    }

    let knowledge = ov.knowledge_slots();
    if knowledge.is_empty() {
        out.push(issue(
            Severity::Critical,
            "没有任何密码/恢复密钥槽位",
            "只剩硬件令牌可以解锁，请添加密码或恢复密钥。",
            None,
        ));
    } else if knowledge.len() == 1 {
        out.push(issue(
            Severity::Warning,
            "只有一个密码/恢复密钥槽位",
            format!("槽位 {} 是唯一的备用解锁方式。", knowledge[0]),
            None,
        ));
    }

    for t in ov.header.tokens.values() {
        if t.keyslots.is_empty() && t.kind != notes::TOKEN_TYPE {
            out.push(issue(
                Severity::Warning,
                format!("孤立令牌 {}（{}）", t.id, t.kind),
                "未关联任何槽位（通常是 luksKillSlot 的遗留）。",
                Some(Request::RemoveOrphanToken { token: t.id }),
            ));
        }
        if t.keyslots.len() > 1 {
            out.push(issue(
                Severity::Info,
                format!("令牌 {} 关联了多个槽位 {:?}", t.id, t.keyslots),
                "systemd-cryptenroll --wipe-slot 会连带擦除其它槽位。",
                None,
            ));
        }
    }
    for s in ov.used() {
        if s.tokens.len() > 1 {
            out.push(issue(
                Severity::Info,
                format!("槽位 {} 关联了多个令牌 {:?}", s.id, s.tokens),
                "通常由其它工具创建。",
                None,
            ));
        }
    }

    for s in ov.used() {
        match &s.tpm2_status {
            Some(TpmStatus::Mismatch { .. }) => out.push(issue(
                Severity::Warning,
                format!("槽位 {} 的 TPM2 策略与当前 PCR 不匹配", s.id),
                format!("{}。", s.tpm2_status.as_ref().unwrap().label()),
                None,
            )),
            Some(TpmStatus::Unknown(why)) => out.push(issue(
                Severity::Info,
                format!("无法判断槽位 {} 的 TPM2 状态", s.id),
                why.clone(),
                None,
            )),
            _ => {}
        }
        if s.kind.is_plain() {
            if let Some(ks) = &s.keyslot {
                if ks.kdf.kind == "pbkdf2" {
                    out.push(issue(
                        Severity::Info,
                        format!("槽位 {} 使用 PBKDF2", s.id),
                        "可在槽位菜单中转换为 Argon2id。",
                        None,
                    ));
                }
            }
        }
        if let SlotKind::OtherToken(t) = &s.kind {
            out.push(issue(
                Severity::Info,
                format!("槽位 {} 由其它工具管理（{t}）", s.id),
                "luks-assistant 不修改其令牌。",
                None,
            ));
        }
    }

    let stale = ov.notes.stale(&ov.header);
    if !stale.is_empty() {
        let list = stale
            .iter()
            .map(|(l, s)| {
                format!(
                    "{s}{}",
                    if *l == Location::Local {
                        "(本机)"
                    } else {
                        ""
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        out.push(issue(
            Severity::Info,
            "存在过期备注",
            format!("槽位 {list} 已被删除或改写。"),
            Some(Request::PruneNotes),
        ));
    }

    if ov.used().count() as u32 >= crate::MAX_SLOTS - 2 {
        out.push(issue(
            Severity::Info,
            "槽位即将用尽",
            "32 个槽位快满了。",
            None,
        ));
    }
    out.sort_by_key(|i| i.severity);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slots::tests::sample_overview;

    #[test]
    fn finds_orphans_and_pbkdf2() {
        let ov = sample_overview();
        let issues = check(&ov);
        assert!(issues.iter().any(|i| i.title.contains("孤立令牌 7")
            && matches!(i.fix, Some(Request::RemoveOrphanToken { token: 7 }))));
        assert!(!issues.iter().any(|i| i.title.contains("孤立令牌 31")));
        assert!(
            !issues
                .iter()
                .any(|i| i.title.contains("槽位 5 使用 PBKDF2"))
        ); // slot 5 is argon2id
        assert!(issues.iter().all(|i| i.severity != Severity::Critical));
    }

    #[test]
    fn critical_without_knowledge() {
        let mut ov = sample_overview();
        for id in [0, 1, 5] {
            ov.slots[id].kind = SlotKind::Empty;
        }
        let issues = check(&ov);
        assert_eq!(issues[0].severity, Severity::Critical);
    }
}
