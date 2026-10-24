//! Header health check.

use crate::notes::{self, Location};
use crate::ops::Request;
use crate::pcr::TpmStatus;
use crate::slots::{Overview, SlotKind};
use crate::t;
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
            Severity::Critical => t!("Critical"),
            Severity::Warning => t!("Warning"),
            Severity::Info => t!("Info"),
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
        out.push(issue(Severity::Warning, t!("Read-only device"), r, None));
    }

    let knowledge = ov.knowledge_slots();
    if knowledge.is_empty() {
        out.push(issue(
            Severity::Critical,
            t!("No password/recovery key slot"),
            t!("Only hardware tokens can unlock it; add a password or a recovery key."),
            None,
        ));
    } else if knowledge.len() == 1 {
        out.push(issue(
            Severity::Warning,
            t!("Only one password/recovery key slot"),
            t!("Slot {} is the only fallback for unlocking.", knowledge[0]),
            None,
        ));
    }

    for t in ov.header.tokens.values() {
        if t.keyslots.is_empty() && !notes::is_notes_token(&t.kind) {
            out.push(issue(
                Severity::Warning,
                t!("Orphaned token {} ({})", t.id, t.kind),
                t!("Not bound to any slot (usually left behind by luksKillSlot)."),
                Some(Request::RemoveOrphanToken { token: t.id }),
            ));
        }
        if t.keyslots.len() > 1 {
            out.push(issue(
                Severity::Info,
                t!(
                    "Token {} is bound to several slots {}",
                    t.id,
                    format!("{:?}", t.keyslots)
                ),
                t!("systemd-cryptenroll --wipe-slot would also wipe the other slots."),
                None,
            ));
        }
    }
    for s in ov.used() {
        if s.tokens.len() > 1 {
            out.push(issue(
                Severity::Info,
                t!(
                    "Slot {} is bound to several tokens {}",
                    s.id,
                    format!("{:?}", s.tokens)
                ),
                t!("Usually created by another tool."),
                None,
            ));
        }
    }

    for s in ov.used() {
        match &s.tpm2_status {
            Some(TpmStatus::Mismatch { .. }) => out.push(issue(
                Severity::Warning,
                t!(
                    "The TPM2 policy of slot {} does not match the current PCRs",
                    s.id
                ),
                t!("{}.", s.tpm2_status.as_ref().unwrap().label()),
                None,
            )),
            Some(TpmStatus::Unknown(why)) => out.push(issue(
                Severity::Info,
                t!("Cannot tell the TPM2 state of slot {}", s.id),
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
                        t!("Slot {} uses PBKDF2", s.id),
                        t!("It can be converted to Argon2id from the slot menu."),
                        None,
                    ));
                }
            }
        }
        if let SlotKind::OtherToken(t) = &s.kind {
            out.push(issue(
                Severity::Info,
                t!("Slot {} is managed by another tool ({})", s.id, t),
                t!("Luks Assistant does not change its tokens."),
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
                        t!("(local)")
                    } else {
                        ""
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        out.push(issue(
            Severity::Info,
            t!("Stale notes"),
            t!("Slot {} was removed or rewritten.", list),
            Some(Request::PruneNotes),
        ));
    }

    if ov.used().count() as u32 >= crate::MAX_SLOTS - 2 {
        out.push(issue(
            Severity::Info,
            t!("Running out of slots"),
            t!("The 32 slots are almost full."),
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
        assert!(issues.iter().any(|i| i.title.contains("Orphaned token 7")
            && matches!(i.fix, Some(Request::RemoveOrphanToken { token: 7 }))));
        assert!(!issues.iter().any(|i| i.title.contains("Orphaned token 31")));
        assert!(
            !issues
                .iter()
                .any(|i| i.title.contains("Slot 5 uses PBKDF2"))
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
