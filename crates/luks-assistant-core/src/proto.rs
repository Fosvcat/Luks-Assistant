//! Protocol between the unprivileged GUI and `Luks-Assistant-Helper` (root).
//!
//! The GUI starts the helper with `pkexec` and talks to it over the
//! helper's stdin/stdout: one JSON object per line. Every [`Call`] gets
//! exactly one final [`Reply`] (`ok` or `err`) with the same id, preceded by
//! any number of `event` replies (progress, command output).
//!
//! Plans stay inside the helper (they hold secrets); the GUI only sees a
//! [`PlanView`] and executes a plan by id.

use crate::ctx::Paths;
use crate::forms::{Form, FormKind};
use crate::health::Issue;
use crate::ops::{Credential, Danger, Plan, Report, Request, StepReport, TokenKind};
use crate::secret::Secret;
use crate::slots::Overview;
use crate::view;
use luks_assistant_sysinfo::tools::Caps;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Call {
    pub id: u64,
    #[serde(flatten)]
    pub method: Method,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Method {
    Hello,
    /// → [`view::SystemView`]; `extra` are image files opened explicitly.
    SystemView {
        extra: Vec<PathBuf>,
    },
    /// → [`DeviceReply`]
    DeviceView {
        path: PathBuf,
    },
    /// → `Vec<view::BackupRow>`
    BackupRows {
        paths: Vec<PathBuf>,
    },
    /// → [`Form`]
    BuildForm {
        path: PathBuf,
        kind: FormKind,
    },
    /// → [`SubmitReply`]
    SubmitForm {
        path: PathBuf,
        form: Form,
    },
    /// → `Vec<String>`: meaning of the selected PCRs and warnings
    PcrNotes {
        pcrs: Vec<u8>,
    },
    /// → [`OverviewReply`]
    Overview {
        path: PathBuf,
    },
    /// → [`PlanView`]
    Plan {
        path: PathBuf,
        request: Request,
    },
    /// Header backups of several devices → `Vec<PlanView>`
    PlanBackups {
        paths: Vec<PathBuf>,
    },
    /// → `Vec<ReportView>`; `confirm` must match the plans' confirm word.
    Execute {
        plans: Vec<u64>,
        confirm: String,
    },
    /// → slot number
    VerifyCredential {
        path: PathBuf,
        credential: Credential,
    },
    /// → [`TokenVerified`]
    VerifyToken {
        path: PathBuf,
        kind: TokenKind,
        pin: Option<Secret>,
    },
    /// → [`Paths`]
    SetBackupDir {
        dir: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub id: u64,
    #[serde(flatten)]
    pub body: ReplyBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyBody {
    Ok(serde_json::Value),
    Err(String),
    Event(Event),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "text", rename_all = "snake_case")]
pub enum Event {
    /// A plan step started.
    Progress(String),
    /// Output of an interactive command ("Please touch the security token").
    Output(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub protocol: u32,
    pub version: String,
    pub paths: Paths,
    pub caps: Caps,
    pub tpm2_device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewReply {
    pub overview: Overview,
    pub issues: Vec<Issue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepView {
    pub desc: String,
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanView {
    pub id: u64,
    pub title: String,
    pub device: PathBuf,
    pub steps: Vec<StepView>,
    pub warnings: Vec<String>,
    pub danger: Danger,
    pub confirm_word: Option<String>,
    pub interactive: bool,
}

impl PlanView {
    pub fn new(id: u64, p: &Plan) -> Self {
        PlanView {
            id,
            title: p.title.clone(),
            device: p.device.clone(),
            steps: p
                .steps
                .iter()
                .map(|s| StepView {
                    desc: s.desc().to_owned(),
                    command: s.command(),
                })
                .collect(),
            warnings: p.warnings.clone(),
            danger: p.danger,
            confirm_word: p.confirm_word.clone(),
            interactive: p.is_interactive(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportView {
    pub title: String,
    pub device: PathBuf,
    pub ok: bool,
    pub steps: Vec<StepReport>,
    pub new_slot: Option<u32>,
    /// Shown once to the user, never stored.
    pub recovery_key: Option<Secret>,
    pub error: Option<String>,
    pub backup_file: Option<PathBuf>,
}

impl ReportView {
    pub fn new(p: &Plan, r: Report) -> Self {
        ReportView {
            title: p.title.clone(),
            device: p.device.clone(),
            ok: r.ok,
            steps: r.steps,
            new_slot: r.new_slot,
            recovery_key: r.recovery_key,
            error: r.error,
            backup_file: r.backup_file,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceReply {
    pub device: view::DeviceView,
    pub boot: Vec<luks_assistant_sysinfo::bootcheck::Item>,
}

/// Result of a submitted form.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubmitReply {
    /// A write operation, to be confirmed and executed.
    Plan(PlanView),
    /// Outcome of a verification.
    Message { ok: bool, text: String },
    /// The backup directory changed.
    Paths(Paths),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenVerified {
    pub token: u32,
    pub slots: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let c = Call {
            id: 3,
            method: Method::Overview {
                path: "/dev/sda2".into(),
            },
        };
        let s = serde_json::to_string(&c).unwrap();
        assert_eq!(
            s,
            r#"{"id":3,"method":"overview","params":{"path":"/dev/sda2"}}"#
        );
        let back: Call = serde_json::from_str(&s).unwrap();
        assert!(matches!(back.method, Method::Overview { .. }));
        let c: Call = serde_json::from_str(r#"{"id":1,"method":"hello"}"#).unwrap();
        assert!(matches!(c.method, Method::Hello));

        let r = Reply {
            id: 3,
            body: ReplyBody::Event(Event::Output("touch".into())),
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"id":3,"event":{"kind":"output","text":"touch"}}"#
        );
        let r: Reply = serde_json::from_str(r#"{"id":3,"err":"x"}"#).unwrap();
        assert!(matches!(r.body, ReplyBody::Err(_)));

        let m = SubmitReply::Message {
            ok: true,
            text: "✓".into(),
        };
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            r#"{"kind":"message","ok":true,"text":"✓"}"#
        );
    }

    #[test]
    fn overview_roundtrip() {
        let ov = crate::slots::tests::sample_overview();
        let s = serde_json::to_string(&ov).unwrap();
        let back: Overview = serde_json::from_str(&s).unwrap();
        assert_eq!(back.slots.len(), 32);
        assert_eq!(back.slots[2].kind, ov.slots[2].kind);
    }
}
