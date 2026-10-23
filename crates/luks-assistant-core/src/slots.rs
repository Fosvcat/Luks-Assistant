//! The 32-slot view of a device: key slots joined with their tokens, notes
//! and TPM2 policy status.

use crate::ctx::Ctx;
use crate::device::LuksDevice;
use crate::error::Result;
use crate::header::{self, Header, Keyslot, Token};
use crate::notes::{self, KeyKind, Notes, SlotNote};
use crate::pcr::{self, Snapshots, Tpm2Token, TpmStatus};
use luks_assistant_sysinfo::tpm::PcrValues;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotKind {
    Empty,
    /// Plain key slot known (from a Luks Assistant note) to hold a typed passphrase.
    Passphrase,
    /// Plain key slot known to hold a key file.
    Keyfile,
    /// Plain key slot of unknown origin: passphrase or key file.
    Secret,
    /// systemd-cryptenroll recovery key.
    Recovery,
    Tpm2,
    Fido2,
    Pkcs11,
    /// A token type Luks Assistant does not manage (clevis, ...).
    OtherToken(String),
    /// Slot used by an online re-encryption.
    Reencrypt,
    /// LUKS1 key slot (shown only; LUKS1 is not supported).
    Luks1,
}

impl SlotKind {
    pub fn label(&self) -> String {
        match self {
            SlotKind::Empty => "空".into(),
            SlotKind::Passphrase => "密码".into(),
            SlotKind::Keyfile => "密钥文件".into(),
            SlotKind::Secret => "密码/密钥文件".into(),
            SlotKind::Recovery => "恢复密钥".into(),
            SlotKind::Tpm2 => "TPM2".into(),
            SlotKind::Fido2 => "FIDO2".into(),
            SlotKind::Pkcs11 => "PKCS#11".into(),
            SlotKind::OtherToken(t) => format!("令牌:{t}"),
            SlotKind::Reencrypt => "重加密".into(),
            SlotKind::Luks1 => "LUKS1 密钥".into(),
        }
    }

    /// Something the user knows or keeps as a backup (passphrase, key file,
    /// recovery key) — as opposed to a hardware token. At least one such
    /// slot must always remain.
    pub fn is_knowledge(&self) -> bool {
        matches!(
            self,
            SlotKind::Passphrase
                | SlotKind::Keyfile
                | SlotKind::Secret
                | SlotKind::Recovery
                | SlotKind::Luks1
        )
    }

    pub fn is_token(&self) -> bool {
        matches!(
            self,
            SlotKind::Recovery
                | SlotKind::Tpm2
                | SlotKind::Fido2
                | SlotKind::Pkcs11
                | SlotKind::OtherToken(_)
        )
    }

    pub fn is_plain(&self) -> bool {
        matches!(
            self,
            SlotKind::Passphrase | SlotKind::Keyfile | SlotKind::Secret
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Token {
    pub rp: Option<String>,
    pub client_pin: Option<bool>,
    pub user_presence: Option<bool>,
    pub user_verification: Option<bool>,
}

impl Fido2Token {
    fn from_token(t: &Token) -> Self {
        let b = |k: &str| t.raw.get(k).and_then(|v| v.as_bool());
        Fido2Token {
            rp: t
                .raw
                .get("fido2-rp")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            client_pin: b("fido2-clientPin-required"),
            user_presence: b("fido2-up-required"),
            user_verification: b("fido2-uv-required"),
        }
    }

    pub fn describe(&self) -> String {
        let flag = |o: Option<bool>, name: &str| match o {
            Some(true) => Some(name.to_owned()),
            _ => None,
        };
        let parts: Vec<String> = [
            flag(self.client_pin, "PIN"),
            flag(self.user_presence, "触摸"),
            flag(self.user_verification, "用户验证"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if parts.is_empty() {
            "无额外要求".into()
        } else {
            format!("需要 {}", parts.join(" + "))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    pub id: u32,
    pub kind: SlotKind,
    pub keyslot: Option<Keyslot>,
    /// Ids of the tokens bound to this slot.
    pub tokens: Vec<u32>,
    pub note: Option<SlotNote>,
    pub tpm2: Option<Tpm2Token>,
    pub tpm2_status: Option<TpmStatus>,
    pub fido2: Option<Fido2Token>,
    pub pkcs11_uri: Option<String>,
}

impl Slot {
    pub fn is_empty(&self) -> bool {
        self.kind == SlotKind::Empty
    }

    /// One-line summary for lists and detail panes.
    pub fn summary(&self) -> String {
        match &self.kind {
            SlotKind::Empty => "空闲".into(),
            SlotKind::Tpm2 => self.tpm2.as_ref().map(|t| t.describe()).unwrap_or_default(),
            SlotKind::Fido2 => self
                .fido2
                .as_ref()
                .map(|f| f.describe())
                .unwrap_or_default(),
            SlotKind::Pkcs11 => self.pkcs11_uri.clone().unwrap_or_default(),
            _ => self
                .keyslot
                .as_ref()
                .map(|k| k.kdf.summary())
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overview {
    pub device: LuksDevice,
    pub header: Header,
    pub notes: Notes,
    pub slots: Vec<Slot>,
    /// Current PCR values per bank (or why they could not be read).
    pub pcr_values: BTreeMap<String, Result<PcrValues, String>>,
    #[serde(skip)]
    pub snapshots: Snapshots,
}

/// Classify a slot from its tokens and note.
pub fn classify(header: &Header, ks: &Keyslot, note: Option<&SlotNote>) -> SlotKind {
    if header.version == 1 {
        return SlotKind::Luks1;
    }
    if ks.kind == "reencrypt" {
        return SlotKind::Reencrypt;
    }
    let mut kind = None;
    for t in header
        .tokens_for(ks.id)
        .filter(|t| !notes::is_notes_token(&t.kind))
    {
        let k = match t.kind.as_str() {
            "systemd-tpm2" => SlotKind::Tpm2,
            "systemd-fido2" => SlotKind::Fido2,
            "systemd-pkcs11" => SlotKind::Pkcs11,
            "systemd-recovery" => SlotKind::Recovery,
            other => SlotKind::OtherToken(other.to_owned()),
        };
        // Prefer the systemd kinds if several tokens point here.
        if kind.is_none() || matches!(kind, Some(SlotKind::OtherToken(_))) {
            kind = Some(k);
        }
    }
    kind.unwrap_or(match note.and_then(|n| n.note.kind) {
        Some(KeyKind::Passphrase) => SlotKind::Passphrase,
        Some(KeyKind::Keyfile) => SlotKind::Keyfile,
        None => SlotKind::Secret,
    })
}

impl Overview {
    pub fn load(ctx: &Ctx, mut device: LuksDevice) -> Result<Self> {
        let header = header::read(ctx, &device.path)?;
        if device.uuid.is_none() {
            device.uuid = Some(header.uuid.clone());
        }
        Ok(Self::build(ctx, device, header))
    }

    /// Assemble the view from an already-read header.
    pub fn build(ctx: &Ctx, device: LuksDevice, header: Header) -> Self {
        let notes = Notes::load(&header, &ctx.paths);
        let snapshots = Snapshots::load(&ctx.paths, &header.uuid);
        let mut pcr_values: BTreeMap<String, Result<PcrValues, String>> = BTreeMap::new();
        let mut slots = Vec::with_capacity(crate::MAX_SLOTS as usize);
        for id in 0..crate::MAX_SLOTS {
            let Some(ks) = header.keyslots.get(&id) else {
                slots.push(Slot {
                    id,
                    kind: SlotKind::Empty,
                    keyslot: None,
                    tokens: Vec::new(),
                    note: None,
                    tpm2: None,
                    tpm2_status: None,
                    fido2: None,
                    pkcs11_uri: None,
                });
                continue;
            };
            let note = notes.for_slot(&header, id);
            let kind = classify(&header, ks, note.as_ref());
            let bound: Vec<&Token> = header
                .tokens_for(id)
                .filter(|t| !notes::is_notes_token(&t.kind))
                .collect();
            let tpm2 = bound.iter().find_map(|t| Tpm2Token::from_token(t));
            let tpm2_status = tpm2.as_ref().map(|t| {
                let vals = pcr_values.entry(t.bank.clone()).or_insert_with(|| {
                    luks_assistant_sysinfo::tpm::read_pcrs(&t.bank, &ctx.tpm2_device)
                });
                pcr::evaluate(t, vals.as_ref().ok(), &snapshots)
            });
            slots.push(Slot {
                id,
                kind,
                keyslot: Some(ks.clone()),
                tokens: bound.iter().map(|t| t.id).collect(),
                tpm2,
                tpm2_status,
                fido2: bound
                    .iter()
                    .find(|t| t.kind == "systemd-fido2")
                    .map(|t| Fido2Token::from_token(t)),
                pkcs11_uri: bound
                    .iter()
                    .find(|t| t.kind == "systemd-pkcs11")
                    .and_then(|t| {
                        t.raw
                            .get("pkcs11-uri")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    }),
                note,
            });
        }
        Overview {
            device,
            header,
            notes,
            slots,
            pcr_values,
            snapshots,
        }
    }

    pub fn slot(&self, id: u32) -> Option<&Slot> {
        self.slots.get(id as usize)
    }

    pub fn used(&self) -> impl Iterator<Item = &Slot> {
        self.slots.iter().filter(|s| !s.is_empty())
    }

    pub fn knowledge_slots(&self) -> Vec<u32> {
        self.used()
            .filter(|s| s.kind.is_knowledge())
            .map(|s| s.id)
            .collect()
    }

    pub fn uuid(&self) -> &str {
        &self.header.uuid
    }

    pub fn read_only_reason(&self) -> Option<String> {
        if !self.header.is_luks2() {
            return Some("不支持 LUKS1，仅支持 LUKS2".into());
        }
        if !self.header.config.requirements.is_empty() {
            return Some(format!(
                "头部有强制要求 {:?}，只读",
                self.header.config.requirements
            ));
        }
        None
    }

    /// Record PCR values for TPM2 tokens whose policy currently matches, so
    /// that a later mismatch can name the PCRs that changed. Also forgets
    /// snapshots of tokens that no longer exist. Returns true if the
    /// snapshot file was updated.
    pub fn remember_pcrs(&mut self, ctx: &Ctx) -> Result<bool> {
        let mut changed = false;
        let mut live = Vec::new();
        for s in &self.slots {
            let (Some(tok), Some(status)) = (&s.tpm2, &s.tpm2_status) else {
                continue;
            };
            if let Some(h) = &tok.policy_hash {
                live.push(h.clone());
            }
            if *status == TpmStatus::Match {
                if let Some(Ok(vals)) = self.pcr_values.get(&tok.bank) {
                    changed |= self.snapshots.remember(tok, vals);
                }
            }
        }
        let before = self.snapshots.policies.len();
        self.snapshots.retain(&live);
        changed |= before != self.snapshots.policies.len();
        if changed {
            self.snapshots.save(&ctx.paths, &self.header.uuid)?;
        }
        Ok(changed)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ctx::Paths;
    use crate::exec::SystemRunner;
    use luks_assistant_sysinfo::tools::{Caps, Tools};

    pub fn test_ctx(root: &std::path::Path) -> Ctx {
        Ctx {
            runner: Box::new(SystemRunner),
            paths: Paths::under(root),
            caps: Caps::default(),
            tools: Tools {
                cryptsetup: None,
                systemd: None,
                has_cryptenroll: false,
                has_tpm2_tools: false,
                has_lsblk: false,
                cryptsetup_new_key_slot: false,
            },
            tpm2_device: "swtpm:host=127.0.0.1,port=1".into(),
            extra_kdf_args: Vec::new(),
        }
    }

    pub fn sample_overview() -> Overview {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let dev = LuksDevice::from_path(std::path::Path::new("/dev/test"));
        Overview::build(&ctx, dev, crate::header::tests::sample())
    }

    #[test]
    fn builds_32_slots() {
        let ov = sample_overview();
        assert_eq!(ov.slots.len(), 32);
        assert_eq!(ov.slots[0].kind, SlotKind::Passphrase); // from the note
        assert_eq!(ov.slots[0].note.as_ref().unwrap().note.text, "主密码");
        assert_eq!(ov.slots[1].kind, SlotKind::Recovery);
        assert_eq!(ov.slots[2].kind, SlotKind::Tpm2);
        assert_eq!(ov.slots[2].tokens, vec![1]);
        assert!(matches!(
            ov.slots[2].tpm2_status,
            Some(TpmStatus::Unknown(_))
        ));
        assert_eq!(ov.slots[3].kind, SlotKind::Fido2);
        assert_eq!(ov.slots[3].summary(), "需要 PIN + 触摸");
        assert_eq!(ov.slots[4].kind, SlotKind::Empty);
        assert_eq!(ov.slots[5].kind, SlotKind::Secret);
        assert_eq!(ov.knowledge_slots(), vec![0, 1, 5]);
        assert!(ov.read_only_reason().is_none());
    }
}
