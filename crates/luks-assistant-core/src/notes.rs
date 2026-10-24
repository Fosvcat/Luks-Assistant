//! Per-slot notes.
//!
//! The LUKS2 header cannot tell a typed passphrase from a key file — both
//! are plain `luks2` key slots — so Luks Assistant lets the user label slots and
//! records the kind of key for slots it creates itself.
//!
//! Notes live either in the header (default; travels with the disk) or in
//! `/etc/luks-assistant/notes/<uuid>.json` (stays on this machine).
//!
//! In the header all notes share ONE token of type `luks-assistant-notes` that is
//! bound to no key slot (`"keyslots": []`). Binding it to slots would be
//! harmful: systemd-cryptenroll `--wipe-slot` also wipes every slot that
//! shares a token with the wiped slot. Because the token is unbound, each
//! note stores a fingerprint of its slot's KDF salt; a note whose
//! fingerprint no longer matches (slot removed or rewritten by another
//! tool) is stale and is ignored.

use crate::ctx::Paths;
use crate::error::{Error, Result};
use crate::header::{Header, Keyslot};
use crate::i18n::Text;
use crate::{t, tx};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const TOKEN_TYPE: &str = "luks-assistant-notes";

/// Is `kind` the type of the notes token?
pub fn is_notes_token(kind: &str) -> bool {
    kind == TOKEN_TYPE
}
pub const MAX_NOTE_CHARS: usize = 64;
/// Bytes kept free in the JSON area when writing notes.
const JSON_HEADROOM: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    Passphrase,
    Keyfile,
}

impl KeyKind {
    pub fn text(self) -> Text {
        match self {
            KeyKind::Passphrase => tx!("Password"),
            KeyKind::Keyfile => tx!("Key file"),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            KeyKind::Passphrase => t!("Password"),
            KeyKind::Keyfile => t!("Key file"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Location {
    Header,
    Local,
}

impl Location {
    pub fn text(self) -> Text {
        match self {
            Location::Header => tx!("In the header"),
            Location::Local => tx!("On this machine (/etc/)"),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Location::Header => t!("In the header"),
            Location::Local => t!("On this machine (/etc/)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    #[serde(default)]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<KeyKind>,
    /// Fingerprint of the slot's KDF salt at the time the note was written.
    pub fp: String,
    #[serde(default)]
    pub updated: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteSet {
    #[serde(default)]
    pub notes: BTreeMap<String, Note>,
}

impl NoteSet {
    pub fn get(&self, slot: u32) -> Option<&Note> {
        self.notes.get(&slot.to_string())
    }

    pub fn set(&mut self, slot: u32, note: Note) {
        self.notes.insert(slot.to_string(), note);
    }

    pub fn remove(&mut self, slot: u32) -> Option<Note> {
        self.notes.remove(&slot.to_string())
    }

    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    pub fn slots(&self) -> impl Iterator<Item = u32> + '_ {
        self.notes.keys().filter_map(|k| k.parse().ok())
    }
}

/// Short, stable identifier of a key slot's current key material.
pub fn fingerprint(ks: &Keyslot) -> String {
    ks.kdf.salt.chars().take(16).collect()
}

/// Notes of one device from both stores.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Notes {
    pub header: NoteSet,
    pub header_token: Option<u32>,
    pub local: NoteSet,
}

/// A note resolved for a slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotNote {
    pub note: Note,
    pub location: Location,
}

impl Notes {
    pub fn load(header: &Header, paths: &Paths) -> Self {
        let (header_token, header_set) = header
            .tokens
            .values()
            .find(|t| is_notes_token(&t.kind))
            .map(|t| {
                (
                    Some(t.id),
                    serde_json::from_value::<NoteSet>(t.raw.clone()).unwrap_or_default(),
                )
            })
            .unwrap_or((None, NoteSet::default()));
        let local = std::fs::read(paths.local_notes(&header.uuid))
            .ok()
            .and_then(|b| serde_json::from_slice::<NoteSet>(&b).ok())
            .unwrap_or_default();
        Notes {
            header: header_set,
            header_token,
            local,
        }
    }

    /// The valid note for `slot` in one store.
    pub fn at(&self, header: &Header, slot: u32, location: Location) -> Option<&Note> {
        let ks = header.keyslots.get(&slot)?;
        let set = match location {
            Location::Header => &self.header,
            Location::Local => &self.local,
        };
        set.get(slot).filter(|n| n.fp == fingerprint(ks))
    }

    /// The valid note for `slot`, preferring the header store.
    pub fn for_slot(&self, header: &Header, slot: u32) -> Option<SlotNote> {
        let ks = header.keyslots.get(&slot)?;
        let fp = fingerprint(ks);
        let pick = |set: &NoteSet, location| {
            set.get(slot).filter(|n| n.fp == fp).map(|n| SlotNote {
                note: n.clone(),
                location,
            })
        };
        pick(&self.header, Location::Header).or_else(|| pick(&self.local, Location::Local))
    }

    /// Notes whose slot is gone or was rewritten: (location, slot).
    pub fn stale(&self, header: &Header) -> Vec<(Location, u32)> {
        let mut out = Vec::new();
        for (loc, set) in [
            (Location::Header, &self.header),
            (Location::Local, &self.local),
        ] {
            for slot in set.slots() {
                let valid = header
                    .keyslots
                    .get(&slot)
                    .is_some_and(|ks| set.get(slot).is_some_and(|n| n.fp == fingerprint(ks)));
                if !valid {
                    out.push((loc, slot));
                }
            }
        }
        out
    }
}

pub fn validate_text(text: &str) -> Result<()> {
    if text.chars().count() > MAX_NOTE_CHARS {
        return Err(Error::Invalid(tx!(
            "Notes are limited to {} characters",
            MAX_NOTE_CHARS
        )));
    }
    if text.chars().any(char::is_control) {
        return Err(Error::Invalid(tx!(
            "Notes cannot contain control characters or line breaks"
        )));
    }
    Ok(())
}

/// Token JSON for the header store.
pub fn token_json(set: &NoteSet) -> String {
    let mut v = serde_json::to_value(set).expect("serializable");
    let obj = v.as_object_mut().expect("object");
    obj.insert("type".into(), TOKEN_TYPE.into());
    obj.insert("keyslots".into(), serde_json::Value::Array(Vec::new()));
    obj.insert("version".into(), 1.into());
    serde_json::to_string(&v).expect("serializable")
}

/// Refuse header writes that would fill the JSON area.
pub fn check_header_space(header: &Header, current: &NoteSet, new: &NoteSet) -> Result<()> {
    let old_len = if current.is_empty() {
        0
    } else {
        token_json(current).len()
    };
    let new_len = if new.is_empty() {
        0
    } else {
        token_json(new).len()
    };
    let projected = header.json_used + new_len.saturating_sub(old_len) + 16;
    let limit = header.config.json_size as usize;
    if limit > 0 && projected + JSON_HEADROOM > limit {
        return Err(Error::Blocked(tx!(
            "Not enough space in the header JSON area (about {} / {} bytes)",
            projected,
            limit
        )));
    }
    Ok(())
}

pub fn write_local(paths: &Paths, uuid: &str, set: &NoteSet) -> Result<()> {
    let path = paths.local_notes(uuid);
    if set.is_empty() {
        match std::fs::remove_file(&path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
    let dir = path.parent().expect("notes dir");
    crate::util::ensure_private_dir(dir, 0o700)?;
    let data = serde_json::to_vec_pretty(set).expect("serializable");
    crate::util::write_atomic(&path, &data, 0o600)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::tests::sample;

    #[test]
    fn reads_header_notes_and_detects_stale() {
        let h = sample();
        let paths = Paths::under(std::path::Path::new("/nonexistent"));
        let mut notes = Notes::load(&h, &paths);
        assert_eq!(notes.header_token, Some(31));
        let n = notes.for_slot(&h, 0).unwrap();
        assert_eq!(n.note.text, "main password");
        assert_eq!(n.note.kind, Some(KeyKind::Passphrase));
        assert_eq!(n.location, Location::Header);
        assert!(notes.stale(&h).is_empty());

        // A note for a slot whose salt changed is stale and ignored.
        notes.header.set(
            5,
            Note {
                text: "old".into(),
                kind: None,
                fp: "nope".into(),
                updated: 0,
            },
        );
        notes.local.set(
            9,
            Note {
                text: "gone".into(),
                kind: None,
                fp: "x".into(),
                updated: 0,
            },
        );
        assert!(notes.for_slot(&h, 5).is_none());
        assert_eq!(
            notes.stale(&h),
            vec![(Location::Header, 5), (Location::Local, 9)]
        );
    }

    #[test]
    fn token_shape() {
        let mut set = NoteSet::default();
        set.set(
            3,
            Note {
                text: "USB stick".into(),
                kind: Some(KeyKind::Keyfile),
                fp: "abc".into(),
                updated: 7,
            },
        );
        let v: serde_json::Value = serde_json::from_str(&token_json(&set)).unwrap();
        assert_eq!(v["type"], TOKEN_TYPE);
        assert_eq!(v["keyslots"], serde_json::json!([]));
        assert_eq!(v["notes"]["3"]["kind"], "keyfile");
        let back: NoteSet = serde_json::from_value(v).unwrap();
        assert_eq!(back, set);
    }

    #[test]
    fn validation_and_space() {
        assert!(validate_text("家里的备用密码").is_ok());
        assert!(validate_text(&"x".repeat(65)).is_err());
        assert!(validate_text("a\nb").is_err());

        let mut h = sample();
        h.json_used = 5000; // typical once TPM2/FIDO2 tokens are present
        let mut big = NoteSet::default();
        for i in 0..32 {
            big.set(
                i,
                Note {
                    text: "长".repeat(64),
                    kind: Some(KeyKind::Keyfile),
                    fp: "0123456789abcdef".into(),
                    updated: 1,
                },
            );
        }
        assert!(check_header_space(&h, &NoteSet::default(), &big).is_err());
        let mut small = NoteSet::default();
        small.set(
            0,
            Note {
                text: "ok".into(),
                kind: None,
                fp: "f".into(),
                updated: 1,
            },
        );
        assert!(check_header_space(&h, &NoteSet::default(), &small).is_ok());
    }

    #[test]
    fn local_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let mut set = NoteSet::default();
        set.set(
            1,
            Note {
                text: "本机".into(),
                kind: None,
                fp: "f".into(),
                updated: 1,
            },
        );
        write_local(&paths, "uuid-1", &set).unwrap();
        let back: NoteSet =
            serde_json::from_slice(&std::fs::read(paths.local_notes("uuid-1")).unwrap()).unwrap();
        assert_eq!(back, set);
        write_local(&paths, "uuid-1", &NoteSet::default()).unwrap();
        assert!(!paths.local_notes("uuid-1").exists());
    }
}
