//! Frontend-neutral forms: which fields an operation needs, and how the
//! filled-in values become a [`Request`]. Shared by the TUI and the GUI.

use crate::ctx::Paths;
use crate::guard;
use crate::header::Priority;
use crate::notes::Location;
use crate::ops::{Credential, KdfChoice, NoteInput, Request, TokenKind};
use crate::secret::Secret;
use crate::slots::{Overview, Slot, SlotKind};
use crate::t;
use luks_assistant_sysinfo::tools::Caps;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Text(String),
    Secret(String),
    Toggle(bool),
    Choice {
        options: Vec<String>,
        index: usize,
    },
    Pcrs([bool; 24]),
    /// Path of an existing file; the GUI adds a file picker.
    File(String),
    /// Path of a file to create; the GUI adds a save dialog.
    SaveFile(String),
    /// Read-only line.
    Label,
    /// Blank space between groups of fields.
    Separator,
}

/// Show a field only while the choice field `key` has one of `any_of` selected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShowIf {
    pub key: String,
    pub any_of: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub key: String,
    pub label: String,
    pub value: Value,
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_if: Option<ShowIf>,
    /// Editable only while the toggle field with this key is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_by: Option<String>,
}

impl Field {
    fn new(key: &str, label: &str, value: Value) -> Self {
        Field {
            key: key.to_owned(),
            label: label.into(),
            value,
            hint: None,
            show_if: None,
            enabled_by: None,
        }
    }
    pub fn text(key: &str, label: &str, init: &str) -> Self {
        Field::new(key, label, Value::Text(init.into()))
    }
    pub fn secret(key: &str, label: &str) -> Self {
        Field::new(key, label, Value::Secret(String::new()))
    }
    pub fn file(key: &str, label: &str, init: &str) -> Self {
        Field::new(key, label, Value::File(init.into()))
    }
    pub fn save_file(key: &str, label: &str, init: &str) -> Self {
        Field::new(key, label, Value::SaveFile(init.into()))
    }
    pub fn toggle(key: &str, label: &str, init: bool) -> Self {
        Field::new(key, label, Value::Toggle(init))
    }
    pub fn choice(key: &str, label: &str, options: &[&str], index: usize) -> Self {
        Field::new(
            key,
            label,
            Value::Choice {
                options: options.iter().map(|s| s.to_string()).collect(),
                index,
            },
        )
    }
    pub fn pcrs(key: &str, label: &str, selected: &[u8]) -> Self {
        let mut set = [false; 24];
        for &p in selected.iter().filter(|p| **p < 24) {
            set[p as usize] = true;
        }
        Field::new(key, label, Value::Pcrs(set))
    }
    pub fn label(text: &str) -> Self {
        Field::new("", text, Value::Label)
    }
    pub fn separator() -> Self {
        Field::new("", "", Value::Separator)
    }
    pub fn hint(mut self, h: &str) -> Self {
        self.hint = Some(h.into());
        self
    }
    pub fn show_if(mut self, key: &str, any_of: &[usize]) -> Self {
        self.show_if = Some(ShowIf {
            key: key.to_owned(),
            any_of: any_of.to_vec(),
        });
        self
    }
    pub fn enabled_by(mut self, toggle: &str) -> Self {
        self.enabled_by = Some(toggle.to_owned());
        self
    }
    pub fn is_input(&self) -> bool {
        !matches!(self.value, Value::Label | Value::Separator)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FormKind {
    AddPassphrase,
    AddKeyfile,
    GenerateKeyfile,
    Recovery {
        replace: Option<u32>,
    },
    Tpm2 {
        replace: Option<u32>,
    },
    Fido2 {
        replace: Option<u32>,
    },
    Pkcs11 {
        replace: Option<u32>,
    },
    Change(u32),
    ConvertKdf(u32),
    Note(u32),
    Priority(u32),
    Remove(u32),
    Verify,
    /// Same fields as `Verify`, but opens the volume.
    Unlock,
    Discards,
    Restore,
    BackupDir,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Form {
    pub title: String,
    pub kind: FormKind,
    pub fields: Vec<Field>,
}

impl Form {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.iter().find(|f| f.key == key).map(|f| &f.value)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.fields
            .iter_mut()
            .find(|f| f.key == key)
            .map(|f| &mut f.value)
    }

    /// Can field `i` be edited, given the current toggles?
    pub fn enabled(&self, i: usize) -> bool {
        match self.fields.get(i).and_then(|f| f.enabled_by.as_deref()) {
            Some(t) => self.toggle(t),
            None => true,
        }
    }

    /// Is field `i` shown, given the current choices?
    pub fn visible(&self, i: usize) -> bool {
        match self.fields.get(i).and_then(|f| f.show_if.as_ref()) {
            Some(c) => c.any_of.contains(&self.choice(&c.key)),
            None => true,
        }
    }

    pub fn text(&self, key: &str) -> String {
        match self.get(key) {
            Some(Value::Text(s) | Value::Secret(s) | Value::File(s) | Value::SaveFile(s)) => {
                s.clone()
            }
            _ => String::new(),
        }
    }

    pub fn toggle(&self, key: &str) -> bool {
        matches!(self.get(key), Some(Value::Toggle(true)))
    }

    pub fn choice(&self, key: &str) -> usize {
        match self.get(key) {
            Some(Value::Choice { index, .. }) => *index,
            _ => 0,
        }
    }

    pub fn pcrs(&self, key: &str) -> Vec<u8> {
        match self.get(key) {
            Some(Value::Pcrs(set)) => (0..24u8).filter(|i| set[*i as usize]).collect(),
            _ => Vec::new(),
        }
    }
}

/// What a submitted form asks for.
#[derive(Debug, Clone)]
pub enum Submit {
    /// A write operation: plan it, confirm, execute.
    Request(Request),
    /// Check a credential or token without changing anything.
    Verify(VerifyMethod),
    Unlock(VerifyMethod),
    SetBackupDir(Option<PathBuf>),
}

#[derive(Debug, Clone)]
pub enum VerifyMethod {
    Credential(Credential),
    Token {
        kind: TokenKind,
        pin: Option<Secret>,
    },
}

/// What a frontend knows when building a form.
pub struct Env<'a> {
    pub ov: &'a Overview,
    pub caps: &'a Caps,
    pub paths: &'a Paths,
    /// Ask token PINs inside the form (no terminal to hand over, i.e. GUI).
    pub ask_pins: bool,
}

const AUTH_METHOD: &str = "auth_method";
const AUTH_PW: &str = "auth_pw";
const AUTH_KF: &str = "auth_kf";

/// Existing credential: method, then password or key file, then a gap
/// before the operation's own settings. `hint` says whose password.
fn auth_fields(hint: &str) -> Vec<Field> {
    vec![
        Field::choice(
            AUTH_METHOD,
            t!("Authenticate with"),
            &[t!("Password"), t!("Key file")],
            0,
        ),
        Field::secret(AUTH_PW, t!("Password"))
            .hint(hint)
            .show_if(AUTH_METHOD, &[0]),
        Field::file(AUTH_KF, t!("Key file"), "").show_if(AUTH_METHOD, &[1]),
        Field::separator(),
    ]
}

fn note_fields(text: &str, loc: Location) -> Vec<Field> {
    vec![
        Field::text("note", t!("Note"), text).hint(t!("Up to 64 characters")),
        Field::choice(
            "note_loc",
            t!("Store note"),
            &[Location::Header.label(), Location::Local.label()],
            usize::from(loc == Location::Local),
        ),
    ]
}

fn kdf_field() -> Field {
    Field::choice(
        "kdf",
        "PBKDF",
        &["argon2id", t!("pbkdf2 (GRUB compatible)")],
        0,
    )
}

fn slot_note(ov: &Overview, id: Option<u32>) -> (String, Location) {
    id.and_then(|i| ov.slot(i))
        .and_then(|s| s.note.as_ref())
        .map(|n| (n.note.text.clone(), n.location))
        .unwrap_or((String::new(), Location::Header))
}

fn any_slot() -> &'static str {
    t!("Password or recovery key of any slot")
}

/// Build the form for `kind`. Fails when the operation is impossible from
/// the start (e.g. removing the last passphrase slot), so the user is told
/// right away instead of after typing credentials.
pub fn build(kind: FormKind, env: &Env) -> Result<Form, String> {
    let ov = env.ov;
    if !matches!(
        kind,
        FormKind::Verify | FormKind::Unlock | FormKind::BackupDir | FormKind::Restore
    ) {
        if let Some(r) = ov.read_only_reason() {
            return Err(r);
        }
    }
    let (title, fields): (String, Vec<Field>) = match &kind {
        FormKind::AddPassphrase => (t!("Add password").into(), {
            let mut f = auth_fields(any_slot());
            f.push(Field::secret("new", t!("New password")));
            f.push(Field::secret("new2", t!("Confirm new password")));
            f.push(Field::text("slot", t!("Slot"), "").hint(t!("Empty: chosen automatically")));
            f.push(kdf_field());
            f.extend(note_fields("", Location::Header));
            f
        }),
        FormKind::AddKeyfile => (t!("Add key file").into(), {
            let mut f = auth_fields(any_slot());
            f.push(Field::file("path", t!("Key file"), ""));
            f.push(Field::text("slot", t!("Slot"), "").hint(t!("Empty: chosen automatically")));
            f.push(kdf_field());
            f.extend(note_fields("", Location::Header));
            f
        }),
        FormKind::GenerateKeyfile => (t!("Generate key file").into(), {
            let short: String = ov.header.uuid.chars().take(8).collect();
            let mut f = auth_fields(any_slot());
            f.push(Field::save_file(
                "path",
                t!("Save to"),
                &format!("/root/luks-{short}.key"),
            ));
            f.push(Field::text("size", t!("Size (bytes)"), "4096"));
            f.push(Field::text("slot", t!("Slot"), "").hint(t!("Empty: chosen automatically")));
            f.extend(note_fields("", Location::Header));
            f
        }),
        FormKind::Recovery { replace } => {
            let (t, l) = slot_note(ov, *replace);
            let mut f = auth_fields(any_slot());
            f.extend(note_fields(&t, l));
            (
                if replace.is_some() {
                    t!("Regenerate recovery key")
                } else {
                    t!("Generate recovery key")
                }
                .into(),
                f,
            )
        }
        FormKind::Tpm2 { replace } => {
            if !env.caps.cryptenroll {
                return Err(t!("Needs systemd-cryptenroll").into());
            }
            let old = replace
                .and_then(|r| ov.slot(r))
                .and_then(|s| s.tpm2.as_ref());
            let pcrs = old.map(|t| t.pcrs.clone()).unwrap_or_else(|| vec![7]);
            let mut f = auth_fields(any_slot());
            f.push(Field::pcrs("pcrs", "PCR", &pcrs));
            if env.caps.tpm2_pin {
                f.push(Field::toggle(
                    "use_pin",
                    t!("Require PIN"),
                    old.is_some_and(|t| t.pin),
                ));
                f.push(Field::secret("pin", "PIN").enabled_by("use_pin"));
                f.push(Field::secret("pin2", t!("Confirm PIN")).enabled_by("use_pin"));
            }
            let (t, l) = slot_note(ov, *replace);
            f.extend(note_fields(&t, l));
            (
                if replace.is_some() {
                    t!("Re-enroll TPM2")
                } else {
                    t!("Enroll TPM2")
                }
                .into(),
                f,
            )
        }
        FormKind::Fido2 { replace } => {
            if !env.caps.cryptenroll {
                return Err(t!("Needs systemd-cryptenroll").into());
            }
            let old = replace
                .and_then(|r| ov.slot(r))
                .and_then(|s| s.fido2.as_ref());
            let mut f = auth_fields(any_slot());
            if env.ask_pins {
                f.push(
                    Field::secret("token_pin", t!("Security key PIN"))
                        .hint(t!("Leave empty if the key has no PIN")),
                );
            }
            if env.caps.fido2_options {
                f.push(Field::toggle(
                    "pin",
                    t!("Require PIN"),
                    old.and_then(|o| o.client_pin).unwrap_or(true),
                ));
                f.push(Field::toggle(
                    "up",
                    t!("Require touch"),
                    old.and_then(|o| o.user_presence).unwrap_or(true),
                ));
                f.push(Field::toggle(
                    "uv",
                    t!("Require user verification"),
                    old.and_then(|o| o.user_verification).unwrap_or(false),
                ));
            }
            let (t, l) = slot_note(ov, *replace);
            f.extend(note_fields(&t, l));
            (
                if replace.is_some() {
                    t!("Re-enroll FIDO2")
                } else {
                    t!("Enroll FIDO2")
                }
                .into(),
                f,
            )
        }
        FormKind::Pkcs11 { replace } => {
            if !env.caps.cryptenroll {
                return Err(t!("Needs systemd-cryptenroll").into());
            }
            let mut f = auth_fields(any_slot());
            if env.ask_pins {
                f.push(Field::secret("token_pin", t!("Smart card PIN")));
            }
            f.push(Field::text("uri", t!("Token URI"), "auto"));
            let (t, l) = slot_note(ov, *replace);
            f.extend(note_fields(&t, l));
            (
                if replace.is_some() {
                    t!("Re-enroll PKCS#11")
                } else {
                    t!("Enroll PKCS#11")
                }
                .into(),
                f,
            )
        }
        FormKind::Change(id) => (t!("Change the password of slot {}", id), {
            let mut f = auth_fields(t!("Current password of this slot"));
            f.push(Field::secret("new", t!("New password")));
            f.push(Field::secret("new2", t!("Confirm new password")));
            f.push(kdf_field());
            f
        }),
        FormKind::ConvertKdf(id) => (
            t!("Convert slot {} to Argon2id", id),
            auth_fields(t!("Password of this slot")),
        ),
        FormKind::Note(id) => {
            let (t, l) = slot_note(ov, Some(*id));
            (t!("Note of slot {}", id), note_fields(&t, l))
        }
        FormKind::Priority(id) => {
            let cur = ov
                .slot(*id)
                .and_then(|s| s.keyslot.as_ref())
                .map(|k| k.priority)
                .unwrap_or(Priority::Normal);
            let idx = [Priority::Ignore, Priority::Normal, Priority::Prefer]
                .iter()
                .position(|p| *p == cur)
                .unwrap_or(1);
            (
                t!("Priority of slot {}", id),
                vec![Field::choice(
                    "prio",
                    t!("Priority"),
                    &[t!("Ignore"), t!("Normal"), t!("Prefer")],
                    idx,
                )],
            )
        }
        FormKind::Remove(id) => {
            guard::check_removal(ov, *id, None).map_err(|e| e.to_string())?;
            (
                t!("Delete slot {}", id),
                auth_fields(t!("Password or recovery key of another slot")),
            )
        }
        FormKind::Verify | FormKind::Unlock => {
            if kind == FormKind::Unlock {
                if let Some(m) = &ov.device.mapping {
                    return Err(t!("Already unlocked ({})", m));
                }
            }
            let mut methods = vec![t!("Password / recovery key"), t!("Key file")];
            for k in [TokenKind::Tpm2, TokenKind::Fido2, TokenKind::Pkcs11] {
                if ov.header.tokens.values().any(|t| t.kind == k.token_type()) {
                    methods.push(k.label());
                }
            }
            let tokens: Vec<usize> = (2..methods.len()).collect();
            let mut f = vec![
                Field::choice("method", t!("Authenticate with"), &methods, 0),
                Field::secret(AUTH_PW, t!("Password")).show_if("method", &[0]),
                Field::file(AUTH_KF, t!("Key file"), "").show_if("method", &[1]),
            ];
            if env.ask_pins && !tokens.is_empty() {
                f.push(
                    Field::secret("token_pin", t!("Token PIN"))
                        .hint("TPM2+PIN / FIDO2 / PKCS#11")
                        .show_if("method", &tokens),
                );
            }
            (
                if kind == FormKind::Unlock {
                    t!("Unlock")
                } else {
                    t!("Verify")
                }
                .into(),
                f,
            )
        }
        FormKind::Discards => {
            if ov.device.mapping.is_none() {
                return Err(t!("The volume is locked; the TRIM flag cannot be written").into());
            }
            let on = ov.header.allows_discards();
            // The label's key records the current state for `submit`.
            let mut f = vec![Field {
                key: if on { "discards_on" } else { "discards_off" }.into(),
                ..Field::label(&t!("Current: {}", if on { t!("on") } else { t!("off") }))
            }];
            f.extend(auth_fields(any_slot()));
            (
                if on {
                    t!("Disable TRIM pass-through")
                } else {
                    t!("Enable TRIM pass-through")
                }
                .into(),
                f,
            )
        }
        FormKind::Restore => {
            let files = crate::backup::list(env.paths, &ov.header.uuid);
            let latest = files.first().map(|f| &f.path);
            let ours = t!(
                "Restore this program's backup: {}",
                latest
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| t!("no backup found").into())
            );
            (
                t!("Restore header").into(),
                vec![
                    Field::choice(
                        "source",
                        t!("Source"),
                        &[&ours, t!("Choose a backup file to restore")],
                        0,
                    ),
                    // never shown: the file behind the first choice
                    Field::text(
                        "latest",
                        "",
                        &latest.map(|p| p.to_string_lossy()).unwrap_or_default(),
                    )
                    .show_if("source", &[]),
                    Field::file("path", t!("Backup file"), "").show_if("source", &[1]),
                ],
            )
        }
        FormKind::BackupDir => (
            t!("Backup location").into(),
            vec![
                Field::text(
                    "dir",
                    t!("Directory"),
                    &env.paths.backup_root.to_string_lossy(),
                )
                .hint(&t!("Empty = {}", env.paths.default_backup_root().display())),
            ],
        ),
    };
    let mut fields = fields;
    if fields.last().is_some_and(|f| f.value == Value::Separator) {
        fields.pop();
    }
    Ok(Form {
        title,
        kind,
        fields,
    })
}

fn cred(form: &Form) -> Result<Credential, String> {
    if form.choice(AUTH_METHOD) == 1 {
        let path = form.text(AUTH_KF);
        if path.trim().is_empty() {
            return Err(t!("Choose the key file").into());
        }
        return Ok(Credential::Keyfile(PathBuf::from(path.trim())));
    }
    let p = form.text(AUTH_PW);
    if p.is_empty() {
        return Err(t!("Enter the password").into());
    }
    Ok(Credential::Passphrase(Secret::from(p)))
}

fn note_input(form: &Form) -> Option<NoteInput> {
    let location = if form.choice("note_loc") == 1 {
        Location::Local
    } else {
        Location::Header
    };
    Some(NoteInput {
        text: form.text("note").trim().to_owned(),
        location,
    })
}

fn new_secret(form: &Form, a: &str, b: &str) -> Result<Secret, String> {
    let (x, y) = (form.text(a), form.text(b));
    if x != y {
        return Err(t!("The two entries do not match").into());
    }
    Ok(Secret::from(x))
}

fn slot_field(form: &Form) -> Result<Option<u32>, String> {
    let s = form.text("slot");
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse()
        .map(Some)
        .map_err(|_| t!("The slot must be a number").to_owned())
}

fn kdf(form: &Form) -> KdfChoice {
    if form.choice("kdf") == 1 {
        KdfChoice::Pbkdf2
    } else {
        KdfChoice::Default
    }
}

fn token_pin(form: &Form) -> Option<Secret> {
    let p = form.text("token_pin");
    (!p.is_empty()).then(|| Secret::from(p))
}

pub fn submit(form: &Form) -> Result<Submit, String> {
    let r = match &form.kind {
        FormKind::AddPassphrase => Request::AddPassphrase {
            auth: cred(form)?,
            new: new_secret(form, "new", "new2")?,
            slot: slot_field(form)?,
            kdf: kdf(form),
            note: note_input(form),
        },
        FormKind::AddKeyfile => Request::AddKeyfile {
            auth: cred(form)?,
            path: PathBuf::from(form.text("path").trim()),
            generate: None,
            slot: slot_field(form)?,
            kdf: kdf(form),
            note: note_input(form),
        },
        FormKind::GenerateKeyfile => Request::AddKeyfile {
            auth: cred(form)?,
            path: PathBuf::from(form.text("path").trim()),
            generate: Some(
                form.text("size")
                    .trim()
                    .parse()
                    .map_err(|_| t!("The size must be a number"))?,
            ),
            slot: slot_field(form)?,
            kdf: KdfChoice::Default,
            note: note_input(form),
        },
        FormKind::Recovery { replace } => Request::AddRecoveryKey {
            auth: cred(form)?,
            replace: *replace,
            note: note_input(form),
        },
        FormKind::Tpm2 { replace } => Request::EnrollTpm2 {
            auth: cred(form)?,
            pcrs: form.pcrs("pcrs"),
            pin: if form.toggle("use_pin") {
                Some(new_secret(form, "pin", "pin2")?)
            } else {
                None
            },
            replace: *replace,
            note: note_input(form),
        },
        FormKind::Fido2 { replace } => Request::EnrollFido2 {
            auth: cred(form)?,
            pin: token_pin(form),
            client_pin: form.get("pin").is_none() || form.toggle("pin"),
            user_presence: form.get("up").is_none() || form.toggle("up"),
            user_verification: form.toggle("uv"),
            replace: *replace,
            note: note_input(form),
        },
        FormKind::Pkcs11 { replace } => Request::EnrollPkcs11 {
            auth: cred(form)?,
            pin: token_pin(form),
            uri: form.text("uri"),
            replace: *replace,
            note: note_input(form),
        },
        FormKind::Change(id) => Request::ChangePassphrase {
            slot: *id,
            old: cred(form)?,
            new: new_secret(form, "new", "new2")?,
            kdf: kdf(form),
        },
        FormKind::ConvertKdf(id) => Request::ConvertKdf {
            slot: *id,
            auth: cred(form)?,
        },
        FormKind::Note(id) => {
            let n = note_input(form).expect("note");
            Request::SetNote {
                slot: *id,
                text: n.text,
                location: n.location,
            }
        }
        FormKind::Priority(id) => Request::SetPriority {
            slot: *id,
            priority: [Priority::Ignore, Priority::Normal, Priority::Prefer]
                [form.choice("prio").min(2)],
        },
        FormKind::Remove(id) => Request::RemoveSlot {
            slot: *id,
            auth: cred(form)?,
        },
        FormKind::Discards => Request::SetDiscards {
            enable: form.get("discards_on").is_none(),
            auth: cred(form)?,
        },
        FormKind::Restore => {
            let ours = form.choice("source") == 0;
            let file = form.text(if ours { "latest" } else { "path" });
            if file.trim().is_empty() {
                return Err(if ours {
                    t!("This program has saved no backup of this volume.")
                } else {
                    t!("Choose a backup file.")
                }
                .into());
            }
            Request::RestoreHeader {
                file: PathBuf::from(file.trim()),
            }
        }
        FormKind::BackupDir => {
            let d = form.text("dir");
            let d = d.trim();
            return Ok(Submit::SetBackupDir(
                (!d.is_empty()).then(|| PathBuf::from(d)),
            ));
        }
        FormKind::Verify | FormKind::Unlock => {
            let method = match form.get("method") {
                Some(Value::Choice { options, index }) => options[*index].clone(),
                _ => String::new(),
            };
            let token = [TokenKind::Tpm2, TokenKind::Fido2, TokenKind::Pkcs11]
                .into_iter()
                .find(|k| k.label() == method);
            let method = match token {
                Some(kind) => VerifyMethod::Token {
                    kind,
                    pin: token_pin(form),
                },
                None if form.choice("method") == 1 => {
                    let p = form.text(AUTH_KF);
                    if p.trim().is_empty() {
                        return Err(t!("Choose the key file").into());
                    }
                    VerifyMethod::Credential(Credential::Keyfile(PathBuf::from(p.trim())))
                }
                None => {
                    let p = form.text(AUTH_PW);
                    if p.is_empty() {
                        return Err(t!("Enter the password").into());
                    }
                    VerifyMethod::Credential(Credential::Passphrase(Secret::from(p)))
                }
            };
            return Ok(if form.kind == FormKind::Unlock {
                Submit::Unlock(method)
            } else {
                Submit::Verify(method)
            });
        }
    };
    Ok(Submit::Request(r))
}

/// Operations offered for a slot, in menu order.
pub fn slot_actions(s: &Slot, caps: &Caps) -> Vec<(String, FormKind)> {
    if s.is_empty() {
        return add_actions(caps);
    }
    let id = s.id;
    let mut v: Vec<(String, FormKind)> = Vec::new();
    match &s.kind {
        k if k.is_plain() => {
            v.push((t!("Change password").into(), FormKind::Change(id)));
            if s.keyslot.as_ref().is_some_and(|k| k.kdf.kind == "pbkdf2") {
                v.push((t!("Convert to Argon2id").into(), FormKind::ConvertKdf(id)));
            }
        }
        SlotKind::Recovery => v.push((
            t!("Regenerate recovery key").into(),
            FormKind::Recovery { replace: Some(id) },
        )),
        SlotKind::Tpm2 => v.push((
            t!("Re-enroll TPM2").into(),
            FormKind::Tpm2 { replace: Some(id) },
        )),
        SlotKind::Fido2 => v.push((
            t!("Re-enroll FIDO2").into(),
            FormKind::Fido2 { replace: Some(id) },
        )),
        SlotKind::Pkcs11 => v.push((
            t!("Re-enroll PKCS#11").into(),
            FormKind::Pkcs11 { replace: Some(id) },
        )),
        _ => {}
    }
    v.push((t!("Edit note").into(), FormKind::Note(id)));
    v.push((t!("Set priority").into(), FormKind::Priority(id)));
    v.push((t!("Delete slot").into(), FormKind::Remove(id)));
    v
}

pub fn add_actions(caps: &Caps) -> Vec<(String, FormKind)> {
    let mut v = vec![
        (t!("Add password").to_owned(), FormKind::AddPassphrase),
        (t!("Add key file").to_owned(), FormKind::AddKeyfile),
        (
            t!("Generate key file").to_owned(),
            FormKind::GenerateKeyfile,
        ),
    ];
    if caps.cryptenroll {
        v.push((
            t!("Generate recovery key").into(),
            FormKind::Recovery { replace: None },
        ));
        v.push((t!("Enroll TPM2").into(), FormKind::Tpm2 { replace: None }));
        v.push((t!("Enroll FIDO2").into(), FormKind::Fido2 { replace: None }));
        v.push((
            t!("Enroll PKCS#11").into(),
            FormKind::Pkcs11 { replace: None },
        ));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slots::tests::sample_overview;

    fn env<'a>(ov: &'a Overview, caps: &'a Caps, paths: &'a Paths) -> Env<'a> {
        Env {
            ov,
            caps,
            paths,
            ask_pins: false,
        }
    }

    #[test]
    fn removal_precheck() {
        let mut ov = sample_overview();
        let caps = Caps::default();
        let paths = Paths::under(std::path::Path::new("/x"));
        assert!(build(FormKind::Remove(0), &env(&ov, &caps, &paths)).is_ok());
        for id in [1, 5] {
            ov.slots[id].kind = SlotKind::Empty;
        }
        let e = build(FormKind::Remove(0), &env(&ov, &caps, &paths)).unwrap_err();
        assert!(e.contains("the last"), "{e}");
    }

    #[test]
    fn add_passphrase_roundtrip() {
        let ov = sample_overview();
        let caps = Caps::default();
        let paths = Paths::under(std::path::Path::new("/x"));
        let mut f = build(FormKind::AddPassphrase, &env(&ov, &caps, &paths)).unwrap();
        for (k, v) in [
            (AUTH_PW, "old"),
            ("new", "n1"),
            ("new2", "n1"),
            ("slot", "9"),
            ("note", "spare"),
        ] {
            match f.get_mut(k).unwrap() {
                Value::Text(s) | Value::Secret(s) | Value::File(s) => *s = v.into(),
                _ => unreachable!(),
            }
        }
        match submit(&f).unwrap() {
            Submit::Request(Request::AddPassphrase { slot, note, .. }) => {
                assert_eq!(slot, Some(9));
                assert_eq!(note.unwrap().text, "spare");
            }
            other => panic!("{other:?}"),
        }
        if let Some(Value::Secret(s)) = f.get_mut("new2") {
            s.push('x');
        }
        assert!(submit(&f).is_err());
    }

    #[test]
    fn auth_method_switches_fields() {
        let ov = sample_overview();
        let caps = Caps::default();
        let paths = Paths::under(std::path::Path::new("/x"));
        let mut f = build(
            FormKind::Recovery { replace: None },
            &env(&ov, &caps, &paths),
        )
        .unwrap();
        let pos = |f: &Form, k: &str| f.fields.iter().position(|x| x.key == k).unwrap();
        let (pw, kf) = (pos(&f, AUTH_PW), pos(&f, AUTH_KF));
        assert!(f.visible(pw) && !f.visible(kf));
        assert_eq!(f.fields[kf + 1].value, Value::Separator);
        assert_eq!(submit(&f).unwrap_err(), "Enter the password");

        if let Some(Value::Choice { index, .. }) = f.get_mut(AUTH_METHOD) {
            *index = 1;
        }
        assert!(!f.visible(pw) && f.visible(kf));
        if let Some(Value::Secret(s)) = f.get_mut(AUTH_PW) {
            *s = "ignored".into();
        }
        assert_eq!(submit(&f).unwrap_err(), "Choose the key file");
        if let Some(Value::File(s)) = f.get_mut(AUTH_KF) {
            *s = "/k.key".into();
        }
        match submit(&f).unwrap() {
            Submit::Request(Request::AddRecoveryKey {
                auth: Credential::Keyfile(p),
                ..
            }) => assert_eq!(p, PathBuf::from("/k.key")),
            other => panic!("{other:?}"),
        }

        // nothing follows the credential: no trailing gap
        let f = build(FormKind::Remove(0), &env(&ov, &caps, &paths)).unwrap();
        assert_ne!(f.fields.last().unwrap().value, Value::Separator);
    }

    #[test]
    fn pin_fields_follow_toggle_and_unlock_mirrors_verify() {
        let ov = sample_overview();
        let caps = Caps {
            cryptenroll: true,
            tpm2_pin: true,
            ..Caps::default()
        };
        let paths = Paths::under(std::path::Path::new("/x"));
        let mut f = build(FormKind::Tpm2 { replace: None }, &env(&ov, &caps, &paths)).unwrap();
        let pin = f.fields.iter().position(|x| x.key == "pin").unwrap();
        assert!(!f.enabled(pin));
        if let Some(Value::Toggle(on)) = f.get_mut("use_pin") {
            *on = true;
        }
        assert!(f.enabled(pin));

        let mut u = build(FormKind::Unlock, &env(&ov, &caps, &paths)).unwrap();
        if let Some(Value::Secret(s)) = u.get_mut(AUTH_PW) {
            *s = "pw".into();
        }
        assert!(matches!(
            submit(&u).unwrap(),
            Submit::Unlock(VerifyMethod::Credential(Credential::Passphrase(_)))
        ));
    }

    #[test]
    fn verify_methods_follow_tokens() {
        let ov = sample_overview();
        let caps = Caps::default();
        let paths = Paths::under(std::path::Path::new("/x"));
        let mut f = build(FormKind::Verify, &env(&ov, &caps, &paths)).unwrap();
        let Some(Value::Choice { options, .. }) = f.get("method") else {
            panic!()
        };
        assert_eq!(
            options,
            &["Password / recovery key", "Key file", "TPM2", "FIDO2"]
        );
        if let Some(Value::Choice { index, .. }) = f.get_mut("method") {
            *index = 2;
        }
        assert!(matches!(
            submit(&f).unwrap(),
            Submit::Verify(VerifyMethod::Token {
                kind: TokenKind::Tpm2,
                ..
            })
        ));
    }

    #[test]
    fn slot_menus() {
        let ov = sample_overview();
        let caps = Caps::default();
        let labels: Vec<String> = slot_actions(&ov.slots[2], &caps)
            .into_iter()
            .map(|a| a.0)
            .collect();
        assert_eq!(labels[0], "Re-enroll TPM2");
        // empty slot without systemd-cryptenroll: only passphrase/key file
        assert_eq!(slot_actions(&ov.slots[4], &caps).len(), 3);
    }
}
