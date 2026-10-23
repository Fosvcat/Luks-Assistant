//! Frontend-neutral forms: which fields an operation needs, and how the
//! filled-in values become a [`Request`]. Shared by the TUI and the GUI.

use crate::ctx::Paths;
use crate::guard;
use crate::header::Priority;
use crate::notes::Location;
use crate::ops::{Credential, KdfChoice, NoteInput, Request, TokenKind};
use crate::secret::Secret;
use crate::slots::{Overview, Slot, SlotKind};
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
    /// Read-only line.
    Label,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub key: String,
    pub label: String,
    pub value: Value,
    pub hint: Option<String>,
}

impl Field {
    pub fn text(key: &str, label: &str, init: &str) -> Self {
        Field {
            key: key.to_owned(),
            label: label.into(),
            value: Value::Text(init.into()),
            hint: None,
        }
    }
    pub fn secret(key: &str, label: &str) -> Self {
        Field {
            key: key.to_owned(),
            label: label.into(),
            value: Value::Secret(String::new()),
            hint: None,
        }
    }
    pub fn toggle(key: &str, label: &str, init: bool) -> Self {
        Field {
            key: key.to_owned(),
            label: label.into(),
            value: Value::Toggle(init),
            hint: None,
        }
    }
    pub fn choice(key: &str, label: &str, options: &[&str], index: usize) -> Self {
        Field {
            key: key.to_owned(),
            label: label.into(),
            value: Value::Choice {
                options: options.iter().map(|s| s.to_string()).collect(),
                index,
            },
            hint: None,
        }
    }
    pub fn pcrs(key: &str, label: &str, selected: &[u8]) -> Self {
        let mut set = [false; 24];
        for &p in selected.iter().filter(|p| **p < 24) {
            set[p as usize] = true;
        }
        Field {
            key: key.to_owned(),
            label: label.into(),
            value: Value::Pcrs(set),
            hint: None,
        }
    }
    pub fn label(text: &str) -> Self {
        Field {
            key: String::new(),
            label: text.into(),
            value: Value::Label,
            hint: None,
        }
    }
    pub fn hint(mut self, h: &str) -> Self {
        self.hint = Some(h.into());
        self
    }
    pub fn is_input(&self) -> bool {
        !matches!(self.value, Value::Label)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FormKind {
    AddPassphrase,
    AddKeyfile,
    GenerateKeyfile,
    Recovery { replace: Option<u32> },
    Tpm2 { replace: Option<u32> },
    Fido2 { replace: Option<u32> },
    Pkcs11 { replace: Option<u32> },
    Change(u32),
    ConvertKdf(u32),
    Note(u32),
    Priority(u32),
    Remove(u32),
    Verify,
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

    pub fn text(&self, key: &str) -> String {
        match self.get(key) {
            Some(Value::Text(s)) | Some(Value::Secret(s)) => s.clone(),
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

const AUTH_PW: &str = "auth_pw";
const AUTH_KF: &str = "auth_kf";

fn auth_fields(label: &str) -> Vec<Field> {
    vec![
        Field::secret(AUTH_PW, label).hint("任一槽位的密码或恢复密钥"),
        Field::text(AUTH_KF, "或 密钥文件", ""),
    ]
}

fn note_fields(text: &str, loc: Location) -> Vec<Field> {
    vec![
        Field::text("note", "备注", text).hint("最多 64 字"),
        Field::choice(
            "note_loc",
            "备注位置",
            &[Location::Header.label(), Location::Local.label()],
            usize::from(loc == Location::Local),
        ),
    ]
}

fn kdf_field() -> Field {
    Field::choice("kdf", "PBKDF", &["argon2id", "pbkdf2（兼容 GRUB）"], 0)
}

fn slot_note(ov: &Overview, id: Option<u32>) -> (String, Location) {
    id.and_then(|i| ov.slot(i))
        .and_then(|s| s.note.as_ref())
        .map(|n| (n.note.text.clone(), n.location))
        .unwrap_or((String::new(), Location::Header))
}

/// Build the form for `kind`. Fails when the operation is impossible from
/// the start (e.g. removing the last passphrase slot), so the user is told
/// right away instead of after typing credentials.
pub fn build(kind: FormKind, env: &Env) -> Result<Form, String> {
    let ov = env.ov;
    if !matches!(
        kind,
        FormKind::Verify | FormKind::BackupDir | FormKind::Restore
    ) {
        if let Some(r) = ov.read_only_reason() {
            return Err(r);
        }
    }
    let (title, fields): (String, Vec<Field>) = match &kind {
        FormKind::AddPassphrase => ("添加密码".into(), {
            let mut f = auth_fields("现有密码");
            f.push(Field::secret("new", "新密码"));
            f.push(Field::secret("new2", "确认新密码"));
            f.push(Field::text("slot", "槽位", "").hint("留空自动选择"));
            f.push(kdf_field());
            f.extend(note_fields("", Location::Header));
            f
        }),
        FormKind::AddKeyfile => ("添加密钥文件".into(), {
            let mut f = auth_fields("现有密码");
            f.push(Field::text("path", "密钥文件", ""));
            f.push(Field::text("slot", "槽位", "").hint("留空自动选择"));
            f.push(kdf_field());
            f.extend(note_fields("", Location::Header));
            f
        }),
        FormKind::GenerateKeyfile => ("生成密钥文件".into(), {
            let short: String = ov.header.uuid.chars().take(8).collect();
            let mut f = auth_fields("现有密码");
            f.push(Field::text(
                "path",
                "保存到",
                &format!("/root/luks-{short}.key"),
            ));
            f.push(Field::text("size", "大小（字节）", "4096"));
            f.push(Field::text("slot", "槽位", "").hint("留空自动选择"));
            f.extend(note_fields("", Location::Header));
            f
        }),
        FormKind::Recovery { replace } => {
            let (t, l) = slot_note(ov, *replace);
            let mut f = auth_fields("现有密码");
            f.extend(note_fields(&t, l));
            (
                if replace.is_some() {
                    "重新生成恢复密钥"
                } else {
                    "生成恢复密钥"
                }
                .into(),
                f,
            )
        }
        FormKind::Tpm2 { replace } => {
            if !env.caps.cryptenroll {
                return Err("需要 systemd-cryptenroll".into());
            }
            let old = replace
                .and_then(|r| ov.slot(r))
                .and_then(|s| s.tpm2.as_ref());
            let pcrs = old.map(|t| t.pcrs.clone()).unwrap_or_else(|| vec![7]);
            let mut f = auth_fields("现有密码");
            f.push(Field::pcrs("pcrs", "PCR", &pcrs));
            if env.caps.tpm2_pin {
                f.push(Field::toggle(
                    "use_pin",
                    "需要 PIN",
                    old.is_some_and(|t| t.pin),
                ));
                f.push(Field::secret("pin", "PIN"));
                f.push(Field::secret("pin2", "确认 PIN"));
            }
            let (t, l) = slot_note(ov, *replace);
            f.extend(note_fields(&t, l));
            (
                if replace.is_some() {
                    "重新录入 TPM2"
                } else {
                    "录入 TPM2"
                }
                .into(),
                f,
            )
        }
        FormKind::Fido2 { replace } => {
            if !env.caps.cryptenroll {
                return Err("需要 systemd-cryptenroll".into());
            }
            let old = replace
                .and_then(|r| ov.slot(r))
                .and_then(|s| s.fido2.as_ref());
            let mut f = auth_fields("现有密码");
            if env.ask_pins {
                f.push(Field::secret("token_pin", "安全密钥 PIN").hint("密钥未设置 PIN 时留空"));
            }
            if env.caps.fido2_options {
                f.push(Field::toggle(
                    "pin",
                    "需要 PIN",
                    old.and_then(|o| o.client_pin).unwrap_or(true),
                ));
                f.push(Field::toggle(
                    "up",
                    "需要触摸",
                    old.and_then(|o| o.user_presence).unwrap_or(true),
                ));
                f.push(Field::toggle(
                    "uv",
                    "需要用户验证",
                    old.and_then(|o| o.user_verification).unwrap_or(false),
                ));
            }
            let (t, l) = slot_note(ov, *replace);
            f.extend(note_fields(&t, l));
            (
                if replace.is_some() {
                    "重新录入 FIDO2"
                } else {
                    "录入 FIDO2"
                }
                .into(),
                f,
            )
        }
        FormKind::Pkcs11 { replace } => {
            if !env.caps.cryptenroll {
                return Err("需要 systemd-cryptenroll".into());
            }
            let mut f = auth_fields("现有密码");
            if env.ask_pins {
                f.push(Field::secret("token_pin", "智能卡 PIN"));
            }
            f.push(Field::text("uri", "令牌 URI", "auto"));
            let (t, l) = slot_note(ov, *replace);
            f.extend(note_fields(&t, l));
            (
                if replace.is_some() {
                    "重新录入 PKCS#11"
                } else {
                    "录入 PKCS#11"
                }
                .into(),
                f,
            )
        }
        FormKind::Change(id) => (
            format!("修改槽位 {id} 的密码"),
            vec![
                Field::secret(AUTH_PW, "当前密码"),
                Field::text(AUTH_KF, "或 当前密钥文件", ""),
                Field::secret("new", "新密码"),
                Field::secret("new2", "确认新密码"),
                kdf_field(),
            ],
        ),
        FormKind::ConvertKdf(id) => (
            format!("槽位 {id} 转换为 Argon2id"),
            vec![
                Field::secret(AUTH_PW, "该槽位的密码"),
                Field::text(AUTH_KF, "或 密钥文件", ""),
            ],
        ),
        FormKind::Note(id) => {
            let (t, l) = slot_note(ov, Some(*id));
            (format!("槽位 {id} 的备注"), note_fields(&t, l))
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
                format!("槽位 {id} 的优先级"),
                vec![Field::choice(
                    "prio",
                    "优先级",
                    &["忽略", "普通", "优先"],
                    idx,
                )],
            )
        }
        FormKind::Remove(id) => {
            guard::check_removal(ov, *id, None).map_err(|e| e.to_string())?;
            (format!("删除槽位 {id}"), auth_fields("其它槽位的密码"))
        }
        FormKind::Verify => {
            let mut methods = vec!["密码 / 恢复密钥", "密钥文件"];
            for k in [TokenKind::Tpm2, TokenKind::Fido2, TokenKind::Pkcs11] {
                if ov.header.tokens.values().any(|t| t.kind == k.token_type()) {
                    methods.push(k.label());
                }
            }
            let mut f = vec![
                Field::choice("method", "方式", &methods, 0),
                Field::secret(AUTH_PW, "密码"),
                Field::text(AUTH_KF, "密钥文件", ""),
            ];
            if env.ask_pins {
                f.push(Field::secret("token_pin", "令牌 PIN").hint("TPM2+PIN / FIDO2 / PKCS#11"));
            }
            ("验证".into(), f)
        }
        FormKind::Discards => {
            if ov.device.mapping.is_none() {
                return Err("卷未解锁，无法写入 TRIM 标志".into());
            }
            let on = ov.header.allows_discards();
            let mut f = vec![Field::label(&format!(
                "当前：{}",
                if on { "已开启" } else { "已关闭" }
            ))];
            f.extend(auth_fields("现有密码"));
            (
                if on {
                    "关闭 TRIM 穿透"
                } else {
                    "开启 TRIM 穿透"
                }
                .into(),
                f,
            )
        }
        FormKind::Restore => {
            let files = crate::backup::list(env.paths, &ov.header.uuid);
            let latest = files
                .first()
                .map(|f| f.path.to_string_lossy().into_owned())
                .unwrap_or_default();
            (
                "恢复头部".into(),
                vec![Field::text("path", "备份文件", &latest)],
            )
        }
        FormKind::BackupDir => (
            "备份位置".into(),
            vec![
                Field::text("dir", "目录", &env.paths.backup_root.to_string_lossy()).hint(
                    &format!("留空 = {}", env.paths.default_backup_root().display()),
                ),
            ],
        ),
    };
    Ok(Form {
        title,
        kind,
        fields,
    })
}

fn cred(form: &Form) -> Result<Credential, String> {
    let path = form.text(AUTH_KF);
    if !path.trim().is_empty() {
        return Ok(Credential::Keyfile(PathBuf::from(path.trim())));
    }
    let p = form.text(AUTH_PW);
    if p.is_empty() {
        return Err("请输入密码或密钥文件".into());
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
        return Err("两次输入不一致".into());
    }
    Ok(Secret::from(x))
}

fn slot_field(form: &Form) -> Result<Option<u32>, String> {
    let s = form.text("slot");
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse().map(Some).map_err(|_| "槽位必须是数字".to_owned())
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
                    .map_err(|_| "大小必须是数字")?,
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
            enable: !form
                .fields
                .first()
                .is_some_and(|f| f.label.contains("已开启")),
            auth: cred(form)?,
        },
        FormKind::Restore => Request::RestoreHeader {
            file: PathBuf::from(form.text("path").trim()),
        },
        FormKind::BackupDir => {
            let d = form.text("dir");
            let d = d.trim();
            return Ok(Submit::SetBackupDir(
                (!d.is_empty()).then(|| PathBuf::from(d)),
            ));
        }
        FormKind::Verify => {
            let method = match form.get("method") {
                Some(Value::Choice { options, index }) => options[*index].clone(),
                _ => String::new(),
            };
            let kind = [TokenKind::Tpm2, TokenKind::Fido2, TokenKind::Pkcs11]
                .into_iter()
                .find(|k| k.label() == method);
            return Ok(Submit::Verify(match kind {
                Some(kind) => VerifyMethod::Token {
                    kind,
                    pin: token_pin(form),
                },
                None if form.choice("method") == 1 => {
                    let p = form.text(AUTH_KF);
                    if p.trim().is_empty() {
                        return Err("请输入密钥文件路径".into());
                    }
                    VerifyMethod::Credential(Credential::Keyfile(PathBuf::from(p.trim())))
                }
                None => {
                    let p = form.text(AUTH_PW);
                    if p.is_empty() {
                        return Err("请输入密码".into());
                    }
                    VerifyMethod::Credential(Credential::Passphrase(Secret::from(p)))
                }
            }));
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
            v.push(("修改密码".into(), FormKind::Change(id)));
            if s.keyslot.as_ref().is_some_and(|k| k.kdf.kind == "pbkdf2") {
                v.push(("转换为 Argon2id".into(), FormKind::ConvertKdf(id)));
            }
        }
        SlotKind::Recovery => v.push((
            "重新生成恢复密钥".into(),
            FormKind::Recovery { replace: Some(id) },
        )),
        SlotKind::Tpm2 => v.push(("重新录入 TPM2".into(), FormKind::Tpm2 { replace: Some(id) })),
        SlotKind::Fido2 => v.push((
            "重新录入 FIDO2".into(),
            FormKind::Fido2 { replace: Some(id) },
        )),
        SlotKind::Pkcs11 => v.push((
            "重新录入 PKCS#11".into(),
            FormKind::Pkcs11 { replace: Some(id) },
        )),
        _ => {}
    }
    v.push(("编辑备注".into(), FormKind::Note(id)));
    v.push(("设置优先级".into(), FormKind::Priority(id)));
    v.push(("删除槽位".into(), FormKind::Remove(id)));
    v
}

pub fn add_actions(caps: &Caps) -> Vec<(String, FormKind)> {
    let mut v = vec![
        ("添加密码".to_owned(), FormKind::AddPassphrase),
        ("添加密钥文件".to_owned(), FormKind::AddKeyfile),
        ("生成密钥文件".to_owned(), FormKind::GenerateKeyfile),
    ];
    if caps.cryptenroll {
        v.push(("生成恢复密钥".into(), FormKind::Recovery { replace: None }));
        v.push(("录入 TPM2".into(), FormKind::Tpm2 { replace: None }));
        v.push(("录入 FIDO2".into(), FormKind::Fido2 { replace: None }));
        v.push(("录入 PKCS#11".into(), FormKind::Pkcs11 { replace: None }));
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
        assert!(e.contains("最后一个"), "{e}");
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
            ("note", "备用"),
        ] {
            match f.get_mut(k).unwrap() {
                Value::Text(s) | Value::Secret(s) => *s = v.into(),
                _ => unreachable!(),
            }
        }
        match submit(&f).unwrap() {
            Submit::Request(Request::AddPassphrase { slot, note, .. }) => {
                assert_eq!(slot, Some(9));
                assert_eq!(note.unwrap().text, "备用");
            }
            other => panic!("{other:?}"),
        }
        if let Some(Value::Secret(s)) = f.get_mut("new2") {
            s.push('x');
        }
        assert!(submit(&f).is_err());
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
        assert_eq!(options, &["密码 / 恢复密钥", "密钥文件", "TPM2", "FIDO2"]);
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
        assert_eq!(labels[0], "重新录入 TPM2");
        // empty slot without systemd-cryptenroll: only passphrase/key file
        assert_eq!(slot_actions(&ov.slots[4], &caps).len(), 3);
    }
}
