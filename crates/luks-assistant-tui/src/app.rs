//! Application state and input handling.

use crate::form::{Field, Form, FormEvent};
use luks_assistant_core::device::LuksDevice;
use luks_assistant_core::exec::Cmd;
use luks_assistant_core::header::Priority;
use luks_assistant_core::health::{self, Issue};
use luks_assistant_core::notes::Location;
use luks_assistant_core::ops::{self, Credential, Hooks, KdfChoice, NoteInput, Plan, Request};
use luks_assistant_core::slots::{Overview, Slot, SlotKind};
use luks_assistant_core::{Ctx, Secret, pcr};
use luks_assistant_sysinfo::SystemInfo;
use luks_assistant_sysinfo::bootcheck;
use luks_assistant_sysinfo::tpm::PcrValues;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Position, Rect};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Slots,
    System,
    Health,
    Boot,
    Log,
}

pub const TABS: [(Tab, &str); 5] = [
    (Tab::Slots, "1 槽位"),
    (Tab::System, "2 系统/TPM"),
    (Tab::Health, "3 体检"),
    (Tab::Boot, "4 开机检查"),
    (Tab::Log, "5 日志"),
];

#[derive(Debug, Clone)]
pub enum FormKind {
    AddPassphrase,
    AddKeyfile,
    GenerateKeyfile,
    Recovery { replace: Option<u32> },
    Tpm2 { replace: Option<u32> },
    Fido2 { replace: Option<u32> },
    Pkcs11 { replace: Option<u32> },
    Change(u32),
    Note(u32),
    Priority(u32),
    Remove(u32),
    TestPass,
    Backup,
    Restore,
}

#[derive(Debug, Clone)]
pub enum MenuItem {
    Form(FormKind),
    TestToken { token: u32, interactive: bool },
    Device(usize),
}

pub enum Modal {
    Menu {
        title: String,
        items: Vec<(String, MenuItem)>,
        sel: usize,
    },
    Form(Form<FormKind>),
    Confirm {
        plan: Plan,
        typed: String,
        scroll: u16,
    },
    Report {
        title: String,
        lines: Vec<String>,
        ok: bool,
        scroll: u16,
    },
    Recovery {
        key: String,
        slot: Option<u32>,
    },
    Message {
        title: String,
        text: String,
    },
    Help,
}

pub enum Job {
    Execute(Plan),
    TestToken(Cmd),
}

#[derive(Default)]
pub struct Rects {
    pub tabs: Vec<(Rect, Tab)>,
    pub slots: Vec<(Rect, u32)>,
    pub menu: Vec<(Rect, usize)>,
    pub issues: Vec<(Rect, usize)>,
}

pub struct App {
    pub ctx: Ctx,
    pub sys: SystemInfo,
    pub devices: Vec<LuksDevice>,
    pub dev_idx: usize,
    pub ov: Option<Overview>,
    pub load_error: Option<String>,
    pub issues: Vec<Issue>,
    pub boot: Option<Vec<bootcheck::Item>>,
    pub pcr_table: Option<Result<PcrValues, String>>,
    pub fido2_devices: Option<Vec<String>>,
    pub tab: Tab,
    pub selected: u32,
    pub issue_sel: usize,
    pub log_scroll: u16,
    pub modal: Option<Modal>,
    pub pending: Option<Job>,
    pub busy: Option<String>,
    pub log: Vec<String>,
    pub status: String,
    pub rects: Rects,
    pub quit: bool,
    last_click: Option<(u32, Instant)>,
}

fn cred(form: &Form<FormKind>, pw: &str, kf: &str) -> Result<Credential, String> {
    let path = form.text(kf);
    if !path.trim().is_empty() {
        return Ok(Credential::Keyfile(PathBuf::from(path.trim())));
    }
    let p = form.text(pw);
    if p.is_empty() {
        return Err("请输入现有密码，或填写密钥文件路径".into());
    }
    Ok(Credential::Passphrase(Secret::from(p)))
}

fn auth_fields(label: &str) -> Vec<Field> {
    vec![
        Field::secret("auth_pw", label).hint("任一现有槽位的密码或恢复密钥"),
        Field::text("auth_kf", "或 密钥文件", "").hint("填写后改用该密钥文件验证"),
    ]
}

fn note_fields(text: &str, loc: Location) -> Vec<Field> {
    vec![
        Field::text("note", "备注", text).hint("最多 64 字。头部未加密，请勿写密码提示"),
        Field::choice(
            "note_loc",
            "备注位置",
            &[Location::Header.label(), Location::Local.label()],
            usize::from(loc == Location::Local),
        ),
    ]
}

fn note_input(form: &Form<FormKind>) -> Option<NoteInput> {
    let text = form.text("note").trim().to_owned();
    let location = if form.choice("note_loc") == 1 {
        Location::Local
    } else {
        Location::Header
    };
    Some(NoteInput { text, location })
}

fn new_secret(form: &Form<FormKind>, a: &str, b: &str) -> Result<Secret, String> {
    let (x, y) = (form.text(a), form.text(b));
    if x != y {
        return Err("两次输入的不一致".into());
    }
    Ok(Secret::from(x))
}

fn slot_field(form: &Form<FormKind>) -> Result<Option<u32>, String> {
    let s = form.text("slot");
    if s.trim().is_empty() {
        return Ok(None);
    }
    s.trim()
        .parse()
        .map(Some)
        .map_err(|_| "槽位必须是数字".to_owned())
}

fn kdf_field() -> Field {
    Field::choice(
        "kdf",
        "PBKDF",
        &["argon2id（默认）", "pbkdf2（GRUB 解锁 /boot 时需要）"],
        0,
    )
}

fn kdf(form: &Form<FormKind>) -> KdfChoice {
    if form.choice("kdf") == 1 {
        KdfChoice::Pbkdf2
    } else {
        KdfChoice::Default
    }
}

impl App {
    pub fn new(ctx: Ctx, sys: SystemInfo, devices: Vec<LuksDevice>, status: String) -> Self {
        let mut app = App {
            ctx,
            sys,
            devices,
            dev_idx: 0,
            ov: None,
            load_error: None,
            issues: Vec::new(),
            boot: None,
            pcr_table: None,
            fido2_devices: None,
            tab: Tab::Slots,
            selected: 0,
            issue_sel: 0,
            log_scroll: 0,
            modal: None,
            pending: None,
            busy: None,
            log: Vec::new(),
            status,
            rects: Rects::default(),
            quit: false,
            last_click: None,
        };
        app.reload();
        app
    }

    pub fn device(&self) -> Option<&LuksDevice> {
        self.devices.get(self.dev_idx)
    }

    pub fn reload(&mut self) {
        self.boot = None;
        self.pcr_table = None;
        let Some(dev) = self.device().cloned() else {
            self.ov = None;
            self.load_error = Some(
                "没有找到 LUKS 设备。可以用参数指定设备或镜像文件：luks-assistant-tui /dev/sdX2".into(),
            );
            return;
        };
        match Overview::load(&self.ctx, dev) {
            Ok(mut ov) => {
                if self.sys.is_root {
                    let _ = ov.remember_pcrs(&self.ctx);
                }
                self.issues = health::check(&ov);
                self.issue_sel = self.issue_sel.min(self.issues.len().saturating_sub(1));
                self.ov = Some(ov);
                self.load_error = None;
            }
            Err(e) => {
                self.ov = None;
                self.issues.clear();
                self.load_error = Some(format!("读取失败: {e}"));
            }
        }
    }

    pub fn selected_slot(&self) -> Option<&Slot> {
        self.ov.as_ref().and_then(|o| o.slot(self.selected))
    }

    pub fn ensure_pcr_table(&mut self) {
        if self.pcr_table.is_none() {
            self.pcr_table = Some(luks_assistant_sysinfo::tpm::read_pcrs(
                "sha256",
                &self.ctx.tpm2_device,
            ));
        }
    }

    fn ensure_boot(&mut self) {
        if self.boot.is_none() {
            let target = self
                .ov
                .as_ref()
                .map(|o| bootcheck::Target {
                    uuid: o.header.uuid.clone(),
                    path: o.device.path.to_string_lossy().into_owned(),
                    mapping: o.device.mapping.clone(),
                })
                .unwrap_or_default();
            self.boot = Some(bootcheck::check(&target));
        }
        if self.fido2_devices.is_none() {
            self.fido2_devices = Some(luks_assistant_sysinfo::fido2::list_devices());
        }
    }

    pub fn set_tab(&mut self, t: Tab) {
        self.tab = t;
        match t {
            Tab::System => {
                self.ensure_pcr_table();
                if self.fido2_devices.is_none() {
                    self.fido2_devices = Some(luks_assistant_sysinfo::fido2::list_devices());
                }
            }
            Tab::Boot => self.ensure_boot(),
            _ => {}
        }
    }

    fn message(&mut self, title: &str, text: impl Into<String>) {
        self.modal = Some(Modal::Message {
            title: title.into(),
            text: text.into(),
        });
    }

    // ---- menus -----------------------------------------------------------

    pub fn add_menu(&self) -> Vec<(String, MenuItem)> {
        let mut v = vec![
            (
                "添加密码".to_owned(),
                MenuItem::Form(FormKind::AddPassphrase),
            ),
            (
                "添加已有密钥文件".to_owned(),
                MenuItem::Form(FormKind::AddKeyfile),
            ),
            (
                "生成新密钥文件并添加".to_owned(),
                MenuItem::Form(FormKind::GenerateKeyfile),
            ),
        ];
        if self.ctx.caps.cryptenroll {
            v.push((
                "生成恢复密钥".into(),
                MenuItem::Form(FormKind::Recovery { replace: None }),
            ));
            v.push((
                "录入 TPM2".into(),
                MenuItem::Form(FormKind::Tpm2 { replace: None }),
            ));
            v.push((
                "录入 FIDO2 安全密钥".into(),
                MenuItem::Form(FormKind::Fido2 { replace: None }),
            ));
            v.push((
                "录入 PKCS#11 智能卡".into(),
                MenuItem::Form(FormKind::Pkcs11 { replace: None }),
            ));
        }
        v
    }

    pub fn slot_menu(&self, s: &Slot) -> Vec<(String, MenuItem)> {
        if s.is_empty() {
            return self.add_menu();
        }
        let id = s.id;
        let mut v: Vec<(String, MenuItem)> = Vec::new();
        match &s.kind {
            k if k.is_plain() => {
                v.push(("修改密码".into(), MenuItem::Form(FormKind::Change(id))));
            }
            SlotKind::Recovery => {
                v.push((
                    "重新生成恢复密钥（替换本槽位）".into(),
                    MenuItem::Form(FormKind::Recovery { replace: Some(id) }),
                ));
            }
            SlotKind::Tpm2 => {
                v.push((
                    "重新录入 TPM2（可修改 PCR，替换本槽位）".into(),
                    MenuItem::Form(FormKind::Tpm2 { replace: Some(id) }),
                ));
            }
            SlotKind::Fido2 => {
                v.push((
                    "重新录入 FIDO2（替换本槽位）".into(),
                    MenuItem::Form(FormKind::Fido2 { replace: Some(id) }),
                ));
            }
            SlotKind::Pkcs11 => {
                v.push((
                    "重新录入 PKCS#11（替换本槽位）".into(),
                    MenuItem::Form(FormKind::Pkcs11 { replace: Some(id) }),
                ));
            }
            _ => {}
        }
        if let Some(&tok) = s.tokens.first() {
            if matches!(s.kind, SlotKind::Tpm2 | SlotKind::Fido2 | SlotKind::Pkcs11) {
                let interactive =
                    s.kind != SlotKind::Tpm2 || s.tpm2.as_ref().is_some_and(|t| t.pin);
                v.push((
                    "实际测试令牌解锁（不挂载）".into(),
                    MenuItem::TestToken {
                        token: tok,
                        interactive,
                    },
                ));
            }
        }
        v.push(("编辑备注".into(), MenuItem::Form(FormKind::Note(id))));
        v.push(("设置优先级".into(), MenuItem::Form(FormKind::Priority(id))));
        v.push(("删除槽位".into(), MenuItem::Form(FormKind::Remove(id))));
        v
    }

    fn open_menu(&mut self, title: String, items: Vec<(String, MenuItem)>) {
        if items.is_empty() {
            return;
        }
        self.modal = Some(Modal::Menu {
            title,
            items,
            sel: 0,
        });
    }

    fn activate(&mut self, item: MenuItem) {
        match item {
            MenuItem::Form(k) => self.open_form(k),
            MenuItem::TestToken { token, interactive } => {
                if let Some(ov) = &self.ov {
                    self.modal = None;
                    self.busy = Some("正在测试令牌…".into());
                    self.pending =
                        Some(Job::TestToken(ops::test_token_cmd(ov, token, interactive)));
                }
            }
            MenuItem::Device(i) => {
                self.modal = None;
                self.dev_idx = i;
                self.selected = 0;
                self.reload();
            }
        }
    }

    // ---- forms -----------------------------------------------------------

    pub fn open_form(&mut self, kind: FormKind) {
        if matches!(kind, FormKind::Tpm2 { .. }) {
            self.ensure_pcr_table();
        }
        let Some(ov) = &self.ov else { return };
        let slot_note = |id: u32| {
            ov.slot(id)
                .and_then(|s| s.note.as_ref())
                .map(|n| (n.note.text.clone(), n.location))
                .unwrap_or((String::new(), Location::Header))
        };
        let (title, mut fields) = match &kind {
            FormKind::AddPassphrase => ("添加密码", {
                let mut f = auth_fields("现有密码");
                f.push(Field::secret("new", "新密码"));
                f.push(Field::secret("new2", "再次输入新密码"));
                f.push(Field::text("slot", "槽位", "").hint("留空自动选择第一个空槽位"));
                f.push(kdf_field());
                f.extend(note_fields("", Location::Header));
                f
            }),
            FormKind::AddKeyfile => ("添加已有密钥文件", {
                let mut f = auth_fields("现有密码");
                f.push(Field::text("path", "密钥文件路径", ""));
                f.push(Field::text("slot", "槽位", "").hint("留空自动选择"));
                f.push(kdf_field());
                f.extend(note_fields("", Location::Header));
                f
            }),
            FormKind::GenerateKeyfile => ("生成新密钥文件并添加", {
                let short: String = ov.header.uuid.chars().take(8).collect();
                let mut f = auth_fields("现有密码");
                f.push(
                    Field::text("path", "新密钥文件路径", &format!("/root/luks-{short}.key"))
                        .hint("文件必须不存在；生成后权限为 0400"),
                );
                f.push(Field::text("size", "大小（字节）", "4096"));
                f.push(Field::text("slot", "槽位", "").hint("留空自动选择"));
                f.extend(note_fields("", Location::Header));
                f
            }),
            FormKind::Recovery { replace } => (
                if replace.is_some() {
                    "重新生成恢复密钥"
                } else {
                    "生成恢复密钥"
                },
                {
                    let mut f = auth_fields("现有密码");
                    let (t, l) = replace
                        .map(slot_note)
                        .unwrap_or((String::new(), Location::Header));
                    f.extend(note_fields(&t, l));
                    f.push(Field::label("恢复密钥只会显示一次，请准备好纸笔"));
                    f
                },
            ),
            FormKind::Tpm2 { replace } => (
                if replace.is_some() {
                    "重新录入 TPM2"
                } else {
                    "录入 TPM2"
                },
                {
                    let old = replace
                        .and_then(|r| ov.slot(r))
                        .and_then(|s| s.tpm2.as_ref());
                    let pcrs = old.map(|t| t.pcrs.clone()).unwrap_or_else(|| vec![7]);
                    let pin = old.is_some_and(|t| t.pin);
                    let mut f = auth_fields("现有密码");
                    f.push(Field::pcrs("pcrs", "PCR", &pcrs).hint("←/→ 移动，空格 勾选"));
                    f.push(Field::toggle("use_pin", "开机时需要 PIN", pin));
                    f.push(Field::secret("pin", "PIN"));
                    f.push(Field::secret("pin2", "再次输入 PIN"));
                    let (t, l) = replace
                        .map(slot_note)
                        .unwrap_or((String::new(), Location::Header));
                    f.extend(note_fields(&t, l));
                    f
                },
            ),
            FormKind::Fido2 { replace } => (
                if replace.is_some() {
                    "重新录入 FIDO2"
                } else {
                    "录入 FIDO2 安全密钥"
                },
                {
                    let old = replace
                        .and_then(|r| ov.slot(r))
                        .and_then(|s| s.fido2.as_ref());
                    let mut f = auth_fields("现有密码");
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
                        "需要用户验证（指纹等）",
                        old.and_then(|o| o.user_verification).unwrap_or(false),
                    ));
                    let (t, l) = replace
                        .map(slot_note)
                        .unwrap_or((String::new(), Location::Header));
                    f.extend(note_fields(&t, l));
                    f.push(Field::label(
                        "确认后会暂时离开界面，在终端里按提示输入 PIN 并触摸密钥",
                    ));
                    f
                },
            ),
            FormKind::Pkcs11 { replace } => ("录入 PKCS#11 智能卡", {
                let mut f = auth_fields("现有密码");
                f.push(Field::text("uri", "令牌 URI", "auto"));
                let (t, l) = replace
                    .map(slot_note)
                    .unwrap_or((String::new(), Location::Header));
                f.extend(note_fields(&t, l));
                f
            }),
            FormKind::Change(id) => ("修改密码", {
                vec![
                    Field::label(&format!("槽位 {id}")),
                    Field::secret("auth_pw", "该槽位当前的密码"),
                    Field::text("auth_kf", "或 该槽位的密钥文件", ""),
                    Field::secret("new", "新密码"),
                    Field::secret("new2", "再次输入新密码"),
                    kdf_field(),
                ]
            }),
            FormKind::Note(id) => ("编辑备注", {
                let (t, l) = slot_note(*id);
                let mut f = vec![Field::label(&format!("槽位 {id}（留空 = 删除备注）"))];
                f.extend(note_fields(&t, l));
                f
            }),
            FormKind::Priority(id) => ("设置优先级", {
                let cur = ov
                    .slot(*id)
                    .and_then(|s| s.keyslot.as_ref())
                    .map(|k| k.priority)
                    .unwrap_or(Priority::Normal);
                let idx = match cur {
                    Priority::Ignore => 0,
                    Priority::Normal => 1,
                    Priority::Prefer => 2,
                };
                vec![
                    Field::label(&format!("槽位 {id}")),
                    Field::choice("prio", "优先级", &["忽略", "普通", "优先"], idx)
                        .hint("“优先”的槽位先被尝试；“忽略”的槽位只有显式指定时才使用"),
                ]
            }),
            FormKind::Remove(id) => ("删除槽位", {
                let mut f = vec![Field::label(&format!(
                    "删除槽位 {id}（{}）。请用另一个保留槽位的凭据验证",
                    ov.slot(*id).map(|s| s.kind.label()).unwrap_or_default()
                ))];
                f.extend(auth_fields("其它槽位的密码"));
                f
            }),
            FormKind::TestPass => ("测试密码", {
                let mut f = auth_fields("密码");
                f.push(Field::label("只验证，不挂载；会显示该密码对应的槽位"));
                f
            }),
            FormKind::Backup => (
                "备份 LUKS 头部",
                vec![Field::text("path", "保存到", "").hint(&format!(
                    "留空 = {}",
                    self.ctx.paths.backups_dir(&ov.header.uuid).display()
                ))],
            ),
            FormKind::Restore => ("从备份恢复 LUKS 头部", {
                let dir = self.ctx.paths.backups_dir(&ov.header.uuid);
                let mut files: Vec<String> = std::fs::read_dir(&dir)
                    .map(|rd| {
                        rd.filter_map(|e| e.ok())
                            .map(|e| e.path().to_string_lossy().into_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                files.sort();
                let latest = files.last().cloned().unwrap_or_default();
                let mut f = vec![Field::text("path", "备份文件", &latest)];
                f.push(Field::label(&format!(
                    "{} 中共有 {} 个备份",
                    dir.display(),
                    files.len()
                )));
                f
            }),
        };
        if fields.is_empty() {
            fields.push(Field::label(""));
        }
        self.modal = Some(Modal::Form(Form::new(title, kind, fields)));
    }

    fn build_request(&self, form: &Form<FormKind>) -> Result<Option<Request>, String> {
        let r = match &form.kind {
            FormKind::AddPassphrase => Request::AddPassphrase {
                auth: cred(form, "auth_pw", "auth_kf")?,
                new: new_secret(form, "new", "new2")?,
                slot: slot_field(form)?,
                kdf: kdf(form),
                note: note_input(form),
            },
            FormKind::AddKeyfile => Request::AddKeyfile {
                auth: cred(form, "auth_pw", "auth_kf")?,
                path: PathBuf::from(form.text("path").trim()),
                generate: None,
                slot: slot_field(form)?,
                kdf: kdf(form),
                note: note_input(form),
            },
            FormKind::GenerateKeyfile => Request::AddKeyfile {
                auth: cred(form, "auth_pw", "auth_kf")?,
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
                auth: cred(form, "auth_pw", "auth_kf")?,
                replace: *replace,
                note: note_input(form),
            },
            FormKind::Tpm2 { replace } => Request::EnrollTpm2 {
                auth: cred(form, "auth_pw", "auth_kf")?,
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
                auth: cred(form, "auth_pw", "auth_kf")?,
                client_pin: form.toggle("pin"),
                user_presence: form.toggle("up"),
                user_verification: form.toggle("uv"),
                replace: *replace,
                note: note_input(form),
            },
            FormKind::Pkcs11 { replace } => Request::EnrollPkcs11 {
                auth: cred(form, "auth_pw", "auth_kf")?,
                uri: form.text("uri"),
                replace: *replace,
                note: note_input(form),
            },
            FormKind::Change(id) => Request::ChangePassphrase {
                slot: *id,
                old: cred(form, "auth_pw", "auth_kf")?,
                new: new_secret(form, "new", "new2")?,
                kdf: kdf(form),
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
                    [form.choice("prio")],
            },
            FormKind::Remove(id) => Request::RemoveSlot {
                slot: *id,
                auth: cred(form, "auth_pw", "auth_kf")?,
            },
            FormKind::Backup => {
                let p = form.text("path");
                Request::BackupHeader {
                    dest: (!p.trim().is_empty()).then(|| PathBuf::from(p.trim())),
                }
            }
            FormKind::Restore => Request::RestoreHeader {
                file: PathBuf::from(form.text("path").trim()),
            },
            FormKind::TestPass => return Ok(None),
        };
        Ok(Some(r))
    }

    fn submit_form(&mut self, form: Form<FormKind>) {
        let Some(ov) = &self.ov else { return };
        if let FormKind::TestPass = form.kind {
            let c = match cred(&form, "auth_pw", "auth_kf") {
                Ok(c) => c,
                Err(e) => return self.form_error(form, e),
            };
            match ops::verify_credential(&self.ctx, &ov.device.path, &c) {
                Ok(slot) => self.message("测试密码", format!("✓ 可以解锁槽位 {slot}")),
                Err(e) => self.message("测试密码", format!("✗ {e}")),
            }
            return;
        }
        if !self.sys.is_root && !ov.device.is_file {
            return self.form_error(form, "需要 root 权限：请用 sudo luks-assistant-tui 运行".into());
        }
        let req = match self.build_request(&form) {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => return self.form_error(form, e),
        };
        match ops::plan(&self.ctx, ov, &req) {
            Ok(plan) => {
                self.modal = Some(Modal::Confirm {
                    plan,
                    typed: String::new(),
                    scroll: 0,
                })
            }
            Err(e) => self.form_error(form, e.to_string()),
        }
    }

    fn form_error(&mut self, mut form: Form<FormKind>, e: String) {
        form.error = Some(e);
        self.modal = Some(Modal::Form(form));
    }

    fn request_plan(&mut self, req: Request) {
        let Some(ov) = &self.ov else { return };
        match ops::plan(&self.ctx, ov, &req) {
            Ok(plan) => {
                self.modal = Some(Modal::Confirm {
                    plan,
                    typed: String::new(),
                    scroll: 0,
                })
            }
            Err(e) => self.message("无法执行", e.to_string()),
        }
    }

    // ---- jobs ------------------------------------------------------------

    pub fn run_job(&mut self, job: Job, terminal: &mut DefaultTerminal) {
        self.busy = None;
        match job {
            Job::Execute(plan) => {
                let mut hooks = TuiHooks { terminal };
                let report = ops::execute(&self.ctx, &plan, &mut hooks);
                let mut lines = vec![format!(
                    "{} — {}",
                    plan.title,
                    if report.ok { "成功" } else { "失败" }
                )];
                if let Some(b) = &report.backup_file {
                    lines.push(format!("头部备份: {}", b.display()));
                }
                lines.push(String::new());
                for s in &report.steps {
                    lines.push(format!("{} {}", if s.ok { "✓" } else { "✗" }, s.desc));
                    if let Some(c) = &s.command {
                        lines.push(format!("    $ {c}"));
                    }
                    for l in s.output.lines().filter(|l| !l.trim().is_empty()) {
                        lines.push(format!("    {l}"));
                    }
                }
                if let Some(e) = &report.error {
                    lines.push(String::new());
                    lines.push(format!("错误: {e}"));
                }
                self.log.push(format!(
                    "[{}] {} — {}",
                    luks_assistant_core::util::format_time(luks_assistant_core::util::now_unix()),
                    plan.title,
                    if report.ok { "成功" } else { "失败" }
                ));
                self.log.extend(
                    lines
                        .iter()
                        .skip(1)
                        .filter(|l| !l.is_empty())
                        .map(|l| format!("  {l}")),
                );
                self.status = format!(
                    "{}: {}",
                    plan.title,
                    if report.ok { "成功" } else { "失败" }
                );
                self.reload();
                if let Some(slot) = report.new_slot {
                    self.selected = slot;
                }
                if let Some(key) = report.recovery_key {
                    self.modal = Some(Modal::Recovery {
                        key: String::from_utf8_lossy(key.expose()).into_owned(),
                        slot: report.new_slot,
                    });
                } else {
                    self.modal = Some(Modal::Report {
                        title: plan.title.clone(),
                        lines,
                        ok: report.ok,
                        scroll: 0,
                    });
                }
            }
            Job::TestToken(cmd) => {
                let display = cmd.display();
                let result = if cmd.interactive {
                    let mut hooks = TuiHooks { terminal };
                    hooks.suspend();
                    let r = self.ctx.runner.run(&cmd);
                    hooks.resume();
                    r.map(|o| (o.code, String::new()))
                } else {
                    self.ctx.runner.run(&cmd).map(|o| (o.code, o.stderr))
                };
                let text = match result {
                    Ok((0, out)) => format!("✓ 令牌可以解锁\n\n$ {display}\n{out}"),
                    Ok((code, out)) => format!(
                        "✗ 令牌未能解锁（退出码 {code}）\n\n$ {display}\n{out}\n提示：需要安装 systemd 的 cryptsetup 令牌插件；TPM2 策略不匹配时也会失败"
                    ),
                    Err(e) => format!("✗ {e}"),
                };
                self.message("测试令牌", text);
            }
        }
    }

    // ---- input -----------------------------------------------------------

    pub fn on_paste(&mut self, s: &str) {
        if let Some(Modal::Form(f)) = &mut self.modal {
            f.on_paste(s);
        }
    }

    pub fn on_key(&mut self, k: KeyEvent) {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if let Some(modal) = self.modal.take() {
            self.on_modal_key(modal, k);
            return;
        }
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') | KeyCode::F(1) => self.modal = Some(Modal::Help),
            KeyCode::Char(c @ '1'..='5') => self.set_tab(TABS[c as usize - '1' as usize].0),
            KeyCode::Tab => {
                let i = TABS.iter().position(|(t, _)| *t == self.tab).unwrap_or(0);
                self.set_tab(TABS[(i + 1) % TABS.len()].0);
            }
            KeyCode::BackTab => {
                let i = TABS.iter().position(|(t, _)| *t == self.tab).unwrap_or(0);
                self.set_tab(TABS[(i + TABS.len() - 1) % TABS.len()].0);
            }
            KeyCode::F(5) => {
                self.devices_rescan();
                self.reload();
                self.set_tab(self.tab);
                self.status = "已刷新".into();
            }
            KeyCode::Char('D') => {
                let items = self
                    .devices
                    .iter()
                    .enumerate()
                    .map(|(i, d)| (d.display_name(), MenuItem::Device(i)))
                    .collect();
                self.open_menu("选择设备".into(), items);
            }
            KeyCode::Char('t') => self.open_form(FormKind::TestPass),
            KeyCode::Char('b') => self.open_form(FormKind::Backup),
            KeyCode::Char('R') => self.open_form(FormKind::Restore),
            KeyCode::Char('a') if self.ov.is_some() => {
                self.open_menu("添加".into(), self.add_menu())
            }
            _ => match self.tab {
                Tab::Slots => self.on_slots_key(k),
                Tab::Health => self.on_health_key(k),
                Tab::Log => match k.code {
                    KeyCode::Up => self.log_scroll = self.log_scroll.saturating_sub(1),
                    KeyCode::Down => self.log_scroll = self.log_scroll.saturating_add(1),
                    _ => {}
                },
                _ => {}
            },
        }
    }

    fn devices_rescan(&mut self) {
        let current = self.device().map(|d| d.path.clone());
        if let Ok(found) = luks_assistant_core::device::discover(&self.ctx) {
            // keep explicitly opened image files
            let mut devs: Vec<LuksDevice> =
                self.devices.iter().filter(|d| d.is_file).cloned().collect();
            devs.extend(found);
            self.devices = devs;
            self.dev_idx = current
                .and_then(|p| self.devices.iter().position(|d| d.path == p))
                .unwrap_or(0);
        }
    }

    fn on_slots_key(&mut self, k: KeyEvent) {
        let cols = 8;
        let s = self.selected as i32;
        let mv = |d: i32| ((s + d).rem_euclid(32)) as u32;
        match k.code {
            KeyCode::Left | KeyCode::Char('h') => self.selected = mv(-1),
            KeyCode::Right | KeyCode::Char('l') => self.selected = mv(1),
            KeyCode::Up | KeyCode::Char('k') => self.selected = mv(-cols),
            KeyCode::Down | KeyCode::Char('j') => self.selected = mv(cols),
            KeyCode::Enter | KeyCode::Char(' ') => self.open_slot_menu(),
            KeyCode::Char('d') | KeyCode::Delete => {
                if self.selected_slot().is_some_and(|s| !s.is_empty()) {
                    self.open_form(FormKind::Remove(self.selected));
                }
            }
            KeyCode::Char('n') => {
                if self.selected_slot().is_some_and(|s| !s.is_empty()) {
                    self.open_form(FormKind::Note(self.selected));
                }
            }
            KeyCode::Char('e') => {
                if let Some(item) = self
                    .selected_slot()
                    .and_then(|s| self.slot_menu(s).into_iter().next())
                {
                    if !self.selected_slot().is_some_and(Slot::is_empty) {
                        self.activate(item.1);
                    }
                }
            }
            _ => {}
        }
    }

    fn open_slot_menu(&mut self) {
        if let Some(s) = self.selected_slot() {
            let title = if s.is_empty() {
                format!("槽位 {}（空）", s.id)
            } else {
                format!("槽位 {}（{}）", s.id, s.kind.label())
            };
            let items = self.slot_menu(s);
            self.open_menu(title, items);
        }
    }

    fn on_health_key(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Up => self.issue_sel = self.issue_sel.saturating_sub(1),
            KeyCode::Down => {
                self.issue_sel = (self.issue_sel + 1).min(self.issues.len().saturating_sub(1))
            }
            KeyCode::Enter => {
                if let Some(fix) = self.issues.get(self.issue_sel).and_then(|i| i.fix.clone()) {
                    self.request_plan(fix);
                }
            }
            _ => {}
        }
    }

    fn on_modal_key(&mut self, modal: Modal, k: KeyEvent) {
        match modal {
            Modal::Menu {
                title,
                items,
                mut sel,
            } => match k.code {
                KeyCode::Esc | KeyCode::Char('q') => {}
                KeyCode::Up | KeyCode::Char('k') => {
                    sel = (sel + items.len() - 1) % items.len();
                    self.modal = Some(Modal::Menu { title, items, sel });
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    sel = (sel + 1) % items.len();
                    self.modal = Some(Modal::Menu { title, items, sel });
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    let item = items[sel].1.clone();
                    self.activate(item);
                }
                _ => self.modal = Some(Modal::Menu { title, items, sel }),
            },
            Modal::Form(mut form) => match form.on_key(k) {
                FormEvent::Cancel => {}
                FormEvent::Submit => self.submit_form(form),
                FormEvent::None => self.modal = Some(Modal::Form(form)),
            },
            Modal::Confirm {
                plan,
                mut typed,
                mut scroll,
            } => match k.code {
                KeyCode::Esc => self.status = "已取消".into(),
                KeyCode::Enter => {
                    let ok = plan.confirm_word.as_ref().is_none_or(|w| typed.trim() == w);
                    if ok {
                        self.busy = Some(format!("正在执行：{}…", plan.title));
                        self.pending = Some(Job::Execute(plan));
                    } else {
                        self.modal = Some(Modal::Confirm {
                            plan,
                            typed,
                            scroll,
                        });
                    }
                }
                KeyCode::Up => {
                    scroll = scroll.saturating_sub(1);
                    self.modal = Some(Modal::Confirm {
                        plan,
                        typed,
                        scroll,
                    });
                }
                KeyCode::Down => {
                    scroll = scroll.saturating_add(1);
                    self.modal = Some(Modal::Confirm {
                        plan,
                        typed,
                        scroll,
                    });
                }
                KeyCode::Backspace => {
                    typed.pop();
                    self.modal = Some(Modal::Confirm {
                        plan,
                        typed,
                        scroll,
                    });
                }
                KeyCode::Char(c) if plan.confirm_word.is_some() => {
                    typed.push(c);
                    self.modal = Some(Modal::Confirm {
                        plan,
                        typed,
                        scroll,
                    });
                }
                _ => {
                    self.modal = Some(Modal::Confirm {
                        plan,
                        typed,
                        scroll,
                    })
                }
            },
            Modal::Report {
                title,
                lines,
                ok,
                mut scroll,
            } => match k.code {
                KeyCode::Up => {
                    scroll = scroll.saturating_sub(1);
                    self.modal = Some(Modal::Report {
                        title,
                        lines,
                        ok,
                        scroll,
                    });
                }
                KeyCode::Down => {
                    scroll = scroll.saturating_add(1);
                    self.modal = Some(Modal::Report {
                        title,
                        lines,
                        ok,
                        scroll,
                    });
                }
                _ => {}
            },
            Modal::Recovery { key, slot } => {
                // Require an explicit acknowledgement so the key is not dismissed by accident.
                if k.code != KeyCode::Char('y') && k.code != KeyCode::Char('Y') {
                    self.modal = Some(Modal::Recovery { key, slot });
                }
            }
            Modal::Message { .. } | Modal::Help => {}
        }
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        let pos = Position::new(m.column, m.row);
        match m.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(Modal::Menu { .. }) = &self.modal {
                    let hit = self
                        .rects
                        .menu
                        .iter()
                        .find(|(r, _)| r.contains(pos))
                        .map(|(_, i)| *i);
                    if let Some(i) = hit {
                        if let Some(Modal::Menu { items, .. }) = self.modal.take() {
                            let item = items[i].1.clone();
                            self.activate(item);
                        }
                    }
                    return;
                }
                if self.modal.is_some() {
                    return;
                }
                if let Some((_, t)) = self.rects.tabs.iter().find(|(r, _)| r.contains(pos)) {
                    let t = *t;
                    self.set_tab(t);
                    return;
                }
                if self.tab == Tab::Slots {
                    if let Some((_, id)) = self
                        .rects
                        .slots
                        .iter()
                        .find(|(r, _)| r.contains(pos))
                        .copied()
                    {
                        let double = self.last_click.is_some_and(|(s, t)| {
                            s == id && t.elapsed() < Duration::from_millis(500)
                        });
                        self.selected = id;
                        self.last_click = Some((id, Instant::now()));
                        if double {
                            self.last_click = None;
                            self.open_slot_menu();
                        }
                    }
                }
                if self.tab == Tab::Health {
                    if let Some((_, i)) = self.rects.issues.iter().find(|(r, _)| r.contains(pos)) {
                        self.issue_sel = *i;
                    }
                }
            }
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let down = matches!(m.kind, MouseEventKind::ScrollDown);
                let code = if down { KeyCode::Down } else { KeyCode::Up };
                self.on_key(KeyEvent::new(code, KeyModifiers::NONE));
            }
            _ => {}
        }
    }
}

/// Leaves and re-enters the TUI around interactive commands (FIDO2 touch, PIN prompts).
struct TuiHooks<'a> {
    terminal: &'a mut DefaultTerminal,
}

impl Hooks for TuiHooks<'_> {
    fn suspend(&mut self) {
        crate::term::leave();
        println!("\n=== luks-assistant：以下步骤需要你在终端中操作（输入 PIN / 触摸安全密钥）===\n");
    }

    fn resume(&mut self) {
        println!("\n=== 按回车键返回 luks-assistant ===");
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
        *self.terminal = crate::term::enter();
    }
}

/// Short label for PCR lists in the UI.
pub fn pcr_label(p: &[u8]) -> String {
    if p.is_empty() {
        "无".into()
    } else {
        pcr::format_list(p)
    }
}
