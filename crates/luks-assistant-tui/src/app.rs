//! Application state and input handling.

use crate::form::{FormEvent, FormState};
use luks_assistant_core::device::{self, BlockTree, LuksDevice};
use luks_assistant_core::forms::{self, Env, FormKind, Submit, VerifyMethod};
use luks_assistant_core::health::{self, Issue};
use luks_assistant_core::i18n::Text;
use luks_assistant_core::ops::{self, Hooks, Plan, Request, TokenKind, TokenTest};
use luks_assistant_core::slots::{Overview, Slot};
use luks_assistant_core::{Ctx, config};
use luks_assistant_core::{n, t, tx};
use luks_assistant_sysinfo::SystemInfo;
use luks_assistant_sysinfo::bootcheck;
use luks_assistant_sysinfo::tpm::PcrValues;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Position, Rect};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Slots,
    System,
    Check,
    Headers,
    Log,
    About,
}

pub const TABS: [(Tab, &str); 6] = [
    (Tab::Slots, n!("1 槽位")),
    (Tab::System, n!("2 系统信息")),
    (Tab::Check, n!("3 自我检查")),
    (Tab::Headers, n!("4 头部管理")),
    (Tab::Log, n!("5 日志")),
    (Tab::About, n!("6 关于")),
];

pub const REPO_URL: &str = "https://github.com/Fosvcat/Luks-Assistant";

#[derive(Debug, Clone)]
pub enum MenuItem {
    Form(FormKind),
    /// Back up / restore the volume with this index in `devices`.
    Backup(usize),
    Restore(usize),
    Prune(usize),
}

/// The buttons of the header page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderButton {
    All,
    Invert,
    Clear,
    Backup,
    Restore,
    Prune,
}

/// What a form is for: a core operation, or the TUI's own log export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormUse {
    Core,
    ExportLog,
}

/// A row of the disk picker: the lsblk tree, LUKS rows selectable.
pub struct PickRow {
    pub depth: usize,
    pub text: String,
    pub device: Option<usize>,
}

pub enum Modal {
    Menu {
        title: String,
        items: Vec<(String, MenuItem)>,
        sel: usize,
    },
    Picker {
        rows: Vec<PickRow>,
        sel: usize,
    },
    Form(FormState, FormUse),
    Confirm {
        plans: Vec<Plan>,
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
    Execute(Vec<Plan>),
    /// Try the tokens in turn: verify only, or open the volume.
    Tokens {
        kind: TokenKind,
        tests: Vec<TokenTest>,
        unlock: bool,
    },
}

#[derive(Default)]
pub struct Rects {
    pub tabs: Vec<(Rect, Tab)>,
    pub slots: Vec<(Rect, u32)>,
    pub menu: Vec<(Rect, usize)>,
    pub issues: Vec<(Rect, usize)>,
    pub backups: Vec<(Rect, usize)>,
    pub header_buttons: Vec<(Rect, HeaderButton)>,
    pub disk: Option<Rect>,
    pub verify: Option<Rect>,
    pub lock: Option<Rect>,
    pub refresh: Option<Rect>,
    pub all_pcrs: Option<Rect>,
}

pub struct App {
    pub ctx: Ctx,
    pub sys: SystemInfo,
    pub tree: BlockTree,
    /// Image files / paths given on the command line.
    pub extra: Vec<LuksDevice>,
    pub devices: Vec<LuksDevice>,
    pub dev_idx: usize,
    pub ov: Option<Overview>,
    pub load_error: Option<String>,
    pub issues: Vec<Issue>,
    pub boot: Option<Vec<bootcheck::Item>>,
    pub pcr_table: Option<Result<PcrValues, String>>,
    pub fido2_devices: Option<Vec<String>>,
    pub pkcs11_tokens: Option<Vec<String>>,
    pub tab: Tab,
    /// Show all 24 PCRs instead of the ones useful for LUKS.
    pub show_all_pcrs: bool,
    pub selected: u32,
    pub issue_sel: usize,
    pub log_scroll: u16,
    pub backup_sel: Vec<bool>,
    pub backup_cursor: usize,
    pub modal: Option<Modal>,
    pub pending: Option<Job>,
    pub busy: Option<String>,
    pub log: Vec<String>,
    pub status: String,
    pub rects: Rects,
    pub quit: bool,
    last_click: Option<(u32, Instant)>,
}

impl App {
    pub fn new(ctx: Ctx, sys: SystemInfo, extra: Vec<LuksDevice>, status: String) -> Self {
        let mut app = App {
            ctx,
            sys,
            tree: BlockTree::default(),
            extra,
            devices: Vec::new(),
            dev_idx: 0,
            ov: None,
            load_error: None,
            issues: Vec::new(),
            boot: None,
            pcr_table: None,
            fido2_devices: None,
            pkcs11_tokens: None,
            tab: Tab::Slots,
            show_all_pcrs: false,
            selected: 0,
            issue_sel: 0,
            log_scroll: 0,
            backup_sel: Vec::new(),
            backup_cursor: 0,
            modal: None,
            pending: None,
            busy: None,
            log: Vec::new(),
            status,
            rects: Rects::default(),
            quit: false,
            last_click: None,
        };
        app.rescan();
        app.reload();
        app
    }

    pub fn device(&self) -> Option<&LuksDevice> {
        self.devices.get(self.dev_idx)
    }

    /// Re-read lsblk; keep the current device selected.
    pub fn rescan(&mut self) {
        let current = self.device().map(|d| d.path.clone());
        match device::block_tree(&self.ctx) {
            Ok(t) => self.tree = t,
            Err(e) => self.status = format!("lsblk: {e}"),
        }
        let mut devs = self.extra.clone();
        for d in self.tree.luks_devices() {
            if !devs.iter().any(|x| x.path == d.path) {
                devs.push(d);
            }
        }
        // keep UUIDs learned from headers (image files have none in lsblk)
        for d in &mut devs {
            if d.uuid.is_none() {
                d.uuid = self
                    .devices
                    .iter()
                    .find(|o| o.path == d.path)
                    .and_then(|o| o.uuid.clone());
            }
        }
        self.devices = devs;
        self.dev_idx = current
            .and_then(|p| self.devices.iter().position(|d| d.path == p))
            .unwrap_or(0);
        self.backup_sel.resize(self.devices.len(), true);
        self.backup_cursor = self.backup_cursor.min(self.devices.len().saturating_sub(1));
    }

    pub fn reload(&mut self) {
        self.boot = None;
        let Some(dev) = self.device().cloned() else {
            self.ov = None;
            self.load_error = Some(t!("没有找到 LUKS 卷").into());
            return;
        };
        match Overview::load(&self.ctx, dev) {
            Ok(mut ov) => {
                if self.sys.is_root {
                    let _ = ov.remember_pcrs(&self.ctx);
                }
                if let Some(d) = self.devices.get_mut(self.dev_idx) {
                    d.uuid = Some(ov.header.uuid.clone());
                }
                self.issues = health::check(&ov);
                self.issue_sel = self.issue_sel.min(self.issues.len().saturating_sub(1));
                self.ov = Some(ov);
                self.load_error = None;
            }
            Err(e) => {
                self.ov = None;
                self.issues.clear();
                self.load_error = Some(t!("读取失败: {}", e));
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
    }

    pub fn set_tab(&mut self, t: Tab) {
        self.tab = t;
        match t {
            Tab::System => {
                self.ensure_pcr_table();
                if self.fido2_devices.is_none() {
                    self.fido2_devices = Some(luks_assistant_sysinfo::fido2::list_devices());
                }
                if self.pkcs11_tokens.is_none() {
                    self.pkcs11_tokens = Some(luks_assistant_sysinfo::fido2::list_pkcs11());
                }
            }
            Tab::Check => self.ensure_boot(),
            _ => {}
        }
    }

    /// PCRs shown in lists and pickers: the ones useful for LUKS, or all.
    pub fn visible_pcrs(&self) -> Vec<u8> {
        if self.show_all_pcrs {
            (0..24).collect()
        } else {
            luks_assistant_core::pcr::PREFERRED.to_vec()
        }
    }

    /// Re-read everything, like the GUI's refresh button.
    pub fn refresh(&mut self) {
        self.rescan();
        self.reload();
        self.pcr_table = None;
        self.fido2_devices = None;
        self.pkcs11_tokens = None;
        self.set_tab(self.tab);
        self.status = t!("已刷新").into();
    }

    /// Add a line to the (English) log.
    fn log_line(&mut self, line: &str) {
        let time = luks_assistant_core::util::format_time(luks_assistant_core::util::now_unix());
        self.log.push(format!("[{time}] {line}"));
    }

    fn message(&mut self, title: &str, text: impl Into<String>) {
        self.modal = Some(Modal::Message {
            title: title.into(),
            text: text.into(),
        });
    }

    // ---- menus and forms ---------------------------------------------------

    fn open_menu(&mut self, title: String, items: Vec<(String, MenuItem)>) {
        if !items.is_empty() {
            self.modal = Some(Modal::Menu {
                title,
                items,
                sel: 0,
            });
        }
    }

    fn open_slot_menu(&mut self) {
        let Some(s) = self.selected_slot() else {
            return;
        };
        let title = if s.is_empty() {
            t!("槽位 {}", s.id)
        } else {
            t!("槽位 {}（{}）", s.id, s.kind.label())
        };
        let items = forms::slot_actions(s, &self.ctx.caps)
            .into_iter()
            .map(|(l, k)| (l, MenuItem::Form(k)))
            .collect();
        self.open_menu(title, items);
    }

    fn open_picker(&mut self) {
        let mut rows: Vec<PickRow> = self
            .extra
            .iter()
            .map(|d| PickRow {
                depth: 0,
                text: t!("{}  镜像文件", d.path.display()),
                device: self.devices.iter().position(|x| x.path == d.path),
            })
            .collect();
        for (depth, n) in self.tree.flatten() {
            let label = n
                .label
                .as_deref()
                .map(|l| format!(" [{l}]"))
                .unwrap_or_default();
            let model = n
                .model
                .as_deref()
                .map(|m| format!(" {m}"))
                .unwrap_or_default();
            let fs = n.fstype.clone().unwrap_or_default();
            let mp = n
                .mountpoints
                .first()
                .map(|m| format!(" {m}"))
                .unwrap_or_default();
            rows.push(PickRow {
                depth,
                text: format!(
                    "{}  {}  {}{}{}{}{}",
                    n.path,
                    n.size.clone().unwrap_or_default(),
                    n.kind,
                    if fs.is_empty() {
                        String::new()
                    } else {
                        format!(" {fs}")
                    },
                    label,
                    model,
                    mp
                ),
                device: n
                    .is_luks()
                    .then(|| {
                        self.devices
                            .iter()
                            .position(|d| d.path.as_os_str() == n.path.as_str())
                    })
                    .flatten(),
            });
        }
        let sel = rows
            .iter()
            .position(|r| r.device == Some(self.dev_idx))
            .unwrap_or(0);
        self.modal = Some(Modal::Picker { rows, sel });
    }

    pub fn open_form(&mut self, kind: FormKind) {
        if matches!(kind, FormKind::Tpm2 { .. }) {
            self.ensure_pcr_table();
        }
        let Some(ov) = &self.ov else { return };
        let env = Env {
            ov,
            caps: &self.ctx.caps,
            paths: &self.ctx.paths,
            ask_pins: false,
        };
        let pcrs: Vec<usize> = self.visible_pcrs().into_iter().map(usize::from).collect();
        match forms::build(kind, &env) {
            Ok(f) => self.modal = Some(Modal::Form(FormState::new(f, pcrs), FormUse::Core)),
            Err(e) => self.message(t!("无法执行"), e),
        }
    }

    fn open_export(&mut self) {
        let time = luks_assistant_core::util::format_time(luks_assistant_core::util::now_unix())
            .trim_end_matches(" UTC")
            .replace(['-', ':'], "")
            .replace(' ', "-");
        let dir = std::env::current_dir().unwrap_or_default();
        let path = dir.join(format!("luks-assistant-log-{time}.txt"));
        let form = forms::Form {
            title: t!("导出日志").into(),
            kind: FormKind::BackupDir,
            fields: vec![forms::Field::save_file(
                "path",
                t!("文件"),
                &path.to_string_lossy(),
            )],
        };
        self.modal = Some(Modal::Form(
            FormState::new(form, Vec::new()),
            FormUse::ExportLog,
        ));
    }

    fn export_log(&mut self, mut state: FormState) {
        let path = state.form.text("path");
        let path = path.trim();
        let mut text = self.log.join("\n");
        text.push('\n');
        match std::fs::write(path, text) {
            Ok(()) => self.status = t!("日志已导出：{}", path),
            Err(e) => {
                state.error = Some(e.to_string());
                self.modal = Some(Modal::Form(state, FormUse::ExportLog));
            }
        }
    }

    fn needs_root(&self) -> bool {
        !self.sys.is_root && !self.ov.as_ref().is_some_and(|o| o.device.is_file)
    }

    fn submit_form(&mut self, mut state: FormState, using: FormUse) {
        if using == FormUse::ExportLog {
            return self.export_log(state);
        }
        let submit = match forms::submit(&state.form) {
            Ok(s) => s,
            Err(e) => {
                state.error = Some(e);
                self.modal = Some(Modal::Form(state, using));
                return;
            }
        };
        match submit {
            Submit::Verify(m) => self.verify(m),
            Submit::Unlock(m) => {
                if !self.sys.is_root {
                    state.error = Some(t!("需要 root：sudo Luks-Assistant-TUI").into());
                    self.modal = Some(Modal::Form(state, using));
                    return;
                }
                if let Err(e) = self.unlock(m) {
                    state.error = Some(e);
                    self.modal = Some(Modal::Form(state, using));
                }
            }
            Submit::SetBackupDir(d) => match config::set_backup_dir(&mut self.ctx.paths, d) {
                Ok(()) => self.status = t!("备份位置: {}", self.ctx.paths.backup_root.display()),
                Err(e) => {
                    state.error = Some(e.to_string());
                    self.modal = Some(Modal::Form(state, using));
                }
            },
            Submit::Request(req) => {
                if self.needs_root() {
                    state.error = Some(t!("需要 root：sudo Luks-Assistant-TUI").into());
                    self.modal = Some(Modal::Form(state, using));
                    return;
                }
                let Some(ov) = &self.ov else { return };
                match ops::plan(&self.ctx, ov, &req) {
                    Ok(plan) => self.confirm(vec![plan]),
                    Err(e) => {
                        state.error = Some(e.to_string());
                        self.modal = Some(Modal::Form(state, using));
                    }
                }
            }
        }
    }

    /// Open the volume with a password or key file right away; tokens may
    /// prompt for a PIN or touch, so they run as a job outside the TUI.
    fn unlock(&mut self, m: VerifyMethod) -> Result<(), String> {
        let Some(ov) = &self.ov else { return Ok(()) };
        match m {
            VerifyMethod::Credential(c) => {
                let cmd = ops::unlock_cmd(ov, &c).map_err(|e| e.to_string())?;
                let out = self.ctx.runner.run(&cmd).map_err(|e| e.to_string())?;
                if !out.success() {
                    let why = match out.code {
                        2 => tx!("密码或密钥文件不正确"),
                        _ => ops::token_failure(&out),
                    };
                    let text = tx!("解锁失败：{}", why);
                    self.log_line(&text.en());
                    return Err(text.to_string());
                }
                self.unlocked();
            }
            VerifyMethod::Token { kind, pin } => {
                let tests =
                    ops::token_unlock_cmds(ov, kind, pin.as_ref()).map_err(|e| e.to_string())?;
                if tests.is_empty() {
                    return Err(t!("没有 {} 令牌", kind.label()));
                }
                self.busy = Some(t!("正在解锁…").into());
                self.pending = Some(Job::Tokens {
                    kind,
                    tests,
                    unlock: true,
                });
            }
        }
        Ok(())
    }

    fn unlocked(&mut self) {
        let Some(ov) = &self.ov else { return };
        let text = tx!(
            "已解锁 {} → {}",
            ov.device.path.display(),
            ops::mapping_name(ov)
        );
        self.log_line(&text.en());
        self.status = text.to_string();
        self.rescan();
        self.reload();
    }

    /// The lock/unlock button: lock an open volume, or ask how to unlock.
    fn toggle_lock(&mut self) {
        let Some(ov) = &self.ov else { return };
        if ov.device.mapping.is_none() {
            return self.open_form(FormKind::Unlock);
        }
        if !self.sys.is_root {
            return self.message(t!("锁定"), t!("需要 root：sudo Luks-Assistant-TUI"));
        }
        let path = ov.device.path.display().to_string();
        let result = ops::lock_cmd(ov)
            .and_then(|cmd| self.ctx.runner.run(&cmd))
            .and_then(|out| out.check("cryptsetup close").map(|_| ()));
        match result {
            Ok(()) => {
                let text = tx!("已锁定 {}", path);
                self.log_line(&text.en());
                self.status = text.to_string();
                self.rescan();
                self.reload();
            }
            Err(e) => {
                self.log_line(&format!("Lock {path} failed: {}", e.text().en()));
                self.message(t!("锁定"), e.to_string());
            }
        }
    }

    fn confirm(&mut self, plans: Vec<Plan>) {
        self.modal = Some(Modal::Confirm {
            plans,
            typed: String::new(),
            scroll: 0,
        });
    }

    fn verify(&mut self, m: VerifyMethod) {
        let Some(ov) = &self.ov else { return };
        match m {
            VerifyMethod::Credential(c) => {
                match ops::verify_credential(&self.ctx, &ov.device.path, &c) {
                    Ok(slot) => {
                        let kind = ov.slot(slot).map(|s| s.kind.label()).unwrap_or_default();
                        self.message(t!("验证"), t!("✓ 槽位 {}（{}）验证成功", slot, kind))
                    }
                    Err(e) => self.message(t!("验证"), format!("✗ {e}")),
                }
            }
            VerifyMethod::Token { kind, pin } => {
                let tests = ops::token_tests(ov, kind, pin.as_ref());
                if tests.is_empty() {
                    self.message(t!("验证"), t!("没有 {} 令牌", kind.label()));
                } else {
                    self.busy = Some(t!("正在验证 {}…", kind.label()));
                    self.pending = Some(Job::Tokens {
                        kind,
                        tests,
                        unlock: false,
                    });
                }
            }
        }
    }

    /// Indices of the checked volumes on the header page.
    pub fn checked_volumes(&self) -> Vec<usize> {
        (0..self.devices.len())
            .filter(|i| self.backup_sel.get(*i).copied().unwrap_or(false))
            .collect()
    }

    fn header_button(&mut self, b: HeaderButton) {
        match b {
            HeaderButton::All => self.backup_sel.iter_mut().for_each(|x| *x = true),
            HeaderButton::Invert => self.backup_sel.iter_mut().for_each(|x| *x = !*x),
            HeaderButton::Clear => self.backup_sel.iter_mut().for_each(|x| *x = false),
            HeaderButton::Backup => self.backup_volumes(self.checked_volumes()),
            HeaderButton::Prune => self.prune_volumes(self.checked_volumes()),
            HeaderButton::Restore => {
                if let [i] = self.checked_volumes()[..] {
                    self.restore_volume(i);
                }
            }
        }
    }

    fn volume_menu(&mut self, i: usize) {
        let Some(d) = self.devices.get(i) else { return };
        self.open_menu(
            d.display_name(),
            vec![
                (t!("备份").into(), MenuItem::Backup(i)),
                (t!("恢复…").into(), MenuItem::Restore(i)),
                (t!("清理旧备份").into(), MenuItem::Prune(i)),
            ],
        );
    }

    fn menu_item(&mut self, item: MenuItem) {
        match item {
            MenuItem::Form(kind) => self.open_form(kind),
            MenuItem::Backup(i) => self.backup_volumes(vec![i]),
            MenuItem::Restore(i) => self.restore_volume(i),
            MenuItem::Prune(i) => self.prune_volumes(vec![i]),
        }
    }

    /// Keep only the newest header backup of each volume.
    fn prune_volumes(&mut self, volumes: Vec<usize>) {
        if !self.sys.is_root
            && volumes
                .iter()
                .any(|i| self.devices.get(*i).is_some_and(|d| !d.is_file))
        {
            return self.message(t!("清理"), t!("需要 root：sudo Luks-Assistant-TUI"));
        }
        let mut plans = Vec::new();
        let mut errors = Vec::new();
        for i in volumes {
            let Some(d) = self.devices.get(i) else {
                continue;
            };
            match Overview::load(&self.ctx, d.clone())
                .and_then(|ov| ops::plan(&self.ctx, &ov, &Request::PruneBackups))
            {
                Ok(p) => plans.push(p),
                // nothing to delete for this one
                Err(luks_assistant_core::Error::Invalid(_)) => {}
                Err(e) => errors.push(format!("{}: {e}", d.path.display())),
            }
        }
        if plans.is_empty() {
            let text = if errors.is_empty() {
                t!("没有可清理的旧备份").to_owned()
            } else {
                errors.join("\n")
            };
            return self.message(t!("清理"), text);
        }
        self.confirm(plans);
    }

    fn restore_volume(&mut self, i: usize) {
        if self.dev_idx != i {
            self.dev_idx = i;
            self.selected = 0;
            self.reload();
        }
        self.open_form(FormKind::Restore);
    }

    fn backup_volumes(&mut self, volumes: Vec<usize>) {
        if !self.sys.is_root
            && volumes
                .iter()
                .any(|i| self.devices.get(*i).is_some_and(|d| !d.is_file))
        {
            return self.message(t!("备份"), t!("需要 root：sudo Luks-Assistant-TUI"));
        }
        let mut plans = Vec::new();
        let mut errors = Vec::new();
        for (i, d) in self.devices.iter().enumerate() {
            if !volumes.contains(&i) {
                continue;
            }
            let r = Overview::load(&self.ctx, d.clone())
                .and_then(|ov| ops::plan(&self.ctx, &ov, &Request::BackupHeader { dest: None }));
            match r {
                Ok(p) => plans.push(p),
                Err(e) => errors.push(format!("{}: {e}", d.path.display())),
            }
        }
        if plans.is_empty() {
            let text = if errors.is_empty() {
                t!("未选择任何卷").to_owned()
            } else {
                errors.join("\n")
            };
            return self.message(t!("备份"), text);
        }
        if let Some(p) = plans.first_mut() {
            p.warnings.extend(
                errors
                    .into_iter()
                    .map(luks_assistant_core::i18n::Text::plain),
            );
        }
        self.confirm(plans);
    }

    // ---- jobs --------------------------------------------------------------

    pub fn run_job(&mut self, job: Job, terminal: &mut DefaultTerminal) {
        self.busy = None;
        match job {
            Job::Execute(plans) => self.execute(plans, terminal),
            Job::Tokens {
                kind,
                tests,
                unlock,
            } => {
                let title = if unlock { t!("解锁") } else { t!("验证") };
                let mut last = Text::plain("");
                for t in tests {
                    let out = if t.cmd.interactive {
                        let mut hooks = TuiHooks { terminal };
                        hooks.suspend();
                        let r = self.ctx.runner.run(&t.cmd);
                        hooks.resume();
                        r
                    } else {
                        self.ctx.runner.run(&t.cmd)
                    };
                    match out {
                        Ok(o) if o.success() && unlock => return self.unlocked(),
                        Ok(o) if o.success() => {
                            let slots = t
                                .slots
                                .iter()
                                .map(u32::to_string)
                                .collect::<Vec<_>>()
                                .join(", ");
                            return self.message(
                                t!("验证"),
                                t!(
                                    "✓ 槽位 {}（{} 令牌 {}）验证成功",
                                    slots,
                                    kind.label(),
                                    t.token
                                ),
                            );
                        }
                        Ok(o) => last = ops::token_failure(&o),
                        Err(e) => last = e.text(),
                    }
                }
                if unlock {
                    self.log_line(&format!(
                        "Unlock with {} failed: {}",
                        kind.label(),
                        last.en()
                    ));
                    self.message(title, t!("✗ 解锁失败：{}", last));
                } else {
                    self.message(title, t!("✗ {} 验证失败\n{}", kind.label(), last));
                }
            }
        }
    }

    fn execute(&mut self, plans: Vec<Plan>, terminal: &mut DefaultTerminal) {
        let mut lines = Vec::new();
        let mut all_ok = true;
        let mut recovery = None;
        let mut new_slot = None;
        let title = if plans.len() == 1 {
            plans[0].title.to_string()
        } else {
            t!("{} 项操作", plans.len())
        };
        for plan in &plans {
            let mut hooks = TuiHooks { terminal };
            let report = ops::execute(&self.ctx, plan, &mut hooks);
            all_ok &= report.ok;
            lines.push(format!(
                "{} {} — {}",
                if report.ok { "✓" } else { "✗" },
                plan.title,
                plan.device.display()
            ));
            if let Some(b) = &report.backup_file {
                lines.push(t!("  备份: {}", b.display()));
            }
            for s in &report.steps {
                lines.push(format!("  {} {}", if s.ok { "✓" } else { "✗" }, s.desc));
                if let Some(c) = &s.command {
                    lines.push(format!("      $ {c}"));
                }
                for l in s
                    .output
                    .to_string()
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                {
                    lines.push(format!("      {l}"));
                }
            }
            if let Some(e) = &report.error {
                lines.push(t!("  错误: {}", e));
            }
            lines.push(String::new());
            recovery = recovery.or(report.recovery_key.clone());
            new_slot = new_slot.or(report.new_slot);
            // The log is always English.
            let time =
                luks_assistant_core::util::format_time(luks_assistant_core::util::now_unix());
            for (i, l) in ops::log_text(plan, &report).lines().enumerate() {
                self.log.push(if i == 0 {
                    format!("[{time}] {l}")
                } else {
                    l.to_owned()
                });
            }
        }
        self.status = format!("{title}: {}", if all_ok { t!("成功") } else { t!("失败") });
        self.rescan();
        self.reload();
        if let Some(s) = new_slot {
            self.selected = s;
        }
        self.modal = Some(match recovery {
            Some(key) => Modal::Recovery {
                key: String::from_utf8_lossy(key.expose()).into_owned(),
                slot: new_slot,
            },
            None => Modal::Report {
                title,
                lines,
                ok: all_ok,
                scroll: 0,
            },
        });
    }

    // ---- input -------------------------------------------------------------

    pub fn on_paste(&mut self, s: &str) {
        if let Some(Modal::Form(f, _)) = &mut self.modal {
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
            KeyCode::Char(c @ '1'..='6') => self.set_tab(TABS[c as usize - '1' as usize].0),
            KeyCode::Tab | KeyCode::BackTab => {
                let i = TABS.iter().position(|(t, _)| *t == self.tab).unwrap_or(0);
                let n = TABS.len();
                let next = if k.code == KeyCode::Tab {
                    (i + 1) % n
                } else {
                    (i + n - 1) % n
                };
                self.set_tab(TABS[next].0);
            }
            KeyCode::F(5) => self.refresh(),
            _ => match self.tab {
                Tab::Slots => self.on_slots_key(k),
                Tab::System => {
                    if k.code == KeyCode::Char('p') {
                        self.show_all_pcrs = !self.show_all_pcrs;
                    }
                }
                Tab::Check => self.on_check_key(k),
                Tab::Headers => self.on_headers_key(k),
                Tab::Log => match k.code {
                    KeyCode::Up => self.log_scroll = self.log_scroll.saturating_sub(1),
                    KeyCode::Down => self.log_scroll = self.log_scroll.saturating_add(1),
                    KeyCode::Char('x') => self.open_export(),
                    _ => {}
                },
                Tab::About => {}
            },
        }
    }

    fn on_slots_key(&mut self, k: KeyEvent) {
        let s = self.selected as i32;
        let mv = |d: i32| ((s + d).rem_euclid(32)) as u32;
        let used = self.selected_slot().is_some_and(|s| !s.is_empty());
        match k.code {
            KeyCode::Left | KeyCode::Char('h') => self.selected = mv(-1),
            KeyCode::Right | KeyCode::Char('l') => self.selected = mv(1),
            KeyCode::Up | KeyCode::Char('k') => self.selected = mv(-8),
            KeyCode::Down | KeyCode::Char('j') => self.selected = mv(8),
            KeyCode::Enter | KeyCode::Char(' ') => self.open_slot_menu(),
            KeyCode::Char('a') if self.ov.is_some() => {
                let items = forms::add_actions(&self.ctx.caps)
                    .into_iter()
                    .map(|(l, k)| (l, MenuItem::Form(k)))
                    .collect();
                self.open_menu(t!("添加").into(), items);
            }
            KeyCode::Char('d') | KeyCode::Delete if used => {
                self.open_form(FormKind::Remove(self.selected))
            }
            KeyCode::Char('n') if used => self.open_form(FormKind::Note(self.selected)),
            KeyCode::Char('e') if used => {
                if let Some((_, kind)) = self
                    .selected_slot()
                    .and_then(|s| forms::slot_actions(s, &self.ctx.caps).into_iter().next())
                {
                    self.open_form(kind);
                }
            }
            KeyCode::Char('v') => self.open_form(FormKind::Verify),
            KeyCode::Char('u') => self.toggle_lock(),
            KeyCode::Char('D') => self.open_picker(),
            _ => {}
        }
    }

    fn on_check_key(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Up => self.issue_sel = self.issue_sel.saturating_sub(1),
            KeyCode::Down => {
                self.issue_sel = (self.issue_sel + 1).min(self.issues.len().saturating_sub(1))
            }
            _ => {}
        }
    }

    fn on_headers_key(&mut self, k: KeyEvent) {
        let n = self.devices.len();
        match k.code {
            KeyCode::Up => self.backup_cursor = self.backup_cursor.saturating_sub(1),
            KeyCode::Down => self.backup_cursor = (self.backup_cursor + 1).min(n.saturating_sub(1)),
            KeyCode::Char(' ') => {
                if let Some(b) = self.backup_sel.get_mut(self.backup_cursor) {
                    *b = !*b;
                }
            }
            KeyCode::Enter if n > 0 => self.volume_menu(self.backup_cursor),
            KeyCode::Char('a') => self.header_button(HeaderButton::All),
            KeyCode::Char('i') => self.header_button(HeaderButton::Invert),
            KeyCode::Char('x') => self.header_button(HeaderButton::Clear),
            KeyCode::Char('b') => self.header_button(HeaderButton::Backup),
            KeyCode::Char('r') => self.header_button(HeaderButton::Restore),
            KeyCode::Char('p') => self.header_button(HeaderButton::Prune),
            KeyCode::Char('c') => self.open_form(FormKind::BackupDir),
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
                KeyCode::Enter | KeyCode::Char(' ') => self.menu_item(items[sel].1.clone()),
                _ => self.modal = Some(Modal::Menu { title, items, sel }),
            },
            Modal::Picker { rows, mut sel } => {
                let step = |sel: usize, dir: isize| -> usize {
                    let n = rows.len() as isize;
                    let mut i = sel as isize;
                    for _ in 0..n {
                        i = (i + dir).rem_euclid(n);
                        if rows[i as usize].device.is_some() {
                            return i as usize;
                        }
                    }
                    sel
                };
                match k.code {
                    KeyCode::Esc | KeyCode::Char('q') => {}
                    KeyCode::Up | KeyCode::Char('k') => {
                        sel = step(sel, -1);
                        self.modal = Some(Modal::Picker { rows, sel });
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        sel = step(sel, 1);
                        self.modal = Some(Modal::Picker { rows, sel });
                    }
                    KeyCode::Enter => match rows.get(sel).and_then(|r| r.device) {
                        Some(i) => self.select_device(i),
                        None => self.modal = Some(Modal::Picker { rows, sel }),
                    },
                    _ => self.modal = Some(Modal::Picker { rows, sel }),
                }
            }
            Modal::Form(mut state, using) => match state.on_key(k) {
                FormEvent::Cancel => {}
                FormEvent::Submit => self.submit_form(state, using),
                FormEvent::None => self.modal = Some(Modal::Form(state, using)),
            },
            Modal::Confirm {
                plans,
                mut typed,
                mut scroll,
            } => {
                let word = plans.iter().find_map(|p| p.confirm_word.clone());
                match k.code {
                    KeyCode::Esc => self.status = t!("已取消").into(),
                    KeyCode::Enter => {
                        if word.as_ref().is_none_or(|w| typed.trim() == w) {
                            self.busy = Some(t!("正在执行…").into());
                            self.pending = Some(Job::Execute(plans));
                        } else {
                            self.modal = Some(Modal::Confirm {
                                plans,
                                typed,
                                scroll,
                            });
                        }
                    }
                    KeyCode::Up => {
                        scroll = scroll.saturating_sub(1);
                        self.modal = Some(Modal::Confirm {
                            plans,
                            typed,
                            scroll,
                        });
                    }
                    KeyCode::Down => {
                        scroll = scroll.saturating_add(1);
                        self.modal = Some(Modal::Confirm {
                            plans,
                            typed,
                            scroll,
                        });
                    }
                    KeyCode::Backspace => {
                        typed.pop();
                        self.modal = Some(Modal::Confirm {
                            plans,
                            typed,
                            scroll,
                        });
                    }
                    KeyCode::Char(c) if word.is_some() => {
                        typed.push(c);
                        self.modal = Some(Modal::Confirm {
                            plans,
                            typed,
                            scroll,
                        });
                    }
                    _ => {
                        self.modal = Some(Modal::Confirm {
                            plans,
                            typed,
                            scroll,
                        })
                    }
                }
            }
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
                if !matches!(k.code, KeyCode::Char('y') | KeyCode::Char('Y')) {
                    self.modal = Some(Modal::Recovery { key, slot });
                }
            }
            Modal::Message { .. } | Modal::Help => {}
        }
    }

    fn select_device(&mut self, i: usize) {
        self.dev_idx = i;
        self.selected = 0;
        self.reload();
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        let pos = Position::new(m.column, m.row);
        let hit = |r: &Option<Rect>| r.is_some_and(|r| r.contains(pos));
        match m.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                match &self.modal {
                    Some(Modal::Menu { .. }) => {
                        if let Some(i) = self
                            .rects
                            .menu
                            .iter()
                            .find(|(r, _)| r.contains(pos))
                            .map(|(_, i)| *i)
                        {
                            if let Some(Modal::Menu { items, .. }) = self.modal.take() {
                                self.menu_item(items[i].1.clone());
                            }
                        }
                        return;
                    }
                    Some(Modal::Picker { rows, .. }) => {
                        let row = self
                            .rects
                            .menu
                            .iter()
                            .find(|(r, _)| r.contains(pos))
                            .map(|(_, i)| *i);
                        if let Some(dev) = row.and_then(|i| rows.get(i)).and_then(|r| r.device) {
                            self.modal = None;
                            self.select_device(dev);
                        }
                        return;
                    }
                    Some(_) => return,
                    None => {}
                }
                if let Some((_, t)) = self.rects.tabs.iter().find(|(r, _)| r.contains(pos)) {
                    let t = *t;
                    self.set_tab(t);
                    return;
                }
                if hit(&self.rects.refresh) {
                    return self.refresh();
                }
                match self.tab {
                    Tab::Slots => {
                        if hit(&self.rects.disk) {
                            return self.open_picker();
                        }
                        if hit(&self.rects.verify) {
                            return self.open_form(FormKind::Verify);
                        }
                        if hit(&self.rects.lock) {
                            return self.toggle_lock();
                        }
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
                    Tab::System => {
                        if hit(&self.rects.all_pcrs) {
                            self.show_all_pcrs = !self.show_all_pcrs;
                        }
                    }
                    Tab::Check => {
                        if let Some((_, i)) =
                            self.rects.issues.iter().find(|(r, _)| r.contains(pos))
                        {
                            self.issue_sel = *i;
                        }
                    }
                    Tab::Headers => {
                        if let Some((_, b)) = self
                            .rects
                            .header_buttons
                            .iter()
                            .find(|(r, _)| r.contains(pos))
                            .copied()
                        {
                            return self.header_button(b);
                        }
                        if let Some((r, i)) = self
                            .rects
                            .backups
                            .iter()
                            .find(|(r, _)| r.contains(pos))
                            .copied()
                        {
                            self.backup_cursor = i;
                            // clicking the checkbox column toggles
                            if pos.x < r.x + 4 {
                                if let Some(b) = self.backup_sel.get_mut(i) {
                                    *b = !*b;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            // context menus, like the GUI's right click
            MouseEventKind::Down(MouseButton::Right) if self.modal.is_none() => match self.tab {
                Tab::Slots => {
                    if let Some((_, id)) = self
                        .rects
                        .slots
                        .iter()
                        .find(|(r, _)| r.contains(pos))
                        .copied()
                    {
                        self.selected = id;
                        self.open_slot_menu();
                    }
                }
                Tab::Headers => {
                    if let Some((_, i)) = self
                        .rects
                        .backups
                        .iter()
                        .find(|(r, _)| r.contains(pos))
                        .copied()
                    {
                        self.backup_cursor = i;
                        self.volume_menu(i);
                    }
                }
                _ => {}
            },
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let code = if matches!(m.kind, MouseEventKind::ScrollDown) {
                    KeyCode::Down
                } else {
                    KeyCode::Up
                };
                self.on_key(KeyEvent::new(code, KeyModifiers::NONE));
            }
            _ => {}
        }
    }
}

/// Leaves and re-enters the TUI around interactive commands.
struct TuiHooks<'a> {
    terminal: &'a mut DefaultTerminal,
}

impl Hooks for TuiHooks<'_> {
    fn suspend(&mut self) {
        crate::term::leave();
        println!(
            "{}",
            t!("\n=== Luks Assistant：请按提示操作（PIN / 触摸安全密钥）===\n")
        );
    }

    fn resume(&mut self) {
        println!("{}", t!("\n=== 按回车返回 ==="));
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
        *self.terminal = crate::term::enter();
    }
}
