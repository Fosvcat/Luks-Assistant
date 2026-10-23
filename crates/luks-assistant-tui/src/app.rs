//! Application state and input handling.

use crate::form::{FormEvent, FormState};
use luks_assistant_core::device::{self, BlockTree, LuksDevice};
use luks_assistant_core::forms::{self, Env, FormKind, Submit, VerifyMethod};
use luks_assistant_core::health::{self, Issue};
use luks_assistant_core::ops::{self, Hooks, Plan, Request, TokenKind, TokenTest};
use luks_assistant_core::slots::{Overview, Slot};
use luks_assistant_core::{Ctx, config};
use luks_assistant_core::{n, t};
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
    Health,
    Boot,
    Backup,
    Log,
}

pub const TABS: [(Tab, &str); 6] = [
    (Tab::Slots, n!("1 槽位")),
    (Tab::System, n!("2 系统信息")),
    (Tab::Health, n!("3 体检")),
    (Tab::Boot, n!("4 开机检查")),
    (Tab::Backup, n!("5 备份")),
    (Tab::Log, n!("6 日志")),
];

#[derive(Debug, Clone)]
pub enum MenuItem {
    Form(FormKind),
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
    Form(FormState),
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
    VerifyTokens {
        kind: TokenKind,
        tests: Vec<TokenTest>,
    },
}

#[derive(Default)]
pub struct Rects {
    pub tabs: Vec<(Rect, Tab)>,
    pub slots: Vec<(Rect, u32)>,
    pub menu: Vec<(Rect, usize)>,
    pub issues: Vec<(Rect, usize)>,
    pub backups: Vec<(Rect, usize)>,
    pub disk: Option<Rect>,
    pub verify: Option<Rect>,
    pub trim: Option<Rect>,
    pub backup_button: Option<Rect>,
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

    /// TRIM support of the current device: (header flag, device accepts discards).
    pub fn trim_state(&self) -> Option<(bool, Option<bool>)> {
        let ov = self.ov.as_ref()?;
        let node = self.tree.find(&ov.device.path.to_string_lossy());
        let dev = node.and_then(|n| n.mapping().and_then(|m| m.trim()).or(n.trim()));
        Some((ov.header.allows_discards(), dev))
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
        match forms::build(kind, &env) {
            Ok(f) => self.modal = Some(Modal::Form(FormState::new(f))),
            Err(e) => self.message(t!("无法执行"), e),
        }
    }

    fn needs_root(&self) -> bool {
        !self.sys.is_root && !self.ov.as_ref().is_some_and(|o| o.device.is_file)
    }

    fn submit_form(&mut self, mut state: FormState) {
        let submit = match forms::submit(&state.form) {
            Ok(s) => s,
            Err(e) => {
                state.error = Some(e);
                self.modal = Some(Modal::Form(state));
                return;
            }
        };
        match submit {
            Submit::Verify(m) => self.verify(m),
            // only the GUI offers an unlock form
            Submit::Unlock(_) => {}
            Submit::SetBackupDir(d) => match config::set_backup_dir(&mut self.ctx.paths, d) {
                Ok(()) => self.status = t!("备份位置: {}", self.ctx.paths.backup_root.display()),
                Err(e) => {
                    state.error = Some(e.to_string());
                    self.modal = Some(Modal::Form(state));
                }
            },
            Submit::Request(req) => {
                if self.needs_root() {
                    state.error = Some(t!("需要 root：sudo Luks-Assistant-TUI").into());
                    self.modal = Some(Modal::Form(state));
                    return;
                }
                let Some(ov) = &self.ov else { return };
                match ops::plan(&self.ctx, ov, &req) {
                    Ok(plan) => self.confirm(vec![plan]),
                    Err(e) => {
                        state.error = Some(e.to_string());
                        self.modal = Some(Modal::Form(state));
                    }
                }
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

    fn request_plan(&mut self, req: Request) {
        let Some(ov) = &self.ov else { return };
        match ops::plan(&self.ctx, ov, &req) {
            Ok(plan) => self.confirm(vec![plan]),
            Err(e) => self.message(t!("无法执行"), e.to_string()),
        }
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
                    self.pending = Some(Job::VerifyTokens { kind, tests });
                }
            }
        }
    }

    fn backup_selected(&mut self) {
        if !self.sys.is_root && self.devices.iter().any(|d| !d.is_file) {
            return self.message(t!("备份"), t!("需要 root：sudo Luks-Assistant-TUI"));
        }
        let mut plans = Vec::new();
        let mut errors = Vec::new();
        for (i, d) in self.devices.iter().enumerate() {
            if !self.backup_sel.get(i).copied().unwrap_or(false) {
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
            Job::VerifyTokens { kind, tests } => {
                let mut last = String::new();
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
                        Ok(o) => last = ops::token_failure(&o).to_string(),
                        Err(e) => last = e.to_string(),
                    }
                }
                self.message(t!("验证"), t!("✗ {} 验证失败\n{}", kind.label(), last));
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
            KeyCode::F(5) => {
                self.rescan();
                self.reload();
                self.pcr_table = None;
                self.fido2_devices = None;
                self.pkcs11_tokens = None;
                self.set_tab(self.tab);
                self.status = t!("已刷新").into();
            }
            _ => match self.tab {
                Tab::Slots => self.on_slots_key(k),
                Tab::Health => self.on_health_key(k),
                Tab::Backup => self.on_backup_key(k),
                Tab::Log => match k.code {
                    KeyCode::Up => self.log_scroll = self.log_scroll.saturating_sub(1),
                    KeyCode::Down => self.log_scroll = self.log_scroll.saturating_add(1),
                    _ => {}
                },
                _ => {}
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
            KeyCode::Char('T') => self.open_form(FormKind::Discards),
            KeyCode::Char('D') => self.open_picker(),
            _ => {}
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

    fn on_backup_key(&mut self, k: KeyEvent) {
        let n = self.devices.len();
        match k.code {
            KeyCode::Up => self.backup_cursor = self.backup_cursor.saturating_sub(1),
            KeyCode::Down => self.backup_cursor = (self.backup_cursor + 1).min(n.saturating_sub(1)),
            KeyCode::Char(' ') => {
                if let Some(b) = self.backup_sel.get_mut(self.backup_cursor) {
                    *b = !*b;
                }
            }
            KeyCode::Char('a') => {
                let all = self.backup_sel.iter().all(|b| *b);
                self.backup_sel.iter_mut().for_each(|b| *b = !all);
            }
            KeyCode::Enter | KeyCode::Char('b') => self.backup_selected(),
            KeyCode::Char('c') => self.open_form(FormKind::BackupDir),
            KeyCode::Char('r') if n > 0 => {
                if self.dev_idx != self.backup_cursor {
                    self.dev_idx = self.backup_cursor;
                    self.reload();
                }
                self.open_form(FormKind::Restore);
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
                    let MenuItem::Form(kind) = items[sel].1.clone();
                    self.open_form(kind);
                }
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
            Modal::Form(mut state) => match state.on_key(k) {
                FormEvent::Cancel => {}
                FormEvent::Submit => self.submit_form(state),
                FormEvent::None => self.modal = Some(Modal::Form(state)),
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
                                let MenuItem::Form(kind) = items[i].1.clone();
                                self.open_form(kind);
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
                match self.tab {
                    Tab::Slots => {
                        if hit(&self.rects.disk) {
                            return self.open_picker();
                        }
                        if hit(&self.rects.verify) {
                            return self.open_form(FormKind::Verify);
                        }
                        if hit(&self.rects.trim) {
                            return self.open_form(FormKind::Discards);
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
                    Tab::Health => {
                        if let Some((_, i)) =
                            self.rects.issues.iter().find(|(r, _)| r.contains(pos))
                        {
                            self.issue_sel = *i;
                        }
                    }
                    Tab::Backup => {
                        if hit(&self.rects.backup_button) {
                            return self.backup_selected();
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
