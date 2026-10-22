//! GUI state and callbacks. All state lives on the UI thread; helper calls
//! run on worker threads and report back with `upgrade_in_event_loop`.

use crate::client::Helper;
use crate::view::{self, colored, line, model};
use crate::{BackupRow, LineItem, MainWindow, PickRow};
use luks_assistant_core::backup::BackupFile;
use luks_assistant_core::device::{BlockTree, LuksDevice};
use luks_assistant_core::forms::{self, Env, Form, FormKind, Submit, Value, VerifyMethod};
use luks_assistant_core::health::Issue;
use luks_assistant_core::ops::{Danger, Request};
use luks_assistant_core::proto::{
    Event, Hello, Method, OverviewReply, PlanView, ReportView, TokenVerified,
};
use luks_assistant_core::slots::Overview;
use luks_assistant_core::util::format_time;
use luks_assistant_sysinfo::SystemInfo;
use luks_assistant_sysinfo::bootcheck::Item;
use luks_assistant_sysinfo::tpm::PcrValues;
use serde::de::DeserializeOwned;
use slint::{ComponentHandle, Model, SharedString, Weak};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

static HELPER: Mutex<Option<Helper>> = Mutex::new(None);
static UI: OnceLock<Weak<MainWindow>> = OnceLock::new();

thread_local! {
    static ST: RefCell<State> = RefCell::new(State::default());
}

#[derive(Default)]
struct State {
    hello: Option<Hello>,
    sys: Option<SystemInfo>,
    tree: BlockTree,
    extra: Vec<LuksDevice>,
    devices: Vec<LuksDevice>,
    dev_idx: usize,
    ov: Option<Overview>,
    issues: Vec<Issue>,
    boot: Vec<Item>,
    pcrs: Option<Result<PcrValues, String>>,
    fido2: Vec<String>,
    pkcs11: Vec<String>,
    backups: HashMap<String, Vec<BackupFile>>,
    backup_sel: Vec<bool>,
    selected: u32,
    actions: Vec<FormKind>,
    pick_map: Vec<Option<usize>>,
    form: Option<Form>,
    plans: Vec<PlanView>,
    busy: Vec<LineItem>,
    log: Vec<String>,
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    ST.with(|s| f(&mut s.borrow_mut()))
}

/// Call the helper (blocking; worker threads only). Events are forwarded to the busy dialog.
fn call<T: DeserializeOwned>(m: Method) -> Result<T, String> {
    let mut guard = HELPER.lock().unwrap();
    let h = guard.as_mut().ok_or("后端未连接")?;
    h.call(m, &mut |e| {
        let text = match e {
            Event::Progress(s) => format!("▶ {s}"),
            Event::Output(s) => s.trim().to_owned(),
        };
        if let Some(w) = UI.get() {
            let _ = w.upgrade_in_event_loop(move |ui| {
                with(|s| {
                    for l in text.lines().filter(|l| !l.trim().is_empty()) {
                        s.busy.push(line(l.to_owned()));
                    }
                    ui.set_modal_lines(model(s.busy.clone()));
                });
            });
        }
    })
}

/// Run `work` on a worker thread, then `done` on the UI thread.
fn bg<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
    done: impl FnOnce(&MainWindow, T) + Send + 'static,
) {
    let w = UI.get().expect("ui").clone();
    std::thread::spawn(move || {
        let r = work();
        let _ = w.upgrade_in_event_loop(move |ui| done(&ui, r));
    });
}

fn message(ui: &MainWindow, title: &str, text: impl Into<SharedString>) {
    ui.set_modal_title(title.into());
    ui.set_message(text.into());
    ui.set_message_closable(true);
    ui.set_modal(6);
}

fn busy(ui: &MainWindow, title: &str) {
    with(|s| s.busy.clear());
    ui.set_modal_title(title.into());
    ui.set_modal_lines(model(Vec::new()));
    ui.set_modal(3);
}

pub fn run(args: Vec<String>) -> Result<(), String> {
    let ui = MainWindow::new().map_err(|e| e.to_string())?;
    let _ = UI.set(ui.as_weak());
    with(|s| {
        s.extra = args
            .iter()
            .map(|a| LuksDevice::from_path(&PathBuf::from(a)))
            .collect()
    });
    wire(&ui);
    ui.set_header("luks-assistant".into());
    ui.set_modal_title("luks-assistant".into());
    ui.set_message("正在请求管理员权限…".into());
    ui.set_message_closable(false);
    ui.set_modal(6);
    connect(&ui);
    ui.run().map_err(|e| e.to_string())
}

fn connect(_ui: &MainWindow) {
    bg(
        || -> Result<Hello, String> {
            let h = Helper::start()?;
            *HELPER.lock().unwrap() = Some(h);
            call(Method::Hello)
        },
        |ui, r| match r {
            Ok(hello) => {
                with(|s| s.hello = Some(hello));
                ui.set_modal(0);
                refresh_all(ui);
            }
            Err(e) => {
                *HELPER.lock().unwrap() = None;
                ui.set_modal_title("无法启动后端".into());
                ui.set_message(format!("{e}\n\n点击“刷新”重试。").into());
                ui.set_message_closable(true);
                ui.set_modal(6);
            }
        },
    );
}

struct Global {
    sys: Result<SystemInfo, String>,
    tree: Result<BlockTree, String>,
    pcrs: Result<PcrValues, String>,
    fido2: Vec<String>,
    pkcs11: Vec<String>,
}

fn refresh_all(ui: &MainWindow) {
    if HELPER.lock().unwrap().is_none() {
        return connect(ui);
    }
    ui.set_status("正在读取…".into());
    bg(
        || Global {
            sys: call(Method::SystemInfo),
            tree: call(Method::BlockTree),
            pcrs: call(Method::Pcrs {
                bank: "sha256".into(),
            }),
            fido2: call(Method::Fido2Devices).unwrap_or_default(),
            pkcs11: call(Method::Pkcs11Tokens).unwrap_or_default(),
        },
        |ui, g| {
            let mut errors = Vec::new();
            with(|s| {
                match g.sys {
                    Ok(v) => s.sys = Some(v),
                    Err(e) => errors.push(e),
                }
                match g.tree {
                    Ok(t) => s.tree = t,
                    Err(e) => errors.push(e),
                }
                s.pcrs = Some(g.pcrs);
                s.fido2 = g.fido2;
                s.pkcs11 = g.pkcs11;
                let current = s.devices.get(s.dev_idx).map(|d| d.path.clone());
                let mut devs = s.extra.clone();
                for d in s.tree.luks_devices() {
                    if !devs.iter().any(|x| x.path == d.path) {
                        devs.push(d);
                    }
                }
                for d in &mut devs {
                    if d.uuid.is_none() {
                        d.uuid = s
                            .devices
                            .iter()
                            .find(|o| o.path == d.path)
                            .and_then(|o| o.uuid.clone());
                    }
                }
                s.devices = devs;
                s.dev_idx = current
                    .and_then(|p| s.devices.iter().position(|d| d.path == p))
                    .unwrap_or(0);
                s.backup_sel.resize(s.devices.len(), true);
            });
            render_header(ui);
            render_system(ui);
            if !errors.is_empty() {
                ui.set_status(errors.join("；").into());
            }
            load_device(ui, |_| {});
        },
    );
}

struct DeviceData {
    overview: Result<OverviewReply, String>,
    boot: Vec<Item>,
    backups: Vec<(String, Vec<BackupFile>)>,
    /// UUIDs learned for devices lsblk did not describe (image files).
    uuids: Vec<(PathBuf, String)>,
}

fn load_device(ui: &MainWindow, then: impl FnOnce(&MainWindow) + Send + 'static) {
    let (path, uuids, unknown) = with(|s| {
        (
            s.devices.get(s.dev_idx).map(|d| d.path.clone()),
            s.devices
                .iter()
                .filter_map(|d| d.uuid.clone())
                .collect::<Vec<_>>(),
            s.devices
                .iter()
                .filter(|d| d.uuid.is_none())
                .map(|d| d.path.clone())
                .collect::<Vec<_>>(),
        )
    });
    let Some(path) = path else {
        with(|s| s.ov = None);
        render_all(ui);
        ui.set_status("没有 LUKS 卷".into());
        return;
    };
    bg(
        move || {
            let overview: Result<OverviewReply, String> =
                call(Method::Overview { path: path.clone() });
            let mut uuids = uuids;
            let learned: Vec<(PathBuf, String)> = unknown
                .into_iter()
                .filter_map(|p| {
                    let o: OverviewReply = call(Method::Overview { path: p.clone() }).ok()?;
                    Some((p, o.overview.header.uuid))
                })
                .collect();
            uuids.extend(learned.iter().map(|(_, u)| u.clone()));
            if let Ok(o) = &overview {
                uuids.push(o.overview.header.uuid.clone());
            }
            uuids.sort();
            uuids.dedup();
            DeviceData {
                boot: call(Method::BootCheck { path }).unwrap_or_default(),
                backups: uuids
                    .into_iter()
                    .map(|u| {
                        let files = call(Method::Backups { uuid: u.clone() }).unwrap_or_default();
                        (u, files)
                    })
                    .collect(),
                overview,
                uuids: learned,
            }
        },
        move |ui, d| {
            let err = with(|s| {
                for (p, u) in d.uuids {
                    if let Some(dev) = s.devices.iter_mut().find(|x| x.path == p) {
                        dev.uuid = Some(u);
                    }
                }
                s.boot = d.boot;
                s.backups = d.backups.into_iter().collect();
                match d.overview {
                    Ok(r) => {
                        if let Some(dev) = s.devices.get_mut(s.dev_idx) {
                            dev.uuid = Some(r.overview.header.uuid.clone());
                        }
                        s.ov = Some(r.overview);
                        s.issues = r.issues;
                        None
                    }
                    Err(e) => {
                        s.ov = None;
                        s.issues.clear();
                        Some(e)
                    }
                }
            });
            render_all(ui);
            ui.set_status(
                err.map(|e| format!("读取失败：{e}"))
                    .unwrap_or_else(|| "就绪".into())
                    .into(),
            );
            then(ui);
        },
    );
}

// ---- rendering --------------------------------------------------------------

fn render_all(ui: &MainWindow) {
    render_header(ui);
    render_slots(ui);
    render_system(ui);
    render_health(ui);
    render_backups(ui);
    render_log(ui);
}

fn render_header(ui: &MainWindow) {
    with(|s| {
        let Some(sys) = &s.sys else { return };
        let ver = |v: Option<luks_assistant_sysinfo::tools::Version>| {
            v.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
        };
        let tpm = match &s.hello {
            Some(h) if h.tpm2_device != "auto" => format!("TPM2 → {}", h.tpm2_device),
            _ if sys.tpm.is_tpm2() => format!("TPM2 ✓ {}", sys.tpm.banks.join("/")),
            _ => "无 TPM".into(),
        };
        ui.set_header(
            format!(
                "{} · 内核 {} · systemd {} · cryptsetup {} · {} · 安全启动 {}",
                sys.os.pretty_name,
                sys.os.kernel,
                ver(sys.tools.systemd),
                ver(sys.tools.cryptsetup),
                tpm,
                sys.firmware.secure_boot_label()
            )
            .into(),
        );
    });
}

fn render_slots(ui: &MainWindow) {
    with(|s| {
        let (luks, total) = s.tree.volume_counts();
        ui.set_volume_count(
            format!("LUKS 卷 {}/{}", luks + s.extra.len(), total + s.extra.len()).into(),
        );
        ui.set_disk_label(
            s.devices
                .get(s.dev_idx)
                .map(|d| {
                    format!(
                        "{}  {}",
                        d.display_name(),
                        d.size.clone().unwrap_or_default()
                    )
                })
                .unwrap_or_else(|| "无".into())
                .into(),
        );
        // picker rows: image files, then the lsblk tree
        let mut rows = Vec::new();
        let mut map = Vec::new();
        for d in &s.extra {
            rows.push(PickRow {
                text: format!("{}  镜像文件", d.path.display()).into(),
                depth: 0,
                enabled: true,
            });
            map.push(s.devices.iter().position(|x| x.path == d.path));
        }
        for (depth, n) in s.tree.flatten() {
            let dev = n
                .is_luks()
                .then(|| {
                    s.devices
                        .iter()
                        .position(|d| d.path.as_os_str() == n.path.as_str())
                })
                .flatten();
            let fs = n
                .fstype
                .clone()
                .map(|f| format!(" {f}"))
                .unwrap_or_default();
            let model_name = n.model.clone().map(|m| format!(" {m}")).unwrap_or_default();
            let mp = n
                .mountpoints
                .first()
                .map(|m| format!(" {m}"))
                .unwrap_or_default();
            rows.push(PickRow {
                text: format!(
                    "{}  {}  {}{fs}{model_name}{mp}",
                    n.path,
                    n.size.clone().unwrap_or_default(),
                    n.kind
                )
                .into(),
                depth: depth as i32,
                enabled: dev.is_some(),
            });
            map.push(dev);
        }
        ui.set_pick_rows(model(rows));
        s.pick_map = map;

        let caps = s.hello.as_ref().map(|h| h.caps.clone()).unwrap_or_default();
        match &s.ov {
            Some(ov) => {
                ui.set_slots(model(view::slot_cards(ov)));
                ui.set_slots_title(
                    format!(
                        "LUKS{} · {} · 已用 {}/32",
                        ov.header.version,
                        ov.header.uuid,
                        ov.used().count()
                    )
                    .into(),
                );
                ui.set_selected(s.selected as i32);
                ui.set_detail(model(view::slot_detail(ov, s.selected)));
                let actions = ov
                    .slot(s.selected)
                    .map(|sl| forms::slot_actions(sl, &caps))
                    .unwrap_or_default();
                ui.set_actions(model(
                    actions
                        .iter()
                        .map(|(l, _)| SharedString::from(l.as_str()))
                        .collect(),
                ));
                s.actions = actions.into_iter().map(|(_, k)| k).collect();
                let node = s.tree.find(&ov.device.path.to_string_lossy());
                let dev_trim = node.and_then(|n| n.mapping().and_then(|m| m.trim()).or(n.trim()));
                ui.set_trim_label(
                    format!(
                        "TRIM 头部:{} 设备:{}",
                        if ov.header.allows_discards() {
                            "开"
                        } else {
                            "关"
                        },
                        match dev_trim {
                            Some(true) => "支持",
                            Some(false) => "不支持",
                            None => "?",
                        }
                    )
                    .into(),
                );
                ui.set_trim_available(ov.device.mapping.is_some());
            }
            None => {
                ui.set_slots(model(Vec::new()));
                ui.set_slots_title("".into());
                ui.set_detail(model(Vec::new()));
                ui.set_actions(model(Vec::new()));
                ui.set_trim_label("".into());
                ui.set_trim_available(false);
            }
        }
    });
}

fn render_system(ui: &MainWindow) {
    with(|s| {
        if let Some(sys) = &s.sys {
            let dev = s
                .hello
                .as_ref()
                .map(|h| h.tpm2_device.clone())
                .unwrap_or_else(|| "auto".into());
            ui.set_sys_lines(model(view::system_lines(sys, &dev, &s.fido2, &s.pkcs11)));
        }
        ui.set_disk_lines(model(view::disk_lines(&s.tree)));
        let bound: Vec<u8> =
            s.ov.as_ref()
                .map(|o| {
                    o.slots
                        .iter()
                        .filter_map(|x| x.tpm2.as_ref())
                        .flat_map(|t| t.pcrs.clone())
                        .collect()
                })
                .unwrap_or_default();
        ui.set_pcr_lines(model(view::pcr_lines(s.pcrs.as_ref(), &bound)));
        ui.set_boot_lines(model(view::boot_lines(&s.boot)));
    });
}

fn render_health(ui: &MainWindow) {
    with(|s| ui.set_issues(model(view::issue_items(&s.issues))));
}

fn render_backups(ui: &MainWindow) {
    with(|s| {
        if let Some(h) = &s.hello {
            ui.set_backup_dir(h.paths.backup_root.to_string_lossy().into_owned().into());
        }
        let rows = s
            .devices
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let uuid = d.uuid.clone().unwrap_or_default();
                let files = s.backups.get(&uuid).cloned().unwrap_or_default();
                let subtitle = match files.first() {
                    Some(b) => format!(
                        "{uuid} · 最后备份 {} · {} · 共 {} 个",
                        format_time(b.modified),
                        b.path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        files.len()
                    ),
                    None => format!("{uuid} · 从未备份"),
                };
                BackupRow {
                    checked: s.backup_sel.get(i).copied().unwrap_or(true),
                    title: format!(
                        "{}  {}",
                        d.display_name(),
                        d.size.clone().unwrap_or_default()
                    )
                    .into(),
                    subtitle: subtitle.into(),
                }
            })
            .collect();
        ui.set_backups(model(rows));
    });
}

fn render_log(ui: &MainWindow) {
    with(|s| {
        ui.set_log_lines(model(
            s.log
                .iter()
                .rev()
                .map(|l| SharedString::from(l.as_str()))
                .collect(),
        ))
    });
}

// ---- forms ------------------------------------------------------------------

fn open_form(ui: &MainWindow, kind: FormKind) {
    let result = with(|s| {
        let (Some(ov), Some(h)) = (&s.ov, &s.hello) else {
            return Err("尚未读取卷信息".to_owned());
        };
        let env = Env {
            ov,
            caps: &h.caps,
            paths: &h.paths,
            ask_pins: true,
        };
        let mut form = forms::build(kind, &env)?;
        if form.kind == FormKind::Restore {
            let latest = s
                .backups
                .get(&ov.header.uuid)
                .and_then(|f| f.first())
                .map(|f| f.path.to_string_lossy().into_owned());
            if let (Some(Value::Text(t)), Some(l)) = (form.get_mut("path"), latest) {
                *t = l;
            }
        }
        s.form = Some(form);
        Ok(())
    });
    match result {
        Ok(()) => {
            render_form(ui);
            ui.set_form_error("".into());
            ui.set_modal(1);
        }
        Err(e) => message(ui, "无法执行", e),
    }
}

fn render_form(ui: &MainWindow) {
    with(|s| {
        let Some(f) = &s.form else { return };
        ui.set_modal_title(f.title.clone().into());
        ui.set_form_fields(model(view::field_items(&f.fields)));
        render_form_notes(ui, s);
    });
}

fn render_form_notes(ui: &MainWindow, s: &State) {
    let Some(f) = &s.form else { return };
    let notes = if f.get("pcrs").is_some() {
        let sb = s.sys.as_ref().and_then(|x| x.firmware.secure_boot);
        view::pcr_notes(&f.pcrs("pcrs"), sb)
    } else if matches!(f.kind, FormKind::Fido2 { .. } | FormKind::Pkcs11 { .. }) {
        vec![colored("执行时请插入并触摸安全密钥", view::GRAY)]
    } else {
        Vec::new()
    };
    ui.set_form_notes(model(notes));
}

fn edit_field(ui: &MainWindow, i: i32, f: impl FnOnce(&mut Value)) {
    with(|s| {
        if let Some(field) = s
            .form
            .as_mut()
            .and_then(|form| form.fields.get_mut(i as usize))
        {
            f(&mut field.value);
        }
        render_form_notes(ui, s);
    });
}

fn submit_form(ui: &MainWindow) {
    let Some(form) = with(|s| s.form.clone()) else {
        return;
    };
    let submit = match forms::submit(&form) {
        Ok(s) => s,
        Err(e) => return ui.set_form_error(e.into()),
    };
    let Some(path) = with(|s| s.ov.as_ref().map(|o| o.device.path.clone())) else {
        return;
    };
    match submit {
        Submit::Request(request) => plan_request(path, request, true),
        Submit::Verify(VerifyMethod::Credential(credential)) => {
            busy(ui, "正在验证…");
            bg(
                move || call::<u32>(Method::VerifyCredential { path, credential }),
                |ui, r| {
                    let text = match r {
                        Ok(slot) => {
                            let kind = with(|s| {
                                s.ov.as_ref()
                                    .and_then(|o| o.slot(slot))
                                    .map(|x| x.kind.label())
                                    .unwrap_or_default()
                            });
                            format!("✓ 槽位 {slot}（{kind}）验证成功")
                        }
                        Err(e) => format!("✗ {e}"),
                    };
                    message(ui, "验证", text);
                },
            );
        }
        Submit::Verify(VerifyMethod::Token { kind, pin }) => {
            busy(
                ui,
                &format!("正在验证 {}…（如需要请触摸安全密钥）", kind.label()),
            );
            bg(
                move || call::<TokenVerified>(Method::VerifyToken { path, kind, pin }),
                move |ui, r| {
                    let text = match r {
                        Ok(v) => format!(
                            "✓ 槽位 {}（{} 令牌 {}）验证成功",
                            v.slots
                                .iter()
                                .map(u32::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                            kind.label(),
                            v.token
                        ),
                        Err(e) => format!("✗ {e}"),
                    };
                    message(ui, "验证", text);
                },
            );
        }
        Submit::SetBackupDir(dir) => set_backup_dir(dir),
    }
}

fn plan_request(path: PathBuf, request: Request, from_form: bool) {
    bg(
        move || call::<PlanView>(Method::Plan { path, request }),
        move |ui, r| match r {
            Ok(p) => show_confirm(ui, vec![p]),
            Err(e) if from_form => ui.set_form_error(e.into()),
            Err(e) => message(ui, "无法执行", e),
        },
    );
}

fn show_confirm(ui: &MainWindow, plans: Vec<PlanView>) {
    let danger = plans
        .iter()
        .map(|p| p.danger)
        .max()
        .unwrap_or(Danger::Normal);
    ui.set_modal_title(
        if plans.len() == 1 {
            plans[0].title.clone()
        } else {
            format!("{} 项操作", plans.len())
        }
        .into(),
    );
    ui.set_modal_accent(match danger {
        Danger::Normal => view::BLUE,
        Danger::High => view::ORANGE,
        Danger::Critical => view::RED,
    });
    ui.set_modal_lines(model(view::plan_lines(&plans)));
    ui.set_confirm_word(
        plans
            .iter()
            .find_map(|p| p.confirm_word.clone())
            .unwrap_or_default()
            .into(),
    );
    ui.set_confirm_typed("".into());
    with(|s| s.plans = plans);
    ui.set_modal(2);
}

fn execute(ui: &MainWindow) {
    let (ids, confirm) = with(|s| {
        (
            s.plans.iter().map(|p| p.id).collect::<Vec<_>>(),
            ui.get_confirm_typed().to_string(),
        )
    });
    let interactive = with(|s| s.plans.iter().any(|p| p.interactive));
    busy(
        ui,
        if interactive {
            "正在执行…（请按提示触摸安全密钥）"
        } else {
            "正在执行…"
        },
    );
    bg(
        move || {
            call::<Vec<ReportView>>(Method::Execute {
                plans: ids,
                confirm,
            })
        },
        |ui, r| {
            let reports = match r {
                Ok(r) => r,
                Err(e) => return message(ui, "执行失败", e),
            };
            let ok = reports.iter().all(|r| r.ok);
            let mut lines = Vec::new();
            let mut key = None;
            let mut new_slot = None;
            for r in &reports {
                lines.push(colored(
                    format!(
                        "{} {} — {}",
                        if r.ok { "✓" } else { "✗" },
                        r.title,
                        r.device.display()
                    ),
                    if r.ok { view::GREEN } else { view::RED },
                ));
                if let Some(b) = &r.backup_file {
                    lines.push(colored(format!("  备份: {}", b.display()), view::GRAY));
                }
                for st in &r.steps {
                    lines.push(line(format!(
                        "  {} {}",
                        if st.ok { "✓" } else { "✗" },
                        st.desc
                    )));
                    if let Some(c) = &st.command {
                        lines.push(colored(format!("      $ {c}"), view::GRAY));
                    }
                    for l in st.output.lines().filter(|l| !l.trim().is_empty()) {
                        lines.push(colored(format!("      {l}"), view::GRAY));
                    }
                }
                if let Some(e) = &r.error {
                    lines.push(colored(format!("  错误: {e}"), view::RED));
                }
                lines.push(line(""));
                key = key.or(r.recovery_key.clone());
                new_slot = new_slot.or(r.new_slot);
                with(|s| {
                    s.log.push(format!(
                        "[{}] {} {} — {}",
                        format_time(luks_assistant_core::util::now_unix()),
                        if r.ok { "✓" } else { "✗" },
                        r.title,
                        r.device.display()
                    ))
                });
            }
            with(|s| {
                s.plans.clear();
                if let Some(n) = new_slot {
                    s.selected = n;
                }
            });
            match key {
                Some(k) => {
                    ui.set_recovery_key(String::from_utf8_lossy(k.expose()).into_owned().into());
                    ui.set_modal(5);
                }
                None => {
                    ui.set_modal_title(if ok { "完成" } else { "失败" }.into());
                    ui.set_modal_accent(if ok { view::GREEN } else { view::RED });
                    ui.set_modal_lines(model(lines));
                    ui.set_modal(4);
                }
            }
            ui.set_status(if ok { "完成" } else { "失败" }.into());
            refresh_all(ui);
        },
    );
}

fn set_backup_dir(dir: Option<PathBuf>) {
    bg(
        move || call::<luks_assistant_core::Paths>(Method::SetBackupDir { dir }),
        |ui, r| match r {
            Ok(paths) => {
                with(|s| {
                    if let Some(h) = s.hello.as_mut() {
                        h.paths = paths;
                    }
                });
                ui.set_modal(0);
                ui.set_status("备份位置已保存".into());
                load_device(ui, |_| {});
            }
            Err(e) => message(ui, "备份位置", e),
        },
    );
}

// ---- wiring -------------------------------------------------------------------

fn wire(ui: &MainWindow) {
    ui.on_select_slot({
        let w = ui.as_weak();
        move |i| {
            let ui = w.unwrap();
            with(|s| s.selected = i as u32);
            render_slots(&ui);
        }
    });
    ui.on_action({
        let w = ui.as_weak();
        move |i| {
            let ui = w.unwrap();
            if let Some(k) = with(|s| s.actions.get(i as usize).cloned()) {
                open_form(&ui, k);
            }
        }
    });
    ui.on_open_verify({
        let w = ui.as_weak();
        move || open_form(&w.unwrap(), FormKind::Verify)
    });
    ui.on_open_trim({
        let w = ui.as_weak();
        move || open_form(&w.unwrap(), FormKind::Discards)
    });
    ui.on_pick_device({
        let w = ui.as_weak();
        move |i| {
            let ui = w.unwrap();
            if let Some(dev) = with(|s| s.pick_map.get(i as usize).copied().flatten()) {
                with(|s| {
                    s.dev_idx = dev;
                    s.selected = 0;
                });
                load_device(&ui, |_| {});
            }
        }
    });
    ui.on_refresh({
        let w = ui.as_weak();
        move || refresh_all(&w.unwrap())
    });
    ui.on_fix_issue({
        move |i| {
            let fix = with(|s| {
                let req = s.issues.get(i as usize).and_then(|x| x.fix.clone())?;
                Some((s.ov.as_ref()?.device.path.clone(), req))
            });
            if let Some((path, req)) = fix {
                plan_request(path, req, false);
            }
        }
    });
    ui.on_backup_toggle({
        let w = ui.as_weak();
        move |i, b| {
            with(|s| {
                if let Some(x) = s.backup_sel.get_mut(i as usize) {
                    *x = b;
                }
            });
            render_backups(&w.unwrap());
        }
    });
    ui.on_backup_all({
        let w = ui.as_weak();
        move || {
            with(|s| {
                let all = s.backup_sel.iter().all(|b| *b);
                s.backup_sel.iter_mut().for_each(|b| *b = !all);
            });
            render_backups(&w.unwrap());
        }
    });
    ui.on_backup_run({
        let w = ui.as_weak();
        move || {
            let ui = w.unwrap();
            let paths: Vec<PathBuf> = with(|s| {
                s.devices
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| s.backup_sel.get(*i).copied().unwrap_or(false))
                    .map(|(_, d)| d.path.clone())
                    .collect()
            });
            if paths.is_empty() {
                return message(&ui, "备份", "未选择任何卷");
            }
            bg(
                move || call::<Vec<PlanView>>(Method::PlanBackups { paths }),
                |ui, r| match r {
                    Ok(plans) => show_confirm(ui, plans),
                    Err(e) => message(ui, "备份", e),
                },
            );
        }
    });
    ui.on_backup_restore({
        let w = ui.as_weak();
        move |i| {
            let ui = w.unwrap();
            let same = with(|s| s.dev_idx == i as usize && s.ov.is_some());
            if same {
                open_form(&ui, FormKind::Restore);
            } else {
                with(|s| s.dev_idx = i as usize);
                load_device(&ui, |ui| open_form(ui, FormKind::Restore));
            }
        }
    });
    ui.on_backup_set_dir({
        move |t| {
            let t = t.trim().to_owned();
            set_backup_dir((!t.is_empty()).then(|| PathBuf::from(t)));
        }
    });
    ui.on_field_text({
        let w = ui.as_weak();
        move |i, t| {
            edit_field(&w.unwrap(), i, |v| {
                if let Value::Text(s) | Value::Secret(s) = v {
                    *s = t.to_string();
                }
            })
        }
    });
    ui.on_field_toggle({
        let w = ui.as_weak();
        move |i, b| {
            edit_field(&w.unwrap(), i, |v| {
                if let Value::Toggle(x) = v {
                    *x = b;
                }
            })
        }
    });
    ui.on_field_choice({
        let w = ui.as_weak();
        move |i, idx| {
            edit_field(&w.unwrap(), i, |v| {
                if let Value::Choice { index, .. } = v {
                    *index = idx.max(0) as usize;
                }
            })
        }
    });
    ui.on_pcr_toggle({
        let w = ui.as_weak();
        move |i, p| {
            let ui = w.unwrap();
            edit_field(&ui, i, |v| {
                if let Value::Pcrs(set) = v {
                    set[p as usize] = !set[p as usize];
                }
            });
            // update only this row so text fields keep their content and focus
            let item = with(|s| {
                s.form
                    .as_ref()
                    .and_then(|f| f.fields.get(i as usize))
                    .map(|f| view::field_items(std::slice::from_ref(f)).remove(0))
            });
            if let Some(item) = item {
                ui.get_form_fields().set_row_data(i as usize, item);
            }
        }
    });
    ui.on_form_submit({
        let w = ui.as_weak();
        move || submit_form(&w.unwrap())
    });
    ui.on_modal_cancel({
        let w = ui.as_weak();
        move || {
            with(|s| {
                s.form = None;
                s.plans.clear();
            });
            w.unwrap().set_modal(0);
        }
    });
    ui.on_confirm_run({
        let w = ui.as_weak();
        move || execute(&w.unwrap())
    });
    ui.on_close_modal({
        let w = ui.as_weak();
        move || {
            let ui = w.unwrap();
            ui.set_recovery_key("".into());
            if HELPER.lock().unwrap().is_none() {
                ui.set_modal(0);
                return connect(&ui);
            }
            ui.set_modal(0);
        }
    });
}
