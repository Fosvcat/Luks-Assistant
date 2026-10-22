//! luks-assistant-tui — developer-oriented terminal UI for LUKS2 key slots.

mod app;
mod form;
mod term;
mod ui;

use luks_assistant_core::Ctx;
use luks_assistant_core::device::{self, LuksDevice};
use luks_assistant_core::slots::Overview;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use std::path::PathBuf;

const USAGE: &str = "\
用法: luks-assistant-tui [选项] [设备或镜像文件]

  不带参数时列出 lsblk 找到的所有 LUKS 设备。

选项:
  --dump [设备]   以 JSON 输出槽位模型后退出（调试用）
  --boot-check    输出开机解锁检查结果后退出
  -h, --help      显示帮助
  -V, --version   显示版本

环境变量（开发用）:
  LUKS_ASSISTANT_TPM2_DEVICE   TPM 设备或 TCTI，例如 swtpm:host=127.0.0.1,port=2321
  LUKS_ASSISTANT_ETC_DIR       备注目录（默认 /etc/luks-assistant）
  LUKS_ASSISTANT_STATE_DIR     备份/快照/日志目录（默认 /var/lib/luks-assistant）
";

fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return;
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("luks-assistant-tui {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let dump = take_flag(&mut args, "--dump");
    let boot_check = take_flag(&mut args, "--boot-check");
    if let Some(bad) = args.iter().find(|a| a.starts_with('-')) {
        eprintln!("未知选项: {bad}\n\n{USAGE}");
        std::process::exit(2);
    }

    let ctx = Ctx::system();
    let mut devices: Vec<LuksDevice> = Vec::new();
    let mut status = String::from("就绪");
    for a in &args {
        devices.push(LuksDevice::from_path(&PathBuf::from(a)));
    }
    match device::discover(&ctx) {
        Ok(found) => {
            for d in found {
                if !devices.iter().any(|x| x.path == d.path) {
                    devices.push(d);
                }
            }
        }
        Err(e) => status = format!("lsblk 失败: {e}"),
    }

    if dump {
        let Some(dev) = devices.first().cloned() else {
            eprintln!("没有找到 LUKS 设备");
            std::process::exit(1);
        };
        match Overview::load(&ctx, dev) {
            Ok(ov) => println!("{}", serde_json::to_string_pretty(&ov).unwrap()),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if boot_check {
        let target = devices
            .first()
            .and_then(|d| Overview::load(&ctx, d.clone()).ok())
            .map(|o| luks_assistant_sysinfo::bootcheck::Target {
                uuid: o.header.uuid.clone(),
                path: o.device.path.to_string_lossy().into_owned(),
                mapping: o.device.mapping.clone(),
            })
            .unwrap_or_default();
        for i in luks_assistant_sysinfo::bootcheck::check(&target) {
            println!(
                "[{}] {}\n    {}",
                i.status.symbol(),
                i.title,
                i.detail.replace('\n', "\n    ")
            );
        }
        return;
    }

    let sys = luks_assistant_sysinfo::SystemInfo::probe();
    if !sys.is_root {
        status = "非 root：只能查看，写操作需要 sudo".into();
    }
    let mut app = app::App::new(ctx, sys, devices, status);
    let mut terminal = term::enter();
    let result = run(&mut terminal, &mut app);
    term::leave();
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    let before = args.len();
    args.retain(|a| a != flag);
    args.len() != before
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut app::App) -> std::io::Result<()> {
    let mut last_layer = None;
    loop {
        // Popups drawn over double-width characters can leave half glyphs
        // behind in some terminals; repaint fully when a popup opens/closes.
        let layer = (
            app.modal.as_ref().map(std::mem::discriminant),
            app.busy.is_some(),
            app.tab as u8,
        );
        if last_layer != Some(layer) {
            terminal.clear()?;
            last_layer = Some(layer);
        }
        terminal.draw(|f| ui::draw(f, app))?;
        if let Some(job) = app.pending.take() {
            app.run_job(job, terminal);
            continue;
        }
        if app.quit {
            return Ok(());
        }
        match event::read()? {
            Event::Key(k) if k.kind == KeyEventKind::Press => app.on_key(k),
            Event::Mouse(m) => app.on_mouse(m),
            Event::Paste(s) => app.on_paste(&s),
            _ => {}
        }
    }
}
