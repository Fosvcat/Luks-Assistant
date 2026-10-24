//! Terminal UI for LUKS2 key slots, run as `Luks-Assistant-TUI` (which
//! `Luks-Assistant-GUI` also execs when started from a terminal or without a display).

mod app;
mod form;
mod term;
mod ui;

use luks_assistant_core::Ctx;
use luks_assistant_core::device::{self, LuksDevice};
use luks_assistant_core::slots::Overview;
use luks_assistant_core::t;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use std::path::PathBuf;

fn usage() -> &'static str {
    t!("\
Usage: Luks-Assistant-TUI [options] [device or image file]

  Without arguments, lists every LUKS device lsblk finds.

Options:
  --dump [device]   print the slot model as JSON and exit (debugging)
  --boot-check      print the boot unlock check and exit
  -h, --help        show this help
  -V, --version     show the version

Environment (development):
  LUKS_ASSISTANT_LANG          en or zh_CN (default: from the locale)
  LUKS_ASSISTANT_TPM2_DEVICE   TPM device or TCTI, e.g. swtpm:host=127.0.0.1,port=2321
  LUKS_ASSISTANT_ETC_DIR       notes directory (default /etc/luks-assistant)
  LUKS_ASSISTANT_STATE_DIR     backups/snapshots/logs directory (default /var/lib/luks-assistant)
")
}

/// Run the TUI (or one of its non-interactive modes) with `args`
/// (without the program name). Never returns.
pub fn main_with_args(mut args: Vec<String>) -> ! {
    use luks_assistant_core::i18n;
    luks_assistant_sysinfo::set_process_name();
    i18n::set_lang(i18n::Lang::from_env());
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{}", usage());
        std::process::exit(0);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("Luks Assistant {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    let dump = take_flag(&mut args, "--dump");
    let boot_check = take_flag(&mut args, "--boot-check");
    if let Some(bad) = args.iter().find(|a| a.starts_with('-')) {
        eprintln!("{}", t!("Unknown option: {}\n\n{}", bad, usage()));
        std::process::exit(2);
    }

    let ctx = Ctx::system();
    let extra: Vec<LuksDevice> = args
        .iter()
        .map(|a| LuksDevice::from_path(&PathBuf::from(a)))
        .collect();
    let mut status = String::from(t!("Ready"));
    let mut devices = extra.clone();
    match device::discover(&ctx) {
        Ok(found) => {
            for d in found {
                if !devices.iter().any(|x| x.path == d.path) {
                    devices.push(d);
                }
            }
        }
        Err(e) => status = format!("lsblk: {e}"),
    }

    if dump {
        let Some(dev) = devices.first().cloned() else {
            eprintln!("{}", t!("No LUKS devices found"));
            std::process::exit(1);
        };
        match Overview::load(&ctx, dev) {
            Ok(ov) => println!("{}", serde_json::to_string_pretty(&ov).unwrap()),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        std::process::exit(0);
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
        std::process::exit(0);
    }

    let sys = luks_assistant_sysinfo::SystemInfo::probe();
    if !sys.is_root {
        status = t!("read-only (changes need sudo)").into();
    }
    let mut app = app::App::new(ctx, sys, extra, status);
    let mut terminal = term::enter();
    let result = run(&mut terminal, &mut app);
    term::leave();
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
    std::process::exit(0);
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
