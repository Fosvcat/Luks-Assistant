//! `luks-assistant` — graphical frontend. Started from a terminal, over SSH or
//! without a display it runs the terminal UI instead; `--gui` / `--tui`
//! force a mode.

mod app;
mod client;
mod view;

slint::include_modules!();

const USAGE: &str = "\
用法: luks-assistant [--gui | --tui] [设备或镜像文件...]

  桌面环境中启动时打开图形界面；在终端中或没有图形环境时打开终端界面。

  --gui        强制图形界面（通过 pkexec 获取管理员权限）
  --tui        强制终端界面
  其它选项见 luks-assistant --tui --help
";

fn isatty(fd: i32) -> bool {
    // SAFETY: isatty has no preconditions.
    unsafe { libc::isatty(fd) == 1 }
}

fn has_display() -> bool {
    ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let force_gui = args.iter().any(|a| a == "--gui");
    let force_tui = args.iter().any(|a| a == "--tui");
    let rest: Vec<String> = args
        .into_iter()
        .filter(|a| a != "--gui" && a != "--tui")
        .collect();
    if !force_tui && rest.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return;
    }
    let tui_flags = rest.iter().any(|a| {
        matches!(
            a.as_str(),
            "--dump" | "--boot-check" | "-h" | "--help" | "-V" | "--version"
        )
    });
    let terminal = isatty(0) && isatty(1);
    if force_tui || tui_flags || (!force_gui && (terminal || !has_display())) {
        luks_assistant_tui::main_with_args(rest);
    }
    if !has_display() {
        eprintln!("没有图形环境（WAYLAND_DISPLAY / DISPLAY 未设置），请使用 luks-assistant --tui");
        std::process::exit(1);
    }
    if let Err(e) = app::run(rest) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
