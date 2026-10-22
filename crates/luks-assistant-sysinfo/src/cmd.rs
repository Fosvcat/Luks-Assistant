//! Minimal helpers for running read-only probing commands.

use std::process::{Command, Stdio};

/// Output of a finished command.
#[derive(Debug, Clone)]
pub struct Output {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Run `program args...` with stdin closed and capture its output.
/// Returns `None` when the program cannot be started (usually: not installed).
pub fn run(program: &str, args: &[&str]) -> Option<Output> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "")
        .output()
        .ok()?;
    Some(Output {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Look `program` up in `$PATH` (and the usual sbin directories, which are
/// often missing from a non-root user's PATH).
pub fn which(program: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let extra = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"];
    std::env::split_paths(&path)
        .chain(extra.iter().map(std::path::PathBuf::from))
        .map(|dir| dir.join(program))
        .find(|p| p.is_file())
}
