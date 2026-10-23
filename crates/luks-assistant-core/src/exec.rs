//! Command execution with secrets kept out of argv.
//!
//! Secrets reach child processes in two ways only:
//! * as an anonymous pipe passed by file descriptor (`/dev/fd/N`), used for
//!   cryptsetup `--key-file` style arguments — exact bytes, no newline
//!   handling, nothing touches the disk;
//! * as environment variables (`PASSWORD`, `NEWPIN`, ...) which is the
//!   documented non-interactive interface of systemd-cryptenroll.

use crate::error::{Error, Result};
use crate::i18n::{Lang, Text};
use crate::secret::Secret;
use crate::util::shell_quote;
use crate::{t, tx};
use std::os::fd::RawFd;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// Largest secret we pass through a pipe; it is written before the child
/// starts, so it must fit in the pipe buffer.
const MAX_PIPE_SECRET: usize = 32 * 1024;

#[derive(Debug, Clone)]
pub enum Arg {
    Plain(String),
    /// Passed as `/dev/fd/N`; `label` is shown instead of the value.
    Secret {
        label: Text,
        value: Secret,
    },
}

#[derive(Debug, Clone)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<Arg>,
    pub env: Vec<(String, Secret)>,
    /// Non-secret data piped to stdin (e.g. token JSON).
    pub stdin: Option<Vec<u8>>,
    /// Answers for prompts of an interactive command run without a user
    /// terminal: (lower-case text the prompt contains, answer).
    pub answers: Vec<(String, Secret)>,
    /// The command talks to the user directly (touch a security key, type a
    /// PIN): run it on the real terminal instead of capturing output.
    pub interactive: bool,
    /// stdout carries a secret (a generated recovery key).
    pub secret_stdout: bool,
}

impl Cmd {
    pub fn new(program: &str) -> Self {
        Cmd {
            program: program.to_owned(),
            args: Vec::new(),
            env: Vec::new(),
            stdin: None,
            answers: Vec::new(),
            interactive: false,
            secret_stdout: false,
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(Arg::Plain(a.into()));
        self
    }

    pub fn args<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args
            .extend(it.into_iter().map(|s| Arg::Plain(s.into())));
        self
    }

    pub fn secret_arg(mut self, label: Text, value: Secret) -> Self {
        self.args.push(Arg::Secret { label, value });
        self
    }

    pub fn secret_env(mut self, name: &str, value: Secret) -> Self {
        self.env.push((name.to_owned(), value));
        self
    }

    pub fn stdin(mut self, data: Vec<u8>) -> Self {
        self.stdin = Some(data);
        self
    }

    /// Answer a prompt containing `prompt` (case-insensitive) with `value`.
    pub fn answer(mut self, prompt: &str, value: Secret) -> Self {
        self.answers.push((prompt.to_lowercase(), value));
        self
    }

    pub fn interactive(mut self) -> Self {
        self.interactive = true;
        self
    }

    pub fn secret_stdout(mut self) -> Self {
        self.secret_stdout = true;
        self
    }

    /// Shell-like rendering with every secret replaced by a placeholder.
    /// A secret pipe is shown as bash process substitution, which is what
    /// one would type to reproduce the call by hand.
    pub fn display(&self) -> String {
        self.display_in(crate::i18n::lang())
    }

    /// [`Cmd::display`] in `lang` (logs are English).
    pub fn display_in(&self, lang: Lang) -> String {
        let mut out = String::new();
        if let Some(data) = &self.stdin {
            let text = String::from_utf8_lossy(data);
            let short: String = text.chars().take(96).collect();
            let ellipsis = if text.chars().count() > 96 { "…" } else { "" };
            out.push_str(&format!(
                "echo {} | ",
                shell_quote(&format!("{short}{ellipsis}"))
            ));
        }
        for (name, _) in &self.env {
            out.push_str(&tx!("{}=<已隐藏> ", name).render(lang));
        }
        out.push_str(&self.program);
        for a in &self.args {
            out.push(' ');
            match a {
                Arg::Plain(s) => out.push_str(&shell_quote(s)),
                Arg::Secret { label, .. } => out.push_str(&format!("<({})", label.render(lang))),
            }
        }
        out
    }
}

#[derive(Debug)]
pub struct CmdOutput {
    pub code: i32,
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.code == 0
    }

    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Turn a non-zero exit into an error carrying stderr.
    pub fn check(self, program: &str) -> Result<CmdOutput> {
        if self.success() {
            Ok(self)
        } else {
            let msg = self.stderr.trim();
            Err(Error::Command {
                program: program.to_owned(),
                code: self.code,
                message: if msg.is_empty() {
                    t!("(无输出)").into()
                } else {
                    msg.to_owned()
                },
            })
        }
    }
}

/// Something that can run commands. The system implementation spawns
/// processes; tests may substitute a recorder.
pub trait Runner: Send + Sync {
    fn run(&self, cmd: &Cmd) -> Result<CmdOutput>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRunner;

struct PipeFd(RawFd);

impl Drop for PipeFd {
    fn drop(&mut self) {
        // SAFETY: we own this descriptor and close it exactly once.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Create a pipe, fill it with `data` and return the read end. The read end
/// is inheritable (no CLOEXEC) so the child can open it as /dev/fd/N.
fn secret_pipe(data: &[u8]) -> Result<PipeFd> {
    if data.len() > MAX_PIPE_SECRET {
        return Err(Error::Invalid(tx!("密钥数据过大")));
    }
    let mut fds = [0 as RawFd; 2];
    // SAFETY: fds is a valid 2-element array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let (read, write) = (PipeFd(fds[0]), PipeFd(fds[1]));
    // The write end must not leak into children.
    // SAFETY: valid descriptor.
    unsafe {
        libc::fcntl(write.0, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let mut off = 0;
    while off < data.len() {
        // SAFETY: pointer/len describe the remaining part of `data`.
        let n = unsafe { libc::write(write.0, data[off..].as_ptr().cast(), data.len() - off) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }
        off += n as usize;
    }
    drop(write);
    Ok(read)
}

/// Build the process for `cmd`. The returned pipes must stay alive until
/// the child has been spawned.
fn prepare(cmd: &Cmd) -> Result<(Command, Vec<PipeFd>)> {
    use std::os::unix::ffi::OsStrExt;
    let mut pipes = Vec::new();
    let mut command = Command::new(&cmd.program);
    for a in &cmd.args {
        match a {
            Arg::Plain(s) => {
                command.arg(s);
            }
            Arg::Secret { value, .. } => {
                let fd = secret_pipe(value.expose())?;
                command.arg(format!("/dev/fd/{}", fd.0));
                pipes.push(fd);
            }
        }
    }
    for (name, value) in &cmd.env {
        command.env(name, std::ffi::OsStr::from_bytes(value.expose()));
    }
    command.env("SYSTEMD_COLORS", "0").env("SYSTEMD_PAGER", "");
    if !cmd.interactive {
        command.env("LC_ALL", "C");
    }
    Ok((command, pipes))
}

fn spawn_error(cmd: &Cmd) -> impl Fn(std::io::Error) -> Error + '_ {
    move |e| Error::Spawn {
        program: cmd.program.clone(),
        source: e,
    }
}

impl Runner for SystemRunner {
    fn run(&self, cmd: &Cmd) -> Result<CmdOutput> {
        use std::io::Write;
        let (mut command, pipes) = prepare(cmd)?;

        if cmd.interactive {
            // The user answers prompts on the real terminal.
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            let status = command.status().map_err(spawn_error(cmd))?;
            drop(pipes);
            return Ok(CmdOutput {
                code: status.code().unwrap_or(-1),
                stdout: Zeroizing::new(Vec::new()),
                stderr: String::new(),
            });
        }

        command
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(spawn_error(cmd))?;
        drop(pipes);
        if let (Some(data), Some(mut stdin)) = (&cmd.stdin, child.stdin.take()) {
            // A child that exits early closes the pipe; that is reported
            // through its exit status, not as a write error.
            let _ = stdin.write_all(data);
        }
        let out = child.wait_with_output()?;
        Ok(CmdOutput {
            code: out.status.code().unwrap_or(-1),
            stdout: Zeroizing::new(out.stdout),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Run an interactive command on a fresh pseudo-terminal, without a human
/// at a terminal: prompts listed in `cmd.answers` are answered
/// automatically, everything the command prints is passed to `on_output`
/// (with answers masked), and a prompt nobody can answer ends the command
/// with an error instead of hanging.
///
/// stdout and stderr are merged; the combined text is returned as `stderr`.
pub fn run_in_pty(
    cmd: &Cmd,
    on_output: &mut dyn FnMut(&str),
    timeout: std::time::Duration,
) -> Result<CmdOutput> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;

    let (mut command, pipes) = prepare(cmd)?;
    let (mut master, mut slave) = (0 as RawFd, 0 as RawFd);
    // SAFETY: valid out-pointers; no name/termios/winsize requested.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let master = PipeFd(master);
    // SAFETY: the descriptors are freshly opened and owned by us.
    unsafe {
        libc::fcntl(master.0, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(slave, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let slave_fd = unsafe { OwnedFd::from_raw_fd(slave) };
    command
        .stdin(Stdio::from(slave_fd.try_clone()?))
        .stdout(Stdio::from(slave_fd.try_clone()?))
        .stderr(Stdio::from(slave_fd.try_clone()?));
    // SAFETY: setsid/ioctl are async-signal-safe; this makes the pty the
    // controlling terminal so /dev/tty prompts land on it.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(spawn_error(cmd))?;
    // The parent must not keep the slave side open, or reads on the master
    // never see the end of output.
    drop(command);
    drop(slave_fd);
    drop(pipes);

    let started = std::time::Instant::now();
    let mut all = String::new();
    let mut since_answer = String::new();
    let mut unanswerable = None;
    let mask = |text: &str| {
        let mut t = text.to_owned();
        for (_, v) in &cmd.answers {
            let v = String::from_utf8_lossy(v.expose()).into_owned();
            if !v.is_empty() {
                t = t.replace(&v, "***");
            }
        }
        t
    };
    let mut buf = [0u8; 4096];
    loop {
        let mut pfd = libc::pollfd {
            fd: master.0,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let r = unsafe { libc::poll(&mut pfd, 1, 200) };
        if r > 0 {
            // SAFETY: buf is valid for buf.len() bytes.
            let n = unsafe { libc::read(master.0, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break; // EIO: the child closed the terminal
            }
            let text = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
            let shown = mask(&text);
            on_output(&shown);
            all.push_str(&shown);
            since_answer.push_str(&text.to_lowercase());
            let tail = since_answer.trim_end();
            if tail.ends_with(':') || tail.ends_with('?') {
                let answer = cmd.answers.iter().find(|(p, _)| tail.contains(p.as_str()));
                match answer {
                    Some((_, v)) => {
                        let mut line = v.expose().to_vec();
                        line.push(b'\n');
                        // SAFETY: valid buffer.
                        unsafe { libc::write(master.0, line.as_ptr().cast(), line.len()) };
                        since_answer.clear();
                    }
                    // "密码": prompts under a Chinese locale
                    None if ["pin", "password", "passphrase", "\u{5bc6}\u{7801}"]
                        .iter()
                        .any(|w| tail.contains(w)) =>
                    {
                        unanswerable = Some(tail.lines().last().unwrap_or(tail).trim().to_owned());
                        let _ = child.kill();
                    }
                    None => {}
                }
            }
        } else if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e.into());
            }
        }
        if r == 0 && matches!(child.try_wait(), Ok(Some(_))) {
            break; // exited and nothing left to read
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Invalid(tx!("{} 超时", &cmd.program)));
        }
    }
    let status = child.wait()?;
    if let Some(p) = unanswerable {
        return Err(Error::Invalid(tx!("需要输入：{}", p)));
    }
    Ok(CmdOutput {
        code: status.code().unwrap_or(-1),
        stdout: Zeroizing::new(Vec::new()),
        stderr: all,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_hides_secrets() {
        let c = Cmd::new("cryptsetup")
            .arg("luksAddKey")
            .arg("/dev/sda2")
            .arg("--key-file")
            .secret_arg(Text::plain("现有密码"), Secret::from_text("hunter2"))
            .secret_arg(Text::plain("新密码"), Secret::from_text("correct horse"));
        let d = c.display();
        assert_eq!(
            d,
            "cryptsetup luksAddKey /dev/sda2 --key-file <(现有密码) <(新密码)"
        );
        assert!(!d.contains("hunter2"));

        let c = Cmd::new("systemd-cryptenroll")
            .secret_env("PASSWORD", Secret::from_text("hunter2"))
            .arg("--tpm2-pcrs=0+7");
        assert_eq!(
            c.display(),
            "PASSWORD=<已隐藏> systemd-cryptenroll --tpm2-pcrs=0+7"
        );
    }

    #[test]
    fn secrets_arrive_exactly() {
        let c = Cmd::new("cat").secret_arg(Text::plain("x"), Secret::from_text("a\nb c"));
        let out = SystemRunner.run(&c).unwrap();
        assert!(out.success());
        assert_eq!(&out.stdout[..], b"a\nb c");

        let c = Cmd::new("sh")
            .args(["-c", "printf %s \"$PASSWORD\""])
            .secret_env("PASSWORD", Secret::from_text("pw"));
        assert_eq!(&SystemRunner.run(&c).unwrap().stdout[..], b"pw");

        let c = Cmd::new("cat").stdin(b"{\"a\":1}".to_vec());
        assert_eq!(&SystemRunner.run(&c).unwrap().stdout[..], b"{\"a\":1}");
    }

    #[test]
    fn pty_answers_prompts_and_masks_them() {
        let script = "printf 'Please enter security token PIN: '; read -r p; echo \"got [$p]\"; [ -t 0 ] && echo tty";
        let c = Cmd::new("sh")
            .args(["-c", script])
            .interactive()
            .answer("PIN", Secret::from_text("123456"));
        let mut seen = String::new();
        let out = run_in_pty(
            &c,
            &mut |t| seen.push_str(t),
            std::time::Duration::from_secs(10),
        )
        .unwrap();
        assert!(out.success(), "{}", out.stderr);
        assert!(seen.contains("got [***]"), "{seen}");
        assert!(seen.contains("tty"));
        assert!(!seen.contains("123456"));
    }

    #[test]
    fn pty_refuses_unanswerable_prompt() {
        let c = Cmd::new("sh")
            .args(["-c", "printf 'Enter passphrase: '; read -r p"])
            .interactive();
        let err = run_in_pty(&c, &mut |_| {}, std::time::Duration::from_secs(10)).unwrap_err();
        assert!(err.to_string().contains("enter passphrase"), "{err}");
    }

    #[test]
    fn failure_is_reported() {
        let out = SystemRunner
            .run(&Cmd::new("sh").args(["-c", "echo boom >&2; exit 3"]))
            .unwrap();
        let err = out.check("sh").unwrap_err().to_string();
        assert!(err.contains("退出码 3") && err.contains("boom"), "{err}");
    }
}
