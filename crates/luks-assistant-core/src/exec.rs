//! Command execution with secrets kept out of argv.
//!
//! Secrets reach child processes in two ways only:
//! * as an anonymous pipe passed by file descriptor (`/dev/fd/N`), used for
//!   cryptsetup `--key-file` style arguments — exact bytes, no newline
//!   handling, nothing touches the disk;
//! * as environment variables (`PASSWORD`, `NEWPIN`, ...) which is the
//!   documented non-interactive interface of systemd-cryptenroll.

use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::util::shell_quote;
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
        label: String,
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
    /// Secret piped to stdin (a PIN answering a prompt).
    pub secret_stdin: Option<Secret>,
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
            secret_stdin: None,
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

    pub fn secret_arg(mut self, label: &str, value: Secret) -> Self {
        self.args.push(Arg::Secret {
            label: label.to_owned(),
            value,
        });
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

    pub fn secret_stdin(mut self, value: Secret) -> Self {
        self.secret_stdin = Some(value);
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
        if self.secret_stdin.is_some() {
            out.push_str("echo <已隐藏> | ");
        }
        for (name, _) in &self.env {
            out.push_str(&format!("{name}=<已隐藏> "));
        }
        out.push_str(&self.program);
        for a in &self.args {
            out.push(' ');
            match a {
                Arg::Plain(s) => out.push_str(&shell_quote(s)),
                Arg::Secret { label, .. } => out.push_str(&format!("<({label})")),
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
                    "(无输出)".into()
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
        return Err(Error::Invalid("密钥数据过大".into()));
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

impl Runner for SystemRunner {
    fn run(&self, cmd: &Cmd) -> Result<CmdOutput> {
        use std::io::Write;
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

        let spawn_err = |e| Error::Spawn {
            program: cmd.program.clone(),
            source: e,
        };

        if cmd.interactive {
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            let status = command.status().map_err(spawn_err)?;
            drop(pipes);
            return Ok(CmdOutput {
                code: status.code().unwrap_or(-1),
                stdout: Zeroizing::new(Vec::new()),
                stderr: String::new(),
            });
        }

        command
            .stdin(if cmd.stdin.is_some() || cmd.secret_stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(spawn_err)?;
        drop(pipes);
        let data = cmd
            .stdin
            .as_deref()
            .or(cmd.secret_stdin.as_ref().map(Secret::expose));
        if let (Some(data), Some(mut stdin)) = (data, child.stdin.take()) {
            // A child that exits early (wrong PIN) closes the pipe; that is
            // reported through its exit status, not as a write error.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_hides_secrets() {
        let c = Cmd::new("cryptsetup")
            .arg("luksAddKey")
            .arg("/dev/sda2")
            .arg("--key-file")
            .secret_arg("现有密码", Secret::from_text("hunter2"))
            .secret_arg("新密码", Secret::from_text("correct horse"));
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
        let c = Cmd::new("cat").secret_arg("x", Secret::from_text("a\nb c"));
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
    fn failure_is_reported() {
        let out = SystemRunner
            .run(&Cmd::new("sh").args(["-c", "echo boom >&2; exit 3"]))
            .unwrap();
        let err = out.check("sh").unwrap_err().to_string();
        assert!(err.contains("退出码 3") && err.contains("boom"), "{err}");
    }
}
