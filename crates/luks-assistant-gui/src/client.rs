//! Talks to `luks-assistant-helper` over its stdin/stdout.

use luks_assistant_core::proto::{Call, Event, Method, Reply, ReplyBody};
use serde::de::DeserializeOwned;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

pub struct Helper {
    child: Child,
    stdin: Option<ChildStdin>,
    out: BufReader<ChildStdout>,
    stderr: Arc<Mutex<String>>,
    next: u64,
}

/// Where the helper binary is installed.
pub fn find_helper() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("LUKS_ASSISTANT_HELPER") {
        return Some(PathBuf::from(p));
    }
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("luks-assistant-helper")));
    sibling
        .into_iter()
        .chain(
            [
                "/usr/libexec/luks-assistant-helper",
                "/usr/local/libexec/luks-assistant-helper",
                "/usr/lib/luks-assistant/luks-assistant-helper",
            ]
            .into_iter()
            .map(PathBuf::from),
        )
        .find(|p| p.is_file())
}

impl Helper {
    /// Start the helper, through pkexec unless we already are root.
    pub fn start() -> Result<Helper, String> {
        let path = find_helper().ok_or("找不到 luks-assistant-helper")?;
        let path = path.canonicalize().unwrap_or(path);
        let mut cmd = if luks_assistant_sysinfo::is_root() {
            Command::new(&path)
        } else {
            let mut c = Command::new("pkexec");
            c.arg(&path);
            c
        };
        // development overrides travel as arguments: pkexec clears the environment
        for (var, flag) in [
            ("LUKS_ASSISTANT_TPM2_DEVICE", "--tpm2-device"),
            ("LUKS_ASSISTANT_ETC_DIR", "--etc-dir"),
            ("LUKS_ASSISTANT_STATE_DIR", "--state-dir"),
        ] {
            if let Ok(v) = std::env::var(var) {
                cmd.arg(flag).arg(v);
            }
        }
        if std::env::var("LUKS_ASSISTANT_FAST_KDF").is_ok_and(|v| v == "1") {
            cmd.arg("--fast-kdf");
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("无法启动 {}: {e}", path.display()))?;
        let stderr = Arc::new(Mutex::new(String::new()));
        if let Some(mut err) = child.stderr.take() {
            let sink = stderr.clone();
            std::thread::spawn(move || {
                let mut s = String::new();
                let _ = err.read_to_string(&mut s);
                sink.lock().unwrap().push_str(&s);
            });
        }
        let stdin = child.stdin.take().expect("piped");
        let out = BufReader::new(child.stdout.take().expect("piped"));
        Ok(Helper {
            child,
            stdin: Some(stdin),
            out,
            stderr,
            next: 0,
        })
    }

    fn dead(&mut self) -> String {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let code = self.child.try_wait().ok().flatten().and_then(|s| s.code());
        let err = self.stderr.lock().unwrap().trim().to_owned();
        match code {
            Some(126) => "已取消管理员认证".into(),
            Some(127) => format!("认证失败或 pkexec 不可用 {err}"),
            _ if !err.is_empty() => format!("后端已退出: {err}"),
            _ => "后端已退出".into(),
        }
    }

    pub fn call<T: DeserializeOwned>(
        &mut self,
        method: Method,
        on_event: &mut dyn FnMut(Event),
    ) -> Result<T, String> {
        self.next += 1;
        let id = self.next;
        let mut line = serde_json::to_string(&Call { id, method }).expect("serializable");
        line.push('\n');
        let sent = match self.stdin.as_mut() {
            Some(w) => w.write_all(line.as_bytes()).and_then(|_| w.flush()).is_ok(),
            None => false,
        };
        if !sent {
            return Err(self.dead());
        }
        loop {
            let mut buf = String::new();
            match self.out.read_line(&mut buf) {
                Ok(0) | Err(_) => return Err(self.dead()),
                Ok(_) => {}
            }
            let reply: Reply =
                serde_json::from_str(&buf).map_err(|e| format!("后端回复无效: {e}"))?;
            if reply.id != id {
                continue;
            }
            match reply.body {
                ReplyBody::Event(e) => on_event(e),
                ReplyBody::Ok(v) => {
                    return serde_json::from_value(v).map_err(|e| format!("后端回复无效: {e}"));
                }
                ReplyBody::Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Closing stdin ends the helper's request loop; it runs as root, so
        // it cannot be killed from here.
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}
