//! Luks-Assistant-Helper — the privileged half of the Luks Assistant GUI.
//!
//! Started by the GUI through `pkexec` (or directly when the GUI already
//! runs as root). Reads one JSON [`Call`] per line on stdin and answers on
//! stdout; see `luks_assistant_core::proto`. Every write still goes through
//! `ops::plan` and its guards, and plans never leave this process.

use luks_assistant_core::device::{self, LuksDevice};
use luks_assistant_core::exec::{Cmd, CmdOutput, Runner, SystemRunner, run_in_pty};
use luks_assistant_core::forms::{self, Env, Form, Submit, VerifyMethod};
use luks_assistant_core::health;
use luks_assistant_core::ops::{self, Plan, Request, TokenKind};
use luks_assistant_core::proto::{
    self, Call, DeviceReply, Event, Hello, Method, OverviewReply, PlanView, Reply, ReplyBody,
    ReportView, SubmitReply, TokenVerified,
};
use luks_assistant_core::slots::Overview;
use luks_assistant_core::{Ctx, Error, Result, Secret, config, view};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const USAGE: &str =
    "Luks-Assistant-Helper — 由 Luks Assistant 图形界面通过 pkexec 启动，不需要手动运行

  --tpm2-device <dev>   TPM 设备或 TCTI（开发用）
  --etc-dir <dir>       备注与配置目录（开发用）
  --state-dir <dir>     状态目录（开发用）
  --fast-kdf            新槽位使用弱 PBKDF2（仅测试）
";

/// Shared writer so that events from inside a running command and final
/// replies never interleave mid-line.
#[derive(Clone)]
struct Out {
    stdout: Arc<Mutex<std::io::Stdout>>,
    current: Arc<AtomicU64>,
}

impl Out {
    fn send(&self, reply: &Reply) {
        let mut line = serde_json::to_string(reply).expect("serializable");
        line.push('\n');
        let mut out = self.stdout.lock().unwrap();
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }

    fn event(&self, e: Event) {
        self.send(&Reply {
            id: self.current.load(Ordering::SeqCst),
            body: ReplyBody::Event(e),
        });
    }
}

/// Runs interactive commands on a pseudo-terminal, streaming their output
/// to the GUI as events.
struct HelperRunner {
    out: Out,
}

impl Runner for HelperRunner {
    fn run(&self, cmd: &Cmd) -> Result<CmdOutput> {
        if !cmd.interactive {
            return SystemRunner.run(cmd);
        }
        let out = self.out.clone();
        run_in_pty(
            cmd,
            &mut |text| {
                let t = text.replace('\r', "");
                if !t.trim().is_empty() {
                    out.event(Event::Output(t));
                }
            },
            Duration::from_secs(180),
        )
    }
}

struct Progress<'a> {
    out: &'a Out,
}

impl ops::Hooks for Progress<'_> {
    fn progress(&mut self, step: &str) {
        self.out.event(Event::Progress(step.to_owned()));
    }
}

struct Helper {
    ctx: Ctx,
    out: Out,
    plans: HashMap<u64, Plan>,
    next_plan: u64,
}

fn json<T: Serialize>(v: T) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(v).expect("serializable"))
}

impl Helper {
    fn overview(&self, path: &Path) -> Result<Overview> {
        let dev = device::discover(&self.ctx)
            .ok()
            .and_then(|d| d.into_iter().find(|d| d.path == path))
            .unwrap_or_else(|| LuksDevice::from_path(path));
        Overview::load(&self.ctx, dev)
    }

    fn store(&mut self, plan: Plan) -> PlanView {
        self.next_plan += 1;
        let view = PlanView::new(self.next_plan, &plan);
        self.plans.insert(self.next_plan, plan);
        view
    }

    fn target(&self, path: &Path) -> luks_assistant_sysinfo::bootcheck::Target {
        self.overview(path)
            .map(|o| luks_assistant_sysinfo::bootcheck::Target {
                uuid: o.header.uuid.clone(),
                path: o.device.path.to_string_lossy().into_owned(),
                mapping: o.device.mapping.clone(),
            })
            .unwrap_or_default()
    }

    fn verify_token(
        &self,
        path: &Path,
        kind: TokenKind,
        pin: Option<&Secret>,
    ) -> Result<TokenVerified> {
        let ov = self.overview(path)?;
        let tests = ops::token_tests(&ov, kind, pin);
        if tests.is_empty() {
            return Err(Error::Invalid(format!("没有 {} 令牌", kind.label())));
        }
        let mut last = String::new();
        for t in tests {
            match self.ctx.runner.run(&t.cmd) {
                Ok(o) if o.success() => {
                    return Ok(TokenVerified {
                        token: t.token,
                        slots: t.slots,
                    });
                }
                Ok(o) => last = ops::token_failure(&o),
                Err(e) => last = e.to_string(),
            }
        }
        Err(Error::Invalid(format!("{} 验证失败：{last}", kind.label())))
    }

    fn submit(&mut self, path: &Path, form: &Form) -> Result<SubmitReply> {
        let submit = forms::submit(form).map_err(Error::Invalid)?;
        Ok(match submit {
            Submit::Request(request) => {
                let ov = self.overview(path)?;
                let plan = ops::plan(&self.ctx, &ov, &request)?;
                SubmitReply::Plan(self.store(plan))
            }
            Submit::Verify(VerifyMethod::Credential(c)) => {
                match ops::verify_credential(&self.ctx, path, &c) {
                    Ok(slot) => {
                        let kind = self
                            .overview(path)
                            .ok()
                            .and_then(|o| o.slot(slot).map(|s| s.kind.label()))
                            .unwrap_or_default();
                        SubmitReply::Message {
                            ok: true,
                            text: format!("槽位 {slot}（{kind}）验证成功"),
                        }
                    }
                    Err(e) => SubmitReply::Message {
                        ok: false,
                        text: e.to_string(),
                    },
                }
            }
            Submit::Verify(VerifyMethod::Token { kind, pin }) => {
                match self.verify_token(path, kind, pin.as_ref()) {
                    Ok(v) => SubmitReply::Message {
                        ok: true,
                        text: format!(
                            "槽位 {}（{} 令牌 {}）验证成功",
                            v.slots
                                .iter()
                                .map(u32::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                            kind.label(),
                            v.token
                        ),
                    },
                    Err(e) => SubmitReply::Message {
                        ok: false,
                        text: e.to_string(),
                    },
                }
            }
            Submit::SetBackupDir(dir) => {
                config::set_backup_dir(&mut self.ctx.paths, dir)?;
                SubmitReply::Paths(self.ctx.paths.clone())
            }
        })
    }

    fn handle(&mut self, m: Method) -> Result<serde_json::Value> {
        match m {
            Method::Hello => json(Hello {
                protocol: proto::VERSION,
                version: env!("CARGO_PKG_VERSION").into(),
                paths: self.ctx.paths.clone(),
                caps: self.ctx.caps.clone(),
                tpm2_device: self.ctx.tpm2_device.clone(),
            }),
            Method::SystemView { extra } => json(view::system_view(&self.ctx, &extra)),
            Method::DeviceView { path } => {
                let mut ov = self.overview(&path)?;
                let _ = ov.remember_pcrs(&self.ctx);
                let issues = health::check(&ov);
                let boot = luks_assistant_sysinfo::bootcheck::check(&self.target(&path));
                json(DeviceReply {
                    device: view::device_view(&self.ctx, &ov, &issues),
                    boot,
                })
            }
            Method::BackupRows { paths } => json(view::backup_rows(&self.ctx, &paths)),
            Method::BuildForm { path, kind } => {
                let ov = self.overview(&path)?;
                let env = Env {
                    ov: &ov,
                    caps: &self.ctx.caps,
                    paths: &self.ctx.paths,
                    ask_pins: true,
                };
                json(forms::build(kind, &env).map_err(Error::Invalid)?)
            }
            Method::SubmitForm { path, form } => json(self.submit(&path, &form)?),
            Method::PcrNotes { pcrs } => {
                let sb = luks_assistant_sysinfo::firmware::Firmware::detect().secure_boot;
                json(view::pcr_notes(&pcrs, sb))
            }
            Method::Overview { path } => {
                let mut ov = self.overview(&path)?;
                let _ = ov.remember_pcrs(&self.ctx);
                let issues = health::check(&ov);
                json(OverviewReply {
                    overview: ov,
                    issues,
                })
            }
            Method::Plan { path, request } => {
                let ov = self.overview(&path)?;
                let plan = ops::plan(&self.ctx, &ov, &request)?;
                json(self.store(plan))
            }
            Method::PlanBackups { paths } => {
                let mut views = Vec::new();
                for p in paths {
                    let ov = self.overview(&p)?;
                    let plan = ops::plan(&self.ctx, &ov, &Request::BackupHeader { dest: None })?;
                    views.push(self.store(plan));
                }
                json(views)
            }
            Method::Execute { plans, confirm } => {
                for id in &plans {
                    let p = self
                        .plans
                        .get(id)
                        .ok_or_else(|| Error::Invalid(format!("计划 {id} 不存在或已执行")))?;
                    if p.confirm_word.as_ref().is_some_and(|w| w != confirm.trim()) {
                        return Err(Error::Blocked("确认文字不正确".into()));
                    }
                }
                let taken: Vec<Plan> = plans
                    .iter()
                    .filter_map(|id| self.plans.remove(id))
                    .collect();
                let mut reports = Vec::new();
                for p in taken {
                    let report = ops::execute(&self.ctx, &p, &mut Progress { out: &self.out });
                    reports.push(ReportView::new(&p, report));
                }
                json(reports)
            }
            Method::VerifyCredential { path, credential } => {
                json(ops::verify_credential(&self.ctx, &path, &credential)?)
            }
            Method::VerifyToken { path, kind, pin } => {
                json(self.verify_token(&path, kind, pin.as_ref())?)
            }
            Method::SetBackupDir { dir } => {
                config::set_backup_dir(&mut self.ctx.paths, dir)?;
                json(self.ctx.paths.clone())
            }
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        // SAFETY (set_var): single-threaded at this point.
        match a.as_str() {
            "--tpm2-device" => unsafe {
                std::env::set_var(
                    "LUKS_ASSISTANT_TPM2_DEVICE",
                    args.next().unwrap_or_default(),
                )
            },
            "--etc-dir" => unsafe {
                std::env::set_var("LUKS_ASSISTANT_ETC_DIR", args.next().unwrap_or_default())
            },
            "--state-dir" => unsafe {
                std::env::set_var("LUKS_ASSISTANT_STATE_DIR", args.next().unwrap_or_default())
            },
            "--fast-kdf" => unsafe { std::env::set_var("LUKS_ASSISTANT_FAST_KDF", "1") },
            "-h" | "--help" => {
                print!("{USAGE}");
                return;
            }
            other => {
                eprintln!("未知参数: {other}\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    if !luks_assistant_sysinfo::is_root() {
        eprintln!("Luks-Assistant-Helper 需要 root 权限");
        std::process::exit(1);
    }
    let out = Out {
        stdout: Arc::new(Mutex::new(std::io::stdout())),
        current: Arc::new(AtomicU64::new(0)),
    };
    let mut ctx = Ctx::system();
    ctx.runner = Box::new(HelperRunner { out: out.clone() });
    let mut helper = Helper {
        ctx,
        out: out.clone(),
        plans: HashMap::new(),
        next_plan: 0,
    };

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let call: Call = match serde_json::from_str(&line) {
            Ok(c) => c,
            Err(e) => {
                out.send(&Reply {
                    id: 0,
                    body: ReplyBody::Err(format!("无效请求: {e}")),
                });
                continue;
            }
        };
        out.current.store(call.id, Ordering::SeqCst);
        let body = match helper.handle(call.method) {
            Ok(v) => ReplyBody::Ok(v),
            Err(e) => ReplyBody::Err(e.to_string()),
        };
        out.send(&Reply { id: call.id, body });
    }
}
