# 架构

## 分层

```
┌──────────────┐   ┌──────────────────────────────┐
│ luks-assistant-tui  │   │ luks-assistant-gui（Slint，普通用户）  │
└──────┬───────┘   └──────────────┬───────────────┘
       │ 直接调用（sudo 运行）       │ pkexec + stdin/stdout 逐行 JSON
       │                    ┌─────▼──────────────────┐
       │                    │ luks-assistant-helper（root）   │
       │                    └─────┬──────────────────┘
┌──────▼──────────────────────────▼──────────────────┐
│ luks-assistant-core                                         │
│  header  slots  notes  pcr  health  guard  ops  exec │
└──────┬───────────────────────────────────────────────┘
┌──────▼──────────┐   ┌──────────────────────────────┐
│ luks-assistant-sysinfo │   │ cryptsetup / systemd-cryptenroll │
└─────────────────┘   └──────────────────────────────┘
```

## 核心流程

1. **读取**：`cryptsetup luksDump`（UUID/版本）+ `luksDump --dump-json-metadata`（槽位、令牌、段、摘要、配置）→ `header::Header`。
2. **建模**：`slots::Overview` 把槽位、令牌、备注组合成 32 个 `Slot`，并对每个 `systemd-tpm2` 令牌调用 `pcr::evaluate`。
3. **计划**：`ops::plan(ctx, overview, Request)` 先检查 `guard` 规则，再生成 `Plan`（步骤、等效命令、警告、危险级别、确认词）。计划阶段只会运行只读命令，例如 `cryptsetup open --test-passphrase`。
4. **执行**：`ops::execute` 加锁（flock）后逐步运行，遇到第一个失败的步骤就停止。会创建槽位的步骤执行后，通过前后对比头部识别新槽位，后续的备注和 PCR 快照步骤会引用它（`SlotRef::New`）。最后写入脱敏日志。

`Request`/`Plan`/`Report` 就是将来 helper 的 D-Bus 接口：GUI 发送 Request，收到 Plan 后展示给用户确认，再请求执行。

## TPM2 策略的本地验证

systemd-cryptenroll 把卷密钥封装在 TPM 策略下，并把策略摘要保存为令牌的 `tpm2-policy-hash`。对于纯 PCR 策略（可加 PIN），摘要完全由所选 PCR 的值决定：

```
policy₀ = 0³²
PolicyPCR:       policy = SHA256(policy ‖ 0x0000017F ‖ TPML_PCR_SELECTION ‖ SHA256(PCR 值按编号拼接))
PolicyAuthValue: policy = SHA256(policy ‖ 0x0000016B)          （使用 PIN 时）
```

luks-assistant 用当前 PCR 值（`/sys/class/tpm/tpm0/pcr-<bank>/N`）重新计算并比较，不访问 TPM 封装对象，就能判断该槽位现在能否自动解锁。测试中的向量取自 systemd 255 + swtpm 的实际输出。签名策略（`--tpm2-public-key`）和 pcrlock 无法这样判断，会显示为“无法判断”。

策略匹配时，luks-assistant 把这些 PCR 的值按策略哈希保存为快照（`/var/lib/luks-assistant/pcr-snapshots/<UUID>.json`）。之后再失配时，与快照对比即可指出是哪个 PCR 变了。

## 图形界面与 helper

- `luks-assistant`（图形界面）以普通用户运行。启动时用 `pkexec /usr/libexec/luks-assistant-helper` 拉起后端，polkit 弹出管理员认证（策略 `io.github.fosvcat.luks-assistant.helper`，`auth_admin_keep`）。本身已是 root 时直接启动 helper。
- 协议见 `luks_assistant_core::proto`：每行一个 JSON 请求，返回同 id 的 `ok` / `err`，执行过程中插入 `event`（步骤进度、命令输出）。
- **计划留在 helper 里**：GUI 只拿到不含秘密的 `PlanView`，按 id 执行；需要确认词的计划在 helper 中再校验一次。护栏全部在 helper 侧的 `ops::plan` 中执行，GUI 无法绕过。
- FIDO2 / PKCS#11 / TPM2+PIN 需要终端交互。helper 在伪终端里运行这些命令，自动回答 PIN 提示（输出中的 PIN 会被打码），把“请触摸安全密钥”等输出实时转发给 GUI；出现无法回答的密码提示时立即报错，不会卡住。
- 表单定义（`luks_assistant_core::forms`）由 TUI 与 GUI 共用，两者行为一致。
- 默认使用 Slint 的 winit 后端与 Fluent 样式（只依赖 fontconfig，OpenGL 不可用时自动用软件渲染）；`--features qt` 改用 Qt 后端与原生 Qt 样式。
