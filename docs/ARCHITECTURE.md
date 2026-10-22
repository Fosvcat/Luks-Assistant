# 架构

## 分层

```
┌──────────────┐   ┌───────────────────────────────┐
│ luks-assistant-tui  │   │ 未来: luks-assistant-gui (Qt/KDE 风格) │  普通用户运行
└──────┬───────┘   └──────────────┬────────────────┘
       │ 直接调用（sudo 运行）       │ D-Bus（system bus）
       │                    ┌─────▼──────────────────┐
       │                    │ 未来: luks-assistant-helper     │  root，按方法做 polkit 授权
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

## 未来的 GUI 与 helper

- `luks-assistant-helper`：system bus 上的 D-Bus 服务（`zbus`），每个方法对应一个 polkit action（如 `org.luks-assistant.read`、`org.luks-assistant.modify-keys`、`org.luks-assistant.restore-header`），由 D-Bus 激活，空闲时退出。
- `luks-assistant-gui`：普通用户运行。候选方案为 CXX-Qt（QML/Kirigami，最接近 KDE 原生）或 Slint。
- FIDO2 的触摸/PIN 提示需要 helper 把 systemd-cryptenroll 的输出流式转发给 GUI，PIN 通过 `PIN` 环境变量传入。
