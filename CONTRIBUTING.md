# 开发指南

## 快速检查

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

单元测试不需要 root。`crates/luks-assistant-core/tests/real_cryptsetup.rs` 中的端到端测试会在**镜像文件**上调用真实的 `cryptsetup` / `systemd-cryptenroll`，不会碰真实磁盘；没有 root 或没装 cryptsetup 时会自动跳过。

## 用 swtpm 测试 TPM2

不需要真实 TPM。在 Debian/Ubuntu 上：

```sh
sudo apt install cryptsetup-bin swtpm swtpm-tools tpm2-tools libtss2-tcti-swtpm0t64
mkdir -p /tmp/swtpm
swtpm socket --tpmstate dir=/tmp/swtpm --tpm2 \
  --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear --daemon
sudo env "PATH=$PATH" LUKS_ASSISTANT_TEST_SWTPM=swtpm:host=127.0.0.1,port=2321 cargo test --workspace
```

测试会录入 TPM2，用 `tpm2_pcrextend` 改变 PCR，检查 luks-assistant 能否报告“PCR 9 已变化”，再带 PIN 重新录入并替换旧槽位。

## 在镜像上手动试用 TUI

```sh
truncate -s 32M /tmp/demo.img
printf 'first-pass' | sudo cryptsetup luksFormat --type luks2 -q \
  --pbkdf pbkdf2 --pbkdf-force-iterations 1000 /tmp/demo.img --key-file=-
sudo env LUKS_ASSISTANT_FAST_KDF=1 \
  LUKS_ASSISTANT_TPM2_DEVICE=swtpm:host=127.0.0.1,port=2321 \
  LUKS_ASSISTANT_ETC_DIR=/tmp/luks-assistant/etc LUKS_ASSISTANT_STATE_DIR=/tmp/luks-assistant/state \
  ./target/debug/luks-assistant-tui /tmp/demo.img
```

| 变量 | 作用 |
|---|---|
| `LUKS_ASSISTANT_TPM2_DEVICE` | `--tpm2-device=` 的值；TCTI 字符串（如 swtpm）会改用 `tpm2_pcrread` 读取 PCR |
| `LUKS_ASSISTANT_ETC_DIR` | 本机备注目录（默认 `/etc/luks-assistant`） |
| `LUKS_ASSISTANT_STATE_DIR` | 头部备份、PCR 快照、日志、锁文件目录（默认 `/var/lib/luks-assistant`） |
| `LUKS_ASSISTANT_FAST_KDF=1` | 新槽位使用极弱的 PBKDF2，**仅用于测试** |

## 图形界面

```sh
sudo apt install libfontconfig1-dev libxkbcommon-dev
cargo build -p luks-assistant-gui -p luks-assistant-helper
# 以 root 运行时 GUI 直接启动 helper，不经过 pkexec；开发用环境变量会转成 helper 参数
sudo env LUKS_ASSISTANT_HELPER=$PWD/target/debug/luks-assistant-helper LUKS_ASSISTANT_FAST_KDF=1 \
  LUKS_ASSISTANT_ETC_DIR=/tmp/luks-assistant/etc LUKS_ASSISTANT_STATE_DIR=/tmp/luks-assistant/state \
  ./target/debug/luks-assistant --gui /tmp/demo.img
```

无显示器的环境可以用 `Xvfb :99` + `DISPLAY=:99`，再用 `xdotool` 点击、`import -window root` 截图。

## 约定

- 写操作一律经过 `luks_assistant_core::ops::plan` → `execute`，前端不自己拼命令。
- 新的安全规则放在 `guard.rs`，被阻止时返回 `Error::Blocked`，不提供绕过选项。
- 秘密用 `Secret` 类型（drop 时清零、`Debug` 不输出内容），只能通过 `Cmd::secret_arg` / `Cmd::secret_env` 传给子进程。
- 功能按工具版本启用（`Caps`），不按发行版名称判断。

## 发布新版本

1. 修改根目录 `Cargo.toml` 中 `[workspace.package]` 的 `version`。
2. 运行 `cargo build`，让 `Cargo.lock` 中的版本号同步更新。
3. 把 `Cargo.toml` 和 `Cargo.lock` 一起提交并推送到 `main`。

Release 工作流会自动创建 `v<版本号>` 标签，编译并发布。也可以在 Actions → Release → Run workflow 手动运行（标签留空即使用 `Cargo.toml` 中的版本）。
