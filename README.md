# Luks Assistant

**Luks Assistant** 用来管理 LUKS2 的 32 个密钥槽：密码、密钥文件、恢复密钥、TPM2（可选 PCR）、FIDO2 安全密钥、PKCS#11 智能卡，以及槽位备注、优先级、头部备份/恢复、元数据体检等。

底层只调用各发行版都有的 `cryptsetup` 和 `systemd-cryptenroll`，因此适用于 Arch、Fedora/RHEL、Debian/Ubuntu 三大系列。

> **仅支持 LUKS2，不支持老旧的 LUKS1。** LUKS1 卷会被识别出来并标为不支持，Luks Assistant 不会对它做任何修改。

> *Luks Assistant manages LUKS2 key slots (passphrases, key files, recovery keys, TPM2 with PCR selection, FIDO2, PKCS#11) on top of cryptsetup and systemd-cryptenroll, with a graphical and a terminal frontend. LUKS2 only; LUKS1 is not supported.*

- **图形界面** `Luks-Assistant-GUI`：普通用户运行，通过 `pkexec` 启动 root 后端 `Luks-Assistant-Helper`
- **终端界面** `Luks-Assistant-TUI`：`sudo` 运行，适合服务器和 SSH

`Luks-Assistant-GUI` 在桌面中启动时打开图形界面；在终端中或没有图形环境时自动进入终端界面（`--gui` / `--tui` 可强制）。

## 功能

- **32 槽位总览**：类型、KDF、优先级、令牌、备注，以及 TPM2 策略是否仍与当前 PCR 匹配
- **密码 / 密钥文件**：添加、修改、生成随机密钥文件（0400）、测试密码对应哪个槽位
- **恢复密钥**：生成 / 重新生成（只显示一次）
- **TPM2**：自选 PCR（显示每个 PCR 的当前值、含义、何时会变）、可选 PIN、**一键重新录入**（先录入新槽位，成功后才擦除旧槽位）
- **PCR 漂移检测**：在本地重新计算 systemd 的 TPM2 策略哈希并与令牌比较，不接触 TPM 就能判断“现在能否自动解锁”；配合自动保存的 PCR 快照，还能指出**具体是哪个 PCR 变了**
- **FIDO2 / PKCS#11**：录入、重新录入（图形界面中直接输入 PIN，终端界面中按提示操作；需要触摸安全密钥）
- **槽位备注**：默认存入 LUKS2 头部（随硬盘走），也可存在本机 `/etc/luks-assistant/`
- **元数据体检**：孤立令牌、过期备注、只剩一个密码槽位、TPM 策略失配等，部分可一键修复
- **开机检查**（只读）：initramfs 钩子、crypttab、内核参数、令牌插件、安全启动等，判断开机时 TPM2/FIDO2 解锁是否可用
- **头部备份 / 恢复**：可自定义备份位置，多个卷一次全部备份
- **TRIM 穿透**（写入头部标志）与 **PBKDF2 → Argon2id** 转换
- **验证**：密码、密钥文件或 TPM2/FIDO2/PKCS#11 令牌，显示通过的槽位，不做任何修改

## 安全护栏

- **永远至少保留一个“密码 / 密钥文件 / 恢复密钥”槽位**。TPM2、FIDO2 等令牌不能作为唯一解锁方式，删除最后一个这类槽位会被直接拒绝，没有“仍然继续”。
- 没有“清空所有槽位”这种操作。
- 删除槽位时必须用**另一个**保留槽位的凭据验证，并输入槽位号确认。
- 每次修改头部之前都会自动备份到备份位置下的 `<UUID>/`（默认 `/var/lib/luks-assistant/backups/`）。
- 执行前显示完整的**等效命令**；秘密一律隐藏，且不会出现在命令行参数里（通过匿名管道 `/dev/fd/N` 或 systemd-cryptenroll 的环境变量传递）。
- 每次操作后重新读取头部，验证结果符合预期。
- 新密码含非 ASCII 字符时警告（initramfs 中通常只有美式键盘、没有输入法）。
- 操作记录（已脱敏）写入 `/var/lib/luks-assistant/history.log`。

## 安装

从 [Releases](https://github.com/Fosvcat/Luks-Assistant/releases) 下载对应架构的安装包：

- `Luks-Assistant-x86_64.tar.gz`
- `Luks-Assistant-aarch64.tar.gz`

每个安装包都同时包含：

| 文件 | 说明 |
|---|---|
| `Luks-Assistant-GUI` | 图形界面（glibc ≥ 2.35） |
| `Luks-Assistant-TUI` | 终端界面（静态链接，任何发行版可用） |
| `Luks-Assistant-Helper` | 图形界面使用的 root 后端（静态链接） |
| `install.sh` 等 | 安装脚本、polkit 策略、桌面启动项 |

```sh
tar xf Luks-Assistant-x86_64.tar.gz && cd Luks-Assistant-x86_64
sudo ./install.sh                # 安装到 /usr/local，含 polkit 策略和桌面启动项
sudo ./install.sh --uninstall
```

运行时依赖：`cryptsetup` ≥ 2.4；TPM2/FIDO2/PKCS#11/恢复密钥需要 `systemd-cryptenroll`（systemd ≥ 248，TPM2+PIN 需要 ≥ 251）；图形界面需要 polkit（`pkexec`）和 fontconfig。功能按工具版本自动启用。

## 从源码构建

需要 Rust ≥ 1.85；图形界面另需 `libfontconfig1-dev`、`libxkbcommon-dev`（或对应发行版的包）。

```sh
cargo build --release
sudo packaging/install.sh                        # 安装 target/release 中的二进制
sudo ./target/release/Luks-Assistant-TUI /dev/nvme0n1p2 # 直接运行终端界面
./target/release/Luks-Assistant-TUI --dump disk.img     # 以 JSON 输出槽位模型
```

`cargo build --release -p luks-assistant-gui --features qt` 使用 Qt 后端和原生 Qt 样式（KDE 外观，需要 Qt 6 开发包）。

### 页面（终端界面按键）

| 页面 | 内容 | 按键 |
|---|---|---|
| 槽位 | 磁盘下拉框（lsblk 树，只能选 LUKS 卷）、LUKS 卷数/本地卷数、验证、TRIM、32 槽位 | ←↑↓→ 选择，Enter/双击 菜单，`a` 添加，`e` 修改/重新录入，`d` 删除，`n` 备注，`v` 验证，`D` 磁盘，`T` TRIM |
| 系统信息 | 系统/TPM/FIDO2/PKCS#11 · 磁盘与 TRIM · PCR | |
| 体检 | 元数据问题，部分可一键修复 | Enter 修复 |
| 开机检查 | TPM2/FIDO2 开机解锁是否可用 | |
| 备份 | 备份位置、所有 LUKS 卷的最后备份 | 空格 勾选，`a` 全选，Enter 备份所选，`r` 恢复，`c` 备份位置 |
| 日志 | 本次会话的操作 | |

`Tab` / `1`–`6` 切换页面，`F5` 刷新，`q` 退出。

## 槽位备注是怎么存的

LUKS2 头部无法区分“键盘输入的密码”和“密钥文件”，两者都是普通的 `luks2` 槽位，所以 Luks Assistant 提供备注，并为它自己创建的槽位记录类型。

- **存入头部**（默认）：所有备注放在**一个** `luks-assistant-notes` 令牌里，该令牌不绑定任何槽位（`"keyslots": []`）。如果绑定了槽位，`systemd-cryptenroll --wipe-slot` 擦除其中一个槽位时，会连带擦除共享同一令牌的其它槽位。每条备注都记录所属槽位 KDF salt 的指纹；槽位被其它工具删除或改写后，备注会自动失效，并在体检中提示清理。
- **存在本机**：`/etc/luks-assistant/notes/<UUID>.json`（0600）。
- 头部未加密，拿到硬盘的人都能读到备注，**不要写密码提示**。

## 项目结构

```
crates/
├── luks-assistant-sysinfo  只读的系统探测：发行版、工具版本与功能、UEFI/安全启动、TPM、PCR、FIDO2/PKCS#11、开机检查
├── luks-assistant-core     头部解析、32 槽位模型、备注、PCR 策略计算、安全护栏、表单、操作计划与执行、通信协议
├── luks-assistant-tui      ratatui 终端界面（库 + Luks-Assistant-TUI 二进制）
├── luks-assistant-helper   root 后端 Luks-Assistant-Helper，由图形界面通过 pkexec 启动
└── luks-assistant-gui      Slint 图形界面（Luks-Assistant-GUI 二进制，终端中自动转为 TUI）
packaging/                  polkit 策略、桌面启动项、安装脚本
```

开发与测试（包括用 swtpm 虚拟 TPM 跑端到端测试）见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

GPL-3.0-or-later，见 [LICENSE](LICENSE)。
