<p align="center"><img src="packaging/icons/luks-assistant.png" alt="Luks Assistant" width="112"></p>

<h1 align="center">Luks Assistant</h1>

**Luks Assistant** 用来管理 LUKS 的密钥槽：密码、密钥文件、恢复密钥、TPM2（可选 PCR）、FIDO2 安全密钥、PKCS#11 智能卡，以及槽位备注、优先级、头部备份/恢复等。
底层调用 `cryptsetup` 和 `systemd-cryptenroll`，因此适用于 Arch、Fedora/RHEL、Debian/Ubuntu 三大系列发行版。

> **仅支持 LUKS2，不支持老旧的 LUKS1。** Luks Assistant 不会对 LUKS1 做任何修改。

- **图形界面** `Luks-Assistant-GUI`：Qt6 Widgets 原生界面（KDE 下使用系统样式，GNOME 下随 Qt 平台主题呈现 GTK 风格），普通用户运行，通过 `pkexec` 启动 root 后端 `Luks-Assistant-Helper`
- **终端界面** `Luks-Assistant-TUI`：`sudo` 运行，适合服务器和 SSH

## 功能

- **32 槽位总览**：类型、KDF、优先级、令牌、备注，以及 TPM2 策略是否仍与当前 PCR 匹配
- **密码 / 密钥文件**：添加、修改、生成随机密钥文件（0400）、测试密码对应哪个槽位
- **恢复密钥**：生成 / 重新生成
- **TPM2**：自选 PCR、可选 PIN、**一键重新录入**
- **PCR 漂移检测**：在本地重新计算 systemd 的 TPM2 策略哈希并与令牌比较，判断能否自动解锁；
- **FIDO2 / PKCS#11**：录入、重新录入
- **槽位备注**：默认存入 LUKS2 头部，也可存在本机 `/etc/luks-assistant/`
- **自我检查**：问题与警告（孤立令牌、过期备注、TPM 策略失配等）；硬件解锁可用性（只读：initramfs 钩子、crypttab、内核参数、令牌插件、安全启动等，开机时 TPM2/FIDO2 是否可用等）
- **头部管理**：备份 / 恢复 LUKS 头部，可自定义备份位置
- **解锁 / 锁定**：用密码、密钥文件或 TPM2/FIDO2/PKCS#11 令牌打开和关闭卷
- **PBKDF2 → Argon2id** 转换
- **验证**：验证 密码、密钥文件或 TPM2/FIDO2/PKCS#11 令牌 是否正确工作
- **界面语言**：图形界面在“关于”页选择（默认跟随系统）
- **日志**

## 安全护栏

- **永远至少保留一个“密码 / 密钥文件 / 恢复密钥”槽位**。TPM2、FIDO2 等令牌不能作为唯一解锁方式。
- 删除槽位时必须用**另一个**保留槽位的凭据验证，并输入槽位号确认。
- 每次修改头部之前都会自动备份到备份位置下的 `<UUID>/`。
- 执行前显示完整的**等效命令**；敏感信息通过匿名管道 `/dev/fd/N` 或 systemd-cryptenroll 的环境变量传递。
- 每次操作后重新读取头部，验证结果符合预期。
- 新密码含非 ASCII 字符时警告。
- 脱敏操作记录。

## 安装

- `Luks-Assistant-x86_64.tar.gz`
- `Luks-Assistant-aarch64.tar.gz`

```sh
tar xf Luks-Assistant-x86_64.tar.gz && cd Luks-Assistant-x86_64
sudo ./install.sh                # 安装到 /usr/local，含 polkit 策略和桌面启动项
sudo ./install.sh --uninstall
```

运行时依赖：`cryptsetup` ≥ 2.4；TPM2/FIDO2/PKCS#11/恢复密钥需要 `systemd-cryptenroll`（systemd ≥ 248，TPM2+PIN 需要 ≥ 251）；图形界面需要 polkit（`pkexec`）和 Qt 6 Widgets（Arch `qt6-base`，Fedora `qt6-qtbase-gui`，Debian/Ubuntu `libqt6widgets6`）。功能按工具版本自动启用。

## 从源码构建

需要 Rust ≥ 1.85；图形界面另需 CMake 与 Qt ≥ 6.2 开发包（Arch `qt6-base`，Fedora `qt6-qtbase-devel`，Debian/Ubuntu `qt6-base-dev`）。

```sh
cargo build --release                            # TUI 与 helper
cmake -S gui -B gui/build -DCMAKE_BUILD_TYPE=Release && cmake --build gui/build   # 图形界面
sudo packaging/install.sh                        # 安装 target/release 与 gui/build 中的二进制
sudo ./target/release/Luks-Assistant-TUI /dev/nvme0n1p2 # 直接运行终端界面
./target/release/Luks-Assistant-TUI --dump disk.img     # 以 JSON 输出槽位模型
```

## 槽位备注

Luks Assistant 提供了槽位备注功能

- **存入头部**（默认）：所有备注放在**一个** `luks-assistant-notes` 令牌里，该令牌不绑定任何槽位（`"keyslots": []`）。如果绑定了槽位，`systemd-cryptenroll --wipe-slot` 擦除其中一个槽位时，会连带擦除共享同一令牌的其它槽位。每条备注都记录所属槽位 KDF salt 的指纹；槽位被其它工具删除或改写后，备注会自动失效，并在体检中提示清理。
- **存在本机**：`/etc/luks-assistant/notes/<UUID>.json`（0600）。

## 项目结构

```
crates/
├── luks-assistant-sysinfo  只读的系统探测：发行版、工具版本与功能、UEFI/安全启动、TPM、PCR、FIDO2/PKCS#11、开机检查
├── luks-assistant-core     头部解析、32 槽位模型、备注、PCR 策略计算、安全护栏、表单、操作计划与执行、通信协议
├── luks-assistant-tui      ratatui 终端界面（库 + Luks-Assistant-TUI 二进制）
└── luks-assistant-helper   root 后端 Luks-Assistant-Helper，由图形界面通过 pkexec 启动
gui/                        C++ Qt6 Widgets 图形界面（Luks-Assistant-GUI，终端中自动转为 TUI）
packaging/                  polkit 策略、桌面启动项、安装脚本
```
