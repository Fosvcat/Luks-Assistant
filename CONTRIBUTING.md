# Contributing

## Quick checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Unit tests do not need root. The end-to-end tests in `crates/luks-assistant-core/tests/real_cryptsetup.rs` run the real `cryptsetup` / `systemd-cryptenroll` on **image files** and never touch real disks; they are skipped without root or without cryptsetup.

## Testing TPM2 with swtpm

No real TPM is needed. On Debian/Ubuntu:

```sh
sudo apt install cryptsetup-bin swtpm swtpm-tools tpm2-tools libtss2-tcti-swtpm0t64
mkdir -p /tmp/swtpm
swtpm socket --tpmstate dir=/tmp/swtpm --tpm2 \
  --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear --daemon
sudo env "PATH=$PATH" LUKS_ASSISTANT_TEST_SWTPM=swtpm:host=127.0.0.1,port=2321 cargo test --workspace
```

The test enrolls TPM2, changes a PCR with `tpm2_pcrextend`, checks that Luks Assistant reports "PCR 9 changed", then re-enrolls with a PIN and replaces the old slot.

## Trying the TUI on an image

```sh
truncate -s 32M /tmp/demo.img
printf 'first-pass' | sudo cryptsetup luksFormat --type luks2 -q \
  --pbkdf pbkdf2 --pbkdf-force-iterations 1000 /tmp/demo.img --key-file=-
sudo env LUKS_ASSISTANT_FAST_KDF=1 \
  LUKS_ASSISTANT_TPM2_DEVICE=swtpm:host=127.0.0.1,port=2321 \
  LUKS_ASSISTANT_ETC_DIR=/tmp/luks-assistant/etc LUKS_ASSISTANT_STATE_DIR=/tmp/luks-assistant/state \
  ./target/debug/Luks-Assistant-TUI /tmp/demo.img
```

| Variable | Effect |
|---|---|
| `LUKS_ASSISTANT_TPM2_DEVICE` | Value for `--tpm2-device=`; with a TCTI string (such as swtpm) PCRs are read with `tpm2_pcrread` |
| `LUKS_ASSISTANT_ETC_DIR` | Local notes directory (default `/etc/luks-assistant`) |
| `LUKS_ASSISTANT_STATE_DIR` | Header backups, PCR snapshots, log and lock file (default `/var/lib/luks-assistant`) |
| `LUKS_ASSISTANT_FAST_KDF=1` | Very weak PBKDF2 for new slots, **for tests only** |
| `LUKS_ASSISTANT_LANG=en` / `zh_CN` | Interface language (default: the locale) |

## GUI

```sh
sudo apt install cmake qt6-base-dev     # Arch: qt6-base; Fedora: qt6-qtbase-devel
cargo build -p luks-assistant-helper -p luks-assistant-tui
cmake -S gui -B gui/build && cmake --build gui/build
# Run as root, the GUI starts the helper directly instead of through pkexec;
# the development variables are passed on to the helper.
sudo env LUKS_ASSISTANT_HELPER=$PWD/target/debug/Luks-Assistant-Helper LUKS_ASSISTANT_FAST_KDF=1 \
  LUKS_ASSISTANT_ETC_DIR=/tmp/luks-assistant/etc LUKS_ASSISTANT_STATE_DIR=/tmp/luks-assistant/state \
  ./gui/build/Luks-Assistant-GUI --gui /tmp/demo.img
```

Without a display, use `Xvfb :99` with `DISPLAY=:99`, click with `xdotool` and take screenshots with `import -window root`.

## Interface text and translations

Source strings are written in **English**. Translations are standard GNU gettext catalogs, shared by the Rust crates and the Qt GUI:

```
po/luks-assistant.pot   template: every translatable string (generated)
po/zh_CN.po             Chinese (Simplified)
```

- Rust: `t!("…")` translates right away into the current language; `tx!("… {}", x)` makes a `Text` that is translated when shown. Plans, steps, reports and errors use `tx!`, so one message can be shown in the interface language and logged in English. Text in `const` tables is marked with `n!("…")` and translated where it is shown with `i18n::tr`. Placeholders are always `{}`.
- Qt: `tr("…")` (placeholders `%1`, `%2`); `.ui` texts are handled by uic. When the same English needs different translations, give the `.ui` string a `comment="…"`; it becomes the entry's `msgctxt`. Messages printed before Qt starts use `AppSettings::cliTr("…")`.

The `catalog` test (part of `cargo test`) extracts all strings and checks that the sources contain no untranslated non-English text, that the template is up to date, and that every `.po` file translates every string with the same placeholders. After changing interface text:

```sh
UPDATE_PO=1 cargo test -p luks-assistant-sysinfo --test catalog
```

This regenerates the template and merges it into each `.po` file: new strings get an empty `msgstr` to fill in (untranslated strings are listed by the test), strings no longer used are dropped. The files work with any PO editor (Poedit, Lokalize, Qt Linguist via `lconvert`) and translation platform (Weblate, Crowdin), and `msgfmt --check po/zh_CN.po` validates them.

### Adding a language

1. `cp po/luks-assistant.pot po/<code>.po` (for example `de.po`, `pt_BR.po`), set `Language:` in the header and translate.
2. Add the catalog to `CATALOGS` in `crates/luks-assistant-sysinfo/src/i18n.rs`.
3. GUI: add the language to the language list on the About page (`languageCombo` in `gui/src/mainwindow.ui` and `AppSettings::Language`). The GUI embeds every `po/*.po` automatically, and "follow the system" picks it up without further changes.

## Conventions

- Every write goes through `luks_assistant_core::ops::plan` → `execute`; frontends never build commands themselves.
- New safety rules go into `guard.rs`; when they block, they return `Error::Blocked` and offer no way around.
- Secrets use the `Secret` type (zeroed on drop, hidden from `Debug`) and reach child processes only through `Cmd::secret_arg` / `Cmd::secret_env`.
- Features are enabled by tool version (`Caps`), never by distribution name.

## Releasing

1. Change `version` under `[workspace.package]` in the root `Cargo.toml`.
2. Run `cargo build` so the version in `Cargo.lock` is updated too.
3. Commit `Cargo.toml` and `Cargo.lock` together and push to `main`.

The Release workflow creates the `v<version>` tag, builds and publishes. It can also be run by hand from Actions → Release → Run workflow (leave the tag empty to use the version in `Cargo.toml`).
