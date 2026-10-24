# Architecture

## Layers

```
┌────────────────────┐   ┌────────────────────────────────────────┐
│ Luks-Assistant-TUI │   │ Luks-Assistant-GUI (C++ Qt6, regular user) │
└─────────┬──────────┘   └──────────────────┬─────────────────────┘
          │ direct calls (run with sudo)     │ pkexec + one JSON message per line on stdin/stdout
          │                      ┌──────────▼────────────────┐
          │                      │ Luks-Assistant-Helper (root) │
          │                      └──────────┬────────────────┘
┌─────────▼─────────────────────────────────▼──────────┐
│ luks-assistant-core                                   │
│  header  slots  notes  pcr  health  guard  ops  exec  │
│  forms  view  proto                                   │
└─────────┬─────────────────────────────────────────────┘
┌─────────▼──────────────┐   ┌──────────────────────────────────┐
│ luks-assistant-sysinfo │   │ cryptsetup / systemd-cryptenroll │
└────────────────────────┘   └──────────────────────────────────┘
```

## Core flow

1. **Read**: `cryptsetup luksDump` (UUID/version) + `luksDump --dump-json-metadata` (key slots, tokens, segments, digests, config) → `header::Header`.
2. **Model**: `slots::Overview` combines key slots, tokens and notes into 32 `Slot`s and calls `pcr::evaluate` for every `systemd-tpm2` token.
3. **Plan**: `ops::plan(ctx, overview, Request)` first checks the `guard` rules, then builds a `Plan` (steps, equivalent commands, warnings, danger level, confirmation word). Planning only runs read-only commands, such as `cryptsetup open --test-passphrase`.
4. **Execute**: `ops::execute` takes a lock (flock) and runs the steps in order, stopping at the first failure. After a step that creates a slot, the new slot is found by comparing the header before and after; later note and PCR snapshot steps refer to it (`SlotRef::New`). Finally a redacted log entry is written.

`Request`/`Plan`/`Report` are also the core of the helper protocol: the GUI sends a Request, shows the returned Plan for confirmation, then asks for it to be executed.

## Checking TPM2 policies locally

systemd-cryptenroll seals the volume key under a TPM policy and stores the policy digest in the token as `tpm2-policy-hash`. For a pure PCR policy (optionally with a PIN) the digest depends only on the values of the selected PCRs:

```
policy₀ = 0³²
PolicyPCR:       policy = SHA256(policy ‖ 0x0000017F ‖ TPML_PCR_SELECTION ‖ SHA256(PCR values concatenated by index))
PolicyAuthValue: policy = SHA256(policy ‖ 0x0000016B)          (with a PIN)
```

Luks Assistant recomputes this from the current PCR values (`/sys/class/tpm/tpm0/pcr-<bank>/N`) and compares, so it can tell whether the slot will unlock automatically right now without touching the sealed TPM object. The test vectors come from real systemd 255 + swtpm output. Signed policies (`--tpm2-public-key`) and pcrlock cannot be checked this way and are shown as "unknown".

While a policy matches, Luks Assistant saves the values of its PCRs as a snapshot keyed by the policy hash (`/var/lib/luks-assistant/pcr-snapshots/<UUID>.json`). When it stops matching later, comparing with the snapshot shows which PCR changed.

## GUI and helper

- `Luks-Assistant-GUI` runs as a regular user. At start-up it launches the backend with `pkexec /usr/libexec/Luks-Assistant-Helper`, and polkit asks for administrator authentication (action `io.github.fosvcat.luks-assistant.helper`, `auth_admin_keep`). When already root, it starts the helper directly.
- The protocol is in `luks_assistant_core::proto`: one JSON request per line, answered with `ok` / `err` under the same id; `event`s (step progress, command output) arrive while a plan runs.
- **Plans stay in the helper**: the GUI only receives a `PlanView` without secrets and executes it by id; plans that need a confirmation word are checked again in the helper. All guards run in `ops::plan` on the helper side, so the GUI cannot bypass them.
- FIDO2 / PKCS#11 / TPM2+PIN need a terminal. The helper runs these commands in a pseudo-terminal, answers the PIN prompts itself (PINs in the output are masked) and forwards output such as "touch your security key" to the GUI as it comes; a password prompt it cannot answer fails right away instead of hanging.
- Form definitions (`luks_assistant_core::forms`) are shared by the TUI and the GUI, so both behave the same: the GUI fetches a form with `build_form` (fields, defaults, hints), builds Qt widgets by field type, and sends it back with `submit_form`; the helper returns a plan, a verification result or an error.
- Display data is prepared by the helper (`luks_assistant_core::view`): `system_view` (system, disks, PCRs, disk picker), `device_view` (32 slots, details, available actions, self-check, boot check), `backup_rows`, `pcr_notes`. The GUI is a thin client without business logic that only displays and interacts.
- The GUI uses Qt6 Widgets (`gui/`, built with CMake) and only standard Qt widgets: on KDE it follows the system style and colors (Breeze etc.), on GNOME the Qt platform theme gives it a GTK look.
- Interface text is English in the source and translated with the gettext catalogs in `po/`, which the Rust crates and the GUI share (see CONTRIBUTING.md).
