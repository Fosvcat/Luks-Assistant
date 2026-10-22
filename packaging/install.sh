#!/bin/sh
# Install luks-assistant from a release archive or a cargo build.
#
#   sudo ./install.sh                 # binaries next to this script, PREFIX=/usr/local
#   sudo PREFIX=/usr ./install.sh
#   sudo ./install.sh --uninstall
#   DESTDIR=/tmp/pkg PREFIX=/usr ./install.sh   # for packagers
set -eu

PREFIX=${PREFIX:-/usr/local}
DESTDIR=${DESTDIR:-}
BINDIR=$PREFIX/bin
LIBEXECDIR=$PREFIX/libexec
APPDIR=$PREFIX/share/applications
# polkit only reads actions from /usr/share
POLKITDIR=/usr/share/polkit-1/actions
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$DESTDIR$BINDIR/luks-assistant" "$DESTDIR$BINDIR/luks-assistant-tui" \
          "$DESTDIR$LIBEXECDIR/luks-assistant-helper" \
          "$DESTDIR$APPDIR/luks-assistant.desktop" \
          "$DESTDIR$POLKITDIR/io.github.fosvcat.luks-assistant.policy"
    echo "已卸载（/etc/luks-assistant 与 /var/lib/luks-assistant 中的备注、备份保持不变）"
    exit 0
fi

find_bin() {
    for d in "$HERE" "$HERE/.." "$HERE/../target/release"; do
        if [ -x "$d/$1" ]; then echo "$d/$1"; return; fi
    done
}

TUI=$(find_bin luks-assistant-tui)
GUI=$(find_bin luks-assistant)
HELPER=$(find_bin luks-assistant-helper)

[ -n "$TUI" ] || { echo "找不到 luks-assistant-tui" >&2; exit 1; }
install -Dm755 "$TUI" "$DESTDIR$BINDIR/luks-assistant-tui"
if [ -n "$GUI" ] && [ -n "$HELPER" ]; then
    install -Dm755 "$GUI" "$DESTDIR$BINDIR/luks-assistant"
    install -Dm755 "$HELPER" "$DESTDIR$LIBEXECDIR/luks-assistant-helper"
    install -Dm644 "$HERE/luks-assistant.desktop" "$DESTDIR$APPDIR/luks-assistant.desktop"
    mkdir -p "$DESTDIR$POLKITDIR"
    sed "s|@LIBEXECDIR@|$LIBEXECDIR|" "$HERE/io.github.fosvcat.luks-assistant.policy.in" \
        > "$DESTDIR$POLKITDIR/io.github.fosvcat.luks-assistant.policy"
    chmod 644 "$DESTDIR$POLKITDIR/io.github.fosvcat.luks-assistant.policy"
    echo "已安装 luks-assistant（图形界面）、luks-assistant-tui 与 $LIBEXECDIR/luks-assistant-helper"
else
    echo "已安装 luks-assistant-tui（未找到图形界面二进制）"
fi
