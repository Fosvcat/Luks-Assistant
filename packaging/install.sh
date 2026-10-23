#!/bin/sh
# Install Luks Assistant from a release archive or a source build
# (cargo build --release + cmake --build gui/build).
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
ICONDIR=$PREFIX/share/icons/hicolor/128x128/apps
PIXMAPDIR=$PREFIX/share/pixmaps
# polkit only reads actions from /usr/share
POLKITDIR=/usr/share/polkit-1/actions
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$DESTDIR$BINDIR/Luks-Assistant-GUI" "$DESTDIR$BINDIR/Luks-Assistant-TUI" \
          "$DESTDIR$LIBEXECDIR/Luks-Assistant-Helper" \
          "$DESTDIR$APPDIR/Luks-Assistant.desktop" \
          "$DESTDIR$ICONDIR/luks-assistant.png" "$DESTDIR$PIXMAPDIR/luks-assistant.png" \
          "$DESTDIR$POLKITDIR/io.github.fosvcat.luks-assistant.policy"
    echo "已卸载（/etc/luks-assistant 与 /var/lib/luks-assistant 中的备注、备份保持不变）"
    exit 0
fi

find_bin() {
    for d in "$HERE" "$HERE/.." "$HERE/../target/release" "$HERE/../gui/build"; do
        if [ -x "$d/$1" ]; then echo "$d/$1"; return; fi
    done
}

TUI=$(find_bin Luks-Assistant-TUI)
GUI=$(find_bin Luks-Assistant-GUI)
HELPER=$(find_bin Luks-Assistant-Helper)

[ -n "$TUI" ] || { echo "找不到 Luks-Assistant-TUI" >&2; exit 1; }
install -Dm755 "$TUI" "$DESTDIR$BINDIR/Luks-Assistant-TUI"
if [ -n "$GUI" ] && [ -n "$HELPER" ]; then
    install -Dm755 "$GUI" "$DESTDIR$BINDIR/Luks-Assistant-GUI"
    install -Dm755 "$HELPER" "$DESTDIR$LIBEXECDIR/Luks-Assistant-Helper"
    install -Dm644 "$HERE/Luks-Assistant.desktop" "$DESTDIR$APPDIR/Luks-Assistant.desktop"
    install -Dm644 "$HERE/icons/luks-assistant-128.png" "$DESTDIR$ICONDIR/luks-assistant.png"
    install -Dm644 "$HERE/icons/luks-assistant.png" "$DESTDIR$PIXMAPDIR/luks-assistant.png"
    if [ -z "$DESTDIR" ] && command -v gtk-update-icon-cache >/dev/null; then
        gtk-update-icon-cache -q -t "$PREFIX/share/icons/hicolor" || true
    fi
    mkdir -p "$DESTDIR$POLKITDIR"
    sed "s|@LIBEXECDIR@|$LIBEXECDIR|" "$HERE/io.github.fosvcat.luks-assistant.policy.in" \
        > "$DESTDIR$POLKITDIR/io.github.fosvcat.luks-assistant.policy"
    chmod 644 "$DESTDIR$POLKITDIR/io.github.fosvcat.luks-assistant.policy"
    echo "已安装 Luks-Assistant-GUI、Luks-Assistant-TUI 与 $LIBEXECDIR/Luks-Assistant-Helper"
else
    echo "已安装 Luks-Assistant-TUI（未找到图形界面二进制）"
fi
