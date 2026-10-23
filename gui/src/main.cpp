// Luks-Assistant-GUI: Qt Widgets frontend. Started from a terminal or
// without a display it runs Luks-Assistant-TUI instead; --gui / --tui
// force a mode.

#include "mainwindow.h"

#include <QApplication>
#include <QFileInfo>
#include <QLibraryInfo>
#include <QLocale>
#include <QTranslator>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

const char *usage =
    "用法: Luks-Assistant-GUI [--gui | --tui] [设备或镜像文件...]\n"
    "\n"
    "  桌面环境中启动时打开图形界面；在终端中或没有图形环境时打开终端界面。\n"
    "\n"
    "  --gui        强制图形界面（通过 pkexec 获取管理员权限）\n"
    "  --tui        强制终端界面（Luks-Assistant-TUI）\n";

bool hasDisplay()
{
    for (const char *v : {"WAYLAND_DISPLAY", "DISPLAY"}) {
        const char *s = std::getenv(v);
        if (s && *s)
            return true;
    }
    return false;
}

std::string selfDir()
{
    char buf[4096];
    const ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0)
        return {};
    std::string path(buf, static_cast<size_t>(n));
    return path.substr(0, path.rfind('/'));
}

[[noreturn]] void runTui(const std::vector<std::string> &args)
{
    std::vector<char *> argv;
    std::string sibling = selfDir() + "/Luks-Assistant-TUI";
    std::string name = "Luks-Assistant-TUI";
    argv.push_back(name.data());
    for (const std::string &a : args)
        argv.push_back(const_cast<char *>(a.c_str()));
    argv.push_back(nullptr);
    if (access(sibling.c_str(), X_OK) == 0)
        execv(sibling.c_str(), argv.data());
    execvp(name.c_str(), argv.data());
    std::fprintf(stderr, "无法启动 Luks-Assistant-TUI: %s\n", std::strerror(errno));
    std::exit(127);
}

} // namespace

int main(int argc, char *argv[])
{
    bool forceGui = false;
    bool forceTui = false;
    std::vector<std::string> rest;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--gui")
            forceGui = true;
        else if (a == "--tui")
            forceTui = true;
        else
            rest.push_back(a);
    }
    for (const std::string &a : rest) {
        if (!forceTui && (a == "-h" || a == "--help")) {
            std::fputs(usage, stdout);
            return 0;
        }
        if (a == "-V" || a == "--version") {
            std::printf("Luks Assistant %s\n", LUKS_ASSISTANT_VERSION);
            return 0;
        }
        if (a == "--dump" || a == "--boot-check")
            forceTui = true;
    }
    const bool terminal = isatty(0) && isatty(1);
    if (forceTui || (!forceGui && (terminal || !hasDisplay())))
        runTui(rest);
    if (!hasDisplay()) {
        std::fputs("没有图形环境（WAYLAND_DISPLAY / DISPLAY 未设置），请使用 Luks-Assistant-TUI\n", stderr);
        return 1;
    }

    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Luks Assistant"));
    QApplication::setApplicationVersion(QStringLiteral(LUKS_ASSISTANT_VERSION));
    QApplication::setDesktopFileName(QStringLiteral("Luks-Assistant"));

    // The interface is Chinese; translate Qt's own buttons (OK, Cancel, …) to match.
    QTranslator qtTranslator;
    if (qtTranslator.load(QLocale(QLocale::Chinese, QLocale::China), QStringLiteral("qtbase"), QStringLiteral("_"),
                          QLibraryInfo::path(QLibraryInfo::TranslationsPath)))
        QApplication::installTranslator(&qtTranslator);

    QStringList devices;
    for (const std::string &a : rest)
        devices << QFileInfo(QString::fromStdString(a)).absoluteFilePath();
    MainWindow window(devices);
    window.show();
    return app.exec();
}
