// Luks-Assistant-GUI: Qt Widgets frontend. Started from a terminal or
// without a display it runs Luks-Assistant-TUI instead; --gui / --tui
// force a mode.

#include "appsettings.h"
#include "mainwindow.h"

#include <QApplication>
#include <QFileInfo>
#include <QIcon>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/prctl.h>
#include <unistd.h>
#include <vector>

namespace {

QByteArray usage()
{
    return AppSettings::cliTr("Usage: Luks-Assistant-GUI [--gui | --tui] [device or image file...]\n"
                              "\n"
                              "  Opens the graphical interface in a desktop session, the terminal\n"
                              "  interface from a terminal or without a display.\n"
                              "\n"
                              "  --gui        force the graphical interface (administrator rights via pkexec)\n"
                              "  --tui        force the terminal interface (Luks-Assistant-TUI)\n");
}

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
    std::fprintf(stderr, AppSettings::cliTr("Cannot start Luks-Assistant-TUI: %s\n").constData(),
                 std::strerror(errno));
    std::exit(127);
}

} // namespace

int main(int argc, char *argv[])
{
    // ps/top/crash reports would cut "Luks-Assistant-GUI" to 15 characters
    prctl(PR_SET_NAME, "Luks-Assistant");
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
            std::fputs(usage().constData(), stdout);
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
        std::fputs(AppSettings::cliTr("No display (WAYLAND_DISPLAY / DISPLAY not set); use Luks-Assistant-TUI\n").constData(),
                   stderr);
        return 1;
    }

    AppSettings::prepareTheme(); // the platform theme is chosen when Qt starts
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Luks Assistant"));
    QApplication::setApplicationVersion(QStringLiteral(LUKS_ASSISTANT_VERSION));
    QApplication::setDesktopFileName(QStringLiteral("Luks-Assistant"));

    QIcon icon(QStringLiteral(":/icons/luks-assistant-128.png"));
    icon.addFile(QStringLiteral(":/icons/luks-assistant.png"));
    QApplication::setWindowIcon(icon); // X11; Wayland takes it from the desktop entry
    AppSettings::applyStyle();
    AppSettings::applyLanguage();

    QStringList devices;
    for (const std::string &a : rest)
        devices << QFileInfo(QString::fromStdString(a)).absoluteFilePath();
    MainWindow window(devices);
    window.show();
    return app.exec();
}
