// Private Wayland fixture for prompt-accessibility.py. No user desktop or keys.
#include <QDBusConnection>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTemporaryDir>
#include <QtWaylandCompositor/QWaylandCompositor>
#include <QtWaylandCompositor/QWaylandOutput>
#include <QtWaylandCompositor/QWaylandOutputMode>
#include <QtWaylandCompositor/QWaylandSeat>
#include <QtWaylandCompositor/QWaylandSurface>
#include <QtWaylandCompositor/QWaylandXdgShell>
#include <cstdio>
#include <memory>

#define SSH_KEYS_UI_TEST
#include "../ui/prompt.cpp"

int main(int argc, char **argv) {
  rlimit core{0, 0};
  if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0)) return 1;
  QStringList arguments;
  for (int i = 1; i < argc; ++i) arguments << QString::fromLocal8Bit(argv[i]);
  const bool client = arguments.removeAll("--client") != 0;
  if (arguments.size() != 1) return 2;
  const QString variant = arguments.first();
  const bool control = variant == "raw-control";
  const bool eventGuard = variant == "event-guard";
  if (!control && !eventGuard && variant != "fixed-pass" && variant != "fixed-confirm") return 3;
  if (client) {
    // Isolate AT-SPI from input-method selection in the positive control.
    if (control && !qputenv("QT_IM_MODULE", "compose")) return 15;
    if (!control && !configureSecretInput()) return 4;
    if (eventGuard) {
      // Independently test the event guard with the real bridge connected.
      // These addresses come only from the runner's private test buses.
      const QByteArray bus = "unix:path=" + qgetenv("XDG_RUNTIME_DIR") + "/bus";
      const QByteArray accessibility = qgetenv("SSH_KEYS_AUDIT_A11Y_BUS_ADDRESS");
      if (accessibility.isEmpty() || !qputenv("DBUS_SESSION_BUS_ADDRESS", bus) ||
          !qputenv("AT_SPI_BUS_ADDRESS", accessibility)) return 13;
    }
    QApplication app(argc, argv);
    const bool busConnected = QDBusConnection::sessionBus().isConnected();
    const bool busEnvironment = qEnvironmentVariableIsSet("DBUS_SESSION_BUS_ADDRESS");
    std::printf("session_bus_connected=%d dbus_env_set=%d\n", busConnected, busEnvironment);
    if (busConnected != (control || eventGuard) || busEnvironment == control) return 5;
    std::unique_ptr<QWidget> window;
    QLineEdit *field;
    int peer = -1;
    if (control) {
      field = new QLineEdit;
      field->setEchoMode(QLineEdit::Password);
      field->setInputMethodHints(Qt::ImhHiddenText | Qt::ImhSensitiveData |
                                Qt::ImhNoPredictiveText);
      window.reset(field);
    } else {
      int pair[2];
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair)) return 6;
      peer = pair[1];
      auto *prompt = new Prompt(pair[0]);
      window.reset(prompt);
      field = prompt->findChild<QLineEdit *>(variant == "fixed-confirm"
                                                ? "confirmation" : "passphrase");
      if (!field) return 7;
      field->show();
    }
    window->resize(400, 400);
    window->show();
    field->setFocus();
    QTimer::singleShot(700, &app, [&] {
      const QString marker = QStringLiteral("kc_audit_FAKE_input");
      // Insert through QLineEdit's normal editing API. Keyboard delivery is
      // covered by the separate IME test; an active AT-SPI keyboard filter
      // can intercept QTest key events in this private registry fixture.
      field->insert(marker);
      const bool correct = field->text() == marker && field->hasFocus();
      std::printf("input_matches=%d input_length=%lld field_focused=%d\n",
                  field->text() == marker, static_cast<long long>(field->text().size()), field->hasFocus());
      const bool bridgeActive = QAccessible::isActive();
      std::printf("accessibility_bridge_active=%d\n", bridgeActive);
      if (bridgeActive != (control || eventGuard)) { app.exit(14); return; }
      std::printf("synthetic_input_correct=%d\n", correct);
      std::fflush(stdout);
      if (!correct) { app.exit(8); return; }
      // Both insertion and removal must remain private. The old Qt bridge
      // exposes the complete text again when the password field is cleared.
      QTimer::singleShot(100, &app, [field] { field->clear(); });
    });
    QTimer::singleShot(1500, &app, &QApplication::quit);
    const int result = app.exec();
    window.reset();
    if (peer >= 0) ::close(peer);
    return result;
  }

  QTemporaryDir runtime;
  if (!runtime.isValid()) return 9;
  const QString sessionRuntime = qEnvironmentVariable("SSH_KEYS_AUDIT_SESSION_RUNTIME");
  if (sessionRuntime.isEmpty()) return 10;
  qputenv("HOME", runtime.path().toUtf8());
  qputenv("XDG_RUNTIME_DIR", runtime.path().toUtf8());
  qputenv("QT_QPA_PLATFORM", "offscreen");
  qputenv("QT_WAYLAND_CLIENT_BUFFER_INTEGRATION", "shm");
  qunsetenv("WAYLAND_DISPLAY");
  qunsetenv("WAYLAND_SOCKET");
  QApplication app(argc, argv);
  QWaylandCompositor compositor;
  compositor.setSocketName("audit-accessibility");
  compositor.setUseHardwareIntegrationExtension(false);
  QWaylandXdgShell shell(&compositor);
  compositor.create();
  QWindow outputWindow;
  outputWindow.resize(800, 600);
  QWaylandOutput output(&compositor, &outputWindow);
  QWaylandOutputMode mode(QSize(800, 600), 60000);
  output.addMode(mode, true);
  output.setCurrentMode(mode);
  QObject::connect(&shell, &QWaylandXdgShell::toplevelCreated, &app,
      [&](QWaylandXdgToplevel *top, QWaylandXdgSurface *surface) {
        top->sendConfigure(QSize(400, 400), QList<QWaylandXdgToplevel::State>{QWaylandXdgToplevel::ActivatedState});
        output.surfaceEnter(surface->surface());
        QTimer::singleShot(200, &app, [&, surface] {
          compositor.defaultSeat()->setKeyboardFocus(surface->surface());
        });
      });
  QTimer frames;
  QObject::connect(&frames, &QTimer::timeout, &app, [&] {
    output.frameStarted(); output.sendFrameCallbacks();
  });
  frames.start(16);
  QProcess child;
  QProcessEnvironment environment;
  environment.insert("PATH", "/usr/bin");
  environment.insert("LANG", "C.UTF-8");
  environment.insert("HOME", runtime.path());
  environment.insert("XDG_RUNTIME_DIR", sessionRuntime);
  environment.insert("QT_QPA_PLATFORM", "wayland");
  environment.insert("WAYLAND_DISPLAY", runtime.path() + "/audit-accessibility");
  environment.insert("QT_WAYLAND_CLIENT_BUFFER_INTEGRATION", "shm");
  if (eventGuard)
    environment.insert("SSH_KEYS_AUDIT_A11Y_BUS_ADDRESS",
                       qEnvironmentVariable("SSH_KEYS_AUDIT_A11Y_BUS_ADDRESS"));
  // Deliberately no DBUS_SESSION_BUS_ADDRESS or AT_SPI_BUS_ADDRESS. Qt must
  // discover this private runtime's real bus socket just as in production.
  child.setProcessEnvironment(environment);
  child.setProcessChannelMode(QProcess::ForwardedChannels);
  QObject::connect(&child, &QProcess::finished, &app,
      [&](int status, QProcess::ExitStatus state) {
        app.exit(state == QProcess::NormalExit ? status : 11);
      });
  child.start(app.applicationFilePath(), {"--client", variant});
  QTimer::singleShot(6000, &app, [&] {
    if (child.state() != QProcess::NotRunning) {
      child.kill(); child.waitForFinished(500);
    }
    app.exit(12);
  });
  return app.exec();
}
