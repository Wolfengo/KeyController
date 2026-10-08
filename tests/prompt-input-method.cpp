// Isolated Wayland wire regression. This compositor uses a fresh private
// runtime and synthetic text; it never connects to the user desktop or key
// service.
#include <QApplication>
#include <QInputMethod>
#include <QInputMethodQueryEvent>
#include <QLineEdit>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStyle>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>
#include <QWindow>
#include <QtWaylandCompositor/QWaylandCompositor>
#include <QtWaylandCompositor/QWaylandKeymap>
#include <QtWaylandCompositor/QWaylandOutput>
#include <QtWaylandCompositor/QWaylandOutputMode>
#include <QtWaylandCompositor/QWaylandSeat>
#include <QtWaylandCompositor/QWaylandSurface>
#include <QtWaylandCompositor/QWaylandTextInputManagerV3>
#include <QtWaylandCompositor/QWaylandTextInputV3>
#include <QtWaylandCompositor/QWaylandXdgShell>
#include <QtWaylandCompositor/private/qwaylandtextinputv3_p.h>
#include <cassert>
#include <cstdio>

#define SSH_KEYS_UI_TEST
#include "../ui/prompt.cpp"
#include <memory>

int main(int argc, char **argv) {
  rlimit core{0, 0};
  if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0))
    return 1;
  const QStringList args = [&] {
    QStringList a;
    for (int i = 1; i < argc; ++i)
      a << QString::fromLocal8Bit(argv[i]);
    return a;
  }();
  if (args.isEmpty()) {
    QCoreApplication driver(argc, argv);
    for (const auto *mode : {"raw-control", "fixed-pass", "fixed-confirm",
                             "guard-pass", "guard-confirm", "guard-invalid"}) {
      QProcess process;
      QProcessEnvironment environment;
      environment.insert("PATH", "/usr/bin");
      environment.insert("LANG", "C.UTF-8");
      process.setProcessEnvironment(environment);
      process.start(driver.applicationFilePath(), {QString::fromLatin1(mode)});
      if (!process.waitForStarted(1000) || !process.waitForFinished(6000)) {
        process.kill();
        process.waitForFinished(500);
        std::fprintf(stderr, "isolated IME test timed out: %s\n", mode);
        return 1;
      }
      const auto result = process.readAllStandardOutput();
      std::fwrite(result.constData(), 1, result.size(), stdout);
      if (process.exitStatus() != QProcess::NormalExit ||
          process.exitCode() != 0) {
        std::fprintf(stderr, "isolated IME test failed: %s\n", mode);
        return 1;
      }
    }
    return 0;
  }
  const QString marker = QStringLiteral("kc_audit_FAKE_input");
  if (args.contains("--client")) {
    if (args.contains("fixed-pass") || args.contains("fixed-confirm")) {
      if (!configureSecretInput())
        return 4;
    }
    QApplication app(argc, argv);
    std::unique_ptr<QWidget> window;
    QLineEdit *field = nullptr;
    int peer = -1;
    if (args.contains("raw-control")) {
      auto *oldField = new QLineEdit;
      oldField->setEchoMode(QLineEdit::Password);
      oldField->setMaxLength(1024);
      oldField->setContextMenuPolicy(Qt::NoContextMenu);
      oldField->setInputMethodHints(Qt::ImhHiddenText | Qt::ImhSensitiveData |
                                    Qt::ImhNoPredictiveText);
      window.reset(oldField);
      field = oldField;
    } else {
      int pair[2];
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair))
        return 5;
      peer = pair[1];
      auto *prompt = new Prompt(pair[0]);
      window.reset(prompt);
      field = prompt->findChild<QLineEdit *>(
          args.contains("fixed-confirm") || args.contains("guard-confirm")
              ? "confirmation"
              : "passphrase");
      if (!field)
        return 6;
      field->show();
    }
    window->resize(400, 400);
    window->show();
    field->setFocus();
    QTimer::singleShot(700, &app, [&] {
      QTest::keyClicks(field, marker);
      app.inputMethod()->update(Qt::ImQueryAll);
      const bool queryContains = field->inputMethodQuery(Qt::ImSurroundingText)
                                     .toString()
                                     .contains(marker);
      const bool echoSafe =
          field->style()->styleHint(QStyle::SH_LineEdit_PasswordMaskDelay,
                                    nullptr, field) == 0;
      std::printf("direct_query_contains_marker=%d typed_correctly=%d "
                  "focused=%d echo_delay_zero=%d\n",
                  queryContains, field->text() == marker, field->hasFocus(),
                  echoSafe);
      std::fflush(stdout);
      assert(field->text() == marker && field->hasFocus() && echoSafe);
      assert(queryContains == args.contains("raw-control"));
    });
    QTimer::singleShot(1200, &app, [&] {
      if (args.contains("fixed-pass") || args.contains("fixed-confirm")) {
        const bool composeWorks =
            field->text() == marker + QString::fromUtf8("é");
        std::printf("native_dead_key_composes=%d\n", composeWorks);
        std::fflush(stdout);
        assert(composeWorks);
      }
    });
    QTimer::singleShot(1400, &app, &QApplication::quit);
    const auto result = app.exec();
    window.reset();
    if (peer >= 0)
      ::close(peer);
    return result;
  }
  QTemporaryDir runtime("/tmp/keycontroller-private-ime-XXXXXX");
  if (!runtime.isValid())
    return 2;
  qputenv("XDG_RUNTIME_DIR", runtime.path().toLocal8Bit());
  qputenv("QT_QPA_PLATFORM", "offscreen");
  qputenv("HOME", runtime.path().toLocal8Bit());
  qunsetenv("WAYLAND_SOCKET");
  qunsetenv("WAYLAND_DISPLAY");
  qunsetenv("QT_IM_MODULE");
  qunsetenv("QT_PLUGIN_PATH");
  qputenv("QT_WAYLAND_CLIENT_BUFFER_INTEGRATION", "shm");
  QApplication app(argc, argv);
  QWaylandCompositor compositor;
  compositor.setSocketName("audit-wayland");
  compositor.setUseHardwareIntegrationExtension(false);
  QWaylandXdgShell shell(&compositor);
  QWaylandTextInputManagerV3 textManager(&compositor);
  compositor.create();
  compositor.defaultSeat()->keymap()->setLayout("us");
  compositor.defaultSeat()->keymap()->setVariant("intl");
  QWindow outputWindow;
  outputWindow.resize(800, 600);
  QWaylandOutput output(&compositor, &outputWindow);
  QWaylandOutputMode mode(QSize(800, 600), 60000);
  output.addMode(mode, true);
  output.setCurrentMode(mode);
  QObject::connect(
      &shell, &QWaylandXdgShell::toplevelCreated, &app,
      [&](QWaylandXdgToplevel *top, QWaylandXdgSurface *surface) {
        top->sendConfigure(QSize(400, 100),
                           QList<QWaylandXdgToplevel::State>{
                               QWaylandXdgToplevel::ActivatedState});
        output.surfaceEnter(surface->surface());
        QTimer::singleShot(200, &app, [&, surface] {
          compositor.defaultSeat()->setKeyboardFocus(surface->surface());
          auto *textObj =
              compositor.defaultSeat()->extension("zwp_text_input_v3");
          if (textObj)
            static_cast<QWaylandTextInputV3Private *>(
                QObjectPrivate::get(textObj))
                ->setFocus(surface->surface());
        });
      });
  if (args.contains("fixed-pass") || args.contains("fixed-confirm")) {
    QTimer::singleShot(950, &app, [&] {
      // Native XKB codes: dead acute (apostrophe in us(intl)), followed by E.
      // These pass through the private Wayland keyboard and Qt compose context.
      for (const auto code : {48u, 26u}) {
        compositor.defaultSeat()->sendKeyPressEvent(code);
        compositor.defaultSeat()->sendKeyReleaseEvent(code);
      }
    });
  }
  QTimer frames;
  QObject::connect(&frames, &QTimer::timeout, &app, [&] {
    output.frameStarted();
    output.sendFrameCallbacks();
  });
  frames.start(16);
  QProcess child;
  QProcessEnvironment env;
  env.insert("PATH", "/usr/bin");
  env.insert("LANG", "C.UTF-8");
  env.insert("HOME", runtime.path());
  env.insert("XDG_RUNTIME_DIR", runtime.path());
  env.insert("QT_QPA_PLATFORM", "wayland");
  env.insert("WAYLAND_DISPLAY", "audit-wayland");
  env.insert("QT_WAYLAND_CLIENT_BUFFER_INTEGRATION", "shm");
  env.insert("WAYLAND_DEBUG", "client");
  if (args.contains("guard-invalid"))
    env.insert("QT_IM_MODULE", "kc_audit_missing");
  child.setProcessEnvironment(env);
  QByteArray stderrData;
  QObject::connect(&child, &QProcess::readyReadStandardError, &app, [&] {
    stderrData += child.readAllStandardError();
    if (stderrData.size() > 256 * 1024) {
      child.kill();
      app.exit(1);
    }
  });
  QObject::connect(&child, &QProcess::readyReadStandardOutput, &app, [&] {
    const auto out = child.readAllStandardOutput();
    std::fwrite(out.data(), 1, out.size(), stdout);
  });
  QObject::connect(
      &child, &QProcess::finished, &app, [&](int status, QProcess::ExitStatus) {
        stderrData += child.readAllStandardError();
        int surroundingCalls = 0, markerCalls = 0, enableCalls = 0,
            nonemptyCalls = 0;
        for (const auto &line : stderrData.split('\n')) {
          if (line.contains(".set_surrounding_text(")) {
            ++surroundingCalls;
            if (line.contains(marker.toUtf8()))
              ++markerCalls;
            const auto text =
                line.mid(line.indexOf(".set_surrounding_text(") + 22);
            if (!text.startsWith("\"\""))
              ++nonemptyCalls;
          }
          if (line.contains("zwp_text_input_v3") && line.contains(".enable("))
            ++enableCalls;
        }
        std::printf("variant=%s qt=%s status=%d surrounding_calls=%d "
                    "marker_on_wire=%d enable_calls=%d nonempty_calls=%d\n",
                    qPrintable(args.value(0, "password")), qVersion(), status,
                    surroundingCalls, markerCalls, enableCalls, nonemptyCalls);
        const bool control = args.contains("raw-control");
        const bool wireSafe =
            control
                ? (enableCalls > 0 && surroundingCalls > 0 && markerCalls > 0)
                : (surroundingCalls == 0 && markerCalls == 0);
        const bool localContext =
            !(args.contains("fixed-pass") || args.contains("fixed-confirm") ||
              args.contains("guard-invalid")) ||
            enableCalls == 0;
        app.exit(status == 0 && wireSafe && localContext ? 0 : 1);
      });
  child.start(app.applicationFilePath(),
              {"--client", args.value(0, "password")});
  QTimer::singleShot(5000, &app, [&] {
    if (child.state() != QProcess::NotRunning) {
      child.kill();
      child.waitForFinished(500);
      app.exit(3);
    }
  });
  return app.exec();
}
