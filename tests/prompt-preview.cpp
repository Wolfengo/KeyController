#define SSH_KEYS_UI_TEST
#include "../ui/prompt.cpp"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonParseError>
#include <QPixmap>
#include <cstdio>
#include <functional>
#include <memory>

// Disposable visual fixture: the only peer is an in-process socketpair.
// No helper, SSH agent, key file, PAM service or fingerprint reader is used.
class Preview final : public QObject {
public:
  explicit Preview(QApplication &application, const QString &output,
                   bool fullscreen)
      : app(application), output(output) {
    if (!QDir().mkpath(output)) {
      fail("cannot create output directory");
      return;
    }
    int sockets[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets)) {
      fail("cannot create fixture socketpair");
      return;
    }
    peer = sockets[1];
    prompt = std::make_unique<Prompt>(sockets[0]);
    app.setQuitOnLastWindowClosed(false);
    connect(prompt.get(), &QDialog::finished, this, [this] {
      if (!finished) fail("prompt closed before all visual states were captured");
    });

    if (fullscreen) {
      backdrop = std::make_unique<QWidget>();
      backdrop->setWindowTitle(QStringLiteral("KeyController — тестовый полноэкранный фон"));
      backdrop->setStyleSheet(QStringLiteral("background: #203343; color: #ffffff;"));
      auto *layout = new QVBoxLayout(backdrop.get());
      auto *caption = new QLabel(QStringLiteral("Тестовый полноэкранный фон\nОкно закроется автоматически"), backdrop.get());
      caption->setAlignment(Qt::AlignCenter);
      layout->addWidget(caption);
      backdrop->showFullScreen();
    }

    const auto previewOperation = qEnvironmentVariable("SSH_KEYS_PROMPT_PREVIEW_OPERATION");
    fingerprint = previewOperation == QStringLiteral("fingerprint");
    if (previewOperation == "settings.global" || previewOperation == "settings.key")
      policyOperation = previewOperation;
    QTimer::singleShot(450, this, [this] {
      QJsonObject job{{"operation", fingerprint ? "unlock" : "sync"},
               {"key", QJsonObject{{"name", QStringLiteral("Production")},
                                   {"path", "/test/.ssh/key"},
                                   {"fingerprint", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}},
               {"rules", QJsonObject{{"lifetime_seconds", 1800}}},
               {"bound", fingerprint},
               {"fingerprint_mode", fingerprint},
               {"caller", "/usr/lib/ssh-keys/panel-client (PID 1234)"},
               {"reason", QStringLiteral("Request from KeyController")}};
      if (!policyOperation.isEmpty()) {
        job["operation"] = policyOperation;
        if (policyOperation == "settings.global") {
          job["key"] = QJsonValue(QJsonValue::Null);
          job["value"] = QJsonObject{{"lifetime_seconds", 60}, {"revoke_on_sleep", true}};
        } else job["value"] = QJsonObject{{"inherits", true}, {"lifetime_seconds", 3600},
                                          {"global_lifetime_seconds", 3600}};
      }
      message(job);
      next();
    });
    QTimer::singleShot(12000, this, [this] { fail("visual fixture timed out"); });
  }

  ~Preview() override {
    finished = true;
    prompt.reset();
    if (peer >= 0) ::close(peer);
  }

private:
  QApplication &app;
  QString output;
  int peer = -1;
  int phase = 0;
  bool finished = false, fingerprint = false;
  QString policyOperation;
  QJsonArray captures;
  std::unique_ptr<Prompt> prompt;
  std::unique_ptr<QWidget> backdrop;
  const QString sample = QStringLiteral("preview-only-not-a-real-key-secret");

  void fail(const char *reason) {
    if (finished) return;
    finished = true;
    std::fprintf(stderr, "PROMPT_PREVIEW_FAILED %s\n", reason);
    std::fflush(stderr);
    if (prompt) prompt->reject();
    if (backdrop) backdrop->close();
    QTimer::singleShot(0, &app, [this] { app.exit(1); });
  }

  template<typename T> T *control(const char *name) {
    auto *result = prompt->findChild<T *>(QString::fromLatin1(name));
    if (!result) fail("expected prompt control is missing");
    return result;
  }

  bool message(const QJsonObject &object) {
    auto packet = QJsonDocument(object).toJson(QJsonDocument::Compact) + '\n';
    qsizetype offset = 0;
    while (offset < packet.size()) {
      const auto count = ::send(peer, packet.constData() + offset,
                                packet.size() - offset, MSG_NOSIGNAL);
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) { fail("cannot deliver fixture message"); return false; }
      offset += count;
    }
    return true;
  }

  bool noReply() {
    char buffer[64];
    const auto count = ::recv(peer, buffer, sizeof(buffer), MSG_DONTWAIT);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
    fail("prompt sent a reply before the simulated user submitted");
    return false;
  }

  bool validateReply() {
    QByteArray packet;
    char buffer[4096];
    while (!packet.contains('\n')) {
      const auto count = ::recv(peer, buffer, sizeof(buffer), MSG_DONTWAIT);
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) { fail("missing local consent reply"); return false; }
      packet.append(buffer, count);
      if (packet.size() > 8192) { fail("oversized local consent reply"); return false; }
    }
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(packet, &error);
    auto expected = QJsonObject{{"consent", true}, {"mode", fingerprint ? "fingerprint" : "password"},
                                     {"passphrase", fingerprint ? QString() : sample}, {"confirmation", ""}};
    if (!policyOperation.isEmpty()) {
      const auto value = policyOperation == "settings.global"
          ? QJsonObject{{"lifetime_seconds", 900}, {"revoke_on_sleep", true}}
          : QJsonObject{{"inherits", false}, {"lifetime_seconds", 900}};
      expected = QJsonObject{{"consent", true}, {"mode", "settings"}, {"passphrase", ""},
                             {"confirmation", ""}, {"value", value}};
    }
    const bool valid = error.error == QJsonParseError::NoError &&
                       document.isObject() && document.object() == expected;
    packet.fill('\0');
    if (!valid) fail("unexpected local consent payload");
    return valid;
  }

  bool capture(const QString &name) {
    if (!prompt->isVisible() || prompt->width() <= 0 || prompt->height() <= 0) {
      fail("prompt is not visible or has invalid dimensions");
      return false;
    }
    if (!prompt->grab().save(QDir(output).filePath(name + ".png"))) {
      fail("cannot save visual capture");
      return false;
    }
    QJsonObject record{{"phase", name}, {"pid", QCoreApplication::applicationPid()},
                       {"width", prompt->width()}, {"height", prompt->height()},
                       {"dpr", prompt->devicePixelRatioF()},
                       {"fullscreen_backdrop", bool(backdrop)}};
    if (const auto *screen = prompt->screen()) {
      const auto geometry = screen->geometry();
      record.insert("screen", screen->name());
      record.insert("screen_geometry", QJsonObject{{"x", geometry.x()}, {"y", geometry.y()},
                                                   {"width", geometry.width()}, {"height", geometry.height()}});
    }
    QJsonArray widgets;
    for (auto *widget : prompt->findChildren<QWidget *>()) {
      if (!widget->isVisible() || widget->objectName().isEmpty()) continue;
      const QRect r = widget->geometry();
      widgets.append(QJsonObject{{"name", widget->objectName()}, {"x", r.x()}, {"y", r.y()},
        {"width", r.width()}, {"height", r.height()}, {"hint_height", widget->sizeHint().height()},
        {"height_for_width", widget->heightForWidth(r.width())}});
    }
    record.insert("widgets", widgets);
    captures.append(record);
    QFile manifest(QDir(output).filePath("preview.json"));
    if (!manifest.open(QIODevice::WriteOnly) ||
        manifest.write(QJsonDocument(captures).toJson()) < 0) {
      fail("cannot save capture metadata");
      return false;
    }
    manifest.close();
    const auto metadata = QJsonDocument(record).toJson(QJsonDocument::Compact);
    std::fprintf(stdout, "PREVIEW_CAPTURE %s\n", metadata.constData());
    std::fflush(stdout);
    return true;
  }

  void next() { QTimer::singleShot(800, this, [this] { advance(); }); }

  // Leave the captured state on screen long enough for a separate read-only
  // driver to inspect Hyprland's layer geometry before the next transition.
  void afterCapture(std::function<bool()> transition) {
    QTimer::singleShot(400, this, [this, transition] {
      if (finished || !transition()) return;
      ++phase;
      next();
    });
  }

  void finishPreview() {
    QTimer::singleShot(400, this, [this] {
      if (finished) return;
      finished = true;
      prompt->reject();
      if (backdrop) backdrop->close();
      std::fputs("SSH_KEYS_PROMPT_PREVIEW_OK local fixture only\n", stdout);
      std::fflush(stdout);
      app.exit(0);
    });
  }

  bool hasStatus(const QLabel *label, PromptI18n::Message message) const {
    return label->text() == PromptI18n::translate(PromptI18n::languageFromEnvironment(), message);
  }

  void advanceFingerprint() {
    auto *proceed = control<QPushButton>("consent");
    auto *password = control<QLineEdit>("passphrase");
    auto *status = control<QLabel>("status");
    if (finished) return;
    if (proceed->isVisible() || password->isVisible() || proceed->isEnabled()) {
      fail("fingerprint prompt is not in automatic progress state"); return;
    }
    if (phase == 0) {
      if (!validateReply() || !capture("initial")) return;
      afterCapture([this] { return message({{"state", "progress"}, {"phase", "fingerprint_waiting"}}); });
    } else if (phase == 1) {
      if (!hasStatus(status, PromptI18n::Message::FingerprintWaiting) || !noReply() || !capture("fingerprint")) return;
      afterCapture([this] { return message({{"state", "progress"}, {"phase", "fingerprint_retry"}}); });
    } else if (phase == 2) {
      if (!hasStatus(status, PromptI18n::Message::FingerprintRetry) || !noReply() || !capture("retry")) return;
      afterCapture([this] { return message({{"state", "progress"}, {"phase", "credential_decrypting"}}); });
    } else if (phase == 3) {
      if (!hasStatus(status, PromptI18n::Message::FingerprintVerified) || !noReply() || !capture("confirmed")) return;
      afterCapture([this] { return message({{"state", "progress"}, {"phase", "key_loading"}}); });
    } else if (phase == 4) {
      if (!hasStatus(status, PromptI18n::Message::KeyLoading) || !noReply() || !capture("loading")) return;
      afterCapture([this] { return message({{"state", "failed"}, {"error_code", "unlock_failed"}}); });
    } else {
      if (!hasStatus(status, PromptI18n::Message::UnlockFailed) || !capture("error")) return;
      finishPreview();
    }
  }

  void advance() {
    if (finished) return;
    if (!policyOperation.isEmpty()) {
      if (phase == 0) {
        if (!noReply() || !capture("initial")) return;
        afterCapture([this] {
          if (policyOperation == "settings.global") control<QCheckBox>("policy-sleep")->setChecked(true);
          else control<QCheckBox>("policy-inherit")->setChecked(false);
          auto *preset = control<QComboBox>("policy-lifetime");
          preset->setCurrentIndex(preset->findData(900));
          return true;
        });
      } else {
        if (!noReply() || !capture("edited")) return;
        control<QPushButton>("consent")->click();
        if (!validateReply()) return;
        finishPreview();
      }
      return;
    }
    if (fingerprint) { advanceFingerprint(); return; }
    auto *proceed = control<QPushButton>("consent");
    auto *password = control<QLineEdit>("passphrase");
    auto *confirmation = control<QLineEdit>("confirmation");
    auto *status = control<QLabel>("status");
    if (finished) return;
    if (phase == 0) {
      if (!proceed->isEnabled() || password->isVisible() || confirmation->isVisible()) {
        fail("invalid initial consent state"); return;
      }
      if (!noReply() || !capture("initial")) return;
      afterCapture([proceed] { proceed->click(); return true; });
    } else if (phase == 1) {
      if (!password->isVisible() || confirmation->isVisible() ||
          password->echoMode() != QLineEdit::Password || !noReply()) {
        fail("invalid password-entry state"); return;
      }
      password->setText(sample);
      if (!capture("password")) return;
      afterCapture([this, proceed, password] {
        proceed->click();
        if (!validateReply()) return false;
        if (!password->text().isEmpty() || password->isVisible()) {
          fail("submitted test password was not cleared and hidden"); return false;
        }
        return message({{"state", "progress"}, {"phase", "fingerprint_waiting"}});
      });
    } else if (phase == 2) {
      if (proceed->isEnabled() || password->isVisible() ||
          !hasStatus(status, PromptI18n::Message::FingerprintWaiting)) {
        fail("invalid fingerprint-progress state"); return;
      }
      if (!capture("fingerprint")) return;
      afterCapture([this] { return message({{"state", "failed"}, {"error_code", "biometric_denied"}}); });
    } else {
      if (proceed->isEnabled() || password->isVisible() ||
          !hasStatus(status, PromptI18n::Message::FingerprintDenied)) {
        fail("invalid error state"); return;
      }
      if (!capture("error")) return;
      finishPreview();
      return;
    }
  }
};

int main(int argc, char **argv) {
  if (!configureSecretInput()) return 1;
  QApplication app(argc, argv);
  app.setApplicationName(QStringLiteral("KeyController Preview"));
  app.setDesktopFileName(QStringLiteral("org.omarchy.keycontroller.prompt-preview"));
  const auto output = qEnvironmentVariable("SSH_KEYS_PROMPT_PREVIEW_OUTPUT");
  if (output.isEmpty()) {
    std::fputs("Set SSH_KEYS_PROMPT_PREVIEW_OUTPUT to a capture directory.\n", stderr);
    return 2;
  }
  const bool fullscreen = qEnvironmentVariableIntValue("SSH_KEYS_PROMPT_PREVIEW_FULLSCREEN") != 0 ||
                          app.arguments().contains(QStringLiteral("--fullscreen"));
  Preview preview(app, QDir(output).absolutePath(), fullscreen);
  return app.exec();
}
