#define SSH_KEYS_UI_TEST
#include "../ui/prompt.cpp"
#include "../ui/prompt_theme.h"
#include <QAccessible>
#include <QClipboard>
#include <QElapsedTimer>
#include <QExposeEvent>
#include <QFileInfo>
#include <QInputMethod>
#include <QStyle>
#include <QScreen>
#include <QRadioButton>
#include <QTemporaryDir>
#include <QTest>
#include <cassert>
#include <cstdio>
#include <memory>
#include <functional>

namespace {
QJsonObject job(const QString &operation = QStringLiteral("unlock"),
                bool bound = true) {
  return {{"operation", operation},
          {"key", QJsonObject{{"name", "disposable test key"},
                              {"path", "/test/.ssh/key"},
                              {"fingerprint", "SHA256:disposable"}}},
          {"rules", QJsonObject{{"lifetime_seconds", 1800}}},
          {"bound", bound},
          {"fingerprint_mode", bound},
          {"caller", "test fixture"},
          {"reason", "test consent only"}};
}

struct Fixture {
  int peer = -1;
  std::unique_ptr<Prompt> prompt;
  explicit Fixture(bool showInitially = true) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    peer = sockets[1];
    prompt = std::make_unique<Prompt>(sockets[0]);
    if (showInitially) prompt->show();
  }
  ~Fixture() {
    prompt.reset();
    if (peer >= 0)
      close(peer);
  }
  template <typename T> T *control(const char *name) {
    auto *widget = prompt->findChild<T *>(QString::fromLatin1(name));
    assert(widget);
    return widget;
  }
  void raw(QByteArray message, bool allowClosed = false) {
    static int sequence = 0;
    ++sequence;
    message.append('\n');
    qsizetype position = 0;
    while (position < message.size()) {
      const auto count = ::send(peer, message.constData() + position,
                                message.size() - position, MSG_NOSIGNAL);
      if (allowClosed && count < 0 && errno == EPIPE)
        return;
      if (count <= 0)
        std::fprintf(stderr, "Prompt fixture frame %d failed: fd=%d errno=%d\n",
                     sequence, peer, errno);
      assert(count > 0);
      position += count;
    }
    QTest::qWait(25);
  }
  void message(const QJsonObject &object, bool allowClosed = false) {
    raw(QJsonDocument(object).toJson(QJsonDocument::Compact), allowClosed);
  }
  void noReply(bool allowClosed = false) {
    char data[8192];
    const auto count = recv(peer, data, sizeof(data), MSG_DONTWAIT);
    assert((count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) ||
           (allowClosed && count == 0));
  }
  QJsonObject reply() {
    char data[8192];
    const auto count = recv(peer, data, sizeof(data), MSG_DONTWAIT);
    assert(count > 0);
    const QByteArray packet(data, count);
    assert(packet.endsWith('\n') && packet.count('\n') == 1);
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(packet, &error);
    assert(error.error == QJsonParseError::NoError && document.isObject());
    return document.object();
  }
  void click(const char *name) {
    auto *button = control<QPushButton>(name);
    QTest::mouseClick(button, Qt::LeftButton, Qt::NoModifier,
                      button->rect().center());
  }
  void noModeSelector() {
    assert(prompt->findChildren<QRadioButton *>().isEmpty());
    assert(!prompt->findChild<QWidget *>("fingerprint-mode"));
    assert(!prompt->findChild<QWidget *>("password-mode"));
  }
  void secretsHiddenAndEmpty() {
    for (const char *name : {"passphrase", "confirmation"}) {
      auto *field = control<QLineEdit>(name);
      assert(!field->isVisible() && field->text().isEmpty());
      assert(field->echoMode() == QLineEdit::Password);
      assert(field->contextMenuPolicy() == Qt::NoContextMenu);
    }
  }
  void compact() {
    QTest::qWait(10);
    assert(prompt->maximumWidth() <= 560);
    assert(prompt->width() > 0 && prompt->width() <= prompt->maximumWidth());
    assert(prompt->screen() &&
           prompt->height() <= prompt->screen()->availableGeometry().height());
    const auto *scroll = prompt->findChild<QScrollArea *>();
    if (scroll && scroll->widget()->width() > scroll->viewport()->width())
      std::fprintf(stderr, "Prompt layout overflow: dialog=%dx%d body=%d viewport=%d\n",
          prompt->width(), prompt->height(), scroll->widget()->width(), scroll->viewport()->width());
    assert(scroll && scroll->widget()->width() <= scroll->viewport()->width());
    for (auto *label : prompt->findChildren<QLabel *>())
      assert(label->textFormat() == Qt::PlainText);
  }
};

void secretFieldsRejectInputMethodQueriesAndPreserveTyping() {
  {
    // Positive control: Qt's meta-object query must actually reach the focused
    // widget, otherwise an empty query could give a false sense of protection.
    QLineEdit ordinary;
    ordinary.setEchoMode(QLineEdit::Password);
    ordinary.setInputMethodHints(Qt::ImhHiddenText | Qt::ImhSensitiveData |
                                 Qt::ImhNoPredictiveText);
    ordinary.setText("disposable-control");
    ordinary.show();
    ordinary.setFocus();
    QTest::qWait(25);
    assert(ordinary.hasFocus());
    assert(QInputMethod::queryFocusObject(Qt::ImSurroundingText, 4096).toString()
           == QStringLiteral("disposable-control"));
  }
  for (const auto &operation : {QStringLiteral("unlock"), QStringLiteral("sync"),
                                QStringLiteral("encrypt")}) {
    Fixture test;
    test.message(job(operation, false));
    if (operation != QStringLiteral("unlock")) test.click("consent");
    for (const char *name : {"passphrase", "confirmation"}) {
      auto *field = test.control<QLineEdit>(name);
      if (!field->isVisible()) continue;
      field->setFocus();
      QTest::keyClicks(field, "disposable-");
      // Ordinary keyboard layouts deliver Unicode in key events; this does not
      // require sending surrounding text to an external input-method service.
      const QString unicode = QString::fromUtf8("пароль-é");
      QKeyEvent unicodeKey(QEvent::KeyPress, 0, Qt::NoModifier, unicode);
      QApplication::sendEvent(field, &unicodeKey);
      const QString expected = QStringLiteral("disposable-") + unicode;
      assert(field->text() == expected);
      field->selectAll();
      assert(field->hasFocus());
      assert(field->style()->styleHint(QStyle::SH_LineEdit_PasswordMaskDelay, nullptr, field) == 0);
      for (const auto query : {Qt::ImSurroundingText, Qt::ImCurrentSelection,
                              Qt::ImTextBeforeCursor, Qt::ImTextAfterCursor}) {
        assert(field->inputMethodQuery(query).toString().isEmpty());
        assert(QInputMethod::queryFocusObject(query, 4096).toString().isEmpty());
        auto *secretField = static_cast<SecretLineEdit *>(field);
        assert(secretField->inputMethodQuery(query, 4096).toString().isEmpty());
      }
      for (const auto queries : {Qt::ImQueryAll, Qt::ImQueryInput}) {
        QInputMethodQueryEvent query(queries);
        QApplication::sendEvent(field, &query);
        assert(query.isAccepted() && query.value(Qt::ImEnabled).toBool());
        for (const auto text : {Qt::ImSurroundingText, Qt::ImCurrentSelection,
                                Qt::ImTextBeforeCursor, Qt::ImTextAfterCursor})
          assert(query.value(text).toString().isEmpty());
        assert(!query.value(Qt::ImCursorPosition).isValid());
        assert(!query.value(Qt::ImAnchorPosition).isValid());
      }
      assert(field->text() == expected);
      test.noReply();
    }
    test.click("cancel");
    assert(!test.reply().value("consent").toBool());
    test.secretsHiddenAndEmpty();
  }
}

void passwordCharactersAreMaskedEvenWhenParentStyleRequestsDelay() {
  QWidget container;
  container.setStyleSheet(QStringLiteral("QLineEdit { lineedit-password-mask-delay: 1000; }"));
  QLineEdit ordinary(&container);
  SecretLineEdit protectedField(&container);
  ordinary.setEchoMode(QLineEdit::Password);
  protectedField.setEchoMode(QLineEdit::Password);
  ordinary.setGeometry(0, 0, 200, 30);
  protectedField.setGeometry(0, 40, 200, 30);
  container.resize(200, 80);
  container.show();
  QTest::qWait(25);
  ordinary.setFocus();
  QTest::keyClicks(&ordinary, "z");
  assert(ordinary.style()->styleHint(QStyle::SH_LineEdit_PasswordMaskDelay, nullptr, &ordinary) == 1000);
  assert(ordinary.displayText() == QStringLiteral("z"));
  protectedField.setFocus();
  QTest::keyClicks(&protectedField, "z");
  assert(protectedField.text() == QStringLiteral("z"));
  assert(protectedField.style()->styleHint(QStyle::SH_LineEdit_PasswordMaskDelay, nullptr, &protectedField) == 0);
  assert(protectedField.displayText() != QStringLiteral("z"));
}

void fingerprintStartsAfterExposureOnlyOnceAndCanBeCancelled() {
  Fixture test(false);
  test.message(job());
  test.noModeSelector();
  test.secretsHiddenAndEmpty();
  assert(test.prompt->isVisible() && test.prompt->windowHandle()->isExposed());
  assert(!test.control<QPushButton>("consent")->isVisible());
  const auto answer = test.reply();
  assert((answer == QJsonObject{{"consent", true}, {"mode", "fingerprint"},
                               {"passphrase", ""}, {"confirmation", ""}}));
  // A remap, repeated exposure, Enter and a stale click must not reauthorize.
  test.prompt->hide();
  test.prompt->show();
  QExposeEvent exposure(QRegion(test.prompt->rect()));
  QCoreApplication::sendEvent(test.prompt->windowHandle(), &exposure);
  QTest::keyClick(test.prompt.get(), Qt::Key_Return);
  test.control<QPushButton>("consent")->click();
  QTest::qWait(25);
  test.noReply();
  test.click("cancel");
  assert((test.reply() == QJsonObject{{"cancel", true}}));
  test.prompt->reject();
  test.noReply();
}

struct BeforeExposure final : QObject {
  std::function<void()> action;
  bool observed = false;
  explicit BeforeExposure(std::function<void()> action) : action(std::move(action)) {}
  bool eventFilter(QObject *, QEvent *event) override {
    if (!observed && event->type() == QEvent::Show) {
      observed = true;
      action();
    }
    return false;
  }
};

void fingerprintDoesNotStartAfterEarlyCancellationEofOrTerminalFrame() {
  {
    Fixture test(false);
    BeforeExposure cancel([&test] { test.noReply(); test.prompt->reject(); });
    test.prompt->installEventFilter(&cancel);
    test.message(job());
    assert(cancel.observed);
    assert(!test.reply().value("consent").toBool());
    QTest::qWait(25);
    test.noReply();
  }
  {
    Fixture test(false);
    BeforeExposure eof([&test] { test.noReply(); close(test.peer); test.peer = -1; });
    test.prompt->installEventFilter(&eof);
    test.message(job());
    assert(eof.observed);
    assert(!test.control<QPushButton>("consent")->isEnabled() || !test.prompt->isVisible());
    test.secretsHiddenAndEmpty();
  }
  {
    Fixture test(false);
    BeforeExposure terminal([&test] {
      test.noReply();
      const QByteArray first("{\"state\":\"err");
      assert(::send(test.peer, first.constData(), first.size(), MSG_NOSIGNAL) == first.size());
      QTimer::singleShot(0, test.prompt.get(), [&test] {
        const QByteArray rest("or\",\"error_code\":\"cancelled\"}\n");
        assert(::send(test.peer, rest.constData(), rest.size(), MSG_NOSIGNAL) == rest.size());
      });
    });
    test.prompt->installEventFilter(&terminal);
    test.message(job());
    assert(terminal.observed);
    test.noReply();
    QTest::qWait(25);
    test.noReply();
    assert(!test.control<QPushButton>("consent")->isEnabled());
  }
  for (const auto *state : {"error", "completed"}) {
    Fixture test(false);
    const QByteArray initial = QJsonDocument(job()).toJson(QJsonDocument::Compact);
    const QByteArray terminal = QJsonDocument(QJsonObject{{"state", state},
        {"error_code", "cancelled"}}).toJson(QJsonDocument::Compact);
    test.raw(initial + '\n' + terminal);
    test.noReply();
    QTest::qWait(25);
    test.noReply();
    test.secretsHiddenAndEmpty();
    assert(!test.control<QPushButton>("consent")->isEnabled());
  }
}

void compactUnlockRetainsIdentityAndRequestProvenance() {
  Fixture test(false);
  auto request = job();
  const QString fingerprint = QStringLiteral("SHA256:") + QString(43, 'W');
  auto key = request.value("key").toObject();
  key["fingerprint"] = fingerprint;
  request["key"] = key;
  request["caller"] = "/usr/lib/ssh-keys/panel-client (PID 1234)";
  request["reason"] = QStringLiteral("Запрос из панели KeyController");
  test.message(request);
  assert(test.reply().value("mode") == "fingerprint");
  const auto description = test.control<QLabel>("request-details")->text();
  assert(description == QStringLiteral("Запрос через: panel-client\nЗапрос из панели KeyController"));
  assert(test.control<QLabel>("metadata")->isVisible());
  const auto *identity = test.control<QLabel>("metadata");
  assert(QString(identity->text()).remove('\n').contains(fingerprint));
  for (const auto &line : identity->text().split('\n')) {
    if (line.contains(QStringLiteral("Срок доступа:"))) break;
    assert(identity->fontMetrics().horizontalAdvance(line) <= identity->width());
  }
  assert(test.control<QLabel>("metadata")->text().contains(QStringLiteral("Срок доступа: 30 мин")));
  assert(!test.control<QLabel>("details")->isVisible());
  test.click("details-toggle");
  const auto details = test.control<QLabel>("details")->text();
  assert(details.contains(fingerprint) && details.contains("/test/.ssh/key"));
  assert(details.contains(QStringLiteral("Срок доступа: 30 мин")));
  assert(details.contains("/usr/lib/ssh-keys/panel-client (PID 1234)"));
  test.compact();
  assert(test.prompt->width() == 340);
}

void encryptionRequiresMatchingNonemptyConfirmation() {
  Fixture test;
  test.message(job("encrypt"));
  test.secretsHiddenAndEmpty();
  test.click("consent");
  test.noReply();
  auto *pass = test.control<QLineEdit>("passphrase");
  auto *confirm = test.control<QLineEdit>("confirmation");
  assert(pass->isVisible() && confirm->isVisible());
  test.click("consent");
  test.noReply();
  pass->setText("example-only");
  confirm->setText("different");
  test.click("consent");
  test.noReply();
  confirm->setText("example-only");
  test.click("consent");
  const auto answer = test.reply();
  assert(answer.value("consent").toBool());
  assert(answer.value("mode").toString() == "password");
  assert(answer.value("passphrase").toString() == "example-only");
  assert(answer.value("confirmation").toString() == "example-only");
  test.secretsHiddenAndEmpty();
}

void passwordUnlockUsesSavedModeAndSubmitsDirectlyOnce() {
  struct Case { bool bound; bool savedFingerprint; };
  for (const auto &scenario : {Case{true, false}, Case{false, false}, Case{false, true}}) {
    // Cover pointer submission and both physical Enter keys. No direct submit
    // call or signal invocation may bypass Qt's focus/key-event behavior.
    for (const int input : {0, 1, 2}) {
      Fixture test;
      auto request = job("unlock", scenario.bound);
      request["fingerprint_mode"] = scenario.savedFingerprint;
      test.message(request);
      test.noModeSelector();
      auto *pass = test.control<QLineEdit>("passphrase");
      auto *confirm = test.control<QLineEdit>("confirmation");
      assert(pass->isVisible() && pass->hasFocus() && pass->text().isEmpty());
      assert(pass->echoMode() == QLineEdit::Password);
      assert(!confirm->isVisible());
      assert(test.control<QPushButton>("consent")->text() == QStringLiteral("Разблокировать"));
      assert(test.control<QLabel>("subtitle")->text() == QStringLiteral("Разблокировка паролем"));
      test.noReply();
      QTest::keyClick(pass, Qt::Key_Return);
      test.noReply();
      QTest::keyClick(pass, Qt::Key_Enter);
      test.noReply();
      test.click("consent");
      test.noReply();
      pass->setFocus();
      QTest::keyClicks(pass, "disposable-password-only");
      test.noReply();
      if (input == 0) test.click("consent");
      else QTest::keyClick(pass, input == 1 ? Qt::Key_Return : Qt::Key_Enter);
      assert((test.reply() == QJsonObject{{"consent", true}, {"mode", "password"},
          {"passphrase", "disposable-password-only"}, {"confirmation", ""}}));
      test.secretsHiddenAndEmpty();
      assert(!test.control<QPushButton>("consent")->isEnabled());
      test.click("consent");
      QTest::keyClick(pass, Qt::Key_Return);
      QTest::keyClick(pass, Qt::Key_Enter);
      test.noReply();
      test.click("cancel");
      assert((test.reply() == QJsonObject{{"cancel", true}}));
      test.prompt->reject();
      test.noReply();
    }
  }
}

void syncConsentPasswordFingerprintProgressAndCancellation() {
  Fixture test;
  test.message(job("sync"));
  test.noReply();
  test.secretsHiddenAndEmpty();
  test.noModeSelector();
  for (const auto *name : {"step-password", "step-fingerprint"}) {
    auto *step = test.control<QLabel>(name);
    assert(step->isVisible());
    assert(step->width() >=
           step->fontMetrics().horizontalAdvance(step->text()));
  }
  assert(test.control<QLabel>("step-password")->isEnabled());
  assert(!test.control<QLabel>("step-fingerprint")->isEnabled());
  test.click("consent");
  test.noReply();
  auto *pass = test.control<QLineEdit>("passphrase");
  assert(pass->isVisible());
  assert(!test.control<QLineEdit>("confirmation")->isVisible());
  test.click("consent");
  test.noReply();
  pass->setText("sync-test-only");
  test.click("consent");
  const auto answer = test.reply();
  assert(answer.value("consent").toBool());
  assert(answer.value("mode").toString() == "password");
  assert(answer.value("passphrase").toString() == "sync-test-only");
  assert(answer.value("confirmation").toString().isEmpty());
  test.secretsHiddenAndEmpty();
  test.message({{"state", "fingerprint"}});
  assert(test.control<QLabel>("status")->text().contains(QStringLiteral("Подключение")));
  test.message({{"state", "progress"}, {"phase", "fingerprint_waiting"}});
  assert(!test.control<QLabel>("step-password")->isEnabled());
  assert(test.control<QLabel>("step-fingerprint")->isEnabled());
  assert(!test.control<QPushButton>("consent")->isEnabled());
  const auto status = test.control<QLabel>("status")->text();
  assert(status.contains(QStringLiteral("пал")) ||
         status.contains(QStringLiteral("отпечат")));
  test.secretsHiddenAndEmpty();
  test.noReply();
  test.click("cancel");
  assert((test.reply() == QJsonObject{{"cancel", true}}));
  test.prompt->reject();
  test.noReply();
}

BusyIndicator *indicator(Fixture &test) {
  return static_cast<BusyIndicator *>(test.control<QWidget>("progress-indicator"));
}

void progressRemainsAnimatedAndNeverRestartsAuthentication() {
  Fixture test(false);
  test.message(job());
  assert(test.reply().value("mode") == "fingerprint");
  auto *busy = indicator(test);
  auto *status = test.control<QLabel>("status");
  assert(busy->isRunning() && busy->isVisible());
  assert(status->text().contains(QStringLiteral("Подключение")));
  assert(status->palette().color(QPalette::WindowText) == PromptTheme::load().foreground);
  const QImage before = busy->grab().toImage();
  QTest::qWait(80);
  assert(before != busy->grab().toImage());
  const QSize size = test.prompt->size();
  for (const auto *phase : {"fingerprint_starting", "fingerprint_waiting", "fingerprint_retry",
                            "fingerprint_waiting", "credential_decrypting", "key_loading"}) {
    test.message({{"state", "progress"}, {"phase", phase}});
    assert(busy->isRunning() && busy->isVisible() && !status->text().isEmpty());
    assert(test.prompt->size() == size);
    assert(!test.control<QPushButton>("consent")->isEnabled());
    assert(test.control<QPushButton>("cancel")->isEnabled());
    test.secretsHiddenAndEmpty();
    test.noReply();
  }
  const QString loading = status->text();
  assert(loading.contains(QStringLiteral("Загрузка")));
  for (const auto *phase : {"fingerprint_starting", "fingerprint_waiting", "fingerprint_retry",
                            "credential_decrypting", "file_encrypting", "credential_sealing",
                            "passphrase_verifying", "<b>unknown</b>", "key_loading"}) {
    test.message({{"state", "progress"}, {"phase", phase}});
    assert(status->text() == loading && busy->isRunning());
    test.noReply();
  }
  test.message({{"state", "fingerprint"}});
  assert(status->text() == loading);
  test.click("cancel");
  assert((test.reply() == QJsonObject{{"cancel", true}}));
  assert(!busy->isRunning());
  test.message({{"state", "progress"}, {"phase", "key_loading"}}, true);
  test.noReply(true);
}

void progressStopsAtEveryTerminalAndCanBeCancelledAtEachStage() {
  struct Flow { QString operation; bool fingerprint; QStringList phases; };
  const QList<Flow> flows{
    {"unlock", true, {"fingerprint_starting", "fingerprint_waiting", "fingerprint_retry", "credential_decrypting", "key_loading"}},
    {"unlock", false, {"key_loading"}},
    {"sync", false, {"passphrase_verifying", "fingerprint_starting", "fingerprint_waiting", "fingerprint_retry", "credential_sealing", "credential_verifying"}},
    {"encrypt", false, {"file_encrypting"}}};
  for (const auto &flow : flows) {
    for (qsizetype last = 0; last < flow.phases.size(); ++last) {
      Fixture test;
      test.message(job(flow.operation, flow.fingerprint));
      if (!flow.fingerprint) {
        assert(!indicator(test)->isRunning());
        const auto initial = test.control<QLabel>("status")->text();
        test.message({{"state", "progress"}, {"phase", flow.phases.first()}});
        assert(!indicator(test)->isRunning() && test.control<QLabel>("status")->text() == initial);
        if (flow.operation != "unlock") test.click("consent");
        test.control<QLineEdit>("passphrase")->setText("progress-fixture-only");
        if (flow.operation == "encrypt") test.control<QLineEdit>("confirmation")->setText("progress-fixture-only");
        test.click("consent");
      }
      assert(test.reply().value("consent").toBool());
      assert(indicator(test)->isRunning());
      for (qsizetype i = 0; i <= last; ++i) test.message({{"state", "progress"}, {"phase", flow.phases[i]}});
      assert(indicator(test)->isRunning());
      test.click("cancel");
      assert((test.reply() == QJsonObject{{"cancel", true}}));
      assert(!indicator(test)->isRunning());
      test.secretsHiddenAndEmpty();
      test.noReply();
    }
  }
  for (const auto *state : {"completed", "error"}) {
    Fixture test;
    test.message(job());
    test.reply();
    test.message({{"state", "progress"}, {"phase", "credential_decrypting"}});
    test.message({{"state", state}, {"error_code", "unlock_failed"}});
    const auto terminal = test.control<QLabel>("status")->text();
    assert(!indicator(test)->isRunning());
    test.message({{"state", "progress"}, {"phase", "key_loading"}}, true);
    assert(!indicator(test)->isRunning() && test.control<QLabel>("status")->text() == terminal);
    test.noReply(true);
  }
}

void cancellingBeforeSubmissionNeverSendsEnteredPassword() {
  for (const auto *operation : {"sync", "unlock"}) {
    Fixture test;
    test.message(job(operation, false));
    if (QString::fromLatin1(operation) == "sync") test.click("consent");
    auto *pass = test.control<QLineEdit>("passphrase");
    assert(pass->isVisible());
    QTest::keyClicks(pass, "do-not-send");
    test.click("cancel");
    const auto answer = test.reply();
    assert(!answer.value("consent").toBool());
    assert(answer.value("passphrase").toString().isEmpty());
    assert(answer.value("confirmation").toString().isEmpty());
    test.secretsHiddenAndEmpty();
    test.prompt->reject();
    test.noReply();
  }
}

void untrustedMetadataRemainsPlainTextAndCompact() {
  Fixture test;
  auto metadata = job("unlock", false);
  const QString markup =
      QStringLiteral("<b>untrusted</b><img src='file:///never-read'>");
  metadata["key"] =
      QJsonObject{{"name", markup},
                  {"path", "/test/" + markup + QString(4096, 'p')},
                  {"fingerprint", "SHA256:" + markup + QString(4096, 'f')}};
  metadata["caller"] = markup;
  metadata["reason"] = markup + QString(4096, 'r');
  test.message(metadata);
  assert(test.control<QLabel>("request-details")->text().contains(markup));
  assert(test.control<QLabel>("details")->text().contains(markup));
  test.compact();
  const int width = test.prompt->width();
  test.click("details-toggle");
  assert(test.control<QLabel>("details")->isVisible());
  test.compact();
  assert(test.prompt->width() == width);
  test.click("consent");
  test.compact();
  assert(test.prompt->width() == width);
  test.noReply();
  test.control<QLineEdit>("passphrase")->setText("example-only");
  test.click("consent");
  assert(test.reply().value("consent").toBool());
  test.message(
      {{"state", "error"}, {"error_code", markup + QString(4096, 'e')}});
  test.compact();
  assert(test.prompt->width() == width);
  assert(!test.control<QPushButton>("consent")->isEnabled());
  test.secretsHiddenAndEmpty();
  test.noReply(true);
}

void unknownAndMalformedMessagesCannotResumeAuthentication() {
  for (const QByteArray &payload :
       {QByteArray("[]"), QByteArray("{"), QByteArray("{}")}) {
    Fixture test;
    test.raw(payload);
    assert(!test.prompt->isVisible());
    assert(!test.control<QPushButton>("consent")->isEnabled());
    test.secretsHiddenAndEmpty();
    test.noReply(true);
  }
  {
    Fixture test;
    test.message(job("unknown-operation"));
    assert(!test.prompt->isVisible());
    assert(!test.control<QPushButton>("consent")->isEnabled());
    test.noReply(true);
  }
  {
    Fixture test;
    test.message(job("sync"));
    test.click("consent");
    test.control<QLineEdit>("passphrase")->setText("never-send-this");
    test.message(
        {{"state", "unrecognized-state"}, {"error_code", "<b>unknown</b>"}});
    assert(!test.control<QPushButton>("consent")->isEnabled());
    test.secretsHiddenAndEmpty();
    test.noReply(true);
    const auto terminalStatus = test.control<QLabel>("status")->text();
    test.message({{"state", "fingerprint"}}, true);
    test.message({{"state", "completed"}}, true);
    assert(!test.control<QPushButton>("consent")->isEnabled());
    assert(test.control<QLabel>("status")->text() == terminalStatus);
    test.secretsHiddenAndEmpty();
    test.noReply(true);
  }
}

void terminalBeforeSubmissionClearsPasswordAndCannotResumeAuthentication() {
  for (const auto *state : {"error", "completed"}) {
    Fixture test;
    test.message(job("unlock", false));
    auto *pass = test.control<QLineEdit>("passphrase");
    QTest::keyClicks(pass, "never-send-this");
    test.message({{"state", state}, {"error_code", "cancelled"}});
    test.secretsHiddenAndEmpty();
    test.noModeSelector();
    test.click("consent");
    QTest::keyClick(pass, Qt::Key_Return);
    QTest::keyClick(pass, Qt::Key_Enter);
    assert(!test.control<QPushButton>("consent")->isEnabled());
    test.noReply();
    // Late frames cannot replace the captured mode or restart the prompt.
    test.message(job("unlock", true), true);
    test.message({{"state", "fingerprint"}}, true);
    test.secretsHiddenAndEmpty();
    assert(!test.control<QPushButton>("consent")->isEnabled());
    test.noReply(true);
  }
}

void closedPeerClearsEnteredSecretsAndClosesPrompt() {
  for (const auto *operation : {"sync", "unlock"}) {
    Fixture test;
    test.message(job(operation, false));
    if (QString::fromLatin1(operation) == "sync") test.click("consent");
    test.control<QLineEdit>("passphrase")->setText("never-send-this");
    close(test.peer);
    test.peer = -1;
    QTest::qWait(25);
    assert(!test.prompt->isVisible());
    test.secretsHiddenAndEmpty();
  }
}

void settingsConfirmExactTargetsWithoutSecretFields() {
  struct Case { QString operation; QJsonValue value; QString description; };
  const QList<Case> cases{
      {"rules.key", QJsonObject{{"lifetime_seconds", 1800}}, QStringLiteral("30 мин")},
      {"rules.key", QJsonObject{{"lifetime_seconds", 0}}, QStringLiteral("без ограничения")},
      {"rules.key", QJsonObject{{"lifetime_seconds", 900}}, QStringLiteral("15 мин")},
      {"rules.key", QJsonValue(QJsonValue::Null), QStringLiteral("наследовать общие настройки")},
      {"unbind", QJsonValue(QJsonValue::Null), QStringLiteral("Удалить привязку отпечатка")}};
  for (const auto &scenario : cases) {
    Fixture test;
    auto request = job(scenario.operation);
    request["value"] = scenario.value;
    test.message(request);
    test.noReply();
    test.secretsHiddenAndEmpty();
    test.compact();
    const auto description = test.control<QLabel>("request-details")->text();
    assert(description.contains(scenario.description));
    assert(description.contains(QStringLiteral("Программа: test fixture")));
    test.noModeSelector();
    assert(!test.control<QLabel>("step-password")->isVisible());
    assert(!test.control<QLabel>("step-fingerprint")->isVisible());
    assert(test.control<QPushButton>("consent")->text() == QStringLiteral("Подтвердить"));
    test.click("consent");
    assert((test.reply() == QJsonObject{{"consent", true}, {"mode", "confirm"},
                                      {"passphrase", ""}, {"confirmation", ""}}));
    test.secretsHiddenAndEmpty();
    test.click("consent");
    test.noReply();
    // A confirmation operation never changes into password/biometric flow.
    test.message({{"state", "fingerprint"}});
    test.secretsHiddenAndEmpty();
    assert(!test.control<QLabel>("step-fingerprint")->isVisible());
    assert(!test.control<QPushButton>("consent")->isEnabled());
    test.noReply();
  }
}

void malformedSettingsTargetsFailClosedAndCancellationDoesNotApprove() {
  const QList<QJsonValue> invalidRules{
      QJsonObject{}, QJsonValue(true), QJsonValue(1800), QJsonValue("1800"),
      QJsonObject{{"lifetime_seconds", -1}}, QJsonObject{{"lifetime_seconds", 0.5}},
      QJsonObject{{"lifetime_seconds", 31536001}}, QJsonObject{{"lifetime_seconds", "1800"}},
      QJsonObject{{"lifetime_seconds", 1800}, {"extra", true}}};
  for (const auto &value : invalidRules) {
    Fixture test;
    auto request = job("rules.key");
    request["value"] = value;
    test.message(request);
    assert(!test.prompt->isVisible());
    assert(!test.control<QPushButton>("consent")->isEnabled());
    test.noReply(true);
  }
  for (const auto &key : {QJsonValue(QJsonValue::Null), QJsonValue(QJsonObject{}),
                          QJsonValue(QJsonObject{{"name", ""}})}) {
    Fixture test;
    auto request = job("rules.key");
    request["key"] = key;
    request["value"] = QJsonObject{{"lifetime_seconds", 1800}};
    test.message(request);
    assert(!test.prompt->isVisible() && !test.control<QPushButton>("consent")->isEnabled());
    test.noReply(true);
  }
  for (const auto &operation : {"rules.key", "unbind"}) {
    Fixture test;
    auto request = job(operation);
    request["value"] = QJsonValue(QJsonValue::Null);
    test.message(request);
    test.click("cancel");
    const auto answer = test.reply();
    assert(!answer.value("consent").toBool());
    assert(answer.value("passphrase").toString().isEmpty());
    assert(answer.value("confirmation").toString().isEmpty());
  }
  // Direct desktop actions must never open an authentication window, even
  // when an outdated peer still tries to deliver their former native job.
  for (const auto &operation : {"mode", "revoke", "rules.global"}) {
    Fixture test;
    auto request = job(operation);
    request["value"] = operation == QStringLiteral("mode")
        ? QJsonValue(QJsonObject{{"fingerprint_mode", true}})
        : operation == QStringLiteral("rules.global") ? QJsonValue(QJsonObject{{"lifetime_seconds", 1800}})
        : QJsonValue(QJsonValue::Null);
    if (operation == QStringLiteral("rules.global")) request["key"] = QJsonValue(QJsonValue::Null);
    test.message(request);
    assert(!test.prompt->isVisible());
    assert(!test.control<QPushButton>("consent")->isEnabled());
    assert(!indicator(test)->isRunning());
    test.secretsHiddenAndEmpty();
    test.click("consent");
    test.noReply(true);
    test.message({{"state", "progress"}, {"phase", "fingerprint_waiting"}}, true);
    assert(!test.prompt->isVisible() && !indicator(test)->isRunning());
    test.noReply(true);
  }
}

QJsonObject policyJob(bool global) {
  auto request = job(global ? "settings.global" : "settings.key");
  if (global) {
    request["key"] = QJsonValue(QJsonValue::Null);
    request["value"] = QJsonObject{{"lifetime_seconds", 1800}, {"revoke_on_sleep", false}};
  } else {
    request["value"] = QJsonObject{{"inherits", true}, {"lifetime_seconds", 1800},
                                    {"global_lifetime_seconds", 3600}};
  }
  return request;
}

void policyEditorSavesOnlyNativeSelectionsAndNeverAuthenticates() {
  for (const auto &language : {"ru", "en"}) {
    qputenv("SSH_KEYS_UI_LANGUAGE", language);
    for (bool global : {true, false}) {
      Fixture test(false);
      test.message(policyJob(global));
      test.noReply();
      test.secretsHiddenAndEmpty();
      test.compact();
      assert(!indicator(test)->isRunning());
      assert(test.control<QWidget>("policy-editor")->isVisible());
      assert(test.control<QPushButton>("consent")->text() ==
          (QByteArray(language) == "ru" ? QStringLiteral("Сохранить") : QStringLiteral("Save")));
      auto *preset = test.control<QComboBox>("policy-lifetime");
      auto *inherit = test.control<QCheckBox>("policy-inherit");
      auto *sleep = test.control<QCheckBox>("policy-sleep");
      assert(inherit->isVisible() == !global && sleep->isVisible() == global);
      if (!global) {
        assert(inherit->isChecked() && !preset->isEnabled());
        assert(test.control<QLabel>("policy-inherited-duration")->text().contains("1"));
        inherit->setChecked(false);
        assert(preset->isEnabled());
        assert(test.control<QLabel>("metadata")->isVisible());
        assert(test.control<QLabel>("metadata")->text().contains("SHA256:disposable"));
      } else sleep->setChecked(true);
      // Metadata/progress from the peer cannot authorize a policy or restart PAM.
      test.message({{"state", "progress"}, {"phase", "fingerprint_waiting"}});
      assert(!indicator(test)->isRunning());
      preset->setCurrentIndex(preset->findData(900));
      test.noReply();
      test.click("consent");
      const QJsonObject value = global
          ? QJsonObject{{"lifetime_seconds", 900}, {"revoke_on_sleep", true}}
          : QJsonObject{{"inherits", false}, {"lifetime_seconds", 900}};
      assert((test.reply() == QJsonObject{{"consent", true}, {"mode", "settings"},
          {"passphrase", ""}, {"confirmation", ""}, {"value", value}}));
      assert(!test.control<QWidget>("policy-editor")->isEnabled());
      test.click("consent");
      test.noReply();
      test.secretsHiddenAndEmpty();
      test.message({{"state", "completed"}});
      assert(!indicator(test)->isRunning());
      assert(test.control<QLabel>("status")->text() ==
          (QByteArray(language) == "ru" ? QStringLiteral("Изменения отправлены")
                                        : QStringLiteral("Changes submitted")));
      test.noReply(true);
    }
  }
  qputenv("SSH_KEYS_UI_LANGUAGE", "ru");
}

void policyEditorPreservesExactCustomDurationInheritanceAndCancellation() {
  for (int seconds : {0, 45, 31536000}) {
    for (bool inherited : {false, true}) {
      Fixture test;
      auto request = policyJob(false);
      request["value"] = QJsonObject{{"inherits", inherited}, {"lifetime_seconds", seconds},
                                     {"global_lifetime_seconds", 300}};
      test.message(request);
      test.noReply();
      auto *custom = test.control<QSpinBox>("policy-custom-seconds");
      assert(custom->isVisible() == (seconds != 0 && !inherited));
      if (seconds != 0) assert(custom->value() == seconds);
      test.compact();
      test.click("consent");
      assert((test.reply().value("value").toObject() ==
              QJsonObject{{"inherits", inherited}, {"lifetime_seconds", seconds}}));
    }
  }
  for (bool global : {true, false}) {
    Fixture test;
    test.message(policyJob(global));
    auto *preset = test.control<QComboBox>("policy-lifetime");
    if (!global) test.control<QCheckBox>("policy-inherit")->setChecked(false);
    preset->setCurrentIndex(preset->findData(-1));
    auto *custom = test.control<QSpinBox>("policy-custom-seconds");
    assert(custom->isVisible());
    custom->setValue(77);
    test.noReply();
    test.click("cancel");
    assert((test.reply() == QJsonObject{{"consent", false}, {"mode", ""},
                                      {"passphrase", ""}, {"confirmation", ""}}));
    assert(!test.prompt->isVisible());
  }
  {
    Fixture test;
    test.message(policyJob(false));
    test.control<QCheckBox>("policy-inherit")->setChecked(false);
    auto *preset = test.control<QComboBox>("policy-lifetime");
    preset->setCurrentIndex(preset->findData(-1));
    test.control<QSpinBox>("policy-custom-seconds")->setValue(77);
    test.click("consent");
    assert((test.reply().value("value").toObject() ==
            QJsonObject{{"inherits", false}, {"lifetime_seconds", 77}}));
  }
}

void policyEditorRejectsMalformedSnapshotsAndLateReplacement() {
  for (bool global : {true, false}) {
    auto valid = policyJob(global);
    QList<QJsonValue> invalid{QJsonValue(QJsonValue::Null), true, "policy", QJsonObject{}};
    for (const auto &seconds : {QJsonValue(-1), QJsonValue(0.5), QJsonValue(31536001), QJsonValue("900")}) {
      auto value = valid.value("value").toObject();
      value["lifetime_seconds"] = seconds;
      invalid.append(value);
    }
    auto unknown = valid.value("value").toObject();
    unknown["unknown"] = true;
    invalid.append(unknown);
    auto invalidBool = valid.value("value").toObject();
    invalidBool[global ? "revoke_on_sleep" : "inherits"] = "true";
    invalid.append(invalidBool);
    if (!global) {
      auto invalidGeneral = valid.value("value").toObject();
      invalidGeneral["global_lifetime_seconds"] = -1;
      invalid.append(invalidGeneral);
    }
    for (const auto &value : invalid) {
      Fixture test;
      auto request = valid;
      request["value"] = value;
      test.message(request);
      assert(!test.prompt->isVisible());
      test.click("consent");
      test.noReply(true);
      test.secretsHiddenAndEmpty();
    }
    {
      Fixture test;
      auto request = valid;
      request["key"] = global ? QJsonValue(QJsonObject{{"name", "extra key"}})
                               : QJsonValue(QJsonValue::Null);
      test.message(request);
      assert(!test.prompt->isVisible());
      test.noReply(true);
    }
    {
      Fixture test;
      test.message(valid);
      auto replacement = valid;
      replacement["value"] = QJsonObject{{"lifetime_seconds", 0}, {"revoke_on_sleep", false}};
      test.message(replacement);
      assert(!test.control<QPushButton>("consent")->isEnabled());
      test.click("consent");
      test.noReply(true);
    }
  }
}

void passwordFieldsDoNotExportClipboardOrAccessibleText() {
  Fixture test;
  test.message(job("encrypt"));
  test.click("consent");
  const QString marker = QStringLiteral("DISPOSABLE-UI-SECRET-ONLY");
  const QString sentinel = QStringLiteral("disposable clipboard sentinel");
  for (const char *name : {"passphrase", "confirmation"}) {
    auto *field = test.control<QLineEdit>(name);
    field->setFocus();
    QTest::keyClicks(field, marker);
    assert(field->text() == marker && !field->displayText().contains(marker));
    assert(!field->dragEnabled());
    auto *clipboard = QApplication::clipboard();
    clipboard->setText(sentinel);
    field->selectAll();
    field->copy();
    assert(clipboard->text() == sentinel);
    QTest::keyClick(field, Qt::Key_C, Qt::ControlModifier);
    assert(clipboard->text() == sentinel);
    field->cut();
    assert(clipboard->text() == sentinel);
    field->setText(marker);
    field->selectAll();
    QTest::keyClick(field, Qt::Key_X, Qt::ControlModifier);
    assert(clipboard->text() == sentinel);
    field->setText(marker);
    auto *accessible = QAccessible::queryAccessibleInterface(field);
    assert(accessible && accessible->state().passwordEdit);
    assert(!accessible->text(QAccessible::Value).contains(marker));
    assert(accessible->textInterface() &&
           !accessible->textInterface()->text(0, marker.size()).contains(marker));
  }
  test.click("cancel");
  assert(!test.reply().value("consent").toBool());
  test.secretsHiddenAndEmpty();
}

void localeSelectionIsStrictAndFixedForEachPrompt() {
  for (const auto *value : {"en", "", "ru_RU.UTF-8", "RU", "fr", "../../ru"}) {
    qputenv("SSH_KEYS_UI_LANGUAGE", value);
    Fixture test(false);
    // The process locale does not override this presentation-only selection.
    auto request = job("unlock", false);
    request["language"] = "ru";
    test.message(request);
    assert(test.control<QPushButton>("cancel")->text() == QStringLiteral("Cancel"));
    assert(test.control<QPushButton>("consent")->text() == QStringLiteral("Unlock"));
    assert(test.control<QLineEdit>("passphrase")->placeholderText() == QStringLiteral("SSH key passphrase"));
    assert(test.control<QLineEdit>("passphrase")->accessibleName() == QStringLiteral("SSH key passphrase"));
    qputenv("SSH_KEYS_UI_LANGUAGE", "ru");
    test.click("consent");
    assert(test.control<QLabel>("status")->text() == QStringLiteral("Enter a nonempty SSH key passphrase."));
    test.noReply();
    test.compact();
  }
  qunsetenv("SSH_KEYS_UI_LANGUAGE");
  {
    Fixture test(false);
    assert(test.control<QPushButton>("cancel")->text() == QStringLiteral("Cancel"));
  }
  qputenv("SSH_KEYS_UI_LANGUAGE", "ru");
  {
    Fixture test(false);
    assert(test.control<QPushButton>("cancel")->text() == QStringLiteral("Отмена"));
  }
  for (const auto &entry : PromptI18n::catalog) {
    assert(entry.russian && entry.english && *entry.russian && *entry.english);
    for (const auto character : QString::fromUtf8(entry.english))
      assert(character.unicode() < 0x0400 || character.unicode() > 0x04ff);
  }
}

void englishUnlockPreservesMetadataAndCompactLayout() {
  qputenv("SSH_KEYS_UI_LANGUAGE", "en");
  for (const auto &scenario : {std::pair{0, "unlimited"}, std::pair{3600, "1 h"},
                               std::pair{1800, "30 min"}, std::pair{45, "45 s"}}) {
    Fixture test(false);
    auto request = job("unlock", false);
    request["rules"] = QJsonObject{{"lifetime_seconds", scenario.first}};
    request["caller"] = "/test/bin/client (PID 1234)";
    request["reason"] = QStringLiteral("Проверить <literal> caller text");
    test.message(request);
    assert(test.prompt->windowTitle() == QStringLiteral("KeyController — access confirmation"));
    assert(test.control<QLabel>("request-details")->text() ==
           QStringLiteral("Request via: client\nПроверить <literal> caller text"));
    const auto details = test.control<QLabel>("details")->text();
    assert(details.contains("SHA256:disposable\n/test/.ssh/key"));
    assert(details.contains(QStringLiteral("Access duration: ") + scenario.second));
    assert(details.contains("Source: /test/bin/client (PID 1234)"));
    assert(test.control<QPushButton>("details-toggle")->accessibleName() == QStringLiteral("Details"));
    test.click("details-toggle");
    assert(test.control<QPushButton>("details-toggle")->accessibleName() == QStringLiteral("Hide"));
    assert(test.control<QPushButton>("details-toggle")->toolTip() == QStringLiteral("Hide"));
    test.compact();
    test.noReply();
  }
  for (const auto &reason : {QString(), QStringLiteral("Запрос из панели KeyController"),
                             QStringLiteral("Caller-defined reason")}) {
    Fixture test(false);
    auto request = job("unlock", false);
    request["caller"] = "/usr/lib/ssh-keys/panel-client (PID 1234)";
    request["reason"] = reason;
    test.message(request);
    const auto expected = QStringLiteral("Request via: panel-client") +
        (reason.isEmpty() ? QString() : "\n" + reason);
    assert(test.control<QLabel>("request-details")->text() == expected);
    test.noReply();
  }
  // Progress remains presentation-only; exactly one authorization frame is
  // sent, and neither the caller's locale field nor late frames can change it.
  {
    Fixture test(false);
    test.message(job());
    assert((test.reply() == QJsonObject{{"consent", true}, {"mode", "fingerprint"},
                                     {"passphrase", ""}, {"confirmation", ""}}));
    const auto initialSize = test.prompt->size();
    const std::pair<const char *, const char *> phases[]{
      {"fingerprint_starting", "Starting fingerprint reader…"},
      {"fingerprint_waiting", "Touch the fingerprint reader"},
      {"fingerprint_retry", "Try again"},
      {"credential_decrypting", "Fingerprint verified…"},
      {"key_loading", "Loading key…"}};
    for (const auto &[phase, caption] : phases) {
      test.message({{"state", "progress"}, {"phase", phase}});
      assert(test.control<QLabel>("status")->text() == QString::fromUtf8(caption));
      assert(indicator(test)->isRunning());
      assert(test.prompt->size() == initialSize);
      test.compact();
      test.secretsHiddenAndEmpty();
      test.noReply();
    }
    test.message({{"state", "completed"}});
    assert(test.control<QLabel>("status")->text() == QStringLiteral("Done"));
    assert(!indicator(test)->isRunning());
    test.noReply(true);
  }
}

void englishBindingEncryptionAndSettingsRemainInteractive() {
  qputenv("SSH_KEYS_UI_LANGUAGE", "en");
  {
    Fixture test;
    test.message(job("sync"));
    assert(test.control<QLabel>("subtitle")->text() == QStringLiteral("Link fingerprint"));
    assert(test.control<QLabel>("step-password")->text() == QStringLiteral("1  Passphrase"));
    assert(test.control<QLabel>("step-fingerprint")->text() == QStringLiteral("2  Fingerprint"));
    assert(test.control<QPushButton>("consent")->text() == QStringLiteral("Link"));
    assert(test.control<QLabel>("status")->text() == QStringLiteral("The key will remain locked after linking."));
    test.noReply();
    test.click("consent");
    assert(test.control<QLabel>("status")->text() == QStringLiteral("Enter this SSH key’s passphrase."));
    test.control<QLineEdit>("passphrase")->setText("disposable-fixture-only");
    test.click("consent");
    assert(test.reply().value("mode") == "password");
    const std::pair<const char *, const char *> phases[]{
      {"passphrase_verifying", "Checking passphrase…"},
      {"fingerprint_waiting", "Touch the fingerprint reader"},
      {"credential_sealing", "Saving fingerprint link…"},
      {"credential_verifying", "Checking fingerprint link…"}};
    for (const auto &[phase, caption] : phases) {
      test.message({{"state", "progress"}, {"phase", phase}});
      assert(test.control<QLabel>("status")->text() == QString::fromUtf8(caption));
      assert(indicator(test)->isRunning());
      test.compact();
      test.noReply();
    }
  }
  {
    Fixture test;
    test.message(job("encrypt"));
    assert(test.control<QLabel>("subtitle")->text() == QStringLiteral("Set passphrase"));
    assert(test.control<QLabel>("status")->text().contains("Existing copies and disk snapshots will remain unencrypted."));
    test.click("consent");
    assert(test.control<QPushButton>("consent")->text() == QStringLiteral("Set passphrase"));
    auto *pass = test.control<QLineEdit>("passphrase");
    auto *confirm = test.control<QLineEdit>("confirmation");
    assert(confirm->placeholderText() == QStringLiteral("Repeat the new passphrase"));
    assert(confirm->accessibleName() == confirm->placeholderText());
    pass->setText("disposable-only");
    confirm->setText("mismatch");
    test.click("consent");
    assert(test.control<QLabel>("status")->text() == QStringLiteral("Passphrases do not match."));
    test.noReply();
    test.compact();
    confirm->setText("disposable-only");
    test.click("consent");
    assert(test.reply().value("confirmation") == "disposable-only");
    assert(test.control<QLabel>("status")->text() == QStringLiteral("Setting passphrase…"));
    test.secretsHiddenAndEmpty();
  }
  const std::pair<const char *, QJsonValue> cases[]{
    {"rules.key", QJsonObject{{"lifetime_seconds", 3600}}},
    {"rules.key", QJsonValue(QJsonValue::Null)},
    {"unbind", QJsonValue(QJsonValue::Null)}};
  for (const auto &[operation, value] : cases) {
    Fixture test;
    auto request = job(operation);
    request["value"] = value;
    test.message(request);
    const auto description = test.control<QLabel>("request-details")->text();
    const auto expected = QString::fromLatin1(operation) == "unbind"
        ? "Unlink the fingerprint from this key."
        : value.isNull() ? "New duration: inherit general settings." : "New duration: 1 h";
    assert(description.contains(expected) && description.contains("Program: test fixture"));
    assert(test.control<QPushButton>("consent")->text() == QStringLiteral("Confirm"));
    test.compact();
    test.noReply();
    test.click("consent");
    assert((test.reply() == QJsonObject{{"consent", true}, {"mode", "confirm"},
                                      {"passphrase", ""}, {"confirmation", ""}}));
    assert(test.control<QLabel>("status")->text() == QStringLiteral("Working…"));
    test.secretsHiddenAndEmpty();
  }
}

void englishErrorsAreFixedTextWithoutUntrustedDetails() {
  qputenv("SSH_KEYS_UI_LANGUAGE", "en");
  const std::pair<const char *, const char *> cases[]{
    {"wrong_passphrase_or_invalid_key", "Incorrect passphrase or invalid key."},
    {"unlock_failed", "Could not load the key."},
    {"agent_unavailable", "Could not load the key."},
    {"biometric_denied", "Fingerprint not verified."},
    {"tpm_unavailable", "TPM unavailable. Fingerprint link was not created."},
    {"credential_unavailable", "Could not save the fingerprint link."},
    {"cancelled", "Operation cancelled."},
    {"<untrusted error data>", "Operation incomplete. See KeyController for details."}};
  for (const auto &[code, caption] : cases) {
    Fixture test;
    test.message(job("unlock", false));
    test.control<QLineEdit>("passphrase")->setText("never-send-this");
    test.message({{"state", "error"}, {"error_code", code}});
    assert(test.control<QLabel>("status")->text() == QString::fromUtf8(caption));
    test.compact();
    test.secretsHiddenAndEmpty();
    test.noReply(true);
  }
}

void writeFile(const QString &path, const QByteArray &data) {
  assert(QDir().mkpath(QFileInfo(path).absolutePath()));
  QFile file(path);
  assert(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
  assert(file.write(data) == data.size());
}

void themeFilesAreBoundedAndCannotInjectStyles() {
  const QByteArray priorHome = qgetenv("HOME");
  QTemporaryDir directory;
  assert(directory.isValid());
  qputenv("HOME", directory.path().toUtf8());
  const QString current =
      directory.path() + "/.local/state/omarchy/current/theme/";
  const QString override = directory.path() + "/.config/omarchy/shell.toml";
  writeFile(current + "colors.toml",
            "background='#fafafa'\nforeground='#171717'\naccent='#008855'\n");
  writeFile(current + "shell.toml",
            "[font]\nbase-size=14\nfamily='monospace'\n[popups]\ntext='"
            "foreground'\nborder='accent'\nradius=8\n");
  writeFile(
      override,
      "[font]\nbase-size=16\nfamily='Adwaita "
      "Sans'\n[popups]\nbackground='#eeeeee'\nborder='#123456'\nradius=4\n");
  auto theme = PromptTheme::load();
  assert(theme.background == QColor("#eeeeee"));
  assert(theme.foreground == QColor("#171717"));
  assert(theme.accent == QColor("#008855"));
  assert(theme.border == QColor("#123456"));
  assert(theme.fontPixels == 16 && theme.fontFamily == "Adwaita Sans" &&
         theme.radius == 4);
  QWidget widget;
  PromptTheme::apply(&widget, theme);
  assert(widget.palette().color(QPalette::Window) == theme.background);
  assert(widget.font().pixelSize() == 16);

  writeFile(override,
            "[font]\nbase-size=999999999999999999999\nfamily='evil; "
            "background:url(file:///never-read)'\n[popups]\nbackground='red; "
            "image:url(file:///never-read)'\nradius=-1\n");
  theme = PromptTheme::load();
  assert(theme.background == QColor("#fafafa"));
  assert(theme.fontFamily == "monospace" && theme.fontPixels == 14 &&
         theme.radius == 8);
  PromptTheme::apply(&widget, theme);
  assert(!widget.styleSheet().contains("url(") &&
         !widget.styleSheet().contains("never-read"));

  writeFile(override,
            QByteArray("[font]\nbase-size=32\n") + QByteArray(128 * 1024, '#'));
  assert(PromptTheme::load().fontPixels == 14);
  assert(QFile::remove(override));
  assert(::mkfifo(QFile::encodeName(override).constData(), 0600) == 0);
  QElapsedTimer elapsed;
  elapsed.start();
  // A regression to blocking open must fail the disposable test process,
  // instead of hanging the entire test runner on this deliberately idle FIFO.
  alarm(2);
  assert(PromptTheme::load().fontPixels == 14);
  alarm(0);
  assert(elapsed.elapsed() < 1000);
  assert(QFile::remove(override));

  writeFile(override, "[font]\nbase-size=32\n");
  {
    Fixture large;
    auto metadata = job("unlock", false);
    metadata["reason"] = QString(4096, 'r');
    large.message(metadata);
    large.compact();
    large.click("consent");
    large.compact();
    large.noReply();
  }
  qputenv("HOME", priorHome);
}
} // namespace

int main(int argc, char **argv) {
  rlimit core{0, 0};
  if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 1;
  QTemporaryDir home;
  assert(home.isValid());
  qputenv("HOME", home.path().toUtf8());
  qputenv("SSH_KEYS_UI_LANGUAGE", "ru");
  // A caller-controlled IME selection must not survive the production setup.
  qputenv("QT_IM_MODULE", "wayland");
  qputenv("QT_IM_MODULES", "ibus;wayland");
  qputenv("QT_LINUX_ACCESSIBILITY_ALWAYS_ON", "1");
  qputenv("AT_SPI_BUS_ADDRESS", "unix:path=/test/disposable-a11y");
  qputenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/test/disposable-session");
  assert(configureSecretInput());
  assert(qEnvironmentVariable("QT_IM_MODULE") == QStringLiteral("compose"));
  assert(!qEnvironmentVariableIsSet("QT_IM_MODULES"));
  assert(!qEnvironmentVariableIsSet("QT_LINUX_ACCESSIBILITY_ALWAYS_ON"));
  assert(qEnvironmentVariable("AT_SPI_BUS_ADDRESS") == QStringLiteral("unix:path=/dev/null"));
  assert(qEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS") == QStringLiteral("unix:path=/dev/null"));
  QApplication app(argc, argv);
  assert(QGuiApplication::platformName() == QStringLiteral("offscreen"));
  app.setQuitOnLastWindowClosed(false);
  secretFieldsRejectInputMethodQueriesAndPreserveTyping();
  passwordCharactersAreMaskedEvenWhenParentStyleRequestsDelay();
  fingerprintStartsAfterExposureOnlyOnceAndCanBeCancelled();
  fingerprintDoesNotStartAfterEarlyCancellationEofOrTerminalFrame();
  compactUnlockRetainsIdentityAndRequestProvenance();
  encryptionRequiresMatchingNonemptyConfirmation();
  passwordUnlockUsesSavedModeAndSubmitsDirectlyOnce();
  syncConsentPasswordFingerprintProgressAndCancellation();
  progressRemainsAnimatedAndNeverRestartsAuthentication();
  progressStopsAtEveryTerminalAndCanBeCancelledAtEachStage();
  cancellingBeforeSubmissionNeverSendsEnteredPassword();
  untrustedMetadataRemainsPlainTextAndCompact();
  unknownAndMalformedMessagesCannotResumeAuthentication();
  terminalBeforeSubmissionClearsPasswordAndCannotResumeAuthentication();
  closedPeerClearsEnteredSecretsAndClosesPrompt();
  settingsConfirmExactTargetsWithoutSecretFields();
  malformedSettingsTargetsFailClosedAndCancellationDoesNotApprove();
  policyEditorSavesOnlyNativeSelectionsAndNeverAuthenticates();
  policyEditorPreservesExactCustomDurationInheritanceAndCancellation();
  policyEditorRejectsMalformedSnapshotsAndLateReplacement();
  passwordFieldsDoNotExportClipboardOrAccessibleText();
  themeFilesAreBoundedAndCannotInjectStyles();
  localeSelectionIsStrictAndFixedForEachPrompt();
  englishUnlockPreservesMetadataAndCompactLayout();
  englishBindingEncryptionAndSettingsRemainInteractive();
  englishErrorsAreFixedTextWithoutUntrustedDetails();
  // Repeat layout and hardening invariants with longer translated captions.
  themeFilesAreBoundedAndCannotInjectStyles();
  untrustedMetadataRemainsPlainTextAndCompact();
  progressStopsAtEveryTerminalAndCanBeCancelledAtEachStage();
  passwordFieldsDoNotExportClipboardOrAccessibleText();
  return 0;
}
