#include <QApplication>
#include <QAccessible>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QFrame>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPainter>
#include <QPushButton>
#include <QScreen>
#include <QScrollArea>
#include <QScrollBar>
#include <QSocketNotifier>
#include <QSpinBox>
#include <QStyleOptionButton>
#include <QSvgRenderer>
#include <QTimer>
#include <QVBoxLayout>
#include <QWindow>
#include <LayerShellQt/Window>
#include <cmath>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "prompt_theme.h"
#include "prompt_i18n.h"
#include "secret_line_edit.h"

// Keep text composition inside this process. Qt's Wayland input context sends
// QLineEdit's plaintext surrounding text despite Password/SensitiveData hints.
// Set this before QApplication and discard Qt's higher-priority module list.
static bool configureSecretInput() {
  // Qt's AT-SPI bridge exports plaintext Password text-change events. Merely
  // unsetting the session-bus address still discovers XDG_RUNTIME_DIR/bus.
  // This prompt uses its inherited IPC/display descriptors, so neither bus is
  // needed. /dev/null cannot become an attacker-controlled Unix socket.
  const QByteArray disabledBus("unix:path=/dev/null");
  if (!qunsetenv("QT_IM_MODULES") || !qputenv("QT_IM_MODULE", "compose") ||
      !qunsetenv("QT_LINUX_ACCESSIBILITY_ALWAYS_ON") ||
      !qputenv("AT_SPI_BUS_ADDRESS", disabledBus) ||
      !qputenv("DBUS_SESSION_BUS_ADDRESS", disabledBus)) return false;
  // Also discard events locally if an accessibility bridge is activated later.
  QAccessible::installUpdateHandler([](QAccessibleEvent *) {});
  return true;
}

// Small monochrome progress ring, painted with the current Omarchy foreground.
// Only this widget repaints during a long operation; the dialog is not rebuilt.
class BusyIndicator final : public QWidget {
public:
  BusyIndicator(int size, const QColor &foreground, QWidget *parent)
      : QWidget(parent), foreground(foreground), animation(this) {
    setObjectName("progress-indicator");
    setFixedSize(size, size);
    setAttribute(Qt::WA_TransparentForMouseEvents);
    animation.setInterval(35);
    connect(&animation, &QTimer::timeout, this, [this] { angle = (angle + 12) % 360; update(); });
    hide();
  }
  void setRunning(bool running) {
    if (running != animation.isActive()) {
      if (running) animation.start();
      else animation.stop();
    }
    setVisible(running);
  }
  bool isRunning() const { return animation.isActive(); }
protected:
  void paintEvent(QPaintEvent *) override {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    const qreal stroke = qMax<qreal>(1.5, width() / 8.0);
    const QRectF ring = QRectF(rect()).adjusted(stroke, stroke, -stroke, -stroke);
    QColor track = foreground;
    track.setAlphaF(0.18);
    painter.setPen(QPen(track, stroke));
    painter.drawEllipse(ring);
    painter.setPen(QPen(foreground, stroke, Qt::SolidLine, Qt::RoundCap));
    painter.drawArc(ring, (90 - angle) * 16, -100 * 16);
  }
private:
  QColor foreground;
  QTimer animation;
  int angle = 0;
};

// Preserve native checkbox interaction while making a checked policy explicit
// even when the Omarchy accent is gray. No theme-supplied image or QSS is loaded.
class PolicyCheckBox final : public QCheckBox {
public:
  PolicyCheckBox(const QString &caption, const QColor &accent, QWidget *parent)
      : QCheckBox(caption, parent), checkColor(contrastingMark(accent)) {}
protected:
  void paintEvent(QPaintEvent *event) override {
    QCheckBox::paintEvent(event);
    if (!isChecked()) return;
    QStyleOptionButton option;
    initStyleOption(&option);
    const QRectF indicator = style()->subElementRect(QStyle::SE_CheckBoxIndicator, &option, this);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(QPen(checkColor, qMax<qreal>(1.5, indicator.width() / 7.0),
                        Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    const QPointF points[]{
      {indicator.left() + indicator.width() * 0.22, indicator.top() + indicator.height() * 0.51},
      {indicator.left() + indicator.width() * 0.43, indicator.top() + indicator.height() * 0.72},
      {indicator.left() + indicator.width() * 0.79, indicator.top() + indicator.height() * 0.28},
    };
    painter.drawPolyline(points, 3);
  }
private:
  static QColor contrastingMark(const QColor &accent) {
    const auto linear = [](qreal value) {
      return value <= 0.04045 ? value / 12.92 : std::pow((value + 0.055) / 1.055, 2.4);
    };
    const qreal luminance = 0.2126 * linear(accent.redF()) +
                            0.7152 * linear(accent.greenF()) + 0.0722 * linear(accent.blueF());
    return (luminance + 0.05) / 0.05 >= 1.05 / (luminance + 0.05) ? Qt::black : Qt::white;
  }
  const QColor checkColor;
};

class Prompt final : public QDialog {
public:
  explicit Prompt(int fd, QWidget *parent = nullptr)
      : QDialog(parent), fd(fd), theme(PromptTheme::load()), language(PromptI18n::languageFromEnvironment()) {
    setObjectName("keycontroller-prompt");
    setWindowTitle(text(PromptI18n::Message::WindowTitle));
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
    PromptTheme::apply(this, theme);
    setAttribute(Qt::WA_TranslucentBackground);
    setAutoFillBackground(false);
    const int padding = px(16);
    layout = new QVBoxLayout(this);
    layout->setContentsMargins(padding, padding, padding, padding);
    layout->setSpacing(px(10));
    auto *header = new QHBoxLayout;
    header->setSpacing(px(9));
    auto *icon = new QLabel(this);
    icon->setObjectName("brand-icon");
    icon->setTextFormat(Qt::PlainText);
    const int iconSize = px(24);
    QPixmap image(iconSize * devicePixelRatioF(), iconSize * devicePixelRatioF());
    image.setDevicePixelRatio(devicePixelRatioF());
    image.fill(Qt::transparent);
    QPainter painter(&image);
    QSvgRenderer renderer(QStringLiteral(":/keycontroller/mark.svg"));
    renderer.render(&painter, QRectF(0, 0, iconSize, iconSize));
    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(QRect(0, 0, iconSize, iconSize), theme.foreground);
    painter.end();
    icon->setPixmap(image);
    icon->setFixedSize(iconSize, iconSize);
    header->addWidget(icon);
    auto *heading = new QVBoxLayout;
    heading->setSpacing(px(3));
    title = label(QStringLiteral("KeyController"), "title");
    title->setWordWrap(false);
    subtitle = label(text(PromptI18n::Message::AccessConfirmation), "subtitle");
    heading->addWidget(title);
    heading->addWidget(subtitle);
    header->addLayout(heading, 1);
    detailsToggle = new QPushButton(text(PromptI18n::Message::Details), this);
    detailsToggle->setObjectName("details-toggle");
    detailsToggle->setAutoDefault(false);
    detailsToggle->setFlat(true);
    header->addWidget(detailsToggle, 0, Qt::AlignTop);
    layout->addLayout(header);

    scroll = new QScrollArea(this);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setStyleSheet(QStringLiteral("QScrollArea { background: transparent; border: none; }"));
    body = new QWidget(scroll);
    body->setObjectName("prompt-body");
    auto *content = new QVBoxLayout(body);
    content->setContentsMargins(0, 0, 0, 0);
    content->setSpacing(px(8));
    keyCard = new QFrame(body);
    keyCard->setObjectName("keyCard");
    auto *keyLayout = new QVBoxLayout(keyCard);
    keyLayout->setContentsMargins(px(12), px(10), px(12), px(10));
    keyLayout->setSpacing(px(3));
    keyName = label({}, "key-name");
    keyName->setWordWrap(false);
    keyName->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    keyMetadata = label({}, "metadata");
    keyLayout->addWidget(keyName);
    keyLayout->addWidget(keyMetadata);
    content->addWidget(keyCard);

    steps = new QWidget(body);
    auto *stepLayout = new QBoxLayout(QBoxLayout::LeftToRight, steps);
    stepLayout->setContentsMargins(0, 0, 0, 0);
    stepPassword = label(text(PromptI18n::Message::PasswordStep), "step-password");
    stepFingerprint = label(text(PromptI18n::Message::FingerprintStep), "step-fingerprint");
    for (auto *step : {stepPassword, label(QStringLiteral("→"), "metadata"), stepFingerprint}) {
      step->setWordWrap(false);
      step->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
      stepLayout->addWidget(step);
    }
    stepLayout->addStretch();
    content->addWidget(steps);
    steps->hide();

    requestDetails = label({}, "request-details");
    content->addWidget(requestDetails);
    requestDetails->hide();
    policyEditor = new QWidget(body);
    policyEditor->setObjectName("policy-editor");
    auto *policyLayout = new QVBoxLayout(policyEditor);
    policyLayout->setContentsMargins(0, 0, 0, 0);
    policyLayout->setSpacing(px(8));
    inheritPolicy = new PolicyCheckBox(text(PromptI18n::Message::InheritSettings), theme.accent, policyEditor);
    inheritPolicy->setObjectName("policy-inherit");
    policyLayout->addWidget(inheritPolicy);
    policyLayout->addWidget(label(text(PromptI18n::Message::DurationLabel), "policy-duration-label"));
    lifetimePreset = new QComboBox(policyEditor);
    lifetimePreset->setObjectName("policy-lifetime");
    lifetimePreset->setAccessibleName(text(PromptI18n::Message::DurationLabel));
    lifetimePreset->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    for (int seconds : {0, 60, 300, 900, 1800, 3600, 14400, 28800, 86400})
      lifetimePreset->addItem(duration(seconds), seconds);
    lifetimePreset->addItem(text(PromptI18n::Message::CustomDuration), -1);
    policyLayout->addWidget(lifetimePreset);
    lifetimeCustom = new QSpinBox(policyEditor);
    lifetimeCustom->setObjectName("policy-custom-seconds");
    lifetimeCustom->setRange(1, 31536000);
    lifetimeCustom->setSuffix(text(PromptI18n::Message::Seconds));
    lifetimeCustom->setAccessibleName(text(PromptI18n::Message::DurationLabel));
    lifetimeCustom->setKeyboardTracking(false);
    lifetimeCustom->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    policyLayout->addWidget(lifetimeCustom);
    inheritSummary = label({}, "policy-inherited-duration");
    policyLayout->addWidget(inheritSummary);
    revokeOnSleep = new PolicyCheckBox(text(PromptI18n::Message::RevokeOnSleep), theme.accent, policyEditor);
    revokeOnSleep->setObjectName("policy-sleep");
    policyLayout->addWidget(revokeOnSleep);
    // Only validated theme colors enter QSS. These controls edit policy inside
    // the native helper; the untrusted caller cannot provide the saved value.
    policyEditor->setStyleSheet(QStringLiteral(
        "QComboBox, QSpinBox { background: %1; color: %2; border: 1px solid %3; "
        "border-radius: %4px; padding: %5px; min-height: %6px; } "
        "QComboBox:focus, QSpinBox:focus { border-color: %7; } "
        "QComboBox:disabled, QSpinBox:disabled, QCheckBox:disabled { color: %8; } "
        "QCheckBox { spacing: %5px; padding: %9px 0; } "
        "QCheckBox::indicator { width: %10px; height: %10px; border: 1px solid %3; "
        "border-radius: %9px; background: %1; } "
        "QCheckBox::indicator:checked { background: %7; border-color: %7; }")
        .arg(theme.well.name(), theme.foreground.name(), theme.border.name())
        .arg(px(qBound(0, theme.radius, 24))).arg(px(7)).arg(px(16))
        .arg(theme.accent.name(), theme.muted.name()).arg(px(3)).arg(px(12)));
    content->addWidget(policyEditor);
    policyEditor->hide();
    connect(inheritPolicy, &QCheckBox::toggled, this, [this] { updatePolicyControls(); });
    connect(lifetimePreset, &QComboBox::currentIndexChanged, this, [this] { updatePolicyControls(); });
    pass = secretField("passphrase", text(PromptI18n::Message::KeyPassphrase));
    confirm = secretField("confirmation", text(PromptI18n::Message::RepeatPassphrase));
    content->addWidget(pass);
    content->addWidget(confirm);
    pass->hide();
    confirm->hide();
    statusRow = new QWidget(body);
    auto *statusLayout = new QHBoxLayout(statusRow);
    statusLayout->setContentsMargins(0, 0, 0, 0);
    statusLayout->setSpacing(px(8));
    progress = new BusyIndicator(px(14), theme.foreground, statusRow);
    status = label({}, "status");
    statusLayout->addWidget(progress, 0, Qt::AlignVCenter);
    statusLayout->addWidget(status, 1);
    content->addWidget(statusRow);
    details = label({}, "details");
    details->setTextInteractionFlags(Qt::TextSelectableByMouse);
    details->hide();
    content->addWidget(details);
    scroll->setWidget(body);
    layout->addWidget(scroll, 1);

    buttons = new QBoxLayout(QBoxLayout::LeftToRight);
    buttons->setSpacing(px(10));
    auto *cancel = new QPushButton(text(PromptI18n::Message::Cancel), this);
    cancel->setObjectName("cancel");
    proceed = new QPushButton(text(PromptI18n::Message::Unlock), this);
    proceed->setObjectName("consent");
    proceed->setEnabled(false);
    proceed->setAutoDefault(false);
    cancel->setAutoDefault(false);
    buttons->addWidget(cancel);
    buttons->addWidget(proceed, 1);
    layout->addLayout(buttons);
    connect(detailsToggle, &QPushButton::clicked, this, [this] {
      details->setVisible(details->isHidden());
      detailsToggle->setText(details->isHidden() ? text(PromptI18n::Message::Details) : text(PromptI18n::Message::Hide));
      fitContent();
    });
    connect(cancel, &QPushButton::clicked, this, &Prompt::reject);
    connect(proceed, &QPushButton::clicked, this, [this] { submit(); });
    connect(pass, &QLineEdit::returnPressed, this, [this] { if (armed) submit(); });
    connect(confirm, &QLineEdit::returnPressed, this, [this] { if (armed) submit(); });
    notifier = new QSocketNotifier(fd, QSocketNotifier::Read, this);
    connect(notifier, &QSocketNotifier::activated, this, [this] { receive(); });
    QTimer::singleShot(120000, this, &Prompt::reject);
    fitContent();
  }
  ~Prompt() override { clearSecrets(); ::close(fd); }
  void reject() override {
    if (!finished) {
      if (sent) send(QJsonObject{{"cancel", true}});
      else send(QJsonObject{{"consent", false}, {"mode", ""}, {"passphrase", ""}, {"confirmation", ""}});
    }
    finished = true;
    progress->setRunning(false);
    notifier->setEnabled(false);
    clearSecrets();
    QDialog::reject();
  }

protected:
  bool eventFilter(QObject *watched, QEvent *event) override {
    if (watched == windowHandle() && event->type() == QEvent::Expose)
      scheduleFingerprint();
    return QDialog::eventFilter(watched, event);
  }
  void paintEvent(QPaintEvent *) override {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setBrush(theme.background);
    painter.setPen(QPen(theme.border, 1));
    painter.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), px(theme.radius), px(theme.radius));
  }

private:
  int fd;
  PromptTheme::Theme theme;
  const PromptI18n::Language language;
  bool initialized = false, armed = false, sent = false, finished = false;
  bool surfacePrepared = false, confirmationOnly = false, fingerprintMode = false;
  bool fingerprintQueued = false;
  bool policyEditing = false;
  int progressRank = 0;
  QString progressPhase;
  QByteArray incoming;
  QString operation, fullName, fingerprintIdentity, metadataDuration;
  QFrame *keyCard;
  QLabel *title, *subtitle, *keyName, *keyMetadata, *requestDetails, *details, *status;
  QLabel *stepPassword, *stepFingerprint;
  QLineEdit *pass, *confirm;
  QPushButton *proceed, *detailsToggle;
  QSocketNotifier *notifier;
  QScrollArea *scroll;
  QWidget *body, *steps, *statusRow;
  QWidget *policyEditor;
  QCheckBox *inheritPolicy, *revokeOnSleep;
  QComboBox *lifetimePreset;
  QSpinBox *lifetimeCustom;
  QLabel *inheritSummary;
  BusyIndicator *progress;
  QVBoxLayout *layout;
  QBoxLayout *buttons;
  QString text(PromptI18n::Message message) const {
    return PromptI18n::translate(language, message);
  }
  int px(int value) const { return PromptTheme::rem(theme, value); }
  QLabel *label(const QString &text, const char *name) {
    auto *result = new QLabel(text, this);
    result->setObjectName(name);
    result->setTextFormat(Qt::PlainText);
    result->setWordWrap(true);
    result->setMinimumWidth(0);
    result->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    return result;
  }
  QLineEdit *secretField(const char *name, const QString &placeholder) {
    auto *field = new SecretLineEdit(this);
    field->setObjectName(name);
    field->setEchoMode(QLineEdit::Password);
    field->setMaxLength(1024);
    field->setPlaceholderText(placeholder);
    field->setAccessibleName(placeholder);
    field->setContextMenuPolicy(Qt::NoContextMenu);
    field->setInputMethodHints(Qt::ImhHiddenText | Qt::ImhSensitiveData | Qt::ImhNoPredictiveText);
    return field;
  }
  static QString bounded(const QString &value, int limit = 512) {
    return value.size() <= limit ? value : value.left(limit - 1) + QChar(0x2026);
  }
  QString duration(int seconds) const {
    if (!seconds) return text(PromptI18n::Message::Unlimited);
    if (seconds % 3600 == 0) return QString::number(seconds / 3600) + text(PromptI18n::Message::Hours);
    if (seconds % 60 == 0) return QString::number(seconds / 60) + text(PromptI18n::Message::Minutes);
    return QString::number(seconds) + text(PromptI18n::Message::Seconds);
  }
  void fitContent() {
    const auto *screen = windowHandle() ? windowHandle()->screen() : QGuiApplication::primaryScreen();
    const QSize available = screen ? screen->availableGeometry().size() : QSize(1024, 768);
    const int width = qMin(qBound(300, px(340), 560), qMax(240, available.width() - 32));
    setFixedWidth(width);
    const auto margins = layout->contentsMargins();
    const int contentWidth = width - margins.left() - margins.right();
    const QString detailCaption = details->isHidden() ? text(PromptI18n::Message::Details) : text(PromptI18n::Message::Hide);
    detailsToggle->setText(detailCaption);
    detailsToggle->setAccessibleName(detailCaption);
    detailsToggle->setToolTip(detailCaption);
    const int headerWidth = px(24 + 18) + title->fontMetrics().horizontalAdvance(title->text()) +
                            detailsToggle->sizeHint().width();
    if (headerWidth > contentWidth) detailsToggle->setText(QString(QChar(0x22ef)));
    const int buttonWidth = buttons->itemAt(0)->minimumSize().width() +
                            buttons->itemAt(1)->minimumSize().width() + buttons->spacing();
    buttons->setDirection(buttonWidth > contentWidth
                              ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight);
    body->setFixedWidth(qMax(120, contentWidth));
    auto *stepLayout = static_cast<QBoxLayout *>(steps->layout());
    const int stepWidth = stepPassword->sizeHint().width() + stepFingerprint->sizeHint().width() +
                          stepLayout->itemAt(1)->widget()->sizeHint().width() + 2 * stepLayout->spacing();
    const bool stackedSteps = stepWidth > contentWidth;
    stepLayout->setDirection(stackedSteps ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight);
    stepLayout->itemAt(1)->widget()->setVisible(!stackedSteps);
    keyName->setText(keyName->fontMetrics().elidedText(fullName, Qt::ElideMiddle, contentWidth - 2 * px(12)));
    // A fingerprint is an unbroken token. QLabel's ordinary word wrapping can
    // clip it, so wrap only its presentation; Details retains the exact string.
    QString wrappedFingerprint, fingerprintLine;
    const int fingerprintWidth = qMax(20, contentWidth - 2 * px(13));
    QString fingerprintToken = fingerprintIdentity;
    const auto metrics = keyMetadata->fontMetrics();
    const int colon = fingerprintToken.indexOf(':');
    if (colon >= 0 && metrics.horizontalAdvance(fingerprintToken) > fingerprintWidth &&
        metrics.horizontalAdvance(fingerprintToken.mid(colon + 1)) <= fingerprintWidth) {
      wrappedFingerprint = fingerprintToken.left(colon + 1) + '\n';
      fingerprintToken = fingerprintToken.mid(colon + 1);
    }
    for (QChar character : fingerprintToken) {
      if (!fingerprintLine.isEmpty() && keyMetadata->fontMetrics().horizontalAdvance(fingerprintLine + character) > fingerprintWidth) {
        wrappedFingerprint += fingerprintLine + '\n';
        fingerprintLine.clear();
      }
      fingerprintLine += character;
    }
    keyMetadata->setText(wrappedFingerprint + fingerprintLine + metadataDuration);
    keyCard->layout()->invalidate();
    keyCard->layout()->activate();
    body->layout()->invalidate();
    body->layout()->activate();
    const int bodyHeight = body->layout()->totalHeightForWidth(body->width());
    int contentHeight = bodyHeight > 0 ? bodyHeight : body->sizeHint().height();
    const int headerAndButtons = margins.top() + margins.bottom() + layout->itemAt(0)->sizeHint().height() +
                                 2 * layout->spacing() + buttons->sizeHint().height();
    const int heightLimit = qMax(200, available.height() - 32);
    if (contentHeight + headerAndButtons > heightLimit) {
      body->setFixedWidth(qMax(120, contentWidth - scroll->verticalScrollBar()->sizeHint().width()));
      body->layout()->activate();
      contentHeight = qMax(contentHeight, body->layout()->totalHeightForWidth(body->width()));
    }
    resize(width, qMin(qMax(px(180), contentHeight + headerAndButtons), heightLimit));
  }
  void present() {
    ensurePolished();
    fitContent();
    if (!surfacePrepared && QGuiApplication::platformName().startsWith("wayland")) {
      winId();
      auto *layer = LayerShellQt::Window::get(windowHandle());
      layer->setScope(QStringLiteral("keycontroller-prompt"));
      layer->setAnchors(LayerShellQt::Window::AnchorNone);
      layer->setMargins({});
      layer->setExclusiveZone(-1);
      layer->setLayer(LayerShellQt::Window::LayerOverlay);
      layer->setKeyboardInteractivity(LayerShellQt::Window::KeyboardInteractivityExclusive);
      layer->setWantsToBeOnActiveScreen(true);
      surfacePrepared = true;
      connect(windowHandle(), &QWindow::screenChanged, this, [this] { QTimer::singleShot(0, this, [this] { fitContent(); }); });
    }
    winId();
    windowHandle()->installEventFilter(this);
    show();
    scheduleFingerprint();
  }
  void scheduleFingerprint() {
    if (!initialized || operation != "unlock" || !fingerprintMode ||
        sent || finished || fingerprintQueued || !incoming.isEmpty() ||
        !isVisible() || !windowHandle() || !windowHandle()->isExposed()) return;
    // Wait until the protected surface is exposed. The event-loop boundary
    // also lets close/terminal frames cancel a request before scanning starts.
    fingerprintQueued = true;
    QTimer::singleShot(0, this, [this] {
      // Drain a pending terminal frame or EOF before authorizing PAM. This is
      // nonblocking and never reads a secret from the display connection.
      receive();
      fingerprintQueued = false;
      if (finished || sent || !incoming.isEmpty() || !isVisible() ||
          !windowHandle() || !windowHandle()->isExposed()) return;
      submit();
    });
  }
  void clearSecrets() { pass->clear(); confirm->clear(); }
  bool send(const QJsonObject &object) {
    QByteArray bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
    bytes.append('\n');
    qsizetype pos = 0;
    while (pos < bytes.size()) {
      auto n = ::send(fd, bytes.constData() + pos, bytes.size() - pos, MSG_NOSIGNAL);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) { bytes.fill('\0'); return false; }
      pos += n;
    }
    bytes.fill('\0');
    return true;
  }
  void receive() {
    char buffer[4096];
    auto n = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
    if (n <= 0) { finished = true; reject(); return; }
    incoming.append(buffer, n);
    if (incoming.size() > 128 * 1024) { finished = true; reject(); return; }
    while (incoming.contains('\n')) {
      auto p = incoming.indexOf('\n');
      QByteArray line = incoming.left(p);
      incoming.remove(0, p + 1);
      QJsonParseError error;
      auto document = QJsonDocument::fromJson(line, &error);
      if (error.error != QJsonParseError::NoError || !document.isObject()) { finished = true; reject(); return; }
      auto object = document.object();
      if (!initialized) {
        const auto op = object.value("operation").toString();
        if (op != "sync" && op != "unlock" && op != "encrypt" && !confirmationOperation(op) && !policyOperation(op)) { finished = true; reject(); return; }
        initialized = true;
        if (!initialize(object)) { finished = true; reject(); return; }
      } else {
        const auto state = object.value("state").toString();
        if (state == "progress") {
          applyProgress(object.value("phase").toString());
        } else if (state == "fingerprint" && sent && !finished && !confirmationOnly && !policyEditing) {
          // Legacy workers announced this before pam_authenticate; it does
          // not prove the sensor is ready to accept a finger.
          applyProgress(QStringLiteral("fingerprint_starting"));
        } else {
          finished = true;
          clearSecrets();
          pass->hide(); confirm->hide();
          proceed->setEnabled(false);
          policyEditor->setEnabled(false);
          setStatus(state == "completed"
              ? text(policyEditing ? PromptI18n::Message::ChangesSubmitted : PromptI18n::Message::Done)
              : errorText(object.value("error_code").toString()));
          QTimer::singleShot(state == "completed" ? 150 : 2500, this, &QDialog::accept);
        }
        if (finished) notifier->setEnabled(false);
        fitContent();
        if (finished) return;
      }
    }
    scheduleFingerprint();
  }
  void setStatus(const QString &text, bool running = false) {
    status->setText(text);
    statusRow->setVisible(!text.isEmpty());
    progress->setRunning(running && !text.isEmpty());
    // Child layout invalidation otherwise reaches the scroll area's parent
    // asynchronously, leaving one stale line of height when an error appears.
    statusRow->layout()->invalidate();
    statusRow->updateGeometry();
    body->layout()->invalidate();
  }
  void applyProgress(const QString &phase) {
    if (!sent || finished || confirmationOnly || policyEditing) return;
    int rank = 0;
    QString caption;
    const bool fingerprintStep = operation == "sync" || (operation == "unlock" && fingerprintMode);
    if (fingerprintStep && phase == "fingerprint_starting") {
      rank = operation == "sync" ? 2 : 1;
      caption = text(PromptI18n::Message::ScannerStarting);
    } else if (fingerprintStep && (phase == "fingerprint_waiting" || phase == "fingerprint_retry")) {
      rank = operation == "sync" ? 3 : 2;
      caption = phase == "fingerprint_waiting" ? text(PromptI18n::Message::FingerprintWaiting)
                                            : text(PromptI18n::Message::FingerprintRetry);
    } else if (operation == "unlock" && fingerprintMode && phase == "credential_decrypting") {
      rank = 3;
      caption = text(PromptI18n::Message::FingerprintVerified);
    } else if (operation == "unlock" && phase == "key_loading") {
      rank = 4;
      caption = text(PromptI18n::Message::KeyLoading);
    } else if (operation == "sync" && phase == "passphrase_verifying") {
      rank = 1;
      caption = text(PromptI18n::Message::PassphraseVerifying);
    } else if (operation == "sync" && phase == "credential_sealing") {
      rank = 4;
      caption = text(PromptI18n::Message::BindingSaving);
    } else if (operation == "sync" && phase == "credential_verifying") {
      rank = 5;
      caption = text(PromptI18n::Message::BindingVerifying);
    } else if (operation == "encrypt" && phase == "file_encrypting") {
      rank = 1;
      caption = text(PromptI18n::Message::PassphraseSetting);
    }
    // Unknown, incompatible and late progress cannot restart an old step or
    // alter the captured operation/mode. Repeats never send another reply.
    if (!rank || rank < progressRank || phase == progressPhase) return;
    progressRank = rank;
    progressPhase = phase;
    setStatus(caption, true);
    if (fingerprintStep && phase.startsWith("fingerprint_")) {
      stepPassword->setEnabled(false);
      stepFingerprint->setEnabled(true);
    }
  }
  QString errorText(const QString &code) const {
    if (code == "wrong_passphrase_or_invalid_key") return text(PromptI18n::Message::WrongPassphrase);
    if (code == "unlock_failed" || code == "agent_unavailable") return text(PromptI18n::Message::UnlockFailed);
    if (code == "biometric_denied") return text(PromptI18n::Message::FingerprintDenied);
    if (code == "tpm_unavailable") return text(PromptI18n::Message::TpmUnavailable);
    if (code == "credential_unavailable") return text(PromptI18n::Message::BindingFailed);
    if (code == "cancelled") return text(PromptI18n::Message::Cancelled);
    return text(PromptI18n::Message::OperationFailed);
  }
  static bool confirmationOperation(const QString &op) {
    return op == "rules.key" || op == "unbind";
  }
  static bool policyOperation(const QString &op) {
    return op == "settings.global" || op == "settings.key";
  }
  static bool validLifetime(const QJsonValue &value, int *seconds) {
    if (!value.isDouble()) return false;
    *seconds = value.toInt(-1);
    return *seconds >= 0 && *seconds <= 31536000 && value.toDouble() == *seconds;
  }
  void updatePolicyControls() {
    if (!policyEditing) return;
    const bool inherited = operation == "settings.key" && inheritPolicy->isChecked();
    lifetimePreset->setEnabled(!inherited);
    lifetimeCustom->setEnabled(!inherited);
    lifetimeCustom->setVisible(lifetimePreset->currentData().toInt() < 0 && !inherited);
    inheritSummary->setVisible(inherited);
    fitContent();
  }
  bool initializePolicy(const QJsonObject &job) {
    if (!job.value("value").isObject()) return false;
    const auto value = job.value("value").toObject();
    const bool global = operation == "settings.global";
    int seconds = 0, generalSeconds = 0;
    if (!validLifetime(value.value("lifetime_seconds"), &seconds)) return false;
    if (global) {
      if (value.size() != 2 || !value.value("revoke_on_sleep").isBool() ||
          !job.value("key").isNull()) return false;
      fullName = text(PromptI18n::Message::GeneralSettings);
      subtitle->setText(text(PromptI18n::Message::GeneralSettings));
      keyCard->hide();
      revokeOnSleep->setChecked(value.value("revoke_on_sleep").toBool());
    } else {
      if (value.size() != 3 || !value.value("inherits").isBool() ||
          !validLifetime(value.value("global_lifetime_seconds"), &generalSeconds) ||
          !job.value("key").isObject() || fullName.isEmpty()) return false;
      subtitle->setText(text(PromptI18n::Message::KeySettings));
      inheritPolicy->setChecked(value.value("inherits").toBool());
      inheritSummary->setText(text(PromptI18n::Message::GeneralLifetime) + duration(generalSeconds));
    }
    inheritPolicy->setVisible(!global);
    revokeOnSleep->setVisible(global);
    const int index = lifetimePreset->findData(seconds);
    lifetimePreset->setCurrentIndex(index >= 0 ? index : lifetimePreset->count() - 1);
    lifetimeCustom->setValue(seconds ? seconds : 1800);
    policyEditor->show();
    proceed->setText(text(PromptI18n::Message::Save));
    setStatus(text(PromptI18n::Message::SettingsExplanation));
    updatePolicyControls();
    return true;
  }
  bool initializeConfirmation(const QJsonObject &job) {
    const auto value = job.value("value");
    QString target;
    if (operation == "rules.key") {
      subtitle->setText(text(PromptI18n::Message::KeyLifetime));
      if (value.isNull()) {
        target = text(PromptI18n::Message::InheritNewLifetime);
      } else {
        if (!value.isObject() || value.toObject().size() != 1) return false;
        const auto lifetime = value.toObject().value("lifetime_seconds");
        if (!lifetime.isDouble()) return false;
        const int seconds = lifetime.toInt(-1);
        if (seconds < 0 || seconds > 31536000 || lifetime.toDouble() != seconds) return false;
        target = text(PromptI18n::Message::NewLifetime) + duration(seconds);
      }
      setStatus(text(PromptI18n::Message::LifetimeExplanation));
    } else {
      if (!value.isNull()) return false;
      subtitle->setText(text(PromptI18n::Message::RemoveBinding));
      target = text(PromptI18n::Message::RemoveBindingTarget);
      setStatus(text(PromptI18n::Message::RemoveBindingExplanation));
    }
    if (!job.value("key").isObject() || fullName.isEmpty()) {
      return false;
    }
    requestDetails->setText(target + text(PromptI18n::Message::Program) + bounded(job.value("caller").toString(), 256)
                            + "\n" + bounded(job.value("reason").toString(), 512));
    requestDetails->show();
    proceed->setText(text(PromptI18n::Message::Confirm));
    return true;
  }
  bool initialize(const QJsonObject &job) {
    operation = job.value("operation").toString();
    confirmationOnly = confirmationOperation(operation);
    policyEditing = policyOperation(operation);
    const auto key = job.value("key").toObject();
    subtitle->setText(operation == "sync" ? text(PromptI18n::Message::FingerprintBinding) : operation == "encrypt" ? text(PromptI18n::Message::SetPassphrase) : text(PromptI18n::Message::SshKeyAccess));
    fullName = bounded(key.value("name").toString(), 256);
    fingerprintIdentity = bounded(key.value("fingerprint").toString(), 128);
    if (operation == "unlock") metadataDuration = text(PromptI18n::Message::AccessDuration) +
        duration(job.value("rules").toObject().value("lifetime_seconds").toInt());
    keyMetadata->setText(fingerprintIdentity + metadataDuration);
    keyMetadata->setVisible(!fingerprintIdentity.isEmpty() || !metadataDuration.isEmpty());
    const QString caller = bounded(job.value("caller").toString(), 256);
    const QString executable = caller.section(QStringLiteral(" (PID "), 0, 0);
    // The transport executable does not attest that a person clicked the bar.
    // Report it literally instead of promoting panel-client to trusted UI intent.
    const QString callerName = executable.startsWith('/') ? executable.section('/', -1) : caller;
    details->setText(bounded(key.value("fingerprint").toString(), 128) + "\n" +
                     bounded(key.value("path").toString(), 2048) +
                     (operation == "unlock" ? text(PromptI18n::Message::AccessDuration) +
                         duration(job.value("rules").toObject().value("lifetime_seconds").toInt()) : QString()) +
                     text(PromptI18n::Message::Source) + caller);
    // Capture the saved choice once. An unbound key always requires its SSH
    // passphrase, even if old settings still contain fingerprint_mode=true.
    fingerprintMode = operation == "unlock" && job.value("bound").toBool()
                      && job.value("fingerprint_mode").toBool();
    if (operation == "unlock") subtitle->setText(fingerprintMode
        ? text(PromptI18n::Message::FingerprintUnlock) : text(PromptI18n::Message::PassphraseUnlock));
    subtitle->setVisible(operation != "unlock");
    steps->setVisible(operation == "sync");
    stepFingerprint->setEnabled(false);
    if (policyEditing) {
      if (!initializePolicy(job)) return false;
      requestDetails->setText(text(PromptI18n::Message::Request) + callerName);
      requestDetails->show();
    } else if (confirmationOnly) {
      if (!initializeConfirmation(job)) return false;
    } else if (operation == "encrypt") {
      proceed->setText(text(PromptI18n::Message::Continue));
      setStatus(text(PromptI18n::Message::EncryptionExplanation));
    } else if (operation == "sync") {
      proceed->setText(text(PromptI18n::Message::Bind));
      setStatus(text(PromptI18n::Message::BindingExplanation));
    } else {
      QString request = text(PromptI18n::Message::Request) + callerName;
      const QString reason = bounded(job.value("reason").toString(), 512).trimmed();
      if (!reason.isEmpty())
        request += "\n" + reason;
      requestDetails->setText(request);
      requestDetails->show();
      setStatus(fingerprintMode ? text(PromptI18n::Message::ScannerStarting) : QString(), fingerprintMode);
      proceed->setVisible(!fingerprintMode);
      if (!fingerprintMode) {
        armed = true;
        pass->show();
      }
    }
    proceed->setEnabled(true);
    present();
    if (operation == "unlock" && !fingerprintMode) pass->setFocus();
    return true;
  }
  void submit() {
    if (sent || finished || !initialized) return;
    if (policyEditing) {
      lifetimeCustom->interpretText();
      const int seconds = lifetimePreset->currentData().toInt() < 0
          ? lifetimeCustom->value() : lifetimePreset->currentData().toInt();
      QJsonObject value{{"lifetime_seconds", seconds}};
      if (operation == "settings.global") value.insert("revoke_on_sleep", revokeOnSleep->isChecked());
      else value.insert("inherits", inheritPolicy->isChecked());
      if (!send(QJsonObject{{"consent", true}, {"mode", "settings"}, {"passphrase", ""},
                           {"confirmation", ""}, {"value", value}})) {
        finished = true; reject(); return;
      }
      sent = true;
      clearSecrets();
      policyEditor->setEnabled(false);
      proceed->setEnabled(false);
      setStatus(text(PromptI18n::Message::Working), true);
      fitContent();
      return;
    }
    if (confirmationOnly) {
      if (!send(QJsonObject{{"consent", true}, {"mode", "confirm"}, {"passphrase", ""}, {"confirmation", ""}})) {
        finished = true; reject(); return;
      }
      sent = true;
      clearSecrets();
      proceed->setEnabled(false);
      setStatus(text(PromptI18n::Message::Working), true);
      fitContent();
      return;
    }
    if (!armed) {
      armed = true;
      if (operation != "unlock") {
        pass->show();
        confirm->setVisible(operation == "encrypt");
        proceed->setText(operation == "encrypt" ? text(PromptI18n::Message::SetPassphraseButton) : text(PromptI18n::Message::Continue));
        if (operation == "sync") setStatus(text(PromptI18n::Message::EnterPassphrase));
        fitContent();
        pass->setFocus();
        return;
      }
    }
    if (!fingerprintMode && pass->text().isEmpty()) {
      setStatus(text(PromptI18n::Message::EnterNonemptyPassphrase)); fitContent(); return;
    }
    if (operation == "encrypt" && pass->text() != confirm->text()) {
      setStatus(text(PromptI18n::Message::PassphraseMismatch)); fitContent(); return;
    }
    const QString mode = fingerprintMode ? "fingerprint" : "password";
    if (!send(QJsonObject{{"consent", true}, {"mode", mode}, {"passphrase", mode == "password" ? pass->text() : QString()}, {"confirmation", operation == "encrypt" ? confirm->text() : QString()}})) {
      finished = true; reject(); return;
    }
    sent = true;
    clearSecrets();
    pass->hide(); confirm->hide();
    proceed->setEnabled(false);
    setStatus(fingerprintMode ? text(PromptI18n::Message::ScannerStarting) :
        operation == "encrypt" ? text(PromptI18n::Message::PassphraseSetting) : text(PromptI18n::Message::PassphraseVerifying), true);
    fitContent();
  }
};

#ifndef SSH_KEYS_UI_TEST
int main(int argc, char **argv) {
  rlimit core{0, 0};
  if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 1;
  ucred peer{};
  socklen_t size = sizeof(peer);
  if (getsockopt(3, SOL_SOCKET, SO_PEERCRED, &peer, &size) || peer.uid != 0 || getuid() == 0) return 1;
  if (qEnvironmentVariable("WAYLAND_SOCKET") != QStringLiteral("4")) return 1;
  int domain = 0, type = 0;
  socklen_t optionSize = sizeof(domain);
  if (getsockopt(4, SOL_SOCKET, SO_DOMAIN, &domain, &optionSize) || domain != AF_UNIX) return 1;
  optionSize = sizeof(type);
  if (getsockopt(4, SOL_SOCKET, SO_TYPE, &type, &optionSize) || type != SOCK_STREAM) return 1;
  peer = {};
  size = sizeof(peer);
  if (getsockopt(4, SOL_SOCKET, SO_PEERCRED, &peer, &size) || peer.uid != getuid() || peer.pid <= 0) return 1;
  if (!configureSecretInput()) return 1;
  QApplication app(argc, argv);
  app.setApplicationName("KeyController");
  app.setDesktopFileName("org.omarchy.keycontroller.prompt");
  Prompt prompt(3);
  QObject::connect(&prompt, &QDialog::finished, &app, [&app](int result) { app.exit(result); });
  return app.exec();
}
#endif
