import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import Quickshell.Io
import qs.Ui
import qs.Commons
import "KeyLocale.js" as KeyLocale

ColumnLayout {
  id: root
  objectName: "ssh-keys-dependencies"
  property bool monitoringEnabled: true
  property bool panelOpen: false
  property string uiLanguage: "en"
  property string status: "checking"
  property var missing: []
  property bool installable: false
  property bool installing: false
  property bool setupRequired: false
  property string errorCode: ""
  property double launchUntil: 0
  property bool launchPending: false
  property bool received: false
  property bool checking: false
  property bool reportReady: false
  readonly property bool ready: !monitoringEnabled || reportReady
  readonly property bool helperUnavailable: status === "missing" && missing.some(function(item) {
    return item.name === "keycontroller" && !item.available && item.reason === "repository_unavailable"
  })
  readonly property string packageStatusUrl: "https://github.com/omacom/omarchy-pkgs/pull/857"
  readonly property string script: decodeURIComponent(Qt.resolvedUrl("dependencies").toString().replace(/^file:\/\//, ""))
  signal languageDetected(string language)
  function t(source) { return KeyLocale.text(uiLanguage, source) }
  function fail(code) {
    reportReady = false
    status = "error"
    errorCode = code
    installable = false
    setupRequired = false
  }
  function accept(reply) {
    if (!reply || reply.schema_version !== 1 || ["ready", "missing", "error"].indexOf(reply.state) < 0
        || ["ru", "en"].indexOf(reply.ui_language) < 0 || !Array.isArray(reply.missing)
        || typeof reply.installable !== "boolean" || typeof reply.installing !== "boolean"
        || typeof reply.setup_required !== "boolean" || typeof reply.migration_required !== "boolean")
      throw new Error("Invalid dependency status")
    if (reply.missing.length > 20 || reply.missing.some(function(item) {
      return !item || typeof item.name !== "string" || !/^[a-z0-9][a-z0-9+_.-]*$/.test(item.name)
        || typeof item.requirement !== "string" || item.requirement.length > 100
        || typeof item.available !== "boolean" || (item.repository !== null && typeof item.repository !== "string")
    })) throw new Error("Invalid dependency list")
    if (reply.state === "ready" && reply.missing.length) throw new Error("Incomplete dependencies")
    received = true
    if (reply.complete !== false) languageDetected(reply.ui_language)
    if (JSON.stringify(missing) !== JSON.stringify(reply.missing)) missing = reply.missing
    installable = reply.installable
    installing = reply.installing
    setupRequired = reply.state === "ready" && (reply.setup_required || reply.migration_required)
    errorCode = reply.error_code || ""
    if (installing || Date.now() >= launchUntil || (reply.state === "ready" && !setupRequired)) launchPending = false
    // A background recheck must not remove and recreate the key controls.
    status = reply.state
    // Publish readiness once the entire report has been validated/applied.
    // An intermediate assignment must not refresh the API during setup.
    reportReady = reply.state === "ready" && !setupRequired && !reply.installing
  }
  function check() {
    if (!monitoringEnabled || checking || probe.running) return
    checking = true
    received = false
    watchdog.restart()
    startCheck()
  }
  function startCheck() {
    runCheck()
  }
  function runCheck() {
    probe.command = ["/bin/sh", script, "--check", "--json"]
    probe.running = true
  }
  function install() {
    if ((!installable && !setupRequired) || checking || installing || launchPending || launcher.running) return
    launchUntil = Date.now() + 8000
    launchPending = true
    startInstall()
  }
  function startInstall() {
    runInstall()
  }
  function runInstall() {
    // A visible original terminal owns sudo/Pacman's prompts. No password is
    // accepted by QML, nor is plugin-supplied Python ever executed as root.
    launcher.command = wizardCommand()
    launcher.running = true
  }
  function wizardCommand() {
    return ["/usr/bin/omarchy", "launch", "terminal", "/bin/sh", script, "--wizard"]
  }
  function reason(item) {
    if (item.available) return item.repository || root.t("Системный репозиторий")
    if (item.reason === "repository_version_too_old") return root.t("Нужна более новая версия")
    if (item.reason === "repository_signatures_disabled") return root.t("Проверка подписи пакета отключена")
    return root.t("Нет в подключённых репозиториях")
  }
  spacing: Style.space(12)
  onPanelOpenChanged: if (panelOpen) check()
  Component.onCompleted: check()

  Process {
    id: probe
    objectName: "ssh-keys-dependency-probe"
    stdout: StdioCollector {
      onStreamFinished: {
        try { root.accept(JSON.parse(text)) }
        catch (error) { root.fail("invalid_response") }
      }
    }
    stderr: StdioCollector {}
    onExited: function(exitCode) {
      watchdog.stop()
      Qt.callLater(function() {
        root.checking = false
        if (!root.received) root.fail("check_failed")
      })
    }
  }
  Timer {
    id: watchdog
    interval: 20000
    onTriggered: {
      probe.running = false
      root.checking = false
      root.fail("check_timeout")
    }
  }
  Process {
    id: launcher
    stdout: StdioCollector {}
    stderr: StdioCollector {}
    onExited: function(exitCode) {
      if (exitCode !== 0) {
        root.launchPending = false
        root.errorCode = "terminal_unavailable"
      }
      root.check()
    }
  }
  Timer {
    interval: 3000
    repeat: true
    running: root.monitoringEnabled && ((root.panelOpen && !root.ready) || root.launchPending || root.installing)
    onTriggered: root.check()
  }
  KeyAction {
    objectName: "ssh-keys-install-dependencies"
    Layout.fillWidth: true
    implicitHeight: Style.space(42)
    text: root.installing || root.launchPending ? root.t("Настройка в терминале…")
      : root.status === "checking" ? root.t("Проверка пакетов…")
      : root.helperUnavailable ? root.t("Пакет пока недоступен")
      : root.setupRequired ? root.t("Настроить KeyController") : root.t("Установить и настроить")
    iconText: root.installing || root.launchPending || root.status === "checking" ? "\uf110" : "\uf019"
    busy: root.installing || root.launchPending || root.status === "checking"
    enabled: (root.installable || root.setupRequired) && !root.checking && !root.installing && !root.launchPending
    onClicked: root.install()
  }
  Text {
    objectName: "ssh-keys-setup-scope"
    Layout.fillWidth: true
    visible: root.installable || root.setupRequired || root.installing || root.launchPending
    text: root.t("Мастер установит нужные пакеты, подключит основной SSH-агент и инструкции для ИИ. Настройки сохранятся в резервной копии; исключения для отдельных серверов останутся.")
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
    font.family: Style.font.family
    font.pixelSize: Style.font.bodySmall
    color: Util.alpha(Color.popups.text, 0.65)
  }
  BorderSurface {
    Layout.fillWidth: true
    visible: root.missing.length > 0
    implicitHeight: packages.implicitHeight + Style.space(24)
    radius: Style.cornerRadius
    color: "transparent"
    borderSpec: Border.flat(Util.alpha(Color.popups.text, 0.12), Style.space(1))
    ColumnLayout {
      id: packages
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.margins: Style.space(12)
      spacing: Style.space(10)
      Repeater {
        model: root.missing
        delegate: ColumnLayout {
          required property var modelData
          Layout.fillWidth: true
          spacing: Style.space(3)
          Text {
            Layout.fillWidth: true
            text: modelData.requirement
            textFormat: Text.PlainText
            font.family: Style.font.family
            font.pixelSize: Style.font.body
            color: Color.popups.text
            elide: Text.ElideRight
          }
          Text {
            Layout.fillWidth: true
            text: root.reason(modelData)
            textFormat: Text.PlainText
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            color: Util.alpha(Color.popups.text, 0.6)
            wrapMode: Text.Wrap
          }
        }
      }
    }
  }
  Text {
    objectName: "ssh-keys-dependencies-message"
    Layout.fillWidth: true
    visible: text !== ""
    text: root.errorCode === "terminal_unavailable" ? root.t("Не удалось открыть терминал")
      : root.errorCode === "unsupported_repositories" ? root.t("Автоматическая установка доступна со штатными репозиториями Omarchy/Arch. Обнаружены другие репозитории; их настройки не изменены.")
      : root.errorCode === "repository_signatures_disabled" ? root.t("Все подключённые репозитории должны требовать доверенную подпись пакетов.")
      : root.helperUnavailable ? root.t("Системный пакет keycontroller пока недоступен в подключённых репозиториях. После его появления нажмите «Проверить снова».")
      : root.errorCode === "python_required" ? root.t("Мастер начнёт с Python, затем проверит остальные пакеты и продолжит настройку")
      : root.status === "error" ? root.t("Не удалось проверить пакеты")
      : root.missing.some(function(item) { return !item.available }) ? root.t("Проверьте репозитории и обновления системы")
      : root.setupRequired || root.status === "missing" ? root.t("Следуйте подсказкам мастера. Команды вводить не нужно.") : ""
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
    font.family: Style.font.family
    font.pixelSize: Style.font.bodySmall
    color: Util.alpha(Color.popups.text, 0.65)
  }
  KeyAction {
    objectName: "ssh-keys-package-status"
    visible: root.helperUnavailable
    text: root.t("Статус публикации пакета")
    iconText: "\uf08e"
    bordered: false
    onClicked: Qt.openUrlExternally(root.packageStatusUrl)
  }
  KeyAction {
    visible: root.status !== "checking"
    text: root.t("Проверить снова")
    iconText: "\uf021"
    enabled: !root.checking
    bordered: false
    onClicked: root.check()
  }
}
