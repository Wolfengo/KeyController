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
  readonly property bool ready: !monitoringEnabled || (status === "ready" && !setupRequired)
  readonly property string script: decodeURIComponent(Qt.resolvedUrl("dependencies").toString().replace(/^file:\/\//, ""))
  signal languageDetected(string language)
  function t(source) { return KeyLocale.text(uiLanguage, source) }
  function fail(code) {
    status = "error"
    errorCode = code
    installable = false
    setupRequired = false
  }
  function accept(reply) {
    if (!reply || reply.schema_version !== 1 || ["ready", "missing", "error"].indexOf(reply.state) < 0
        || ["ru", "en"].indexOf(reply.ui_language) < 0 || !Array.isArray(reply.missing)
        || typeof reply.installable !== "boolean" || typeof reply.installing !== "boolean")
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
    setupRequired = reply.state === "ready" && reply.setup_required === true
    errorCode = reply.error_code || ""
    if (installing || Date.now() >= launchUntil || (reply.state === "ready" && !setupRequired)) launchPending = false
    // A background recheck must not remove and recreate the key controls.
    status = reply.state
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
    launcher.command = ["/usr/bin/omarchy", "launch", "terminal", "/bin/sh", script, setupRequired ? "--setup" : "--install"]
    launcher.running = true
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
    text: root.installing || root.launchPending ? root.t("Установка в терминале…")
      : root.status === "checking" ? root.t("Проверка пакетов…") : root.setupRequired ? root.t("Настроить KeyController") : root.t("Установить пакеты")
    iconText: root.installing || root.launchPending || root.status === "checking" ? "\uf110" : "\uf019"
    busy: root.installing || root.launchPending || root.status === "checking"
    enabled: (root.installable || root.setupRequired) && !root.checking && !root.installing && !root.launchPending
    onClicked: root.install()
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
    Layout.fillWidth: true
    visible: text !== ""
    text: root.errorCode === "terminal_unavailable" ? root.t("Не удалось открыть терминал")
      : root.errorCode === "python_required" ? root.t("Сначала установите Python, затем проверим остальные пакеты")
      : root.status === "error" ? root.t("Не удалось проверить пакеты")
      : root.setupRequired ? root.t("Подключить управляемый SSH-агент и инструкции для ИИ")
      : root.missing.some(function(item) { return item.name === "keycontroller" && !item.available })
        ? root.t("Установите системный пакет keycontroller из выпуска KeyController")
      : root.missing.some(function(item) { return !item.available }) ? root.t("Проверьте репозитории и обновления системы")
      : root.status === "missing" ? root.t("Установка откроется в терминале. Полный список покажет Pacman") : ""
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
    font.family: Style.font.family
    font.pixelSize: Style.font.bodySmall
    color: Util.alpha(Color.popups.text, 0.65)
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
