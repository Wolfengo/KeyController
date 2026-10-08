import QtQuick
import "KeyLocale.js" as KeyLocale
import QtQuick.Controls as Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons

Panel {
  id: root
  moduleName: "org.omarchy.keycontroller"
  ipcTarget: "org.omarchy.keycontroller"
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight
  property bool checkDependencies: manageIpc
  readonly property bool dependenciesReady: dependencies.ready
  function startDependencyCheck() { dependencies.runCheck() }
  function startDependencyInstall() { dependencies.runInstall() }

  // The helper's system locale is authoritative; Qt is only the startup fallback.
  property string uiLanguage: KeyLocale.language(Qt.locale().name)
  onUiLanguageChanged: if (message) message = KeyLocale.notice(uiLanguage, message)
  function t(source) { return KeyLocale.text(uiLanguage, source) }
  function receiveLanguage(value) {
    if (value !== "ru" && value !== "en") throw new Error("Invalid UI language metadata")
    if (uiLanguage !== value) uiLanguage = value
  }

  property var rows: []
  property var globalRules: ({lifetime_seconds: 0, revoke_on_sleep: false})
  property bool globalRulesReady: false
  property string activeRequest: ""
  property string activeRequestKey: ""
  onActiveRequestChanged: if (!activeRequest) activeRequestKey = ""
  property string message: ""
  property bool showCandidates: false
  property bool firstScanRequested: false
  property string settingsKey: ""
  property var settingsRow: null
  property bool settingsOpen: false
  property int settingsRevision: 0
  property int globalSaveRevision: -1
  property bool detailsExpanded: false
  property double clockSeconds: Math.floor(Date.now() / 1000)
  property string currentAction: ""
  property string deferredAction: ""
  property var queuedCall: null
  // Process.running notifies asynchronously. Latch accepted clicks here so
  // progress and duplicate protection take effect in the same input event.
  property string submittingAction: ""
  property string submittingKey: ""
  property bool rpcInFlight: false
  property int rpcSerial: 0
  property bool rpcReplied: false
  property bool rpcTimedOut: false
  readonly property bool launchingUnlock: submittingAction === "keys.unlock"
  readonly property bool requestBusy: launchingUnlock || activeRequest !== ""
  readonly property bool actionBusy: submittingAction !== "" || queuedCall !== null || (rpc.running && !isPoll(currentAction))
  readonly property var visibleRows: showCandidates ? rows : rows.filter(function(k, i, a) {
    return k.encrypted && a.findIndex(function(other) { return other.key_id === k.key_id && other.encrypted }) === i
  })

  function isPoll(action) { return action === "panel.list" || action === "requests.status" }
  function clearSubmission(action) {
    if (submittingAction !== action) return
    submittingAction = ""
    submittingKey = ""
  }
  function dispatchCall(action, key, value, request) {
    currentAction = action
    rpcSerial++
    rpcInFlight = true
    rpcReplied = false
    rpcTimedOut = false
    rpcWatchdog.restart()
    try {
      var started = startCall(action, key, value, request)
      if (!started || !rpc.running) {
        rpcInFlight = false
        rpcWatchdog.stop()
        clearSubmission(action)
      }
      return started
    } catch (error) {
      rpcInFlight = false
      rpcWatchdog.stop()
      clearSubmission(action)
      message = describe("helper_unavailable")
      return false
    }
  }
  function call(action, key, value, request) {
    if (!dependenciesReady) return false
    if (submittingAction || queuedCall) return false
    if (rpcInFlight || rpc.running) {
      if (isPoll(action) || !isPoll(currentAction)) return false
      submittingAction = action
      submittingKey = key || ""
      queuedCall = {action: action, key: key, value: value, request: request}
      followup.restart()
      return true
    }
    if (!isPoll(action)) {
      submittingAction = action
      submittingKey = key || ""
    }
    return dispatchCall(action, key, value, request)
  }
  function startCall(action, key, value, request) {
    currentAction = action
    rpc.command = ["/usr/lib/ssh-keys/panel-client", JSON.stringify({
      api_version: 1, action: action, key: key || null, value: value === undefined ? null : value,
      request_id: request || null, interactive: true, reason: ""
    })]
    rpc.running = true
    return true
  }
  function defer(action) { deferredAction = action; followup.restart() }
  function refresh() { call("panel.list") }
  function showRequestFailure(reply) {
    // A rejected/cancelled request must never bring the panel back over the
    // user's work or lock screen. Startup and operation errors remain visible.
    if (reply.state !== "error" && reply.state !== "partial") return false
    return ["cancelled", "biometric_denied", "session_locked", "session_locked_or_unavailable", "sleep_in_progress"].indexOf(reply.error_code) === -1
  }
  function updateRows(nextRows) {
    if (JSON.stringify(rows) !== JSON.stringify(nextRows)) rows = nextRows
  }
  function updateKeyStatus(reply) {
    // Access and preferences belong to the fingerprint; file metadata belongs
    // to each discovered path. Do not replace aliases with the canonical row.
    var fields = ["state", "bound", "mode", "rules", "inherits", "lifetime_known", "expires_at"]
    var nextRows = rows.map(function(row) {
      if (row.key_id !== reply.key_id) return row
      var next = Object.assign({}, row)
      fields.forEach(function(field) { if (reply[field] !== undefined) next[field] = reply[field] })
      next.busy = !!reply.busy
      // A direct revoke may coexist with sync/encrypt, which never load a
      // key. Its null request_id describes this reply, not the ongoing job.
      if (!next.busy) { next.request_id = null; delete next.operation }
      return next
    })
    updateRows(nextRows)
    if (settingsRow) {
      var current = nextRows.find(function(row) { return row.path === settingsRow.path })
      if (current) settingsRow = current
    }
    if (reply.operation === "revoke" && !reply.busy && activeRequestKey === reply.key_id) activeRequest = ""
  }
  function validGlobalRules(rules) {
    return !!rules && Object.keys(rules).length === 2 && typeof rules.revoke_on_sleep === "boolean"
      && typeof rules.lifetime_seconds === "number" && Number.isInteger(rules.lifetime_seconds)
      && rules.lifetime_seconds >= 0 && rules.lifetime_seconds <= 31536000
  }
  function receiveGlobalRules(rules) {
    if (!validGlobalRules(rules)) throw new Error("Invalid global settings metadata")
    var first = !globalRulesReady
    if (JSON.stringify(globalRules) !== JSON.stringify(rules)) globalRules = rules
    globalRulesReady = true
    // A form opened before the first reply cannot edit defaults. Fill it once
    // with authoritative metadata; later polling must preserve the user's draft.
    if (first && settingsOpen && !settingsRow) {
      lifetime.value = rules.lifetime_seconds
      sleepRevoke.checked = rules.revoke_on_sleep
    }
  }
  function applyGlobalRules(reply) {
    var rules = reply.global_rules
    var partial = reply.state === "partial" && reply.error_code === "settings_durability_unknown"
    if ((!partial && (reply.state !== "ready" || reply.error_code)) || reply.operation !== "rules.global" || reply.request_id !== null
        || !validGlobalRules(rules))
      throw new Error("Invalid global settings response")
    receiveGlobalRules(rules)
    // Per-key lifetime rules govern future loads. Do not change current state, known expiry,
    // biometric preferences, or a key's explicitly configured rules.
    updateRows(rows.map(function(row) {
      return row.inherits ? Object.assign({}, row, {rules: {lifetime_seconds: rules.lifetime_seconds}}) : row
    }))
    // A reply to an older form must not dismiss another draft opened meanwhile.
    if (!partial && !settingsRow && settingsRevision === globalSaveRevision) settingsOpen = false
  }
  function reconcileVisibleRows() {
    // Replacing a JS-array Repeater model destroys every row on each poll.
    // Preserve delegates and focus; only insert, move, remove or update changes.
    for (var i = 0; i < visibleRows.length; ++i) {
      var row = visibleRows[i]
      var identity = row.path
      var signature = JSON.stringify(row)
      if (i >= visibleKeys.count || visibleKeys.get(i).identity !== identity) {
        var found = -1
        for (var j = i + 1; j < visibleKeys.count; ++j) {
          if (visibleKeys.get(j).identity === identity) { found = j; break }
        }
        if (found >= 0) visibleKeys.move(found, i, 1)
        else visibleKeys.insert(i, {identity: identity, signature: signature, rowData: row})
      }
      if (visibleKeys.get(i).signature !== signature) {
        visibleKeys.setProperty(i, "rowData", row)
        visibleKeys.setProperty(i, "signature", signature)
      }
    }
    if (visibleKeys.count > visibleRows.length) visibleKeys.remove(visibleRows.length, visibleKeys.count - visibleRows.length)
  }
  onVisibleRowsChanged: reconcileVisibleRows()
  ListModel { id: visibleKeys; dynamicRoles: true }
  function settingsFor(row) {
    settingsRevision++
    settingsRow = row
    settingsKey = row ? row.key_id : ""
    inherit.checked = row ? row.inherits : false
    lifetime.value = row ? row.rules.lifetime_seconds : globalRules.lifetime_seconds
    if (!row) sleepRevoke.checked = globalRules.revoke_on_sleep === true
    detailsExpanded = !!row && (!!row.unavailable || row.unencrypted_copies.length > 0)
    settingsOpen = true
  }
  function keyCountText(count) { return KeyLocale.keyCount(uiLanguage, count) }
  function durationLabel(seconds) {
    if (!seconds) return root.t("без ограничения")
    if (seconds % 3600 === 0) return (seconds / 3600) + root.t(" ч")
    if (seconds % 60 === 0) return (seconds / 60) + root.t(" мин")
    return seconds + root.t(" с")
  }
  function compactStateText(row, now) {
    if (row.unavailable) return root.t("Недоступен")
    if (row.busy) return root.t("Ожидание")
    if (!row.encrypted) return root.t("Без пароля")
    if (row.state !== "unlocked") return root.t("Закрыт")
    if (!row.lifetime_known) return root.t("Срок неизвестен")
    if (!row.expires_at) return "∞"
    var remaining = Math.max(0, Math.ceil(row.expires_at - now))
    if (remaining >= 86400) return Math.floor(remaining / 86400) + root.t(" д ") + Math.floor(remaining / 3600) % 24 + root.t(" ч")
    if (remaining >= 3600) return Math.floor(remaining / 3600) + root.t(" ч ") + Math.floor(remaining / 60) % 60 + root.t(" мин")
    return String(Math.floor(remaining / 60)).padStart(2, "0") + ":" + String(remaining % 60).padStart(2, "0")
  }
  function candidateText(row) {
    var state = row.unavailable ? root.t("Недоступен") : row.encrypted ? root.t("Добавлен") : root.t("Без пароля")
    return state + " · " + row.path.replace(/^\/home\/[^/]+\//, "~/")
  }
  function stateText(row) {
    if (row.unavailable) return describe(row.unavailable)
    if (row.busy) return root.t("Операция выполняется…")
    if (!row.encrypted) return root.t("Без пароля")
    if (row.state !== "unlocked") return root.t("Закрыт")
    if (!row.lifetime_known) return root.t("Открыт · срок неизвестен")
    if (!row.expires_at) return root.t("Открыт · без ограничения")
    return root.t("Открыт до ") + new Date(row.expires_at * 1000).toLocaleTimeString()
  }
  function describe(code) {
    var labels = {
      scanned: root.t("Список обновлён"), encrypted: root.t("Пароль установлен; ключ закрыт"), synced: root.t("Привязка сохранена; ключ закрыт"),
      unlocked: root.t("Ключ разблокирован"), locked: root.t("Ключ отозван"), revoked: root.t("Ключи отозваны"), cancelled: root.t("Операция отменена"), denied: root.t("Доступ не подтверждён"), expired: root.t("Время ожидания истекло"),
      busy: root.t("Другая операция ещё выполняется"), cooldown: root.t("После отмены нужно подождать 30 секунд"), rate_limited: root.t("Слишком много запросов. Подождите минуту"),
      helper_unavailable: root.t("Системный помощник KeyController недоступен"), agent_unavailable: root.t("Управляемый SSH-агент недоступен"),
      prompt_unavailable: root.t("Не удалось открыть защищённое окно. Попробуйте ещё раз"), prompt_failed: root.t("Защищённое окно завершилось с ошибкой"),
      worker_failed: root.t("Помощник не смог завершить запрос"), io_error: root.t("Не удалось завершить обмен с защищённым окном"),
      session_locked_or_unavailable: root.t("Нужен активный разблокированный локальный сеанс"), biometric_denied: root.t("Отпечаток не подтверждён"),
      session_unavailable: root.t("Не удалось проверить защищённое соединение с Hyprland"),
      ptrace_protection_required: root.t("Для защиты ввода нужен kernel.yama.ptrace_scope ≥ 1"), hardening_failed: root.t("Не удалось включить защиту процесса"),
      invalid_confirmation: root.t("Подтверждение недействительно"), invalid_passphrase: root.t("Пароль должен быть не длиннее 1023 байт, без перевода строки"),
      tpm_unavailable: root.t("TPM недоступен. Можно разблокировать ключ паролем"), credential_unavailable: root.t("Привязка недоступна. Используйте пароль или повторите привязку"),
      wrong_passphrase_or_invalid_key: root.t("Пароль не подошёл или файл ключа повреждён"), unlock_failed: root.t("Не удалось загрузить ключ"),
      unsupported_format: root.t("Формат не поддерживается; нужен OpenSSH"), unsupported_algorithm: root.t("Этот тип ключа не поддерживается"),
      outside_ssh_directory: root.t("Ссылка ведёт за пределы ~/.ssh"), multiple_hard_links: root.t("У файла несколько жёстких ссылок"),
      unsafe_key_file: root.t("Неверный владелец или слишком открытые права файла"), unsafe_directory: root.t("Небезопасные права каталога"),
      file_conflict: root.t("Файл изменился во время операции; исходник не заменён"), partial_commit: root.t("Файл уже зашифрован; последующий шаг не завершён. Обновите список"),
      commit_state_unknown: root.t("Не удалось подтвердить состояние файла после операции. Обновите список"),
      key_unavailable: root.t("Файл ключа недоступен. Обновите список"), key_not_found: root.t("Ключ больше не найден. Обновите список"),
      request_not_found: root.t("Запрос больше не найден"), not_bound: root.t("Сначала привяжите отпечаток"), empty_passphrase: root.t("Введите непустой пароль"),
      confirmation_mismatch: root.t("Пароли не совпадают"), operation_failed: root.t("Не удалось завершить операцию"), service_timeout: root.t("Помощник не ответил вовремя"),
      settings_durability_unknown: root.t("Настройки применены, но сохранность после сбоя не подтверждена."),
      sleep_in_progress: root.t("Идёт подготовка ко сну. Повторите после пробуждения."),
      api_mismatch: root.t("Несовместимые версии виджета и системного помощника")
    }
    return labels[code] || (root.t("Ошибка KeyController: ") + code)
  }
  function responseDescription(reply) {
    var code = reply.error_code || reply.state
    var text = describe(code)
    // Only an unlock cancellation/denial starts the service's cooldown.
    // Binding, revocation and settings confirmations do not delay access.
    if (reply.operation === "unlock" && ["cancelled", "denied", "biometric_denied"].indexOf(code) !== -1) text += root.t(" · пауза 30 с")
    return text
  }
  onOpenedChanged: if (opened) {
    clockSeconds = Math.floor(Date.now() / 1000)
    if (activeRequest) call("requests.status", null, null, activeRequest)
    else refresh()
  }

  Process {
    id: rpc
    objectName: "ssh-keys-rpc"
    stdout: StdioCollector {
      onStreamFinished: {
        if (root.rpcTimedOut) return
        try {
          var reply = JSON.parse(text)
          root.rpcReplied = true
          if (reply.api_version !== 1) { root.message = root.t("Несовместимая версия помощника"); return }
          if (reply.error_code) root.message = root.responseDescription(reply)
          else if (["synced", "encrypted", "cancelled", "denied", "expired", "partial"].indexOf(reply.state) !== -1) root.message = root.responseDescription(reply)
          if (root.currentAction === "rules.global") {
            if (!reply.error_code || (reply.state === "partial" && reply.error_code === "settings_durability_unknown")) {
              root.applyGlobalRules(reply)
              if (!reply.error_code) root.message = ""
              root.defer("panel.list")
            }
            return
          }
          if (reply.keys) {
            root.receiveLanguage(reply.ui_language)
            root.receiveGlobalRules(reply.global_rules)
            root.updateRows(reply.keys)
            // A completed worker disappears from panel.list before its result
            // is consumed. Retain the local ID until requests.status returns it.
            if (!root.activeRequest && reply.active_request) root.activeRequest = reply.active_request
            if (root.activeRequest && !root.activeRequestKey) {
              var activeRow = reply.keys.find(function(row) { return row.request_id === root.activeRequest })
              if (activeRow) root.activeRequestKey = activeRow.key_id
            }
            if (!reply.scanned && !root.firstScanRequested && !root.activeRequest) {
              root.firstScanRequested = true
              root.defer("scan")
            }
          }
          if (reply.state === "pending") {
            if (!reply.request_id) throw new Error("Missing request ID")
            root.activeRequest = reply.request_id
            if (reply.key_id) root.activeRequestKey = reply.key_id
            // The layer-shell popup otherwise covers the separate Qt window.
            if (["keys.unlock", "sync", "encrypt", "rules.key", "unbind"].indexOf(root.currentAction) !== -1) root.close()
          }
          else if (root.currentAction === "requests.status" || root.currentAction === "requests.cancel") {
            root.activeRequest = ""
            root.defer("panel.list")
            if (!root.opened && root.showRequestFailure(reply)) root.open()
          }
          else if (root.currentAction === "mode" || root.currentAction === "revoke") {
            if (!reply.error_code && reply.key_id && ["locked", "unlocked"].indexOf(reply.state) !== -1) {
              root.updateKeyStatus(reply)
              root.message = ""
            }
            root.defer("panel.list")
          }
        } catch (error) { root.message = root.t("Не удалось связаться с помощником KeyController") }
        finally { root.clearSubmission(root.currentAction) }
      }
    }
    stderr: StdioCollector { onStreamFinished: if (text.length) root.message = root.t("Помощник KeyController недоступен") }
    onExited: function(exitCode) {
      rpcWatchdog.stop()
      var action = root.currentAction
      var serial = root.rpcSerial
      // Collectors may finish in the same event-loop turn as Process exits.
      Qt.callLater(function() {
        if (root.rpcSerial !== serial) return
        root.rpcInFlight = false
        root.clearSubmission(action)
        if (exitCode === 127) root.message = root.t("Установите системный пакет keycontroller")
        else if (!root.rpcReplied && !root.rpcTimedOut) root.message = root.describe("helper_unavailable")
      })
    }
  }
  Timer {
    id: rpcWatchdog
    objectName: "ssh-keys-rpc-watchdog"
    interval: 12000
    onTriggered: {
      root.rpcTimedOut = true
      root.clearSubmission(root.currentAction)
      root.message = root.describe("service_timeout")
      rpc.running = false
      var serial = root.rpcSerial
      Qt.callLater(function() { if (root.rpcSerial === serial) root.rpcInFlight = false })
      // Do not retry an unlock or discard an accepted request. Its existing
      // ID remains available for status/cancellation after a transport error.
    }
  }
  Timer {
    id: followup
    interval: 20
    onTriggered: {
      if (root.rpcInFlight || rpc.running) { restart(); return }
      if (root.queuedCall) {
        var queued = root.queuedCall
        root.queuedCall = null
        root.dispatchCall(queued.action, queued.key, queued.value, queued.request)
        if (root.deferredAction) restart()
        return
      }
      var action = root.deferredAction
      root.deferredAction = ""
      if (action) root.call(action)
    }
  }
  Timer {
    interval: 1000; repeat: true; running: root.dependenciesReady && (root.opened || root.activeRequest !== "")
    onTriggered: {
      if (root.deferredAction) return
      if (root.activeRequest) root.call("requests.status", null, null, root.activeRequest)
      else root.refresh()
    }
  }
  // The clock never changes row metadata or recreates delegates.
  Timer {
    interval: 1000; repeat: true; running: root.opened
    onTriggered: root.clockSeconds = Math.floor(Date.now() / 1000)
  }
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    tooltipText: root.launchingUnlock ? root.t("KeyController · Открытие…") : root.activeRequest ? root.t("KeyController · Ожидание…") : "KeyController"
    Controls.BusyIndicator {
      objectName: "ssh-keys-bar-busy"
      anchors.right: parent.right
      anchors.bottom: parent.bottom
      width: Style.space(12)
      height: width
      running: root.requestBusy
      visible: running
      palette.windowText: Color.accent
      palette.text: Color.accent
      palette.dark: Color.accent
      palette.highlight: Color.accent
    }
    iconComponent: KeyControllerIcon {
      barIcon: true
      foreground: button.active && button.useActiveColor ? button.activeColor : button.foreground
    }
    onPressed: root.toggle()
  }
  KeyboardPanel {
    id: popup
    anchorItem: button; owner: root; bar: root.bar; open: root.opened
    padding: Style.space(20)
    contentWidth: popup.fittedContentWidth(Style.space(400))
    contentHeight: popup.fittedContentHeight(content.implicitHeight, Style.space(680))
    focusTarget: content
    ColumnLayout {
      id: content
      anchors.fill: parent
      spacing: Style.space(18)
      Keys.onEscapePressed: {
        if (root.settingsOpen) root.settingsOpen = false
        else if (root.showCandidates) root.showCandidates = false
        else root.close()
      }

      RowLayout {
        Layout.fillWidth: true
        Layout.minimumHeight: Style.space(44)
        spacing: Style.space(10)
        KeyAction {
          visible: root.dependenciesReady && (root.settingsOpen || root.showCandidates)
          iconText: "\uf104"
          bordered: false
          implicitWidth: Style.space(30)
          tooltipText: root.t("Назад")
          onClicked: { if (root.settingsOpen) root.settingsOpen = false; else root.showCandidates = false }
        }
        KeyControllerIcon {
          visible: !root.dependenciesReady || (!root.settingsOpen && !root.showCandidates)
          foreground: Color.popups.text
          Layout.preferredWidth: Style.font.display
          Layout.preferredHeight: Style.font.display
        }
        ColumnLayout {
          Layout.fillWidth: true
          spacing: Style.space(4)
          Text {
            Layout.fillWidth: true
            text: !root.dependenciesReady ? "KeyController" : root.settingsOpen ? (root.settingsRow ? root.settingsRow.name : root.t("Настройки")) : root.showCandidates ? root.t("Добавить ключ") : "KeyController"
            textFormat: Text.PlainText
            elide: Text.ElideRight
            color: Color.popups.text
            font.family: Style.font.family
            font.pixelSize: Style.fontPx(1.5)
            font.weight: Font.DemiBold
          }
          Text {
            objectName: "ssh-keys-summary"
            Layout.fillWidth: true
            text: !root.dependenciesReady ? root.t("Подготовка к работе") : root.settingsOpen ? (root.settingsRow ? root.t("Настройки ключа") : root.t("Общие настройки"))
              : root.showCandidates ? root.t("Найдены в ~/.ssh")
              : KeyLocale.keySummary(root.uiLanguage, root.visibleRows.length, root.visibleRows.filter(function(k) { return k.state === "unlocked" }).length)
            color: Util.alpha(Color.popups.text, 0.65)
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
            elide: Text.ElideRight
          }
        }
        Row {
          visible: root.dependenciesReady && !root.settingsOpen
          spacing: Style.space(4)
          KeyAction { implicitWidth: Style.space(30); implicitHeight: Style.space(32); bordered: false; iconText: "\uf021"; tooltipText: root.t("Обновить"); enabled: !root.activeRequest && !root.actionBusy; onClicked: root.call("scan") }
          KeyAction { implicitWidth: Style.space(30); implicitHeight: Style.space(32); bordered: false; iconText: "+"; selected: root.showCandidates; tooltipText: root.t("Добавить ключ"); onClicked: root.showCandidates = !root.showCandidates }
          KeyAction { implicitWidth: Style.space(30); implicitHeight: Style.space(32); bordered: false; iconText: "\uf013"; tooltipText: root.t("Настройки"); onClicked: root.settingsFor(null) }
        }
      }

      Rectangle {
        visible: root.dependenciesReady && root.message !== ""
        Layout.fillWidth: true
        implicitHeight: notice.implicitHeight + Style.space(16)
        radius: Style.cornerRadius
        color: Style.normalFillFor(Color.popups.text, Color.accent)
        RowLayout {
          id: notice
          anchors.left: parent.left; anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter
          anchors.margins: Style.space(8)
          Text { Layout.fillWidth: true; text: root.message; textFormat: Text.PlainText; color: Color.popups.text; wrapMode: Text.Wrap; font.family: Style.font.family; font.pixelSize: Style.font.bodySmall }
          KeyAction { bordered: false; iconText: "\uf00d"; tooltipText: root.t("Скрыть сообщение"); onClicked: root.message = "" }
        }
      }
      RowLayout {
        visible: root.dependenciesReady && root.activeRequest !== ""
        Controls.BusyIndicator { running: parent.visible; implicitWidth: Style.space(22); implicitHeight: Style.space(22) }
        Text { text: root.t("Ожидание…"); color: Color.popups.text; font.family: Style.font.family; font.pixelSize: Style.font.bodySmall; Layout.fillWidth: true }
        KeyAction { text: root.t("Отмена"); enabled: !root.actionBusy; onClicked: root.call("requests.cancel", null, null, root.activeRequest) }
      }

      Controls.ScrollView {
        id: scroll
        Layout.fillWidth: true
        Layout.fillHeight: true
        Layout.preferredHeight: Math.min(pages.implicitHeight, Style.space(500))
        clip: true
        contentWidth: availableWidth
        Controls.ScrollBar.horizontal.policy: Controls.ScrollBar.AlwaysOff
        Column {
          id: pages
          width: scroll.availableWidth
          KeyDependencies {
            id: dependencies
            width: parent.width
            visible: !ready
            monitoringEnabled: root.checkDependencies
            panelOpen: root.opened
            uiLanguage: root.uiLanguage
            function startCheck() { root.startDependencyCheck() }
            function startInstall() { root.startDependencyInstall() }
            onLanguageDetected: function(language) { root.receiveLanguage(language) }
            onReadyChanged: if (ready && root.opened) Qt.callLater(function() {
              if (root.dependenciesReady && root.opened) root.refresh()
            })
          }
          ColumnLayout {
            visible: root.dependenciesReady && root.settingsOpen
            width: parent.width
            spacing: Style.space(14)
            BorderSurface {
              Layout.fillWidth: true
              implicitHeight: settingsBody.implicitHeight + Style.space(30)
              radius: Style.cornerRadius
              color: "transparent"
              borderSpec: Border.flat(Util.alpha(Color.popups.text, 0.12), Style.space(1))
              ColumnLayout {
                id: settingsBody
                anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                anchors.margins: Style.space(15)
                spacing: Style.space(14)
                KeyAction {
                  id: inherit
                  objectName: "ssh-key-inherit"
                  property bool checked: false
                  property string label: root.t("Общий срок")
                  visible: !!root.settingsRow
                  Layout.fillWidth: true
                  implicitHeight: Style.space(44)
                  bordered: false
                  tooltipText: root.t("Наследовать общий срок доступа")
                  Accessible.role: Accessible.CheckBox
                  Accessible.checked: checked
                  onClicked: {
                    checked = !checked
                    if (checked) lifetime.value = root.globalRules.lifetime_seconds
                  }
                  RowLayout {
                    anchors.fill: parent
                    spacing: Style.space(12)
                    ColumnLayout {
                      Layout.fillWidth: true
                      spacing: Style.space(3)
                      Text { text: inherit.label; color: Color.popups.text; font.family: Style.font.family; font.pixelSize: Style.font.body }
                      Text { text: root.t("Сейчас ") + root.durationLabel(root.globalRules.lifetime_seconds); color: Util.alpha(Color.popups.text, 0.6); font.family: Style.font.family; font.pixelSize: Style.font.caption }
                    }
                    ToggleSwitch {
                      checked: inherit.checked
                      interactive: false
                      cursorRing: false
                      trackHeight: Style.space(19)
                      trackWidth: Style.space(33)
                      knobSize: Style.space(13)
                      foreground: Color.popups.text
                    }
                  }
                }
                PanelSeparator { visible: !!root.settingsRow; Layout.fillWidth: true; foreground: Color.popups.text }
                Text { text: root.t("Срок доступа"); color: Util.alpha(Color.popups.text, 0.65); font.family: Style.font.family; font.pixelSize: Style.font.body }
                KeyDuration {
                  id: lifetime
                  uiLanguage: root.uiLanguage
                  objectName: "ssh-key-lifetime"
                  Layout.fillWidth: true
                  enabled: root.settingsRow ? !inherit.checked : root.globalRulesReady && root.submittingAction !== "rules.global"
                }
                Text {
                  text: root.t("Применится при следующей разблокировке")
                  Layout.fillWidth: true
                  wrapMode: Text.WordWrap
                  color: Util.alpha(Color.popups.text, 0.55)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                }
                PanelSeparator { visible: !root.settingsRow; Layout.fillWidth: true; foreground: Color.popups.text }
                KeyAction {
                  id: sleepRevoke
                  objectName: "ssh-keys-revoke-on-sleep"
                  property bool checked: false
                  property string label: root.t("Отзывать перед сном")
                  visible: !root.settingsRow
                  Layout.fillWidth: true
                  implicitHeight: Style.space(36)
                  bordered: false
                  enabled: root.globalRulesReady && root.submittingAction !== "rules.global"
                  tooltipText: root.t("Отзывать все ключи управляемого SSH-агента перед сном")
                  Accessible.role: Accessible.CheckBox
                  Accessible.checked: checked
                  onClicked: if (enabled) checked = !checked
                  RowLayout {
                    anchors.fill: parent
                    spacing: Style.space(12)
                    Text {
                      Layout.fillWidth: true
                      text: sleepRevoke.label
                      color: Color.popups.text
                      font.family: Style.font.family
                      font.pixelSize: Style.font.body
                    }
                    ToggleSwitch {
                      checked: sleepRevoke.checked
                      interactive: false
                      cursorRing: false
                      trackHeight: Style.space(19)
                      trackWidth: Style.space(33)
                      knobSize: Style.space(13)
                      foreground: Color.popups.text
                    }
                  }
                }
              }
            }
            KeyAction {
              objectName: "ssh-key-save-rules"
              Layout.fillWidth: true
              text: !root.settingsRow && root.submittingAction === "rules.global" ? root.t("Сохранение…") : root.t("Сохранить")
              selected: true
              enabled: !root.actionBusy && (!!root.settingsRow || root.globalRulesReady)
              onClicked: {
                if (!root.settingsRow && !root.globalRulesReady) return
                var rules = {lifetime_seconds: lifetime.value}
                if (root.settingsRow) {
                  if (root.call("rules.key", root.settingsKey, inherit.checked ? null : rules)) root.settingsOpen = false
                } else {
                  rules.revoke_on_sleep = sleepRevoke.checked
                  var revision = root.settingsRevision
                  if (root.call("rules.global", root.settingsKey, rules)) root.globalSaveRevision = revision
                }
              }
            }
            ColumnLayout {
              visible: !!root.settingsRow
              Layout.fillWidth: true
              spacing: Style.space(10)
              PanelSeparator { Layout.fillWidth: true; foreground: Color.popups.text }
              Text {
                visible: root.settingsRow && (!!root.settingsRow.unavailable || root.settingsRow.unencrypted_copies.length > 0)
                text: root.settingsRow ? (root.settingsRow.unavailable ? root.describe(root.settingsRow.unavailable) : root.t("Есть незашифрованные копии ключа")) : ""
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: Color.urgent
                font.family: Style.font.family
                font.pixelSize: Style.font.bodySmall
              }
              KeyAction {
                text: root.t("О ключе")
                iconText: root.detailsExpanded ? "\uf107" : "\uf105"
                bordered: false
                horizontalPadding: 0
                foreground: Util.alpha(Color.popups.text, 0.7)
                tooltipText: root.t("Показать путь, отпечаток и состояние ключа")
                onClicked: root.detailsExpanded = !root.detailsExpanded
              }
              ColumnLayout {
                visible: root.detailsExpanded
                Layout.fillWidth: true
                spacing: Style.space(8)
                Text { text: root.settingsRow ? root.stateText(root.settingsRow) : ""; Layout.fillWidth: true; wrapMode: Text.Wrap; color: Color.popups.text; font.family: Style.font.family; font.pixelSize: Style.font.bodySmall }
                Text { text: root.settingsRow ? root.settingsRow.path : ""; textFormat: Text.PlainText; Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; color: Util.alpha(Color.popups.text, 0.65); font.family: Style.font.family; font.pixelSize: Style.font.bodySmall }
                Text { text: root.settingsRow ? root.settingsRow.fingerprint : ""; textFormat: Text.PlainText; Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; color: Util.alpha(Color.popups.text, 0.65); font.family: Style.font.family; font.pixelSize: Style.font.caption }
                Text { visible: root.settingsRow && root.settingsRow.unencrypted_copies.length > 0; text: root.settingsRow ? root.t("Незашифрованные копии\n") + root.settingsRow.unencrypted_copies.join("\n") : ""; textFormat: Text.PlainText; Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; color: Color.popups.text; font.family: Style.font.family; font.pixelSize: Style.font.bodySmall }
              }
              KeyAction {
                text: root.t("Удалить привязку")
                iconText: "\udb80\ude37"
                bordered: false
                horizontalPadding: 0
                foreground: Util.alpha(Color.popups.text, 0.65)
                visible: root.settingsRow && root.settingsRow.bound
                tooltipText: root.t("Отозвать ключ и удалить привязку отпечатка")
                enabled: !root.actionBusy
                onClicked: { if (root.call("unbind", root.settingsKey)) root.settingsOpen = false }
              }
            }
          }
          BorderSurface {
            visible: root.dependenciesReady && !root.settingsOpen
            width: parent.width
            implicitHeight: list.implicitHeight + Style.space(16)
            radius: Style.cornerRadius
            color: "transparent"
            borderSpec: Border.flat(Util.alpha(Color.popups.text, 0.12), Style.space(1))
            Column {
              id: list
              anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
              anchors.margins: Style.space(8)
              spacing: Style.space(8)
              Repeater {
                id: keyRepeater
                objectName: "ssh-key-rows"
                model: visibleKeys
                delegate: BorderSurface {
                  id: keyCard
                  required property var rowData
                  readonly property var modelData: rowData
                  readonly property bool loaded: modelData.state === "unlocked"
                  readonly property bool timed: loaded && modelData.lifetime_known && !!modelData.expires_at
                  readonly property bool launching: root.launchingUnlock && root.submittingKey === modelData.key_id
                  objectName: "ssh-key-row:" + modelData.path
                  width: list.width
                  implicitHeight: keyBody.implicitHeight + Style.space(28)
                  radius: Style.cornerRadius
                  color: loaded ? Style.selectedFillFor(Color.popups.text, Color.accent) : Style.normalFillFor(Color.popups.text, Color.accent)
                  borderSpec: loaded ? Border.controlSpec("selected", Color.popups.text, Color.accent) : Border.none()
                  ColumnLayout {
                    id: keyBody
                    anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                    anchors.leftMargin: Style.space(12); anchors.rightMargin: Style.space(12); anchors.topMargin: Style.space(14)
                    spacing: Style.space(14)
                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.space(8)
                      Text {
                        Layout.fillWidth: true
                        text: modelData.name
                        textFormat: Text.PlainText
                        elide: Text.ElideRight
                        color: Color.popups.text
                        font.family: Style.font.family
                        font.pixelSize: Style.font.title
                        font.weight: Font.DemiBold
                      }
                      KeyAction {
                        visible: modelData.unavailable || modelData.unencrypted_copies.length > 0
                        implicitWidth: Style.space(18)
                        implicitHeight: Style.space(18)
                        horizontalPadding: 0
                        verticalPadding: 0
                        bordered: false
                        iconText: "\uf071"
                        foreground: Color.urgent
                        tooltipText: modelData.unavailable ? root.describe(modelData.unavailable) : root.t("Есть незашифрованные копии")
                        onClicked: root.settingsFor(modelData)
                      }
                      Item {
                        // Keep the allotted space stable while the label ticks.
                        Layout.preferredWidth: keyCard.timed ? countdownMetrics.width + Style.space(10) : stateLabel.implicitWidth
                        implicitHeight: stateLabel.implicitHeight
                        TextMetrics { id: countdownMetrics; font.family: Style.font.family; font.pixelSize: Style.font.bodySmall; text: root.t("000 д 00 ч") }
                        Row {
                          id: stateLabel
                          anchors.right: parent.right
                          spacing: Style.space(5)
                          Rectangle {
                            width: Style.space(5); height: width; radius: width / 2
                            anchors.verticalCenter: parent.verticalCenter
                            color: keyCard.loaded ? Color.accent : Util.alpha(Color.popups.text, 0.45)
                          }
                          Text {
                            objectName: "ssh-key-state"
                            text: root.compactStateText(modelData, root.clockSeconds)
                            color: keyCard.loaded ? Color.accent : Util.alpha(Color.popups.text, 0.65)
                            font.family: Style.font.family
                            font.pixelSize: Style.font.bodySmall
                            font.features: ({"tnum": 1})
                            Accessible.name: root.stateText(modelData)
                          }
                        }
                      }
                    }
                    Text {
                      visible: root.showCandidates
                      Layout.fillWidth: true
                      text: root.candidateText(modelData)
                      textFormat: Text.PlainText
                      elide: Text.ElideMiddle
                      color: Util.alpha(Color.popups.text, 0.65)
                      font.family: Style.font.family
                      font.pixelSize: Style.font.bodySmall
                    }
                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.space(8)
                      KeyAction {
                        visible: !root.showCandidates
                        objectName: "ssh-key-method"
                        text: modelData.bound ? (modelData.mode === "fingerprint" ? root.t("Отпечаток ⇅") : root.t("Пароль ⇅")) : root.t("Привязать")
                        iconText: modelData.bound ? (modelData.mode === "fingerprint" ? "\udb80\ude37" : "\uf084") : "\uf0c1"
                        fontSize: Style.font.bodySmall
                        horizontalPadding: Style.space(2)
                        bordered: false
                        foreground: Util.alpha(Color.popups.text, 0.7)
                        tooltipText: !modelData.bound ? root.t("Привязать отпечаток; ключ останется закрытым") : modelData.mode === "fingerprint" ? root.t("Следующая разблокировка: переключить на пароль") : root.t("Следующая разблокировка: переключить на отпечаток")
                        enabled: !root.activeRequest && !root.actionBusy && (modelData.bound || !modelData.unavailable)
                        onClicked: root.call(modelData.bound ? "mode" : "sync", modelData.key_id,
                          modelData.bound ? {fingerprint_mode: modelData.mode !== "fingerprint"} : null)
                      }
                      Item { Layout.fillWidth: true }
                      KeyAction {
                        visible: root.showCandidates
                        objectName: "ssh-key-encrypt"
                        text: modelData.encrypted ? root.t("Добавлен") : root.t("Установить пароль")
                        iconText: modelData.encrypted ? "\uf00c" : "\uf023"
                        tooltipText: modelData.encrypted ? root.t("Уже добавлен") : root.t("Установить пароль")
                        enabled: !modelData.encrypted && !modelData.unavailable && !root.activeRequest && !root.actionBusy
                        onClicked: root.call("encrypt", modelData.path)
                      }
                      KeyAction {
                        visible: !root.showCandidates
                        objectName: "ssh-key-access"
                        text: keyCard.launching ? root.t("Открытие…") : keyCard.loaded ? root.t("Закрыть") : root.t("Открыть")
                        iconText: keyCard.launching ? "\uf110" : keyCard.loaded ? "\uf09c" : "\uf023"
                        busy: keyCard.launching
                        fontSize: Style.font.body
                        selected: keyCard.loaded
                        tooltipText: keyCard.loaded ? root.t("Отозвать ключ") : root.t("Разблокировать ключ")
                        enabled: (keyCard.loaded || (!root.activeRequest && !modelData.unavailable)) && !root.actionBusy
                        onClicked: root.call(keyCard.loaded ? "revoke" : "keys.unlock", modelData.key_id, null)
                      }
                      KeyAction {
                        implicitWidth: Style.space(28)
                        bordered: false
                        iconText: "\uf013"
                        tooltipText: root.t("Сведения и настройки")
                        foreground: Util.alpha(Color.popups.text, 0.7)
                        onClicked: root.settingsFor(modelData)
                      }
                    }
                  }
                }
              }
              Item {
                visible: root.visibleRows.length === 0
                width: parent.width; height: Style.space(100)
                Column {
                  anchors.centerIn: parent
                  spacing: Style.space(10)
                  KeyControllerIcon { anchors.horizontalCenter: parent.horizontalCenter; foreground: Util.alpha(Color.popups.text, 0.4) }
                  Text { text: root.showCandidates ? root.t("Ключи не найдены") : root.t("Добавьте ключ через +"); font.family: Style.font.family; font.pixelSize: Style.font.bodySmall; color: Util.alpha(Color.popups.text, 0.6) }
                }
              }
            }
          }
        }
      }
      KeyAction {
        visible: root.dependenciesReady && !root.settingsOpen && !root.showCandidates
        text: root.t("Общий срок · ") + root.durationLabel(root.globalRules.lifetime_seconds)
        iconText: "\uf017"
        fontSize: Style.font.bodySmall
        implicitHeight: Style.space(24)
        horizontalPadding: Style.space(2)
        bordered: false
        foreground: Util.alpha(Color.popups.text, 0.65)
        tooltipText: root.t("Настроить общий срок доступа")
        onClicked: root.settingsFor(null)
      }
    }
  }
}
