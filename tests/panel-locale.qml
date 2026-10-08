import QtQuick
import Quickshell
import QtTest
import "plugin" as Plugin
import "plugin/KeyLocale.js" as KeyLocale

// Artificial metadata only. No native prompt, real key or system helper.
ShellRoot {
  id: test
  property var rpc: null
  property string metadataLanguage: "en"
  property int calls: 0
  property double expiry: Math.floor(Date.now() / 1000) + 7200
  property var fixture: [
    {key_id:"SHA256:locale", name:"Ключ / Key", path:"/test/.ssh/ключ", fingerprint:"SHA256:locale", encrypted:true,
      unavailable:null, unencrypted_copies:[], state:"unlocked", expires_at:test.expiry, lifetime_known:true,
      bound:true, mode:"fingerprint", inherits:true, rules:{lifetime_seconds:7200}},
    {key_id:"SHA256:locked", name:"Locked", path:"/test/.ssh/locked", fingerprint:"SHA256:locked", encrypted:true,
      unavailable:null, unencrypted_copies:[], state:"locked", expires_at:null, lifetime_known:false,
      bound:false, mode:"password", inherits:true, rules:{lifetime_seconds:7200}}
  ]
  function check(condition, message) {
    if (!condition) { console.error("LOCALE_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
  }
  function find(object, name, seen) {
    if (!object || typeof object !== "object") return null
    seen = seen || []
    if (seen.indexOf(object) >= 0) return null
    seen.push(object)
    if (object.objectName === name) return object
    for (var property of ["data", "children", "contentItem"]) {
      var value = object[property]
      if (!value) continue
      var list = value.length === undefined ? [value] : value
      for (var i = 0; i < list.length; ++i) {
        var found = find(list[i], name, seen)
        if (found) return found
      }
    }
    return null
  }
  function metadata(language) {
    metadataLanguage = language
    check(panel.call("panel.list"), "metadata request was rejected")
    var end = Date.now() + 2500
    while ((rpc.running || panel.rpcInFlight) && Date.now() < end) clock.wait(15)
    check(!rpc.running && !panel.rpcInFlight, "metadata reply did not complete")
  }
  Plugin.Panel {
    id: panel
    manageIpc: false
    function refresh() {}
    function startCall(action, key, value, request) {
      test.check(action === "panel.list", "language changed access or settings")
      test.calls++
      var reply = {api_version:1, state:"ready", error_code:null, request_id:null, ui_language:test.metadataLanguage,
        keys:test.fixture, global_rules:{lifetime_seconds:7200, revoke_on_sleep:true}, scanned:true, scan_root:"/test/.ssh", scan_requires_consent:false, active_request:null}
      test.rpc.command = ["/usr/bin/python3", Quickshell.env("SSH_KEYS_TEST_REPLY"), JSON.stringify(reply)]
      test.rpc.running = true
      return true
    }
  }
  TestCase { id: clock; when: false }
  Timer {
    interval: 150; running: true
    onTriggered: {
      test.rpc = test.find(panel, "ssh-keys-rpc")
      test.check(test.rpc, "missing Process")
      test.check(panel.uiLanguage === Quickshell.env("SSH_KEYS_EXPECT_LANGUAGE"), "Qt startup language fallback differs")
      for (var locale of ["ru", "ru_RU.UTF-8", "ru-RU", "RU_RU@variant"]) test.check(KeyLocale.language(locale) === "ru", "Russian locale not recognized: " + locale)
      for (var fallback of ["", "C", "POSIX", "en_US.UTF-8", "de_DE.UTF-8", "russian", "true"]) test.check(KeyLocale.language(fallback) === "en", "unsupported locale did not fall back to English: " + fallback)
      for (var source in KeyLocale.english) {
        test.check(KeyLocale.text("ru", source) === source, "Russian source text changed")
        test.check(KeyLocale.text("en", source).length > 0 && !/[А-Яа-яЁё]/.test(KeyLocale.text("en", source)), "English catalog still contains Russian")
        test.check(KeyLocale.text("unsupported", source) === KeyLocale.text("en", source), "catalog fallback is not English")
      }

      test.metadata("ru")
      test.check(panel.uiLanguage === "ru" && panel.message === "", "Russian metadata was not accepted")
      var summary = test.find(panel, "ssh-keys-summary")
      test.check(summary && summary.text === "2 ключа · открыто 1", "Russian header count changed")
      var repeater = test.find(panel, "ssh-key-rows")
      var first = repeater.itemAt(0)
      var access = test.find(first, "ssh-key-access")
      var method = test.find(first, "ssh-key-method")
      var lockedAccess = test.find(repeater.itemAt(1), "ssh-key-access")
      test.check(access.text === "Закрыть" && method.text === "Отпечаток ⇅" && lockedAccess.text === "Открыть", "Russian action labels differ")
      var counts = [1, 2, 5, 11, 21, 22, 25, 101, 111]
      var russian = ["1 ключ", "2 ключа", "5 ключей", "11 ключей", "21 ключ", "22 ключа", "25 ключей", "101 ключ", "111 ключей"]
      for (var i = 0; i < counts.length; ++i) test.check(panel.keyCountText(counts[i]) === russian[i], "Russian pluralization differs")
      panel.settingsFor(test.fixture[0])
      var edit = test.find(panel, "ssh-key-edit-rules")
      var policy = test.find(panel, "ssh-key-policy-summary")
      var rows = JSON.stringify(panel.rows)
      panel.message = panel.responseDescription({operation:"unlock", state:"cancelled"})
      test.metadata("en")
      test.check(panel.uiLanguage === "en", "system language not applied")
      test.check(repeater.itemAt(0) === first && JSON.stringify(panel.rows) === rows, "language refresh recreated rows or changed access")
      test.check(panel.settingsOpen && policy.text === "2 h · Default duration", "effective policy not translated")
      test.check(access.text === "Lock" && access.tooltipText === "Revoke key" && method.text === "Fingerprint ⇅" && lockedAccess.text === "Unlock", "English actions or tooltips not refreshed")
      test.check(edit.text === "Edit access rules", "editor launcher not translated")
      test.check(panel.message === "Operation cancelled · wait 30 s", "visible notice/cooldown was not translated")
      test.check(panel.keyCountText(0) === "0 keys" && panel.keyCountText(1) === "1 key" && panel.keyCountText(21) === "21 keys", "English pluralization differs")
      test.check(panel.durationLabel(0) === "unlimited" && panel.durationLabel(3600) === "1 h" && panel.durationLabel(120) === "2 min" && panel.durationLabel(45) === "45 s", "English duration labels differ")
      test.check(panel.compactStateText({encrypted:true,state:"unlocked",lifetime_known:true,expires_at:90061}, 0) === "1 d 1 h", "English countdown units differ")
      test.check(panel.stateText(test.fixture[0]) === "Unlocked until " + new Date(test.expiry * 1000).toLocaleTimeString(), "message language changed regional time formatting")
      test.check(panel.describe("unsupported_format") === "Unsupported format; OpenSSH is required", "error description not translated")
      test.check(panel.describe("future_code") === "KeyController error: future_code", "stable unknown error identifier changed")
      test.check(panel.candidateText(test.fixture[0]).indexOf("/test/.ssh/ключ") !== -1 && panel.rows[0].name === "Ключ / Key", "user content was translated")

      panel.settingsOpen = false
      test.check(summary.text === "2 keys · 1 unlocked", "English header count order differs")
      test.check(KeyLocale.keySummary("en", 1, 0) === "1 key · 0 unlocked", "English header singular differs")
      panel.settingsOpen = true
      panel.message = panel.describe("future_code")
      test.metadata("ru")
      test.check(panel.message === "Ошибка KeyController: future_code" && edit.text === "Изменить правила доступа", "reverse metadata refresh not translated")
      test.check(panel.settingsOpen && policy.text === "2 ч · Общий срок", "reverse refresh changed policy")
      test.metadata("fr")
      test.check(panel.uiLanguage === "ru" && panel.message === "Не удалось связаться с помощником KeyController", "invalid normalized backend language was trusted")
      test.check(test.calls === 4 && panel.rows[0].expires_at === test.expiry && !panel.activeRequest, "locale testing caused an operation or extended lifetime")
      console.log("SSH_KEYS_LOCALE_REGRESSION_OK", Quickshell.env("SSH_KEYS_EXPECT_LANGUAGE"))
      Qt.quit()
    }
  }
}
