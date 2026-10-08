import QtQuick
import Quickshell
import "plugin" as Plugin

// Exercise the real settings controls and save handlers with an intercepted
// API. No system helper, lockscreen or real SSH key is used.
ShellRoot {
  id: test
  property var calls: []
  property int loadedExpiry: Math.floor(Date.now() / 1000) + 872
  property var fixture: [
    {key_id:"SHA256:inherited",name:"Inherited timer",path:"/test/.ssh/inherited",fingerprint:"SHA256:inherited",encrypted:true,unavailable:null,unencrypted_copies:[],state:"unlocked",lifetime_known:true,expires_at:test.loadedExpiry,bound:false,mode:"password",inherits:true,rules:{lifetime_seconds:1800}},
    {key_id:"SHA256:custom",name:"Custom timer",path:"/test/.ssh/custom",fingerprint:"SHA256:custom",encrypted:true,unavailable:null,unencrypted_copies:[],state:"locked",bound:false,mode:"password",inherits:false,rules:{lifetime_seconds:600}},
    {key_id:"SHA256:bound",name:"Bound key",path:"/test/.ssh/bound",fingerprint:"SHA256:bound",encrypted:true,unavailable:null,unencrypted_copies:[],state:"locked",bound:true,mode:"fingerprint",inherits:true,rules:{lifetime_seconds:1800}},
    {key_id:"SHA256:plain",name:"Plain key",path:"/test/.ssh/plain",fingerprint:"SHA256:plain",encrypted:false,unavailable:null,unencrypted_copies:[],state:"locked",bound:false,mode:"password",inherits:true,rules:{lifetime_seconds:1800}}
  ]
  function check(condition, message) {
    if (!condition) { console.error("SETTINGS_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
  }
  function collect(object, predicate, seen, matches) {
    seen = seen || []
    matches = matches || []
    if (!object || typeof object !== "object" || seen.indexOf(object) >= 0) return matches
    seen.push(object)
    if (predicate(object)) matches.push(object)
    var properties = ["data", "children", "contentItem"]
    for (var i = 0; i < properties.length; ++i) {
      var value = object[properties[i]]
      if (!value) continue
      var list = value.length === undefined ? [value] : value
      for (var j = 0; j < list.length; ++j) collect(list[j], predicate, seen, matches)
    }
    return matches
  }
  function named(name) {
    var found = collect(panel, function(o) { return o.objectName === name })
    check(found.length === 1, "missing or duplicate control: " + name)
    return found[0]
  }
  function saved(save, action, key, value) {
    var before = calls.length
    save.clicked()
    check(calls.length === before + 1, "save did not submit exactly once")
    var actual = calls[calls.length - 1]
    check(actual.action === action && actual.key === key, "wrong settings target")
    check(JSON.stringify(actual.value) === JSON.stringify(value), "settings payload differs from its global or per-key schema")
    if (action === "rules.global") {
      check(panel.settingsOpen, "global settings closed before the helper replied")
      panel.applyGlobalRules({state:"ready", operation:"rules.global", request_id:null, global_rules:value})
    }
    check(!panel.settingsOpen, "successful save did not close settings")
    check(panel.rows[0].expires_at === loadedExpiry && panel.rows[0].state === "unlocked", "saving rules changed the existing loaded key or its deadline")
    check(panel.rows.every(function(row) { return Object.keys(row.rules).length === 1 && typeof row.rules.lifetime_seconds === "number" }),
      "global-only sleep policy leaked into per-key rules")
  }
  function action(control, actionName, key) {
    check(control && control.enabled, "missing or disabled action: " + actionName)
    var before = calls.length
    control.clicked()
    check(calls.length === before + 1, actionName + " did not submit exactly once")
    var actual = calls[calls.length - 1]
    check(actual.action === actionName && actual.key === key, "wrong action or key for " + actionName)
    check(panel.rows[0].expires_at === loadedExpiry, actionName + " extended the loaded deadline")
  }
  Plugin.Panel {
    uiLanguage: "ru"
    id: panel
    manageIpc: false
    globalRulesReady: true // This fixture begins with known artificial metadata.
    rows: test.fixture
    function refresh() {}
    function startCall(action, key, value, request) {
      test.calls.push({action: action, key: key, value: value})
      return true
    }
  }
  Timer {
    interval: 180
    running: true
    onTriggered: {
      var inherit = test.named("ssh-key-inherit")
      var lifetime = test.named("ssh-key-lifetime")
      var sleepRevoke = test.named("ssh-keys-revoke-on-sleep")
      var save = test.named("ssh-key-save-rules")
      var labelledChecks = test.collect(panel, function(o) {
        return typeof o.checked === "boolean" && (typeof o.label === "string" || typeof o.text === "string")
      })
      test.check(labelledChecks.length === 2 && labelledChecks.indexOf(inherit) !== -1 && labelledChecks.indexOf(sleepRevoke) !== -1,
        "settings must contain only timer inheritance and global sleep revocation")
      test.check(JSON.stringify(panel.globalRules) === '{"lifetime_seconds":0,"revoke_on_sleep":false}', "incorrect compatibility defaults")

      panel.settingsFor(null)
      test.check(lifetime.value === 0 && lifetime.enabled, "global unlimited timer not editable")
      test.saved(save, "rules.global", "", {lifetime_seconds: 0, revoke_on_sleep: false})
      panel.settingsFor(null)
      lifetime.value = 1800
      test.saved(save, "rules.global", "", {lifetime_seconds: 1800, revoke_on_sleep: false})
      panel.globalRules = {lifetime_seconds: 1800, revoke_on_sleep: false}
      panel.settingsFor(null)
      var beforeToggle = test.calls.length
      sleepRevoke.clicked()
      test.check(sleepRevoke.checked && !panel.globalRules.revoke_on_sleep && test.calls.length === beforeToggle,
        "sleep checkbox changed policy before Save")
      test.saved(save, "rules.global", "", {lifetime_seconds: 1800, revoke_on_sleep: true})
      panel.settingsFor(null)
      test.check(sleepRevoke.checked, "opening global settings lost the saved sleep policy")

      panel.settingsFor(test.fixture[0])
      test.check(inherit.checked && lifetime.value === 1800 && !lifetime.enabled, "inherited timer must use and lock the global value")
      test.saved(save, "rules.key", "SHA256:inherited", null)

      panel.settingsFor(test.fixture[1])
      test.check(!inherit.checked && lifetime.value === 600 && lifetime.enabled, "custom timer not restored")
      lifetime.value = 900
      test.saved(save, "rules.key", "SHA256:custom", {lifetime_seconds: 900})

      panel.settingsFor(test.fixture[1])
      inherit.clicked()
      test.check(inherit.checked && lifetime.value === 1800 && !lifetime.enabled, "enabling inheritance did not restore the global timer")
      test.saved(save, "rules.key", "SHA256:custom", null)

      panel.settingsFor(test.fixture[0])
      inherit.clicked()
      test.check(!inherit.checked && lifetime.enabled, "disabling inheritance did not enable the timer")
      lifetime.value = 0
      test.saved(save, "rules.key", "SHA256:inherited", {lifetime_seconds: 0})

      // Presets and custom units edit a local draft. They never unlock, reload,
      // or write policy before the explicit save action.
      var units = test.named("ssh-key-duration-unit")
      var amount = test.named("ssh-key-duration-amount")
      var presets = [900, 1800, 3600, 0]
      for (var i = 0; i < presets.length; ++i) {
        panel.settingsFor(null)
        var beforePreset = test.calls.length
        var preset = test.named("ssh-key-duration-preset-" + presets[i])
        preset.clicked()
        test.check(lifetime.value === presets[i] && preset.selected, "preset did not select its exact duration")
        test.check(test.calls.length === beforePreset, "preset submitted API before Save")
        test.saved(save, "rules.global", "", {lifetime_seconds: presets[i], revoke_on_sleep: true})
      }

      var legacySeconds = [45, 90, 31536000]
      for (var j = 0; j < legacySeconds.length; ++j) {
        var legacy = JSON.parse(JSON.stringify(test.fixture[1]))
        legacy.rules.lifetime_seconds = legacySeconds[j]
        panel.settingsFor(legacy)
        var beforeUnits = test.calls.length
        test.check(lifetime.value === legacySeconds[j], "opening settings rounded an existing duration")
        units.changed("60")
        test.check(lifetime.value === legacySeconds[j] && units.value === "60", "minutes conversion changed the duration")
        units.changed("3600")
        test.check(lifetime.value === legacySeconds[j] && units.value === "3600", "hours conversion changed the duration")
        test.check(test.calls.length === beforeUnits, "display unit switch submitted API")
        test.saved(save, "rules.key", "SHA256:custom", {lifetime_seconds: legacySeconds[j]})
      }

      panel.settingsFor(test.fixture[1])
      var beforeCustom = test.calls.length
      units.changed("3600")
      amount.text = "2"
      amount.textEdited()
      test.check(lifetime.value === 7200, "custom hours did not convert to seconds")
      units.changed("60")
      test.check(lifetime.value === 7200 && amount.text === "120", "switching units reinterpreted the number instead of preserving duration")
      amount.text = "17"
      amount.textEdited()
      test.check(lifetime.value === 1020, "custom minutes did not convert to seconds")
      for (var invalid of ["", "-1", "1.5", "not-a-number", "525601"]) {
        amount.text = invalid
        amount.textEdited()
        test.check(lifetime.value === 1020, "invalid input changed the valid draft: " + invalid)
      }
      amount.editingFinished()
      test.check(amount.text === "17", "invalid input was not restored to the valid draft")
      var refreshed = JSON.parse(JSON.stringify(test.fixture))
      refreshed[1].busy = false
      panel.updateRows(refreshed)
      test.check(lifetime.value === 1020, "metadata refresh overwrote the unsaved draft")
      test.check(test.calls.length === beforeCustom, "custom editing submitted API before Save")
      test.saved(save, "rules.key", "SHA256:custom", {lifetime_seconds: 1020})

      panel.settingsFor(test.fixture[0])
      var inheritedDuration = lifetime.value
      test.named("ssh-key-duration-preset-900").clicked()
      units.changed("3600")
      amount.text = "2"
      amount.textEdited()
      test.check(lifetime.value === inheritedDuration && !lifetime.enabled, "inherited duration accepted an edit")
      panel.settingsOpen = false

      var repeater = test.named("ssh-key-rows")
      var revoke = test.collect(repeater.itemAt(0), function(o) { return o.objectName === "ssh-key-access" })[0]
      test.check(revoke && revoke.enabled && revoke.tooltipText === "Отозвать ключ", "manual revocation control missing")
      panel.activeRequest = "fixture-native-confirmation"
      var lockedAccess = test.collect(repeater.itemAt(1), function(o) { return o.objectName === "ssh-key-access" })[0]
      test.check(revoke.enabled && !lockedAccess.enabled, "pending confirmation must allow revoke and block another unlock")
      test.action(revoke, "revoke", "SHA256:inherited")
      panel.activeRequest = ""
      var sync = test.collect(repeater.itemAt(1), function(o) { return o.objectName === "ssh-key-method" })[0]
      test.action(sync, "sync", "SHA256:custom")
      var mode = test.collect(repeater.itemAt(2), function(o) { return o.objectName === "ssh-key-method" })[0]
      test.action(mode, "mode", "SHA256:bound")
      test.check(JSON.stringify(test.calls[test.calls.length - 1].value) === '{"fingerprint_mode":false}', "method switch did not send an explicit desired mode")
      test.check(panel.rows[2].state === "locked", "mode switch optimistically unlocked the key")
      panel.showCandidates = true
      var encrypt = test.collect(repeater.itemAt(3), function(o) { return o.objectName === "ssh-key-encrypt" })[0]
      test.action(encrypt, "encrypt", "/test/.ssh/plain")
      console.log("SSH_KEYS_SETTINGS_REGRESSION_OK")
      Qt.quit()
    }
  }
}
