import QtQuick
import Quickshell
import QtTest
import "plugin" as Plugin

ShellRoot {
  id: test
  property var rpc: null
  property var watchdog: null
  property var save: null
  property var lifetime: null
  property var sleepRevoke: null
  property var repeater: null
  property var firstRow: null
  property string outcome: "success"
  property real replyDelay: 0.25
  property int saves: 0
  property int lists: 0
  property var savedRules: ({lifetime_seconds:900, revoke_on_sleep:true})
  property double expiry: Math.floor(Date.now() / 1000) + 450
  property var fixture: [
    {key_id:"SHA256:global-loaded", name:"TEST — inherited loaded", path:"/test/.ssh/loaded",
      fingerprint:"SHA256:global-loaded", encrypted:true, unavailable:null, unencrypted_copies:[],
      state:"unlocked", expires_at:test.expiry, lifetime_known:true, bound:true, mode:"fingerprint",
      inherits:true, rules:{lifetime_seconds:900}},
    {key_id:"SHA256:global-custom", name:"TEST — custom locked", path:"/test/.ssh/custom",
      fingerprint:"SHA256:global-custom", encrypted:true, unavailable:null, unencrypted_copies:[],
      state:"locked", expires_at:null, lifetime_known:false, bound:false, mode:"password",
      inherits:false, rules:{lifetime_seconds:60}}
  ]
  function check(condition, message) {
    if (!condition) { console.error("GLOBAL_SETTINGS_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
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
  function waitFor(condition, message) {
    var end = Date.now() + 2500
    while (!condition() && Date.now() < end) clock.wait(15)
    check(condition(), message)
    clock.wait(25)
  }
  function idle() { return !rpc.running && !panel.rpcInFlight && !panel.submittingAction && !panel.queuedCall && !panel.deferredAction }
  function prepare(seconds, revokeOnSleep) {
    panel.settingsFor(null)
    lifetime.value = seconds
    if (revokeOnSleep !== undefined) sleepRevoke.checked = revokeOnSleep
    panel.message = ""
  }
  function submit(seconds, queued) {
    var before = saves
    var beforeRules = JSON.stringify(panel.globalRules)
    var desiredSleep = sleepRevoke.checked
    save.clicked()
    check(panel.settingsOpen && panel.opened, "submit closed settings or popup before reply")
    check(panel.submittingAction === "rules.global" && !save.enabled && save.text === "Сохранение…", "save has no synchronous feedback")
    check(!lifetime.enabled && !sleepRevoke.enabled, "submitted global draft remained editable")
    sleepRevoke.clicked()
    check(sleepRevoke.checked === desiredSleep, "disabled sleep checkbox changed submitted draft")
    check(JSON.stringify(panel.globalRules) === beforeRules, "save optimistically changed effective rules")
    check(!panel.activeRequest && !panel.requestBusy, "global save created an unlock request")
    save.clicked()
    check(saves === before + (queued ? 0 : 1), "duplicate save was dispatched")
    if (queued) check(panel.queuedCall && panel.queuedCall.value.lifetime_seconds === seconds
      && panel.queuedCall.value.revoke_on_sleep === desiredSleep, "poll queue changed desired settings")
  }
  function accessUnchanged() {
    check(panel.rows[0].state === "unlocked" && panel.rows[0].expires_at === expiry && panel.rows[0].lifetime_known,
      "global rules changed a loaded identity or its current deadline")
    check(panel.rows[0].mode === "fingerprint" && panel.rows[0].bound, "global rules changed biometric preference/binding")
    check(panel.rows[1].state === "locked" && panel.rows[1].rules.lifetime_seconds === 60 && !panel.rows[1].inherits,
      "global rules changed a custom key or loaded it")
    check(panel.rows.every(function(row) { return Object.keys(row.rules).length === 1 && typeof row.rules.lifetime_seconds === "number" }),
      "global sleep policy leaked into per-key rules")
    check(repeater.itemAt(0) === firstRow, "response recreated row delegates")
  }
  Plugin.Panel {
    uiLanguage: "ru"
    id: panel
    manageIpc: false
    rows: test.fixture
    firstScanRequested: true
    function refresh() {}
    function startCall(action, key, value, request) {
      var result = {api_version:1, state:"ready", error_code:null, request_id:null}
      if (action === "rules.global") {
        test.saves++
        test.check(!key && !request && Object.keys(value).length === 2
          && typeof value.lifetime_seconds === "number" && typeof value.revoke_on_sleep === "boolean",
          "global save did not atomically carry timer and sleep policy")
        result.operation = "rules.global"
        if (test.outcome === "error") {
          result.state = "error"
          result.error_code = "sleep_in_progress"
        } else if (test.outcome === "wrong-state") {
          result.state = "pending"
          result.request_id = "must-not-be-followed"
        } else if (test.outcome === "invalid-rules") {
          result.global_rules = {lifetime_seconds:"1800", revoke_on_sleep:true}
        } else if (test.outcome === "invalid-sleep") {
          result.global_rules = {lifetime_seconds:1800, revoke_on_sleep:"true"}
        } else if (test.outcome === "missing-sleep") {
          result.global_rules = {lifetime_seconds:1800}
        } else if (test.outcome === "missing-rules") {
          result.global_rules = null
        } else {
          result.global_rules = value
          if (test.outcome === "partial") {
            result.state = "partial"
            result.error_code = "settings_durability_unknown"
          }
          if (test.outcome === "success" || test.outcome === "partial") test.savedRules = value
        }
      } else if (action === "panel.list") {
        test.lists++
        result.ui_language = "ru"
        result.global_rules = test.savedRules
        result.keys = test.fixture.map(function(row) {
          return row.inherits ? Object.assign({}, row, {rules:{lifetime_seconds:test.savedRules.lifetime_seconds}}) : row
        })
        result.scanned = true
        result.active_request = null
        result.sleep_preparing = false
      } else test.check(false, "unexpected API action: " + action)
      var output = action === "rules.global" && test.outcome === "malformed" ? "not-json"
        : action === "rules.global" && test.outcome === "empty" ? "EMPTY" : JSON.stringify(result)
      test.rpc.command = ["/usr/bin/python3", Quickshell.env("SSH_KEYS_TEST_REPLY"), output, String(test.replyDelay)]
      test.rpc.running = true
      return true
    }
  }
  TestCase { id: clock; when: false }
  Timer {
    interval: 100; running: true
    onTriggered: {
      test.rpc = test.find(panel, "ssh-keys-rpc")
      test.watchdog = test.find(panel, "ssh-keys-rpc-watchdog")
      test.save = test.find(panel, "ssh-key-save-rules")
      test.lifetime = test.find(panel, "ssh-key-lifetime")
      test.sleepRevoke = test.find(panel, "ssh-keys-revoke-on-sleep")
      test.repeater = test.find(panel, "ssh-key-rows")
      test.check(test.rpc && test.watchdog && test.save && test.lifetime && test.sleepRevoke && test.repeater, "missing controls")
      panel.open()
      clock.wait(350)
      test.firstRow = test.repeater.itemAt(0)

      // Open before the first metadata reply. Placeholder defaults must never
      // become a write that disables an existing policy or resets its duration.
      panel.settingsFor(null)
      test.check(!panel.globalRulesReady && test.lifetime.value === 0 && !test.sleepRevoke.checked,
        "cold-start fixture did not begin with unknown placeholder settings")
      test.check(!test.save.enabled && !test.lifetime.enabled && !test.sleepRevoke.enabled,
        "unknown global settings remained editable")
      test.save.clicked()
      test.sleepRevoke.clicked()
      test.check(test.saves === 0 && !test.sleepRevoke.checked, "cold-start Save submitted placeholder defaults")
      panel.call("panel.list")
      test.save.clicked()
      test.waitFor(test.idle, "initial metadata did not finish")
      test.check(test.saves === 0 && panel.globalRulesReady && panel.settingsOpen
        && test.lifetime.value === 900 && test.sleepRevoke.checked
        && test.save.enabled && test.lifetime.enabled && test.sleepRevoke.enabled,
        "first metadata did not initialize the already-open global draft")
      test.accessUnchanged()

      test.prepare(1800, false)
      test.check(test.sleepRevoke.visible && !test.sleepRevoke.checked, "sleep policy control/default missing from global form")
      var beforeToggle = test.saves
      var effectiveBeforeToggle = JSON.stringify(panel.globalRules)
      test.sleepRevoke.clicked()
      test.check(test.sleepRevoke.checked && JSON.stringify(panel.globalRules) === effectiveBeforeToggle && test.saves === beforeToggle,
        "draft toggle performed an API operation")
      test.submit(1800, false)
      clock.wait(60)
      test.check(panel.settingsOpen && test.lifetime.value === 1800, "pending response lost draft")
      test.waitFor(test.idle, "successful save did not finish")
      test.check(panel.opened && !panel.settingsOpen && panel.globalRules.lifetime_seconds === 1800 && panel.globalRules.revoke_on_sleep === true,
        "success did not update global rules and return to the list")
      test.check(panel.rows[0].rules.lifetime_seconds === 1800, "inherited future rules not refreshed")
      test.accessUnchanged()

      test.prepare(0, false)
      panel.call("panel.list")
      test.submit(0, true)
      test.waitFor(test.idle, "queued save did not finish")
      test.check(panel.globalRules.lifetime_seconds === 0 && panel.rows[0].rules.lifetime_seconds === 0 && panel.globalRules.revoke_on_sleep === false && !panel.settingsOpen,
        "queued save was lost or poll replaced the submitted draft")
      test.accessUnchanged()

      test.outcome = "partial"
      test.prepare(1200, true)
      var beforePartial = test.saves
      var listsBeforePartial = test.lists
      test.submit(1200, false)
      test.waitFor(test.idle, "partial save did not finish")
      test.check(panel.settingsOpen && panel.opened && test.lifetime.value === 1200 && test.lifetime.enabled && test.sleepRevoke.checked && test.sleepRevoke.enabled,
        "partial save discarded or disabled the draft")
      test.check(panel.globalRules.lifetime_seconds === 1200 && panel.rows[0].rules.lifetime_seconds === 1200 && panel.globalRules.revoke_on_sleep === true,
        "partial save did not publish the actual post-rename rules")
      test.check(panel.message === panel.describe("settings_durability_unknown") && !panel.activeRequest,
        "partial save hid its durability uncertainty or created a request")
      test.check(test.saves === beforePartial + 1 && test.lists === listsBeforePartial + 1,
        "partial save retried the mutation or skipped metadata reconciliation")
      test.accessUnchanged()

      for (var outcome of ["error", "malformed", "empty", "wrong-state", "invalid-rules", "invalid-sleep", "missing-sleep", "missing-rules"]) {
        test.outcome = outcome
        var previous = JSON.stringify(panel.globalRules)
        test.prepare(2700, false)
        test.submit(2700, false)
        test.waitFor(test.idle, outcome + " did not finish")
        test.check(panel.opened && panel.settingsOpen && test.lifetime.value === 2700 && test.lifetime.enabled && !test.sleepRevoke.checked && test.sleepRevoke.enabled,
          outcome + " discarded or disabled draft")
        test.check(panel.message !== "" && JSON.stringify(panel.globalRules) === previous,
          outcome + " accepted incorrect response or hid error")
        test.check(!panel.activeRequest && !panel.requestBusy, outcome + " started request polling")
        test.accessUnchanged()
      }
      test.outcome = "timeout"
      test.replyDelay = 1
      test.watchdog.interval = 100
      test.prepare(3000, false)
      test.submit(3000, false)
      test.waitFor(test.idle, "timeout did not finish")
      test.check(panel.settingsOpen && test.lifetime.value === 3000 && !test.sleepRevoke.checked && panel.message === panel.describe("service_timeout"),
        "timeout discarded draft or hid uncertainty")
      test.accessUnchanged()

      // Late replies may update effective data but cannot close another draft.
      test.outcome = "success"
      test.replyDelay = 0.25
      test.watchdog.interval = 12000
      test.prepare(3600)
      test.submit(3600, false)
      panel.settingsFor(test.fixture[1])
      test.check(!test.sleepRevoke.visible, "per-key form exposed a sleep policy override")
      test.lifetime.value = 120
      test.waitFor(test.idle, "navigated save did not finish")
      test.check(panel.settingsOpen && panel.settingsKey === test.fixture[1].key_id && test.lifetime.value === 120,
        "global reply dismissed or rewrote a per-key draft")
      test.accessUnchanged()

      test.prepare(7200, false)
      test.submit(7200, false)
      panel.settingsFor(null)
      test.lifetime.value = 2400
      test.sleepRevoke.checked = true
      test.waitFor(test.idle, "reopened global save did not finish")
      test.check(panel.settingsOpen && !panel.settingsRow && test.lifetime.value === 2400 && test.sleepRevoke.checked,
        "old response closed or replaced a newly opened global draft")
      test.check(panel.globalRules.lifetime_seconds === 7200 && panel.globalRules.revoke_on_sleep === false, "reopened draft prevented factual rules update")
      test.accessUnchanged()
      test.check(test.saves === 14, "unexpected global save count")
      console.log("SSH_KEYS_GLOBAL_SETTINGS_REGRESSION_OK cold-start defaults blocked, delay, queued poll, atomic timer/sleep saves, duplicate latch, errors, post-rename partial, timeout, drafts, timer-only per-key rules, loaded TTL")
      Qt.quit()
    }
  }
}
