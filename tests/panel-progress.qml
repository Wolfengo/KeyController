import QtQuick
import Quickshell
import QtTest
import "plugin" as Plugin

// All subprocesses print fixtures. No call reaches panel-client or the helper.
ShellRoot {
  id: test
  property var rpc: null
  property var watchdog: null
  property var access: null
  property var barBusy: null
  property var repeater: null
  property var row: null
  property var calls: []
  property string outcome: "pending"
  property string statusOutcome: "pending"
  property real replyDelay: 0.3
  property var fixture: ({key_id:"SHA256:progress-fixture", name:"TEST — launch feedback",
    path:"/test/.ssh/key", fingerprint:"SHA256:progress-fixture", encrypted:true,
    unavailable:null, unencrypted_copies:[], state:"locked", bound:true,
    mode:"fingerprint", inherits:true, rules:{lifetime_seconds:60}})
  function check(condition, message) {
    if (!condition) { console.error("PROGRESS_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
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
    var end = Date.now() + 2200
    while (!condition() && Date.now() < end) clock.wait(15)
    check(condition(), message)
    clock.wait(25)
  }
  function idle() { return !rpc.running && !panel.submittingAction && !panel.queuedCall && !panel.deferredAction }
  function countUnlocks() { return calls.filter(function(call) { return call === "keys.unlock" }).length }
  function assertIdle(message) {
    waitFor(idle, message)
    check(!panel.requestBusy && !barBusy.running && !access.busy && access.text === "Открыть", message + " (indicators)")
    check(repeater.itemAt(0) === row, message + " (delegate)")
  }
  function launch() {
    panel.open()
    var before = countUnlocks()
    check(panel.call("keys.unlock", fixture.key_id), "initial click rejected")
    check(panel.submittingAction === "keys.unlock" && panel.submittingKey === fixture.key_id,
      "submission latch was not synchronous")
    check(panel.actionBusy && panel.requestBusy && barBusy.running && access.busy && access.text === "Открытие…",
      "first input event did not show launch feedback")
    check(!panel.call("keys.unlock", fixture.key_id), "same-event duplicate accepted")
    check(countUnlocks() === before + (panel.queuedCall ? 0 : 1), "unexpected dispatch count")
  }
  function cancel() {
    waitFor(function() { return !rpc.running }, "pending reply did not finish")
    check(panel.call("requests.cancel", null, null, panel.activeRequest), "cancel rejected")
    assertIdle("cancel did not clear progress")
  }
  Plugin.Panel {
    uiLanguage: "ru"
    id: panel
    manageIpc: false
    rows: [test.fixture]
    firstScanRequested: true
    function refresh() {}
    function startCall(action, key, value, request) {
      test.calls.push(action)
      var result = {api_version:1, state:"ready", request_id:null, error_code:null}
      var delay = test.replyDelay
      if (action === "keys.unlock") {
        test.check(key === test.fixture.key_id, "wrong key")
        result = {api_version:test.outcome === "api" ? 2 : 1,
          state:test.outcome === "denied" ? "error" : "pending",
          request_id:test.outcome === "denied" ? null : "fixture-pending",
          key_id:key, operation:"unlock", error_code:test.outcome === "denied" ? "cooldown" : null}
      } else if (action === "requests.status") {
        test.check(request === "fixture-pending", "lost request ID")
        result = {api_version:1, state:test.statusOutcome, request_id:request, operation:"unlock", error_code:null}
      } else if (action === "requests.cancel") {
        result = {api_version:1, state:"cancelled", request_id:request, operation:"unlock", error_code:"cancelled"}
        delay = 0
      } else if (action === "panel.list") {
        result.keys = [test.fixture]
        result.scanned = true
        result.ui_language = "ru"
        result.global_rules = {lifetime_seconds:60, revoke_on_sleep:false}
      } else test.check(false, "unexpected operation: " + action)
      var output = action === "keys.unlock" && test.outcome === "malformed" ? "not-json"
        : action === "keys.unlock" && test.outcome === "empty" ? "EMPTY" : JSON.stringify(result)
      var failedSpawn = action === "keys.unlock" && test.outcome === "spawn"
      test.rpc.command = failedSpawn ? ["/nonexistent/keycontroller-test-command"]
        : ["/usr/bin/python3", Quickshell.env("SSH_KEYS_TEST_REPLY"), output, String(delay)]
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
      test.barBusy = test.find(panel, "ssh-keys-bar-busy")
      test.repeater = test.find(panel, "ssh-key-rows")
      test.check(test.rpc && test.watchdog && test.barBusy && test.repeater, "missing fixture objects")
      panel.open()
      clock.wait(350)
      test.row = test.repeater.itemAt(0)
      test.access = test.find(test.row, "ssh-key-access")
      test.check(test.access, "missing access button")
      var barSize = [panel.implicitWidth, panel.implicitHeight]

      test.launch()
      clock.wait(70)
      test.check(panel.opened && test.access.busy && test.barBusy.running, "feedback ended before reply")
      test.waitFor(function() { return !!panel.activeRequest && !test.rpc.running }, "pending reply not retained")
      test.check(!panel.opened && !test.access.busy && test.barBusy.running, "pending handoff lost bar progress")
      test.check(panel.activeRequestKey === test.fixture.key_id, "pending handoff lost target")
      panel.call("requests.status", null, null, panel.activeRequest)
      test.waitFor(function() { return !test.rpc.running }, "status reply not finished")
      test.check(panel.activeRequestKey === test.fixture.key_id && test.barBusy.running, "status without key erased target/progress")
      test.cancel()

      // The UI must acknowledge clicks even while metadata is still arriving.
      panel.open()
      panel.call("panel.list")
      test.launch()
      test.check(panel.queuedCall && test.access.busy, "queued click not visible")
      test.waitFor(function() { return !!panel.activeRequest && !test.rpc.running }, "queued unlock did not become pending")
      test.cancel()

      for (var outcome of ["denied", "malformed", "api", "empty", "spawn"]) {
        test.outcome = outcome
        test.watchdog.interval = 500
        panel.message = ""
        test.launch()
        test.assertIdle(outcome + " did not clear submission")
        test.check(panel.message !== "" && !panel.activeRequest, outcome + " did not report failure")
      }

      test.outcome = "pending"
      test.replyDelay = 1
      test.watchdog.interval = 100
      panel.message = ""
      var beforeTimeout = test.countUnlocks()
      test.launch()
      test.assertIdle("RPC timeout did not clear launch feedback")
      test.check(panel.message === panel.describe("service_timeout") && test.countUnlocks() === beforeTimeout + 1,
        "timeout retried unlock or hid its error")

      // Transport failure after acceptance must keep the known request ID.
      test.replyDelay = 0
      test.watchdog.interval = 500
      test.launch()
      test.waitFor(function() { return !!panel.activeRequest && !test.rpc.running }, "recovery launch not accepted")
      test.replyDelay = 1
      test.watchdog.interval = 100
      panel.call("requests.status", null, null, panel.activeRequest)
      test.waitFor(function() { return !test.rpc.running }, "status timeout did not end RPC")
      test.check(panel.activeRequest === "fixture-pending" && test.barBusy.running,
        "transient poll timeout discarded the accepted request")
      test.replyDelay = 0
      test.watchdog.interval = 500
      test.cancel()
      test.check(JSON.stringify([panel.implicitWidth, panel.implicitHeight]) === JSON.stringify(barSize), "progress changed bar geometry")
      console.log("SSH_KEYS_PROGRESS_REGRESSION_OK synchronous/queued progress, pending handoff, failures, timeout, cancellation, no retries")
      Qt.quit()
    }
  }
}
