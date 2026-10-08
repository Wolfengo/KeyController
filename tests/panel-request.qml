import QtQuick
import Quickshell
import QtTest
import "plugin" as Plugin

// Real button -> call/queue -> Process -> StdioCollector; direct and pending actions.
// Only startCall's executable is replaced; no system API or real key is used.
ShellRoot {
  id: test
  property var rpc: null
  property var repeater: null
  property var row: null
  property var access: null
  property var calls: []
  property int scenario: -1
  property string phase: "initialize"
  property int statusCalls: 0
  property int unlockCalls: 0
  property int syncCalls: 0
  property int revokeCalls: 0
  property int modeCalls: 0
  property int directRefreshes: 0
  property int loadedExpiry: Math.floor(Date.now() / 1000) + 1800
  property bool sawEmptyList: false
  property bool accepted: false
  property bool delayNextList: false
  property double openedAt: 0
  property var rowGeometry: null
  property var cases: [
    {action:"sync", row:0, state:"cancelled", code:"cancelled", reopen:false},
    {row:0, state:"unlocked", code:null, reopen:false},
    {row:0, state:"cancelled", code:"cancelled", reopen:false},
    {row:0, state:"error", code:"cooldown", reopen:true, immediate:true},
    {state:"denied", code:"biometric_denied", reopen:false},
    {state:"cancelled", code:"session_locked", reopen:false},
    {state:"error", code:"session_locked_or_unavailable", reopen:false},
    {state:"error", code:"sleep_in_progress", reopen:false},
    {state:"error", code:"prompt_failed", reopen:true},
    {action:"mode", row:2, direct:true, initialMode:"fingerprint", desired:false, state:"unlocked", code:null},
    {action:"mode", row:2, direct:true, initialMode:"password", desired:true, state:"unlocked", code:null},
    {action:"mode", row:2, direct:true, initialMode:"fingerprint", desired:false, state:"error", code:"busy"},
    {action:"revoke", row:2, direct:true, unavailable:true, state:"error", code:"agent_unavailable"},
    {action:"revoke", row:2, direct:true, unavailable:true, active:true, state:"locked", code:null}
  ]
  property var fixture: {
    "key_id":"SHA256:request-test", "name":"TEST — request lifecycle", "path":"/test/.ssh/key",
    "fingerprint":"SHA256:request-test", "encrypted":true, "unavailable":null,
    "unencrypted_copies":[], "state":"locked", "bound":false, "mode":"password",
    "inherits":true, "rules":{"lifetime_seconds":0}
  }
  property var fixtures: [fixture,
    Object.assign({}, fixture, {key_id:"SHA256:request-test-2", name:"TEST — second key", path:"/test/.ssh/key2"}),
    Object.assign({}, fixture, {key_id:"SHA256:request-test-3", name:"TEST — third key", path:"/test/.ssh/key3"}),
    Object.assign({}, fixture, {key_id:"SHA256:request-test-3", name:"TEST — same fingerprint alias", path:"/test/.ssh/alias3"})]
  function check(condition, message) {
    if (!condition) { console.error("REQUEST_REGRESSION_FAILED", scenario, phase, message); Qt.exit(1); throw new Error(message) }
  }
  function find(object, predicate, seen) {
    if (!object || typeof object !== "object") return null
    seen = seen || []
    if (seen.indexOf(object) >= 0) return null
    seen.push(object)
    if (predicate(object)) return object
    for (var property of ["data", "children", "contentItem"]) {
      var value = object[property]
      if (!value) continue
      var list = value.length === undefined ? [value] : value
      for (var i = 0; i < list.length; ++i) {
        var found = find(list[i], predicate, seen)
        if (found) return found
      }
    }
    return null
  }
  function requestId() { return "fixture-request-" + scenario }
  function rowIndex() { return cases[scenario].row === undefined ? scenario % 3 : cases[scenario].row }
  function operation() { return cases[scenario].action || "unlock" }
  function reply(action, key, value, request) {
    var response = {api_version:1, state:"ready", error_code:null, request_id:null}
    if (action === "panel.list") {
      response.keys = fixtures.map(function(row) { return Object.assign({}, row) })
      response.ui_language = "ru"
      response.global_rules = {lifetime_seconds:0, revoke_on_sleep:false}
      response.active_request = scenario >= 0 && cases[scenario].active && !accepted ? "fixture-pending-unlock" : null
      response.scanned = true
      response.session_available = true
      if (accepted) sawEmptyList = true
    } else if (action === "mode" || action === "revoke") {
      var scenarioCase = cases[scenario]
      check(scenarioCase.direct && action === scenarioCase.action, "unexpected direct operation")
      check(key === fixtures[rowIndex()].key_id, "direct operation targeted another key")
      if (action === "mode") {
        modeCalls++
        check(JSON.stringify(value) === JSON.stringify({fingerprint_mode:scenarioCase.desired}), "mode request must state the desired boolean")
      } else {
        revokeCalls++
        check(value === null, "revoke must send null value")
      }
      accepted = true
      if (scenarioCase.code) {
        response.state = "error"
        response.error_code = scenarioCase.code
        response.operation = action
        return response
      }
      fixtures = fixtures.map(function(row) {
        if (row.key_id !== key) return row
        var next = Object.assign({}, row)
        if (action === "mode") next.mode = value.fingerprint_mode ? "fingerprint" : "password"
        else { next.state = "locked"; next.expires_at = null; next.lifetime_known = false }
        next.busy = false
        next.request_id = null
        delete next.operation
        return next
      })
      response = Object.assign({}, fixtures[rowIndex()], {api_version:1, error_code:null, operation:action, request_id:null})
    } else if (action === "keys.unlock" || action === "sync") {
      check(key === fixtures[rowIndex()].key_id, "button targeted a different key")
      check(action === (cases[scenario].action || "keys.unlock"), "wrong action for scenario")
      if (action === "sync") syncCalls++
      else unlockCalls++
      response.operation = operation()
      response.key_id = key
      if (cases[scenario].immediate) {
        response.state = cases[scenario].state
        response.error_code = cases[scenario].code
      } else {
        response.state = "pending"
        response.request_id = requestId()
      }
      accepted = true
    } else if (action === "requests.status") {
      check(accepted && request === requestId(), "status lost or changed the request ID")
      check(!panel.opened, "background status poll required reopening the popup")
      statusCalls++
      response.request_id = requestId()
      response.operation = operation()
      if (statusCalls === 1) response.state = "pending"
      else {
        response.state = cases[scenario].state
        response.error_code = cases[scenario].code
      }
    } else check(false, "unexpected API action: " + action)
    return response
  }
  function geometry() {
    return [row.x, row.y, row.width, row.height, access.x, access.y, access.width, access.height]
  }
  Plugin.Panel {
    uiLanguage: "ru"
    id: panel
    manageIpc: false
    function startCall(action, key, value, request) {
      test.calls.push({action:action, key:key, value:value, request:request})
      if (action === "panel.list" && test.scenario >= 0 && test.cases[test.scenario].direct && test.accepted) {
        test.check(panel.opened, "direct action closed the popup")
        test.check(test.repeater.itemAt(test.rowIndex()) === test.row, "direct response replaced the delegate")
        var scenarioCase = test.cases[test.scenario]
        var displayed = test.row.modelData
        if (!scenarioCase.code) {
          test.check(displayed.state === scenarioCase.state, "direct state waited for the metadata poll")
          if (scenarioCase.action === "mode") {
            test.check(displayed.mode === (scenarioCase.desired ? "fingerprint" : "password"), "method waited for the metadata poll")
            test.check(displayed.expires_at === test.loadedExpiry && displayed.lifetime_known, "method switch changed active access or deadline")
          } else test.check(!panel.activeRequest && !panel.activeRequestKey && !displayed.busy, "revoke retained the cancelled pending unlock")
          test.check(panel.rows[3].path === "/test/.ssh/alias3" && panel.rows[3].name === "TEST — same fingerprint alias", "direct status replaced alias metadata")
          test.check(panel.rows[3].state === displayed.state && panel.rows[3].mode === displayed.mode, "direct status did not reach the same fingerprint alias")
          // Reapplying an identical response cannot toggle a mode or reload it.
          var before = JSON.stringify(panel.rows)
          panel.updateKeyStatus(Object.assign({}, displayed, {operation:scenarioCase.action}))
          test.check(JSON.stringify(panel.rows) === before, "same direct status was not idempotent")
        } else test.check(displayed.state === "unlocked" && displayed.expires_at === test.loadedExpiry, "failed direct action optimistically changed access")
        test.directRefreshes++
      }
      currentAction = action
      var direct = test.scenario >= 0 && test.cases[test.scenario].direct
      var delay = (action === "panel.list" && (test.delayNextList || direct && test.accepted)) ? "0.3"
        : (action === "mode" || action === "revoke" || action === "keys.unlock") ? "0.6" : "0"
      if (action === "panel.list") test.delayNextList = false
      test.rpc.command = ["/usr/bin/python3", Quickshell.env("SSH_KEYS_TEST_REPLY"), JSON.stringify(test.reply(action, key, value, request)), delay]
      test.rpc.running = true
      return true
    }
  }
  TestCase { id: pointer; name: "KeyControllerPointer"; when: false }
  Timer {
    interval: 25; running: true; repeat: true
    onTriggered: {
      if (test.phase === "initialize") {
        test.rpc = test.find(panel, function(o) { return o.objectName === "ssh-keys-rpc" })
        test.repeater = test.find(panel, function(o) { return o.objectName === "ssh-key-rows" })
        test.check(test.rpc && test.repeater, "fixture objects missing")
        for (var op of ["sync", "revoke", "rules.key"]) {
          for (var code of ["cancelled", "denied", "biometric_denied"]) {
            test.check(panel.responseDescription({operation:op, state:"cancelled", error_code:code}) === panel.describe(code), "unrelated operation claims an unlock cooldown")
          }
        }
        var stillBinding = Object.assign({}, test.fixture, {request_id:"fixture-still-binding", operation:"sync", busy:true})
        panel.updateRows([stillBinding])
        panel.activeRequest = stillBinding.request_id
        panel.activeRequestKey = stillBinding.key_id
        panel.updateKeyStatus(Object.assign({}, stillBinding, {operation:"revoke", request_id:null, state:"locked"}))
        test.check(panel.activeRequest === stillBinding.request_id && panel.activeRequestKey === stillBinding.key_id,
          "revoke cleared an ongoing binding request")
        test.check(panel.rows[0].busy && panel.rows[0].request_id === stillBinding.request_id && panel.rows[0].operation === "sync",
          "direct revoke replaced the still-running job metadata")
        panel.activeRequest = ""
        panel.updateRows([])
        test.phase = "next"
      }
      if (test.rpc.running || panel.rpcInFlight || panel.deferredAction || panel.queuedCall) return
      if (test.phase === "next") {
        panel.close()
        test.scenario++
        if (test.scenario === test.cases.length) {
          test.check(test.unlockCalls === 8 && test.syncCalls === 1 && test.revokeCalls === 2 && test.modeCalls === 3 && test.directRefreshes >= 5, "click did not submit exactly once per scenario")
          console.log("SSH_KEYS_REQUEST_REGRESSION_OK", test.cases.length, "button requests; direct mode/revoke; unchanged TTL; alias metadata; early refresh; duplicate suppression; closed-popup unlock polling")
          Qt.quit()
          return
        }
        test.accepted = false
        test.sawEmptyList = false
        test.statusCalls = 0
        panel.message = ""
        panel.activeRequest = ""
        if (test.cases[test.scenario].direct) {
          var item = test.cases[test.scenario]
          test.fixtures = test.fixtures.map(function(row, index) {
            if (index < 2) return row
            return Object.assign({}, row, {state:"unlocked", bound:true, mode:item.initialMode || "fingerprint",
              unavailable:item.unavailable ? "key_unavailable" : null,
              lifetime_known:true, expires_at:test.loadedExpiry, busy:!!item.active,
              request_id:item.active ? "fixture-pending-unlock" : null})
          })
        }
        test.phase = "click"
        panel.open()
        test.openedAt = Date.now()
      } else if (test.phase === "click") {
        // Wait for the actual layer window and popup fade before injecting
        // pointer events through Qt's event dispatch and hit testing.
        if (Date.now() - test.openedAt < 350) return
        test.check(test.repeater.count === 3, "fixture row missing")
        test.row = test.repeater.itemAt(test.rowIndex())
        test.access = test.find(test.row, function(o) { return o.objectName === "ssh-key-access" })
        test.check(test.access && test.access.enabled && panel.opened, "unlock button unavailable: " + JSON.stringify({enabled:test.access && test.access.enabled, opened:panel.opened, active:panel.activeRequest, submitting:panel.submittingAction, action:panel.currentAction, inFlight:panel.rpcInFlight, row:test.row.modelData}))
        test.phase = test.cases[test.scenario].direct ? "direct" : test.cases[test.scenario].immediate ? "immediate" : "pending"
        if (test.scenario === 1) {
          // A click often lands during the normal one-second list poll. It
          // must queue exactly one unlock without disabling the idle button.
          test.delayNextList = true
          panel.refresh()
          test.check(test.rpc.running && test.access.enabled, "poll disabled the unlock button")
        }
        var target = ["sync", "mode"].indexOf(test.cases[test.scenario].action) !== -1
          ? test.find(test.row, function(o) { return o.objectName === "ssh-key-method" }) : test.access
        test.check(target && target.enabled, "requested button unavailable")
        pointer.mouseClick(target, target.width / 2, target.height / 2, Qt.LeftButton)
        if (!test.cases[test.scenario].direct && test.cases[test.scenario].action !== "sync") {
          test.check(panel.submittingAction === "keys.unlock" && panel.submittingKey === test.row.modelData.key_id,
            "unlock has no synchronous submission state")
          test.check(panel.actionBusy && panel.requestBusy && test.access.busy && test.access.text === "Открытие…",
            "unlock did not immediately show progress")
          test.check(!panel.call("keys.unlock", test.row.modelData.key_id), "synchronous duplicate unlock was accepted")
        }
        if (test.scenario === 1) test.check(!test.accepted && panel.queuedCall && panel.queuedCall.action === "keys.unlock", "pointer click during poll did not queue unlock")
        else test.check(test.accepted, "real pointer click did not reach action handler")
        if (test.cases[test.scenario].direct) {
          var count = test.calls.filter(function(call) { return call.action === "mode" || call.action === "revoke" }).length
          pointer.mouseClick(target, target.width / 2, target.height / 2, Qt.LeftButton)
          test.check(test.calls.filter(function(call) { return call.action === "mode" || call.action === "revoke" }).length === count, "duplicate direct click was accepted")
          // Process.running can report the requested state before its notify
          // signal arrives. The synchronous call guard must already reject
          // the second click; controls must follow after the event-loop turn.
          pointer.wait(10)
          test.check(test.rpc.running && panel.actionBusy && !target.enabled, "direct action did not disable the button while running")
          test.check(panel.opened, "direct action closed popup before reply")
        }
      } else if (test.phase === "direct") {
        test.check(panel.opened && !panel.actionBusy, "direct reply closed popup or left the action busy")
        test.check(test.access.enabled === (test.row.modelData.state === "unlocked" || !test.row.modelData.unavailable), "direct reply left the wrong access availability")
        test.check(!panel.activeRequest && test.statusCalls === 0, "direct action created or retained a pending request")
        test.check(test.repeater.itemAt(test.rowIndex()) === test.row, "direct refresh replaced delegate")
        var scenarioCase = test.cases[test.scenario]
        if (scenarioCase.code) test.check(panel.message === panel.describe(scenarioCase.code), "direct failure not visible")
        else test.check(panel.message === "", "direct success retained a stale error")
        test.phase = "next"
      } else if (test.phase === "immediate") {
        test.check(panel.activeRequest === "" && panel.opened && test.access.enabled, "cooldown left a stale request or disabled unlock")
        test.check(!panel.requestBusy && panel.submittingAction === "", "immediate rejection left progress active")
        test.check(test.statusCalls === 0 && panel.message === panel.describe("cooldown"), "cooldown was hidden or polled as pending")
        test.phase = "next"
      } else if (test.phase === "pending") {
        test.check(panel.activeRequest === test.requestId() && !panel.opened, "pending did not close popup and retain request")
        test.check(panel.submittingAction === "" && panel.requestBusy && !test.access.busy, "pending did not hand off launch progress")
        test.check(!test.access.enabled, "pending request allowed another unlock")
        // Simulate the worker having already left the active list before its
        // final status is consumed; this response must not discard our ID.
        test.phase = "empty-list"
        panel.refresh()
      } else if (test.phase === "empty-list") {
        test.check(test.sawEmptyList && panel.activeRequest === test.requestId(), "panel.list discarded the completed request ID")
        test.rowGeometry = test.geometry()
        test.phase = "background"
      } else if (test.phase === "background") {
        if (test.statusCalls < 2) {
          test.check(panel.activeRequest === test.requestId() && !panel.opened, "request vanished or popup opened while pending")
          test.check(test.repeater.itemAt(test.rowIndex()) === test.row, "status polling recreated row")
          test.check(JSON.stringify(test.geometry()) === JSON.stringify(test.rowGeometry), "unchanged metadata/status polling changed row geometry")
          return
        }
        test.check(panel.activeRequest === "", "terminal result left request active")
        test.check(!panel.requestBusy && panel.submittingAction === "", "terminal result left progress active")
        test.check(panel.opened === test.cases[test.scenario].reopen, "wrong terminal popup behavior")
        test.check(test.access.enabled && test.repeater.itemAt(test.rowIndex()) === test.row, "terminal result recreated or disabled row")
        if (test.cases[test.scenario].code) {
          var code = test.cases[test.scenario].code
          var pause = test.operation() === "unlock" && ["cancelled", "denied", "biometric_denied"].indexOf(code) !== -1
          test.check(panel.message === panel.describe(code) + (pause ? " · пауза 30 с" : ""), "terminal error/cooldown message did not match the operation")
        }
        test.check(test.calls.filter(function(c) { return c.action === "keys.unlock" || c.action === "sync" || c.action === "revoke" }).length === test.scenario + 1, "polling retried an access operation")
        test.phase = "next"
      }
    }
  }
  Timer {
    interval: 35000; running: true
    onTriggered: test.check(false, "request lifecycle timed out")
  }
}
