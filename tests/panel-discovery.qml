import QtQuick
import Quickshell
import QtTest
import "plugin" as Plugin

ShellRoot {
  id: test
  property var rpc: null
  property int scans: 0
  property bool approved: false
  property bool scanned: false
  property string outcome: "pending"
  property string requestId: ""
  property string directory: "/test/<local-user>/.ssh"
  function check(value, message) {
    if (!value) { console.error("DISCOVERY_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
  }
  function find(object, name, seen) {
    if (!object || typeof object !== "object") return null
    seen = seen || []; if (seen.indexOf(object) >= 0) return null; seen.push(object)
    if (object.objectName === name) return object
    for (var prop of ["data", "children", "contentItem"]) {
      var value = object[prop]; if (!value) continue
      var list = value.length === undefined ? [value] : value
      for (var i = 0; i < list.length; ++i) { var found = find(list[i], name, seen); if (found) return found }
    }
    return null
  }
  function idle() { return !rpc.running && !panel.rpcInFlight && !panel.queuedCall && !panel.submittingAction && !panel.deferredAction }
  function waitFor(fn, message) { var until = Date.now()+3000; while (!fn() && Date.now()<until) clock.wait(15); check(fn(), message) }
  function refresh() { panel.call("panel.list"); waitFor(idle, "metadata did not settle") }
  function status() { panel.call("requests.status", null, null, requestId); waitFor(idle, "scan result did not settle") }
  Plugin.Panel {
    id: panel
    manageIpc: false
    inventoryReady: false
    scanned: false
    discoveryApproved: false
    function refresh() { if (test.rpc && !activeRequest) call("panel.list") }
    function startCall(action, key, value, request) {
      var result = {api_version:1, state:"ready", error_code:null, request_id:null, key_id:null}
      if (action === "panel.list") {
        result.ui_language = "en"; result.global_rules = {lifetime_seconds:60, revoke_on_sleep:true}
        result.scanned = test.scanned; result.scan_root = test.directory; result.scan_requires_consent = !test.approved
        result.keys = []; result.active_request = null
      } else if (action === "scan") {
        test.scans++; test.requestId = "discovery-"+test.scans
        result.state = "pending"; result.request_id = test.requestId
      } else if (action === "requests.status") {
        test.check(request === test.requestId, "wrong discovery request")
        result.state = test.outcome; result.request_id = request
        if (test.outcome === "error") result.error_code = "scan_failed"
        if (test.outcome === "scanned") { test.approved = true; test.scanned = true }
      } else test.check(false, "unexpected action or dialog: "+action)
      test.rpc.command = ["/usr/bin/python3", Quickshell.env("SSH_KEYS_TEST_REPLY"), JSON.stringify(result), "0.10"]
      test.rpc.running = true
      return true
    }
  }
  TestCase { id: clock; when: false }
  Timer {
    interval:100; running:true
    onTriggered: {
      test.rpc = test.find(panel, "ssh-keys-rpc")
      test.check(test.rpc, "RPC missing")
      test.check(!panel.scanKeys(), "scan accepted before location known")
      panel.open(); test.waitFor(test.idle, "opening metadata pending")
      test.refresh()
      var intro = test.find(panel, "ssh-keys-first-scan")
      var path = test.find(panel, "ssh-keys-scan-root")
      var confirm = test.find(panel, "ssh-keys-confirm-scan")
      var later = test.find(panel, "ssh-keys-defer-scan")
      test.check(intro && path && confirm && later, "inline discovery UI missing")
      test.check(intro.visible && panel.needsInitialScan && confirm.enabled, "first-use consent not shown")
      test.check(path.text === test.directory && path.textFormat === Text.PlainText, "wrong or rich-text scope")
      test.check(confirm.text === "Scan" && later.text === "Later", "English consent untranslated")
      panel.uiLanguage = "ru"
      test.check(confirm.text === "Сканировать" && later.text === "Позже", "Russian consent untranslated")
      panel.uiLanguage = "en"
      clock.wait(1200); test.waitFor(test.idle, "poll pending")
      test.check(test.scans === 0, "background poll silently discovered files")
      later.clicked(); test.check(!panel.opened, "Later did not close")
      panel.open(); test.waitFor(test.idle, "reopen pending")
      test.check(test.scans === 0 && panel.needsInitialScan, "Later persisted approval or started scan")
      for (var outcome of ["cancelled", "error", "scanned"]) {
        test.outcome = "pending"
        var before = test.scans
        confirm.clicked()
        test.check(!panel.scanKeys(), "duplicate first click accepted")
        test.waitFor(function() { return test.idle() && panel.activeRequest === test.requestId }, "scan not tracked")
        test.check(test.scans === before+1 && panel.opened && !confirm.enabled, "scan opened dialog or allowed duplicates")
        test.outcome = outcome; test.status()
        test.check(!panel.activeRequest, "terminal scan result left busy latch")
        test.check(panel.needsInitialScan === (outcome !== "scanned"), "approval changed before successful discovery")
        if (outcome !== "scanned") test.check(confirm.enabled, "failed scan cannot be retried")
      }
      test.check(panel.discoveryApproved && !intro.visible, "successful scan did not dismiss intro")
      // Cache invalidation must not silently rescan or ask for first-use consent again.
      test.scanned = false; var before = test.scans
      test.refresh(); panel.close(); panel.open(); test.waitFor(test.idle, "invalidated reopen pending")
      test.check(!panel.needsInitialScan && !panel.scanned && test.scans === before, "inventory invalidation reset approval or autoscanned")
      test.outcome = "pending"
      test.check(panel.scanKeys(), "manual refresh unavailable after inventory invalidation")
      test.waitFor(function() { return test.idle() && panel.activeRequest === test.requestId }, "manual refresh not pending")
      test.outcome = "scanned"; test.status()
      test.check(test.scans === before+1, "manual refresh count wrong")
      panel.close(); console.log("KEYCONTROLLER_DISCOVERY_REGRESSION_OK"); Qt.quit()
    }
  }
}
