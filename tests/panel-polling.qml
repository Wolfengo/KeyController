import QtQuick
import Quickshell
import "plugin" as Plugin

// Run through tests/panel-polling.py in an unlocked graphical session.
// All calls are intercepted: this fixture never contacts the system helper.
ShellRoot {
  id: test
  property var first: null
  property var second: null
  property var repeater: null
  property var rpc: null
  property var access: null
  property var calls: []
  property var fixture: [
    {key_id:"SHA256:test1",name:"UI TEST 1",path:"/test/.ssh/key1",algorithm:"ssh-ed25519",fingerprint:"SHA256:test1",encrypted:true,unavailable:null,unencrypted_copies:[],state:"locked",bound:false,mode:"password",inherits:true,rules:{lifetime_seconds:0}},
    {key_id:"SHA256:test2",name:"UI TEST 2",path:"/test/.ssh/key2",algorithm:"ssh-ed25519",fingerprint:"SHA256:test2",encrypted:true,unavailable:null,unencrypted_copies:[],state:"locked",bound:true,mode:"fingerprint",inherits:true,rules:{lifetime_seconds:0}}
  ]
  function check(condition, message) {
    if (!condition) { console.error("POLLING_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
  }
  function find(object, name, seen) {
    if (!object || typeof object !== "object") return null
    seen = seen || []
    if (seen.indexOf(object) >= 0) return null
    seen.push(object)
    if (object.objectName === name) return object
    var properties = ["data", "children", "contentItem"]
    for (var i = 0; i < properties.length; ++i) {
      var value = object[properties[i]]
      if (!value) continue
      var list = value.length === undefined ? [value] : value
      for (var j = 0; j < list.length; ++j) {
        var result = find(list[j], name, seen)
        if (result) return result
      }
    }
    return null
  }
  Plugin.Panel {
    uiLanguage: "ru"
    id: panel
    manageIpc: false
    rows: test.fixture
    function refresh() {}
    function startCall(action, key, value, request) { test.calls.push({action: action, key: key, value: value}); return true }
    Component.onCompleted: open()
  }
  Timer {
    interval: 180; running: true
    onTriggered: {
      test.repeater = test.find(panel, "ssh-key-rows")
      test.rpc = test.find(panel, "ssh-keys-rpc")
      test.check(test.repeater && test.rpc, "test objects not found")
      test.check(test.repeater.count === 2, "initial rows")
      test.first = test.repeater.itemAt(0)
      test.second = test.repeater.itemAt(1)
      test.access = test.find(test.first, "ssh-key-access")
      test.check(test.access && test.access.enabled, "initial control enabled")
      test.access.forceActiveFocus()
      for (var i = 0; i < 5; ++i) panel.updateRows(JSON.parse(JSON.stringify(test.fixture)))
      test.check(test.repeater.itemAt(0) === test.first && test.repeater.itemAt(1) === test.second, "identical polls replaced delegates")
      test.check(test.access.activeFocus, "identical polls lost keyboard focus")
      var changed = JSON.parse(JSON.stringify(test.fixture))
      changed[0].state = "unlocked"
      changed[0].lifetime_known = false
      panel.updateRows(changed)
      test.check(test.repeater.itemAt(0) === test.first && test.repeater.itemAt(1) === test.second, "status update replaced delegates")
      test.check(test.first.modelData.state === "unlocked" && test.access.tooltipText === "Отозвать ключ", "status update did not reach controls")
      panel.updateRows([changed[1], changed[0]])
      test.check(test.repeater.itemAt(0) === test.second && test.repeater.itemAt(1) === test.first, "reorder replaced delegates")
      panel.currentAction = "panel.list"
      test.rpc.command = ["/usr/bin/sleep", "0.3"]
      test.rpc.running = true
      test.check(!panel.actionBusy && test.access.enabled, "background poll dimmed controls")
      test.check(panel.call("mode", "SHA256:test1", {fingerprint_mode:true}), "click during poll was dropped")
      test.check(!panel.call("mode", "SHA256:test1", {fingerprint_mode:true}), "duplicate click was accepted")
      test.check(test.calls.length === 0 && panel.actionBusy, "queued action ran before poll completed")
    }
  }
  Timer {
    interval: 650; running: true
    onTriggered: {
      test.check(test.calls.length === 1 && test.calls[0].action === "mode" && test.calls[0].key === "SHA256:test1", "queued action was not delivered once")
      test.check(JSON.stringify(test.calls[0].value) === '{"fingerprint_mode":true}', "queue changed the desired mode")
      test.check(!panel.actionBusy && test.access.enabled, "controls stayed disabled after queued action")
      panel.close()
      console.log("SSH_KEYS_POLLING_REGRESSION_OK")
      Qt.quit()
    }
  }
}
