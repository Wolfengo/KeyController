import QtQuick
import Quickshell
import QtTest
import "plugin" as Plugin

// The widget can open an editor, but cannot submit policy or consent values.
ShellRoot {
  id: test
  property var calls: []
  property var row: ({key_id:"SHA256:fixture", name:"Fixture", path:"/test/.ssh/fixture",
    fingerprint:"SHA256:fixture", encrypted:true, unavailable:null, unencrypted_copies:[],
    state:"unlocked", expires_at:2000000000, lifetime_known:true, bound:true,
    mode:"fingerprint", inherits:true, rules:{lifetime_seconds:60}})
  function check(value, message) {
    if (!value) { console.error("SETTINGS_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
  }
  function find(object, name, seen) {
    if (!object || typeof object !== "object") return null
    seen = seen || []
    if (seen.indexOf(object) >= 0) return null
    seen.push(object)
    if (object.objectName === name) return object
    for (var prop of ["data", "children", "contentItem"]) {
      var value = object[prop]
      if (!value) continue
      var list = value.length === undefined ? [value] : value
      for (var i = 0; i < list.length; ++i) {
        var found = find(list[i], name, seen)
        if (found) return found
      }
    }
    return null
  }
  Plugin.Panel {
    id: panel
    uiLanguage: "en"
    manageIpc: false
    rows: [test.row]
    function refresh() {}
    function startCall(action, key, value, request) {
      test.calls.push({action:action,key:key,value:value,request:request})
      return true
    }
  }
  TestCase {id: clock; when:false}
  Timer {
    interval:100; running:true
    onTriggered: {
      panel.open(); clock.wait(100)
      var before = JSON.stringify(panel.rows)
      test.check(!panel.editRules(null) && !test.calls.length, "unknown settings opened an editor")
      panel.receiveGlobalRules({lifetime_seconds:60,revoke_on_sleep:true})
      test.check(panel.editRules(null), "global editor did not open")
      test.check(test.calls[0].action === "settings.global" && test.calls[0].key === null && test.calls[0].value === null,
        "global launch supplied policy/approval")
      test.check(panel.editRules(test.row), "key editor did not open")
      test.check(test.calls[1].action === "settings.key" && test.calls[1].key === test.row.key_id && test.calls[1].value === null,
        "key launch supplied policy/approval")
      panel.activeRequest = "pending-editor"
      test.check(!panel.editRules(test.row) && test.calls.length === 2, "duplicate active editor")
      panel.activeRequest = ""
      panel.settingsFor(test.row)
      clock.wait(100)
      test.check(panel.settingsOpen && test.find(panel, "ssh-key-policy-summary").text === "1 min · Default duration",
        "inline details lost effective policy")
      test.check(!test.find(panel, "ssh-key-save-rules") && !test.find(panel, "ssh-key-lifetime"), "QML still edits policy")
      var edit = test.find(panel, "ssh-key-edit-rules")
      test.check(edit.visible && edit.enabled, "details lack editor launcher")
      edit.clicked()
      test.check(test.calls.length === 3 && test.calls[2].action === "settings.key" && test.calls[2].value === null,
        "details did not open protected editor")
      test.check(JSON.stringify(panel.rows) === before, "opening editors changed access or rules")
      panel.close()
      console.log("SSH_KEYS_SETTINGS_REGRESSION_OK")
      Qt.quit()
    }
  }
}
