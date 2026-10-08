import QtQuick
import Quickshell
import "plugin" as Plugin

// The real Process and StdioCollector run repeatedly. Only the executable is
// replaced by a fixture that prints valid, unchanged API metadata.
ShellRoot {
  id: test
  property var rpc: null
  property var repeater: null
  property var first: null
  property var access: null
  property var popup: null
  property bool baselineReady: false
  property int replies: 0
  property int uiChanges: 0
  property var geometry: null
  function check(condition, message) {
    if (!condition) { console.error("PROCESS_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
  }
  function changed(property) {
    if (baselineReady) { uiChanges++; console.error("UNEXPECTED_UI_CHANGE", property) }
  }
  function find(object, predicate, seen) {
    if (!object || typeof object !== "object") return null
    seen = seen || []
    if (seen.indexOf(object) >= 0) return null
    seen.push(object)
    if (predicate(object)) return object
    var properties = ["data", "children", "contentItem"]
    for (var i = 0; i < properties.length; ++i) {
      var value = object[properties[i]]
      if (!value) continue
      var list = value.length === undefined ? [value] : value
      for (var j = 0; j < list.length; ++j) {
        var found = find(list[j], predicate, seen)
        if (found) return found
      }
    }
    return null
  }
  function rectangle() {
    return [popup.contentWidth, popup.contentHeight, first.x, first.y, first.width, first.height, access.x, access.y, access.width, access.height]
  }
  Plugin.Panel {
    uiLanguage: "ru"
    id: panel
    manageIpc: false
    function startCall(action, key, value, request) {
      test.check(action === "panel.list", "unexpected API action")
      currentAction = action
      test.rpc.command = ["/usr/bin/python3", Quickshell.env("SSH_KEYS_TEST_REPLY")]
      test.rpc.running = true
      return true
    }
    onRowsChanged: test.changed("rows")
    onGlobalRulesChanged: test.changed("globalRules")
    onActionBusyChanged: test.changed("actionBusy")
    onActiveRequestChanged: test.changed("activeRequest")
    onMessageChanged: test.changed("message")
    onImplicitWidthChanged: test.changed("barWidth")
    onImplicitHeightChanged: test.changed("barHeight")
  }
  Connections {
    target: test.rpc
    function onExited() { test.replies++ }
  }
  Connections {
    target: test.access
    function onEnabledChanged() { test.changed("controlEnabled") }
    function onActiveFocusChanged() { test.changed("controlFocus") }
    function onXChanged() { test.changed("controlX") }
    function onYChanged() { test.changed("controlY") }
    function onWidthChanged() { test.changed("controlWidth") }
    function onHeightChanged() { test.changed("controlHeight") }
  }
  Connections {
    target: test.first
    function onXChanged() { test.changed("rowX") }
    function onYChanged() { test.changed("rowY") }
    function onWidthChanged() { test.changed("rowWidth") }
    function onHeightChanged() { test.changed("rowHeight") }
  }
  Connections {
    target: test.popup
    function onContentWidthChanged() { test.changed("popupWidth") }
    function onContentHeightChanged() { test.changed("popupHeight") }
  }
  Timer {
    interval: 100; running: true
    onTriggered: {
      test.rpc = test.find(panel, function(o) { return o.objectName === "ssh-keys-rpc" })
      test.repeater = test.find(panel, function(o) { return o.objectName === "ssh-key-rows" })
      test.popup = test.find(panel, function(o) { return typeof o.open === "boolean" && o.contentWidth !== undefined && o.anchorItem !== undefined })
      test.check(test.rpc && test.repeater && test.popup, "fixture objects missing")
      panel.open()
    }
  }
  Timer {
    interval: 700; running: true
    onTriggered: {
      test.check(test.replies === 1 && test.repeater.count === 1, "first real subprocess response")
      test.first = test.repeater.itemAt(0)
      test.access = test.find(test.first, function(o) { return o.objectName === "ssh-key-access" })
      test.check(test.access.enabled, "control initially disabled")
      test.access.forceActiveFocus()
      test.geometry = test.rectangle()
      test.baselineReady = true
    }
  }
  Timer {
    interval: 7400; running: true
    onTriggered: {
      test.check(test.replies >= 7, "not enough real Process responses")
      test.check(test.uiChanges === 0, "unchanged polls changed UI properties")
      test.check(test.repeater.itemAt(0) === test.first, "delegate replaced")
      test.check(test.access.enabled && test.access.activeFocus && !panel.actionBusy, "enabled/focus/busy changed")
      test.check(JSON.stringify(test.rectangle()) === JSON.stringify(test.geometry), "popup or row geometry changed")
      test.baselineReady = false
      panel.close()
      console.log("SSH_KEYS_PROCESS_REGRESSION_OK", test.replies, "responses; 0 UI property changes")
      Qt.quit()
    }
  }
}
