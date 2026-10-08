import QtQuick
import Quickshell
import "plugin" as Plugin

// Four visual states with artificial metadata. All API calls are intercepted.
ShellRoot {
  id: test
  property var popup: null
  property var repeater: null
  property int phase: 0
  property bool capturePending: false
  property var captured: []
  property var fixture: [
    {key_id:"SHA256:test1",name:"ExampleServer",path:"/test/.ssh/servers/example-server",algorithm:"ssh-ed25519",fingerprint:"SHA256:artificial-main-key",encrypted:true,unavailable:null,unencrypted_copies:[],state:"locked",bound:false,mode:"password",inherits:true,rules:{lifetime_seconds:0}},
    {key_id:"SHA256:test2",name:"Personal laptop",path:"/test/.ssh/laptop",algorithm:"ssh-ed25519",fingerprint:"SHA256:artificial-bound-key",encrypted:true,unavailable:null,unencrypted_copies:[],state:"unlocked",bound:true,mode:"fingerprint",inherits:false,lifetime_known:true,expires_at:Math.floor(Date.now() / 1000) + 872,rules:{lifetime_seconds:3600}},
    {key_id:"SHA256:test3",name:"A deliberately long SSH key name for checking card truncation",path:"/test/.ssh/archive/a-deliberately-long-key-path-for-layout-verification",algorithm:"ssh-ed25519",fingerprint:"SHA256:artificial-password-key",encrypted:true,unavailable:null,unencrypted_copies:["/test/.ssh/old-copy"],state:"locked",bound:true,mode:"password",inherits:true,rules:{lifetime_seconds:0}},
    {key_id:"SHA256:test4",name:"Local development",path:"/test/.ssh/development",algorithm:"ssh-ed25519",fingerprint:"SHA256:artificial-unencrypted-key",encrypted:false,unavailable:null,unencrypted_copies:[],state:"locked",bound:false,mode:"password",inherits:true,rules:{lifetime_seconds:0}},
    {key_id:"unsupported:/test/.ssh/legacy",name:"Legacy format",path:"/test/.ssh/legacy",algorithm:"ssh-ed25519",fingerprint:"",encrypted:false,unavailable:"unsupported_format",unencrypted_copies:[],state:"locked",bound:false,mode:"password",inherits:true,rules:{lifetime_seconds:0}}
  ]
  function check(condition, message) {
    if (!condition) { console.error("DESIGN_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
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
        var result = find(list[j], predicate, seen)
        if (result) return result
      }
    }
    return null
  }
  function controlFits(control, card) {
    check(control && control.visible && control.width > 0, "missing visible control")
    var point = control.mapToItem(card, 0, 0)
    check(point.x >= -0.5 && point.x + control.width <= card.width + 0.5, "control exceeds card: " + control.text)
    var label = find(control, function(o) { return o !== control && o.visible && o.text === control.text && o.font !== undefined && typeof o.mapToItem === "function" })
    check(label !== null, "button text not found: " + control.text)
    var labelPoint = label.mapToItem(control, 0, 0)
    check(labelPoint.x >= -0.5 && labelPoint.x + label.contentWidth <= control.width + 0.5, "button text exceeds bounds: " + control.text)
  }
  function capture(name) {
    var content = popup.contentItem[0]
    check(content && content.width > 0 && content.height > 0, "content has invalid dimensions in " + name)
    check(popup.contentWidth <= popup.availableCardWidth && popup.contentHeight <= popup.availableCardHeight, "popup exceeds screen in " + name)
    // Include KeyboardPanel's BorderSurface, so translucent bubble fills are
    // captured over their actual popup background instead of transparency.
    var card = content.parent.parent
    check(card && card.width > 0 && card.height > 0, "popup surface unavailable")
    capturePending = true
    check(card.grabToImage(function(image) {
      check(image.saveToFile(Quickshell.env("SSH_KEYS_DESIGN_OUTPUT") + "/" + name + ".png"), "failed to save " + name)
      captured.push(name)
      capturePending = false
      next.restart()
    }), "failed to capture " + name)
  }
  Plugin.Panel {
    uiLanguage: Quickshell.env("SSH_KEYS_DESIGN_LANGUAGE") || "ru"
    id: panel
    manageIpc: false
    globalRulesReady: true // This fixture begins with known artificial metadata.
    rows: test.fixture
    function startCall(action, key, value, request) { return true }
    Component.onCompleted: open()
  }
  Timer {
    id: next
    interval: 500; running: true
    onTriggered: {
      test.check(!test.capturePending, "previous capture pending")
      if (test.phase === 0) {
        test.popup = test.find(panel, function(o) { return typeof o.open === "boolean" && o.contentWidth !== undefined && o.anchorItem !== undefined })
        test.repeater = test.find(panel, function(o) { return o.objectName === "ssh-key-rows" })
        test.check(test.popup && test.repeater, "required objects missing")
        test.check(test.repeater.count === 3, "main list must contain encrypted keys only")
        for (var i = 0; i < test.repeater.count; ++i) {
          var card = test.repeater.itemAt(i)
          test.check(card.width > 0 && card.width <= test.popup.contentWidth, "key card has invalid width")
          var access = test.find(card, function(o) { return o.objectName === "ssh-key-access" })
          var method = test.find(card, function(o) { return o.objectName === "ssh-key-method" })
          test.controlFits(access, card)
          test.controlFits(method, card)
          test.check(method.mapToItem(card, method.width, 0).x <= access.mapToItem(card, 0, 0).x, "method/access controls overlap")
        }
        test.phase = 1
        test.capture("main")
      } else if (test.phase === 1) {
        // Put a supported unencrypted key first so Set passphrase is visible
        // in the bounded candidate capture rather than below the scroll fold.
        panel.rows = [test.fixture[3], test.fixture[0], test.fixture[4], test.fixture[1], test.fixture[2]]
        panel.showCandidates = true
        test.phase = 2
        next.restart()
      } else if (test.phase === 2) {
        test.check(test.repeater.count === 5, "candidate list must include supported and unsupported private keys")
        for (var j = 0; j < test.repeater.count; ++j) {
          var candidate = test.repeater.itemAt(j)
          test.controlFits(test.find(candidate, function(o) { return o.objectName === "ssh-key-encrypt" }), candidate)
        }
        test.phase = 3
        test.capture("candidates")
      } else if (test.phase === 3) {
        panel.showCandidates = false
        panel.rows = test.fixture
        panel.settingsFor(test.fixture[1])
        test.phase = 4
        next.restart()
      } else if (test.phase === 4) {
        test.check(panel.settingsOpen && panel.settingsKey === "SHA256:test2", "individual settings state")
        test.phase = 5
        test.capture("key-settings")
      } else if (test.phase === 5) {
        panel.settingsFor(null)
        test.phase = 6
        next.restart()
      } else if (test.phase === 6) {
        test.check(panel.settingsOpen && panel.settingsKey === "" && !panel.settingsRow, "global settings state")
        var sleep = test.find(panel, function(o) { return o.objectName === "ssh-keys-revoke-on-sleep" })
        var label = test.find(sleep, function(o) { return o.text === sleep.label && o.font !== undefined && typeof o.mapToItem === "function" })
        test.check(label && label.contentWidth <= label.width + 0.5, "general sleep label exceeds available width")
        test.controlFits(test.find(panel, function(o) { return o.objectName === "ssh-key-save-rules" }), test.popup.contentItem[0])
        test.phase = 7
        test.capture("global-settings")
      } else {
        test.check(test.captured.length === 4, "missing visual state")
        panel.close()
        console.log("SSH_KEYS_DESIGN_REGRESSION_OK")
        Qt.quit()
      }
    }
  }
}
