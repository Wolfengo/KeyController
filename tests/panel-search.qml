import QtQuick
import QtTest
import Quickshell
import "plugin" as Plugin

// Artificial public metadata only. No API call or filesystem discovery is used.
ShellRoot {
  id: test
  property var search: null
  property var repeater: null
  property var scroll: null
  property var clearButton: null
  property int calls: 0
  property var fixture: [
    key("alpha", "Alpha server", "/test/.ssh/team/alpha", "SHA256:MiXeDAlpha", true),
    key("alpine", "Alpine laptop", "/test/.ssh/alpine", "SHA256:Other", true),
    key("work", "Работа", "/test/.ssh/СЕРВЕР/ключ", "SHA256:Work", true),
    key("literal", "[backup].*", "/test/.ssh/literal", "SHA256:Literal", true),
    key("candidate", "Candidate only", "/test/.ssh/NEW/candidate", "SHA256:Candidate", false),
    key("alpha", "Deployment alias", "/test/.ssh/deployment-copy", "SHA256:MiXeDAlpha", true)
  ]
  function key(id, name, path, fingerprint, encrypted) {
    return {key_id: id, name: name, path: path, fingerprint: fingerprint, encrypted: encrypted,
      algorithm: "ssh-ed25519", unavailable: null, unencrypted_copies: [], state: "locked",
      bound: false, mode: "password", inherits: true, lifetime_known: false, expires_at: null,
      rules: {lifetime_seconds: 0}}
  }
  function check(value, message) {
    if (!value) { console.error("SEARCH_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
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
        var result = find(list[i], name, seen)
        if (result) return result
      }
    }
    return null
  }
  function waitFor(predicate, message) {
    var until = Date.now() + 2500
    while (!predicate() && Date.now() < until) keyboard.wait(15)
    check(predicate(), message)
  }
  function replaceText(value) {
    search.remove(0, search.length)
    search.insert(0, value)
  }
  Plugin.Panel {
    id: panel
    manageIpc: false
    uiLanguage: "en"
    rows: test.fixture
    function refresh() {}
    function startCall(action, key, value, request) { test.calls++; return false }
    Component.onCompleted: open()
  }
  TestCase { id: keyboard; when: false }
  Timer {
    interval: 180; running: true
    onTriggered: {
      test.search = test.find(panel, "ssh-keys-search")
      test.repeater = test.find(panel, "ssh-key-rows")
      test.scroll = test.find(panel, "ssh-keys-scroll")
      test.clearButton = test.find(panel, "ssh-keys-search-clear")
      test.check(test.search && test.repeater && test.scroll && test.clearButton, "controls missing")
      test.check(test.search.readOnly, "native clipboard-reading editor is enabled")
      keyboard.parent = test.search
      test.waitFor(function() { return test.search.activeFocus }, "popup did not focus search")
      test.check(test.repeater.count === 4, "main list dedup/encrypted scope changed")
      var alpha = test.repeater.itemAt(0)
      var alpine = test.repeater.itemAt(1)

      // Real keyboard events must reach the focused input, filter immediately,
      // and never activate a row or send any request.
      keyboard.keyClick(Qt.Key_A)
      test.check(test.search.text === "a" && test.repeater.count === 4, "first typed character")
      keyboard.keyClick(Qt.Key_L)
      test.check(test.search.text === "al" && test.repeater.count === 3, "second typed character")
      keyboard.keyClick(Qt.Key_P)
      test.check(test.search.text === "alp" && test.repeater.count === 2, "third typed character")
      test.check(test.repeater.itemAt(0) === alpha && test.repeater.itemAt(1) === alpine, "typing replaced surviving delegates")
      keyboard.keyClick(Qt.Key_H)
      test.check(test.repeater.count === 1 && test.repeater.itemAt(0) === alpha, "fourth character did not narrow")
      test.check(test.search.activeFocus, "typing lost focus")
      keyboard.keyClick(Qt.Key_Backspace)
      test.check(test.search.text === "alp", "backspace")
      keyboard.keyClick(Qt.Key_Z, Qt.ControlModifier)
      test.check(test.search.text === "alph", "bounded undo")
      keyboard.keyClick(Qt.Key_Z, Qt.ControlModifier | Qt.ShiftModifier)
      test.check(test.search.text === "alp", "bounded redo")
      keyboard.keyClick(Qt.Key_H)

      // An identical poll and an access-state change preserve both text and
      // row identity, including the edit cursor/selection.
      test.search.select(1, 3)
      for (var i = 0; i < 4; ++i) panel.updateRows(JSON.parse(JSON.stringify(test.fixture)))
      var updated = JSON.parse(JSON.stringify(test.fixture))
      updated[0].state = "unlocked"
      panel.updateRows(updated)
      test.check(test.repeater.itemAt(0) === alpha && alpha.modelData.state === "unlocked", "poll replaced filtered row")
      test.check(test.search.text === "alph" && test.search.activeFocus && test.search.selectedText === "lp", "poll disturbed editing")
      test.find(alpha, "ssh-key-access").forceActiveFocus()
      keyboard.keyClick(Qt.Key_F, Qt.ControlModifier)
      test.check(test.search.activeFocus && test.search.selectedText === "alph", "Ctrl+F did not return to search")

      keyboard.mouseClick(test.clearButton, test.clearButton.width / 2, test.clearButton.height / 2, Qt.LeftButton)
      test.check(test.search.text === "" && test.repeater.count === 4 && test.search.activeFocus, "clear button")

      // TextInput insertion is the same text-change route used by an input
      // method; QtTest's key enum cannot represent Cyrillic characters.
      test.search.insert(0, "РА")
      test.check(test.repeater.count === 1 && test.repeater.itemAt(0).modelData.name === "Работа", "Cyrillic uppercase prefix")
      test.search.insert(test.search.length, "БОТА")
      test.check(test.repeater.count === 1, "Cyrillic typing")
      test.replaceText("сервер")
      test.check(test.repeater.count === 1 && test.repeater.itemAt(0).modelData.name === "Работа", "case-insensitive path")
      test.replaceText("mixedalpha")
      test.check(test.repeater.count === 1 && test.repeater.itemAt(0).modelData.key_id === "alpha", "case-insensitive fingerprint")
      test.replaceText("DEPLOYMENT-COPY")
      test.check(test.repeater.count === 1 && test.repeater.itemAt(0).modelData.path === "/test/.ssh/deployment-copy", "encrypted alias path")
      test.replaceText("[backup].*")
      test.check(test.repeater.count === 1 && test.repeater.itemAt(0).modelData.key_id === "literal", "query interpreted as regex")
      test.replaceText("[not-a-regex")
      test.check(test.repeater.count === 0 && panel.searchHasNoResults, "no match")
      var empty = test.find(panel, "ssh-keys-empty-message")
      test.check(empty.visible && empty.text === "No matches", "no-match copy")
      panel.uiLanguage = "ru"
      test.check(empty.text === "Нет совпадений" && test.search.placeholderText === "Поиск по имени, пути или отпечатку", "search localization")
      panel.uiLanguage = "en"
      keyboard.keyClick(Qt.Key_Escape)
      test.check(panel.opened && test.search.text === "" && test.repeater.count === 4, "Escape did not clear before closing")

      test.replaceText("candidate")
      test.check(test.repeater.count === 0, "unencrypted candidate leaked into main")
      panel.showCandidates = true
      test.check(test.search.text === "" && test.repeater.count === 6, "candidate switch did not reset search")
      test.replaceText("NEW/CANDIDATE")
      test.check(test.repeater.count === 1 && !test.repeater.itemAt(0).modelData.encrypted, "candidate path filtering")
      var candidate = test.repeater.itemAt(0)
      panel.updateRows(JSON.parse(JSON.stringify(test.fixture)))
      test.check(test.repeater.itemAt(0) === candidate, "candidate poll replaced row")
      panel.showCandidates = false
      test.check(test.search.text === "" && test.repeater.count === 4, "back to main did not reset search")

      // Keep enough metadata for an actual scroll range. Search changes return
      // to the top; a routine status poll must keep the current scroll offset.
      var many = test.fixture.slice()
      for (var j = 0; j < 10; ++j) many.push(test.key("extra" + j, "Extra " + j, "/test/.ssh/extra" + j, "SHA256:extra" + j, true))
      panel.updateRows(many)
      keyboard.wait(60)
      test.scroll.contentItem.contentY = 100
      panel.updateRows(JSON.parse(JSON.stringify(many)))
      test.check(test.scroll.contentItem.contentY === 100, "poll reset scroll")
      test.replaceText("Extra")
      test.waitFor(function() { return test.scroll.contentItem.contentY === 0 }, "search did not reset scroll")
      test.check(test.repeater.count === 10, "large-list search")

      panel.updateRows([])
      test.check(!panel.searchHasNoResults && empty.text === "Add a key with +", "empty main conflated with no matches")
      panel.showCandidates = true
      test.replaceText("anything")
      test.check(!panel.searchHasNoResults && empty.text === "No keys found", "empty inventory conflated with no matches")
      panel.close()
      test.check(panel.searchInput === null && panel.searchQuery === "", "closed panel retained its search editor")
      panel.open()
      test.search = test.find(panel, "ssh-keys-search")
      test.check(test.search && test.search.readOnly && test.search.text === "", "reopened editor is not safe/empty")
      keyboard.parent = test.search
      test.waitFor(function() { return test.search.activeFocus }, "reopened popup did not focus input")
      test.check(test.calls === 0, "local filtering dispatched API calls")
      panel.close()
      console.log("SSH_KEYS_SEARCH_REGRESSION_OK")
      Qt.quit()
    }
  }
}
