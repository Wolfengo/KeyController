import QtQuick
import QtQuick.Window
import QtTest
import Quickshell
import Quickshell.Io
import "plugin" as Plugin

// The production components are copied unchanged. Only the Python executable's
// input provider and Omarchy's visual TextField wrapper are synthetic fixtures.
ShellRoot {
  id: fixture
  property string scenario: Quickshell.env("KEYCONTROLLER_PASTE_TEST_CASE")
  property bool panelOpen: true
  property bool editorPresent: true
  property bool pastePresent: true
  property int failures: 0
  readonly property var editor: editorLoader.item
  readonly property var paste: pasteLoader.item
  onPanelOpenChanged: if (!panelOpen && paste) paste.cancel()
  onEditorChanged: if (!editor && paste) paste.cancel()

  function check(value, message) {
    if (!value) {
      console.error("CLIPBOARD_PASTE_REGRESSION_FAILED", scenario, message)
      Qt.exit(1)
      throw new Error(message)
    }
  }
  function until(predicate, timeout, message) {
    var end = Date.now() + timeout
    while (!predicate() && Date.now() < end) clock.wait(10)
    check(predicate(), message)
  }
  function events() {
    eventFile.reload()
    return eventFile.text()
  }

  FileView {
    id: eventFile
    path: Quickshell.env("KEYCONTROLLER_PASTE_TEST_EVENTS")
    blockLoading: true
    blockAllReads: true
  }
  FileView {
    id: releaseFile
    path: Quickshell.env("KEYCONTROLLER_PASTE_TEST_RELEASE")
    blockWrites: true
  }
  Loader {
    id: pasteLoader
    active: fixture.pastePresent
    sourceComponent: Plugin.ClipboardPaste {
      onFailed: fixture.failures++
    }
  }
  Window {
    id: window
    visible: true
    width: 480
    height: 160
    Loader {
      id: editorLoader
      active: fixture.panelOpen && fixture.editorPresent
      width: parent.width
      height: 48
      sourceComponent: Plugin.SearchInput {
        text: "base"
        onPasteRequested: fixture.paste.start(this)
        onActiveFocusChanged: {
          if (!activeFocus && fixture.scenario === "focus_cancel" && fixture.paste)
            fixture.paste.cancel()
        }
      }
    }
    Item { id: alternateFocus; y: 80; width: 100; height: 40 }
  }
  TestCase { id: clock; name: "Synthetic clipboard paste"; when: false }
  Timer {
    interval: 50
    running: true
    onTriggered: {
      fixture.until(function() { return fixture.editor && fixture.paste }, 1000, "components missing")
      fixture.editor.forceActiveFocus()
      fixture.until(function() { return fixture.editor.activeFocus }, 1000, "offscreen editor focus missing")
      fixture.editor.cursorPosition = fixture.editor.length
      fixture.check(fixture.editor.readOnly, "production search became editable")
      fixture.editor.pasteRequested()
      fixture.until(function() { return fixture.events().indexOf("started") >= 0 }, 1000, "fake child did not start")
      fixture.check(fixture.paste.busy && fixture.editor.text === "base", "data applied before successful exit")
      // Duplicate user gestures must not spawn another clipboard reader.
      fixture.editor.pasteRequested()
      clock.wait(40)
      fixture.check(fixture.events().split("started").length === 2, "duplicate process started")

      var input = fixture.editor
      var started = Date.now()
      if (fixture.scenario === "stale_text") input.text = "changed"
      else if (fixture.scenario === "stale_cursor") input.cursorPosition = 0
      else if (fixture.scenario === "stale_selection") input.select(1, input.length)
      else if (fixture.scenario === "stale_focus" || fixture.scenario === "focus_cancel") alternateFocus.forceActiveFocus()
      else if (fixture.scenario === "close_panel") fixture.panelOpen = false
      else if (fixture.scenario === "destroy_editor") fixture.editorPresent = false
      else if (fixture.scenario === "destroy_paste") fixture.pastePresent = false

      var cancelled = ["focus_cancel", "close_panel", "destroy_editor", "destroy_paste"].indexOf(fixture.scenario) >= 0
      if (cancelled || fixture.scenario === "timeout") {
        fixture.until(function() { return fixture.events().indexOf("terminated") >= 0 },
                      fixture.scenario === "timeout" ? 4500 : 1000, "fake child was not cancelled")
      } else {
        releaseFile.setText("finish")
      }
      fixture.until(function() { return !fixture.paste || !fixture.paste.busy }, 1000, "process remained busy")
      clock.wait(30)

      if (fixture.scenario === "success") {
        fixture.check(input.text === "basePASTE", "explicit successful paste missing")
        fixture.check(input.cursorPosition === 9 && fixture.failures === 0, "successful paste state incorrect")
      } else if (fixture.editor) {
        fixture.check(fixture.editor.text === (fixture.scenario === "stale_text" ? "changed" : "base"), "stale or failed paste was applied")
      }
      if (fixture.scenario === "nonzero" || fixture.scenario === "timeout") {
        fixture.check(fixture.failures === 1, "failed operation was not reported exactly once")
      } else fixture.check(fixture.failures === 0, "cancelled or stale operation reported an error")
      if (fixture.scenario === "timeout") {
        fixture.check(Date.now() - started < 4000, "UI watchdog exceeded its bounded deadline")
      }
      if (fixture.paste) {
        fixture.check(fixture.paste.pending === null && fixture.paste.editor === null, "pending editor survived completion")
      }
      console.log("CLIPBOARD_PASTE_REGRESSION_OK", fixture.scenario)
      Qt.quit()
    }
  }
}
