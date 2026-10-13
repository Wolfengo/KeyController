import QtQuick
import Quickshell.Io

// No clipboard object, dataChanged subscription or eager clipboard query.
// Only a SearchInput user gesture may start this short-lived bounded reader.
QtObject {
  id: root
  property var editor: null
  property var pending: null
  property string replyOutput: ""
  property bool busy: reader.running
  readonly property string script: decodeURIComponent(Qt.resolvedUrl("clipboard.py").toString().replace(/^file:\/\//, ""))
  signal failed(string code)

  function start(input) {
    if (reader.running || !input || !input.activeFocus) return
    editor = input
    replyOutput = ""
    pending = {revision: input.revision, start: input.selectionStart, end: input.selectionEnd,
      cursor: input.cursorPosition}
    reader.command = ["/usr/bin/python3", "-I", root.script]
    reader.running = true
    deadline.restart()
  }
  function cancel() {
    editor = null
    pending = null
    replyOutput = ""
    deadline.stop()
    if (reader.running) reader.signal(15)
  }
  function receive(output) {
    var input = editor
    var saved = pending
    editor = null
    pending = null
    deadline.stop()
    if (!input || !saved || !input.activeFocus || input.revision !== saved.revision
        || input.cursorPosition !== saved.cursor || input.selectionStart !== saved.start
        || input.selectionEnd !== saved.end) return
    try {
      if (output.length > 100000) throw new Error("invalid clipboard reply")
      var reply = JSON.parse(output)
      if (reply.ok !== true) { failed("clipboard_unavailable"); return }
      if (typeof reply.text !== "string" || reply.text.length > 4096
          || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(reply.text))
        throw new Error("invalid clipboard text")
      if (reply.text !== "" && !input.replaceSelection(reply.text)) failed("clipboard_unavailable")
    } catch (error) {
      failed("clipboard_unavailable")
    }
  }
  property Timer deadline: Timer {
    // Independent UI watchdog; the reader enforces its own shorter deadline.
    interval: 3000
    onTriggered: { root.cancel(); root.failed("clipboard_unavailable") }
  }
  property Process reader: Process {
    stdout: StdioCollector { onStreamFinished: if (root.pending) root.replyOutput = this.text }
    // Never send third-party clipboard output to the shell's journal.
    stderr: StdioCollector {}
    onExited: function(exitCode, exitStatus) {
      if (root.pending) {
        if (exitCode === 0 && exitStatus === 0) root.receive(root.replyOutput)
        else { root.cancel(); root.failed("clipboard_unavailable") }
      }
      root.replyOutput = ""
    }
  }
  Component.onDestruction: cancel()
}
