import QtQuick
import qs.Ui

// Qt's editable TextInput probes the clipboard on every clipboard change,
// including when unfocused/hidden. Keep the native editor read-only for its
// entire lifetime. Public insert/remove retain Qt's layout and selection;
// only explicit keyboard events edit this small, non-secret search string.
// Never temporarily set readOnly=false, even for typing or undo.
TextField {
  id: root
  readOnly: true
  maximumLength: 4096
  selectByMouse: true
  cursorVisible: activeFocus
  signal pasteRequested()
  property int revision: 0
  property bool changing: false
  property var undoStates: []
  property var redoStates: []

  function snapshot() {
    return {text: text, cursor: cursorPosition, start: selectionStart, end: selectionEnd}
  }
  function restore(state) {
    changing = true
    text = state.text
    cursorPosition = state.cursor
    if (state.start !== state.end) select(state.start, state.end)
    changing = false
  }
  function remember() {
    undoStates = undoStates.concat([snapshot()]).slice(-32)
    redoStates = []
  }
  function replaceSelection(value) {
    if (!value || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(value)) return false
    var available = maximumLength - (length - (selectionEnd - selectionStart))
    if (value.length > available) return false
    remember()
    changing = true
    var position = selectionStart
    remove(selectionStart, selectionEnd)
    insert(position, value)
    cursorPosition = position + value.length
    changing = false
    return true
  }
  function previousPosition(position) {
    if (position <= 0) return 0
    var code = text.charCodeAt(position - 1)
    return position > 1 && code >= 0xdc00 && code <= 0xdfff ? position - 2 : position - 1
  }
  function nextPosition(position) {
    if (position >= length) return length
    var code = text.charCodeAt(position)
    return position + 1 < length && code >= 0xd800 && code <= 0xdbff ? position + 2 : position + 1
  }
  function erase(backward, word) {
    var start = selectionStart
    var end = selectionEnd
    if (start === end) {
      if (backward) {
        start = previousPosition(start)
        if (word) {
          while (start > 0 && /\s/.test(text.charAt(start))) start = previousPosition(start)
          while (start > 0 && !/\s/.test(text.charAt(previousPosition(start)))) start = previousPosition(start)
        }
      } else {
        end = nextPosition(end)
        if (word) {
          while (end < length && !/\s/.test(text.charAt(end))) end = nextPosition(end)
          while (end < length && /\s/.test(text.charAt(end))) end = nextPosition(end)
        }
      }
    }
    if (start === end) return
    remember()
    changing = true
    remove(start, end)
    cursorPosition = start
    changing = false
  }
  function undoEdit() {
    if (!undoStates.length) return
    redoStates = redoStates.concat([snapshot()]).slice(-32)
    var state = undoStates[undoStates.length - 1]
    undoStates = undoStates.slice(0, -1)
    restore(state)
  }
  function redoEdit() {
    if (!redoStates.length) return
    undoStates = undoStates.concat([snapshot()]).slice(-32)
    var state = redoStates[redoStates.length - 1]
    redoStates = redoStates.slice(0, -1)
    restore(state)
  }
  onTextChanged: {
    revision++
    if (!changing) { undoStates = []; redoStates = [] }
  }
  Keys.priority: Keys.BeforeItem
  Keys.onPressed: function(event) {
    if (event.matches(StandardKey.Paste)) {
      pasteRequested()
    } else if (event.matches(StandardKey.Undo)) {
      undoEdit()
    } else if (event.matches(StandardKey.Redo)) {
      redoEdit()
    } else if (event.matches(StandardKey.Cut)) {
      if (selectedText !== "") { copy(); erase(false, false) }
    } else if (event.key === Qt.Key_Backspace || event.key === Qt.Key_Delete) {
      erase(event.key === Qt.Key_Backspace, !!(event.modifiers & Qt.ControlModifier))
    } else {
      var command = !!(event.modifiers & (Qt.ControlModifier | Qt.MetaModifier))
      var altGraph = !!(event.modifiers & Qt.GroupSwitchModifier)
        || !!(event.modifiers & Qt.ControlModifier) && !!(event.modifiers & Qt.AltModifier)
      if (event.text && (!command || altGraph)
          && !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(event.text)) {
        replaceSelection(event.text)
      } else {
        event.accepted = false
        return
      }
    }
    event.accepted = true
  }
  // No native context menu or PRIMARY-selection paste. The explicit keyboard
  // paste action is handled out of process by ClipboardPaste, never paste().
  MouseArea {
    anchors.fill: parent
    acceptedButtons: Qt.RightButton | Qt.MiddleButton
    onPressed: function(mouse) { mouse.accepted = true }
  }
}
