import QtQuick
import "plugin" as Plugin

// The real SearchInput component is staged unchanged by search-clipboard.py.
// Only Omarchy's visual TextField wrapper is replaced with a small style stub;
// Qt Quick Controls' native TextField implementation remains the one under test.
Item {
  id: fixture
  width: 480
  height: 160
  property bool searchActive: true
  property bool controlActive: false
  property bool searchWasWritable: false

  Loader {
    id: searchLoader
    active: fixture.searchActive
    width: parent.width
    height: 48
    sourceComponent: Plugin.SearchInput {
      objectName: "bounded-search"
      onReadOnlyChanged: if (!readOnly) fixture.searchWasWritable = true
    }
  }
  Loader {
    active: fixture.controlActive
    y: 70
    width: parent.width
    height: 48
    sourceComponent: TextInput {
      objectName: "editable-control"
      readOnly: false
    }
  }
}
