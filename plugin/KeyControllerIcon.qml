import QtQuick
import QtQuick.Effects
import qs.Commons

// Share Omarchy's live palette and optical sizing in both the bar and popup.
Item {
  id: root

  property color foreground: Color.popups.text
  // The simplified shield belongs only to the bar, regardless of icon size.
  property bool barIcon: false

  implicitWidth: Style.font.display
  implicitHeight: Style.font.display

  Image {
    id: mask
    anchors.fill: parent
    source: Qt.resolvedUrl(root.barIcon ? "icons/bar.svg" : "icons/mark.svg")
    fillMode: Image.PreserveAspectFit
    readonly property int rasterSize: Math.max(1, Math.round(Math.min(width, height) * Screen.devicePixelRatio))
    sourceSize: Qt.size(rasterSize, rasterSize)
    visible: false
    layer.enabled: true
  }

  MultiEffect {
    anchors.fill: mask
    source: mask
    // Use only the SVG alpha: solid pixels exactly match Omarchy
    // foreground, independent of SVG RGB or the loaded-key state.
    contrast: -1
    brightness: 0.5
    colorization: 1
    colorizationColor: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 1)
    opacity: root.foreground.a
  }
}
