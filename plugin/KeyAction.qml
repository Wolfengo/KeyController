import QtQuick
import qs.Ui as Ui
import qs.Commons

Ui.Button {
  id: root
  property bool busy: false
  iconSpinning: busy
  focusable: true
  radius: Style.cornerRadius
  bordered: true
  fontSize: Style.font.body
  iconSize: Style.font.title
  foreground: Color.popups.text
  horizontalPadding: Style.spacing.controlPaddingX
  verticalPadding: Style.spacing.controlPaddingY
  implicitHeight: Style.space(text !== "" ? 34 : 32)
  implicitWidth: text !== ""
    ? Math.max(Style.space(52), metrics.width + horizontalPadding * 2 + _reservedBorderLeft + _reservedBorderRight + (iconText !== "" ? iconSize + Style.spacing.controlGap : 0))
    : Style.space(iconText.indexOf(" ") >= 0 ? 48 : 30)
  opacity: enabled || busy ? 1 : 0.35
  Accessible.name: tooltipText || text
  TextMetrics { id: metrics; font.family: root.fontFamily; font.pixelSize: root.fontSize; font.bold: root.selected; text: root.text }
}
