import QtQuick
import "KeyLocale.js" as KeyLocale
import QtQuick.Layouts
import qs.Ui as Ui
import qs.Commons

Item {
  id: root

  property string uiLanguage: KeyLocale.language(Qt.locale().name)
  function t(source) { return KeyLocale.text(uiLanguage, source) }

  // The panel and API always exchange exact seconds; units are presentation only.
  property int value: 0
  readonly property int maximumValue: 31536000
  property int _unitSeconds: 60
  property bool _editingValue: false
  property bool _ready: false
  readonly property int _displayUnit: exactUnit(value)
  readonly property bool _fractionalUnit: value % _unitSeconds !== 0

  implicitWidth: Style.space(300)
  implicitHeight: body.implicitHeight
  Accessible.name: root.t("Срок доступа")

  function exactUnit(seconds) {
    if (seconds === 0) return 60
    if (seconds % 3600 === 0) return 3600
    return seconds % 60 === 0 ? 60 : 1
  }

  function syncEditor() {
    amount.text = _fractionalUnit ? "" : String(value / _unitSeconds)
    units.value = String(_unitSeconds)
  }

  function chooseUnit(unit) {
    if (!enabled || [1, 60, 3600].indexOf(unit) < 0) return
    _unitSeconds = unit
    // A non-integral conversion leaves the input empty, never rounds the timer.
    syncEditor()
  }

  function setPreset(seconds) {
    if (!enabled) return
    value = seconds
    _unitSeconds = exactUnit(seconds)
    syncEditor()
  }

  function editAmount(text) {
    if (!enabled || !/^[0-9]+$/.test(text)) return
    var seconds = Number(text) * _unitSeconds
    if (!isFinite(seconds) || seconds < 0 || seconds > maximumValue) return
    _editingValue = true
    value = seconds
    _editingValue = false
  }

  onValueChanged: {
    if (!_ready || _editingValue) return
    _unitSeconds = exactUnit(value)
    syncEditor()
  }
  onEnabledChanged: {
    if (_ready && !enabled) {
      units.close()
      syncEditor()
    }
  }
  Component.onCompleted: {
    _ready = true
    _unitSeconds = exactUnit(value)
    syncEditor()
  }

  ColumnLayout {
    id: body
    width: parent.width
    spacing: Style.space(12)

    RowLayout {
      Layout.fillWidth: true
      Layout.topMargin: Style.space(2)
      Layout.bottomMargin: Style.space(3)
      spacing: Style.space(7)

      Text {
        objectName: "ssh-key-duration-value"
        text: root.value === 0 ? "∞" : String(root.value / root._displayUnit)
        color: Color.popups.text
        font.family: Style.font.family
        font.pixelSize: Math.round(32 * Style.fontScale)
        font.weight: Font.Medium
        font.features: ({"tnum": 1})
        Layout.alignment: Qt.AlignBaseline
      }
      Text {
        text: root.value === 0 ? root.t("без ограничения") : root._displayUnit === 3600 ? root.t("ч") : root._displayUnit === 60 ? root.t("мин") : root.t("сек")
        color: Util.alpha(Color.popups.text, 0.6)
        font.family: Style.font.family
        font.pixelSize: Style.font.title
        Layout.alignment: Qt.AlignBaseline
        Layout.fillWidth: true
      }
    }

    RowLayout {
      Layout.fillWidth: true
      spacing: Style.space(5)
      Repeater {
        model: [
          {seconds: 900, label: root.t("15 мин")},
          {seconds: 1800, label: root.t("30 мин")},
          {seconds: 3600, label: root.t("1 ч")},
          {seconds: 0, label: "∞"}
        ]
        delegate: Ui.Button {
          required property var modelData
          objectName: "ssh-key-duration-preset-" + modelData.seconds
          Layout.fillWidth: true
          Layout.preferredWidth: 0
          Layout.minimumHeight: Style.space(33)
          text: modelData.label
          selected: root.value === modelData.seconds
          bordered: true
          focusable: true
          foreground: Color.popups.text
          fontSize: Style.font.bodySmall
          horizontalPadding: Style.space(3)
          verticalPadding: Style.space(7)
          tooltipText: modelData.seconds === 0 ? root.t("Без ограничения") : root.t("Срок доступа: ") + modelData.label
          Accessible.name: tooltipText
          onClicked: root.setPreset(modelData.seconds)
        }
      }
    }

    RowLayout {
      Layout.fillWidth: true
      spacing: Style.space(7)
      Text {
        Layout.fillWidth: true
        text: root.t("Другое")
        color: Util.alpha(Color.popups.text, 0.6)
        font.family: Style.font.family
        font.pixelSize: Style.font.bodySmall
      }
      Ui.TextField {
        id: amount
        objectName: "ssh-key-duration-amount"
        Layout.preferredWidth: Style.space(86)
        Layout.minimumHeight: Style.space(30)
        foreground: Color.popups.text
        font.pixelSize: Style.font.bodySmall
        horizontalPadding: Style.space(7)
        verticalPadding: Style.space(5)
        horizontalAlignment: TextInput.AlignHCenter
        placeholderText: root.t("Целое")
        inputMethodHints: Qt.ImhDigitsOnly
        validator: IntValidator { bottom: 0; top: Math.floor(root.maximumValue / root._unitSeconds) }
        Accessible.name: root.t("Срок доступа: ") + (root._unitSeconds === 3600 ? root.t("часы") : root._unitSeconds === 60 ? root.t("минуты") : root.t("секунды"))
        onTextEdited: root.editAmount(text)
        onEditingFinished: root.syncEditor()
      }
      Ui.Dropdown {
        id: units
        objectName: "ssh-key-duration-unit"
        Layout.preferredWidth: Style.space(94)
        rowHeight: Style.space(30)
        showLabel: false
        label: root.t("Единица времени")
        options: root.value % 60 !== 0 || root._unitSeconds === 1
          ? [{value: "1", label: root.t("сек")}, {value: "60", label: root.t("мин")}, {value: "3600", label: root.t("ч")}]
          : [{value: "60", label: root.t("мин")}, {value: "3600", label: root.t("ч")}]
        Accessible.name: label
        onChanged: function(value) { root.chooseUnit(Number(value)) }
      }
    }

    Text {
      visible: root._fractionalUnit
      Layout.fillWidth: true
      text: root.t("Введите целое число — срок пока не изменён")
      wrapMode: Text.WordWrap
      color: Util.alpha(Color.popups.text, 0.55)
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }
  }
}
