#pragma once

#include <QInputMethodQueryEvent>
#include <QLineEdit>

class SecretLineEdit final : public QLineEdit {
  Q_OBJECT
public:
  explicit SecretLineEdit(QWidget *parent = nullptr) : QLineEdit(parent) {
    // Override only this documented style hint; keep Omarchy's palette and
    // geometry inherited from the surrounding prompt.
    setStyleSheet(QStringLiteral("lineedit-password-mask-delay: 0;"));
    // QLineEdit caches this hint. Resolve the local stylesheet, then let its
    // normal style-change handler refresh the cached value before any input.
    ensurePolished();
    QEvent styleChange(QEvent::StyleChange);
    QLineEdit::changeEvent(&styleChange);
  }
  // Local composition stays enabled; no text, selection or cursor metadata is
  // exposed through either query dispatch path.
  QVariant inputMethodQuery(Qt::InputMethodQuery query) const override {
    return query == Qt::ImEnabled ? QVariant(isEnabled() && !isReadOnly())
                                  : QVariant();
  }
  Q_INVOKABLE QVariant inputMethodQuery(Qt::InputMethodQuery query,
                                        const QVariant &) const {
    return inputMethodQuery(query);
  }

protected:
  bool event(QEvent *event) override {
    if (event->type() == QEvent::InputMethodQuery) {
      // QWidget can dispatch the two-argument QLineEdit query through its meta
      // object, bypassing the virtual overload. Block the whole query event as
      // well, including future query types, even if Qt selects another context.
      auto *query = static_cast<QInputMethodQueryEvent *>(event);
      const auto requested = static_cast<quint32>(query->queries());
      for (unsigned bit = 0; bit < 32; ++bit) {
        const auto flag = quint32(1) << bit;
        if (requested & flag)
          query->setValue(static_cast<Qt::InputMethodQuery>(flag), QVariant());
      }
      query->setValue(Qt::ImEnabled, inputMethodQuery(Qt::ImEnabled));
      query->accept();
      return true;
    }
    return QLineEdit::event(event);
  }
};
