#pragma once

#include <QByteArray>
#include <QColor>
#include <QDir>
#include <QFile>
#include <QFont>
#include <QMap>
#include <QPalette>
#include <QString>
#include <QWidget>
#include <QtGlobal>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace PromptTheme {

struct Theme {
  QColor background = QColor(QStringLiteral("#101315"));
  QColor foreground = QColor(QStringLiteral("#cacccc"));
  QColor accent = QColor(QStringLiteral("#cacccc"));
  QColor muted = QColor(QStringLiteral("#707880"));
  QColor border = QColor(QStringLiteral("#707880"));
  QColor well = QColor(QStringLiteral("#181b1d"));
  QString fontFamily = QStringLiteral("monospace");
  int fontPixels = 12;
  int radius = 12;
};

// Layout constants are expressed at Omarchy's 12px font root.
inline int rem(const Theme &theme, int pixels) {
  return pixels <= 0 ? 0 : qMax(1, qRound(qMin(pixels, 4096) *
                                         qBound(8, theme.fontPixels, 32) / 12.0));
}

namespace Detail {
using Values = QMap<QString, QString>;
constexpr qsizetype maximumFileBytes = 128 * 1024;

inline QByteArray boundedRead(const QString &path) {
  const QByteArray name = QFile::encodeName(path);
  if (name.contains('\0'))
    return {};
  // The current theme is normally a symlink. Follow it, but only read a
  // bounded regular file; a user-controlled FIFO must never stall a prompt.
  const int fd = ::open(name.constData(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
  if (fd < 0)
    return {};
  struct stat info {};
  if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
      info.st_size < 0 || info.st_size > maximumFileBytes) {
    ::close(fd);
    return {};
  }
  QByteArray data;
  char buffer[4096];
  while (data.size() <= maximumFileBytes) {
    const auto count = ::read(fd, buffer, qMin<qsizetype>(sizeof(buffer),
                                  maximumFileBytes + 1 - data.size()));
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0) {
      data.clear();
      break;
    }
    if (count == 0)
      break;
    data.append(buffer, static_cast<qsizetype>(count));
  }
  ::close(fd);
  return data.size() > maximumFileBytes || data.contains('\0') ? QByteArray() : data;
}

inline bool permittedKey(const QString &key) {
  return key == QLatin1String("background") || key == QLatin1String("foreground") ||
         key == QLatin1String("accent") || key == QLatin1String("muted") ||
         key == QLatin1String("popups.background") || key == QLatin1String("popups.text") ||
         key == QLatin1String("popups.border") || key == QLatin1String("popups.radius") ||
         key == QLatin1String("hyprland.active-border") ||
         key == QLatin1String("hyprland.active-border-foreground") ||
         key == QLatin1String("font.base-size") || key == QLatin1String("font.family");
}

inline QString uncomment(const QString &line) {
  QChar quote;
  bool escape = false;
  for (qsizetype i = 0; i < line.size(); ++i) {
    const QChar c = line[i];
    if (!quote.isNull()) {
      if (escape) {
        escape = false;
      } else if (quote == QLatin1Char('"') && c == QLatin1Char('\\')) {
        escape = true;
      } else if (c == quote) {
        quote = QChar();
      }
    } else if (c == QLatin1Char('"') || c == QLatin1Char('\'')) {
      quote = c;
    } else if (c == QLatin1Char('#')) {
      return line.left(i).trimmed();
    }
  }
  return line.trimmed();
}

inline Values readValues(const QString &path) {
  Values result;
  QString section;
  const auto lines = QString::fromUtf8(boundedRead(path)).split(QLatin1Char('\n'));
  for (const auto &raw : lines) {
    if (raw.size() > 2048)
      continue;
    const QString line = uncomment(raw);
    if (line.isEmpty())
      continue;
    if (line.startsWith(QLatin1Char('['))) {
      section = line.endsWith(QLatin1Char(']')) ? line.mid(1, line.size() - 2).trimmed()
                                               : QStringLiteral("!");
      continue;
    }
    const qsizetype equal = line.indexOf(QLatin1Char('='));
    if (equal < 1)
      continue;
    QString key = line.left(equal).trimmed();
    if (!section.isEmpty())
      key = section + QLatin1Char('.') + key;
    if (!permittedKey(key))
      continue;
    QString value = line.mid(equal + 1).trimmed();
    if (value.isEmpty() || value.size() > 256)
      continue;
    if (value.front() == QLatin1Char('"') || value.front() == QLatin1Char('\'')) {
      const QChar quote = value.front();
      if (value.size() < 2 || value.back() != quote)
        continue;
      value = value.mid(1, value.size() - 2);
      // Only simple scalar strings are used here. Escapes, interpolation,
      // arrays and multiline TOML are deliberately outside this reader.
      if (value.contains(quote) || value.contains(QLatin1Char('\\')))
        continue;
    } else if (key != QLatin1String("font.base-size") && key != QLatin1String("popups.radius")) {
      continue;
    }
    result.insert(key, value);
  }
  return result;
}

inline bool reference(const QString &value) {
  return value == QLatin1String("foreground") || value == QLatin1String("text") ||
         value == QLatin1String("background") || value == QLatin1String("accent") ||
         value == QLatin1String("muted") || value == QLatin1String("hyprland.active-border") ||
         value == QLatin1String("hyprland.active-border-foreground");
}

inline QColor literalColor(QString value) {
  // Omarchy's Hyprland border token can contain a gradient. A QWidget border
  // uses its first stop; no raw theme text is ever placed into a stylesheet.
  value = value.trimmed();
  const qsizetype space = value.indexOf(QLatin1Char(' '));
  if (space >= 0)
    value.truncate(space);
  if ((value.startsWith(QLatin1String("rgb(")) || value.startsWith(QLatin1String("rgba("))) &&
      value.endsWith(QLatin1Char(')'))) {
    const bool alpha = value.startsWith(QLatin1String("rgba("));
    const QString hex = value.mid(alpha ? 5 : 4, value.size() - (alpha ? 6 : 5));
    bool ok = false;
    const uint n = hex.toUInt(&ok, 16);
    if (!ok || hex.size() != (alpha ? 8 : 6))
      return {};
    return alpha ? QColor((n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255)
                 : QColor((n >> 16) & 255, (n >> 8) & 255, n & 255);
  }
  return QColor(value);
}

inline bool fontFamilyAllowed(const QString &value) {
  if (value.isEmpty() || value.size() > 96)
    return false;
  for (QChar c : value) {
    if (!c.isLetterOrNumber() && c != QLatin1Char(' ') &&
        !QStringLiteral("-_+.,()").contains(c))
      return false;
  }
  return !value.trimmed().isEmpty();
}

inline bool integer(const QString &text, int minimum, int maximum, int *result) {
  if (text.isEmpty())
    return false;
  for (QChar c : text)
    if (c < QLatin1Char('0') || c > QLatin1Char('9'))
      return false;
  bool ok = false;
  const int n = text.toInt(&ok);
  if (!ok || n < minimum || n > maximum)
    return false;
  *result = n;
  return true;
}

inline bool validValue(const QString &key, const QString &value) {
  int ignored;
  if (key == QLatin1String("font.family"))
    return fontFamilyAllowed(value);
  if (key == QLatin1String("font.base-size"))
    return integer(value, 8, 32, &ignored);
  if (key == QLatin1String("popups.radius"))
    return integer(value, 0, 24, &ignored);
  return reference(value) || literalColor(value).isValid();
}

inline void overlay(Values &base, const Values &next) {
  for (auto it = next.cbegin(); it != next.cend(); ++it)
    if (validValue(it.key(), it.value()))
      base.insert(it.key(), it.value());
}

inline QColor resolve(QString value, const Values &shell, const Values &palette,
                      const QColor &fallback) {
  // Bound reference resolution also handles malformed/cyclic user overrides.
  for (int depth = 0; depth < 8; ++depth) {
    if (!reference(value)) {
      const QColor color = literalColor(value);
      return color.isValid() ? color : fallback;
    }
    if (value == QLatin1String("text"))
      value = QStringLiteral("foreground");
    const QString next = value.startsWith(QLatin1String("hyprland."))
                             ? shell.value(value) : palette.value(value);
    if (next.isEmpty())
      return fallback;
    value = next;
  }
  return fallback;
}

inline QColor blend(const QColor &front, const QColor &back, double opacity) {
  const double a = qBound(0.0, opacity, 1.0);
  return QColor::fromRgbF(front.redF() * a + back.redF() * (1 - a),
                          front.greenF() * a + back.greenF() * (1 - a),
                          front.blueF() * a + back.blueF() * (1 - a));
}
inline QColor opaque(const QColor &color, const QColor &back) {
  return blend(color, back, color.alphaF());
}
} // namespace Detail

inline Theme load() {
  Theme theme;
  const QString home = qEnvironmentVariable("HOME");
  if (home.isEmpty() || home.size() > 4096 || home.contains(QChar::Null) || !QDir::isAbsolutePath(home))
    return theme;
  const QString current = home + QStringLiteral("/.local/state/omarchy/current/theme/");
  Detail::Values palette;
  Detail::overlay(palette, Detail::readValues(current + QStringLiteral("colors.toml")));
  const auto paletteColor = [&](const QString &name, const QColor &fallback) {
    return Detail::resolve(palette.value(name), {}, palette, fallback);
  };
  theme.background = Detail::opaque(paletteColor(QStringLiteral("background"), theme.background), theme.background);
  theme.foreground = Detail::opaque(paletteColor(QStringLiteral("foreground"), theme.foreground), theme.background);
  theme.accent = Detail::opaque(paletteColor(QStringLiteral("accent"), theme.accent), theme.background);
  theme.muted = Detail::opaque(paletteColor(QStringLiteral("muted"),
                                Detail::blend(theme.foreground, theme.background, 0.55)), theme.background);

  Detail::Values shell;
  Detail::overlay(shell, Detail::readValues(current + QStringLiteral("shell.toml")));
  Detail::overlay(shell, Detail::readValues(home + QStringLiteral("/.config/omarchy/shell.toml")));
  const auto surfaceColor = [&](const QString &name, const QColor &fallback) {
    return Detail::resolve(shell.value(name), shell, palette, fallback);
  };
  theme.background = Detail::opaque(surfaceColor(QStringLiteral("popups.background"), theme.background), theme.background);
  theme.foreground = Detail::opaque(surfaceColor(QStringLiteral("popups.text"), theme.foreground), theme.background);
  theme.border = Detail::opaque(surfaceColor(QStringLiteral("popups.border"), theme.accent), theme.background);
  theme.well = Detail::blend(theme.foreground, theme.background, 0.045);
  if (shell.contains(QStringLiteral("font.family")))
    theme.fontFamily = shell.value(QStringLiteral("font.family"));
  Detail::integer(shell.value(QStringLiteral("font.base-size")), 8, 32, &theme.fontPixels);
  Detail::integer(shell.value(QStringLiteral("popups.radius")), 0, 24, &theme.radius);
  return theme;
}

inline void apply(QWidget *widget, const Theme &theme) {
  if (!widget)
    return;
  // Family names never enter QSS: validated font metadata goes through QFont.
  QFont font(Detail::fontFamilyAllowed(theme.fontFamily) ? theme.fontFamily : QStringLiteral("monospace"));
  font.setPixelSize(qBound(8, theme.fontPixels, 32));
  widget->setFont(font);
  QPalette palette = widget->palette();
  palette.setColor(QPalette::Window, theme.background);
  palette.setColor(QPalette::WindowText, theme.foreground);
  palette.setColor(QPalette::Base, theme.well);
  palette.setColor(QPalette::Text, theme.foreground);
  palette.setColor(QPalette::Button, theme.well);
  palette.setColor(QPalette::ButtonText, theme.foreground);
  palette.setColor(QPalette::PlaceholderText, theme.muted);
  palette.setColor(QPalette::Highlight, theme.accent);
  const QColor selectedText = theme.accent.lightnessF() > 0.55 ? QColor(Qt::black) : QColor(Qt::white);
  palette.setColor(QPalette::HighlightedText, selectedText);
  palette.setColor(QPalette::Disabled, QPalette::Text, theme.muted);
  palette.setColor(QPalette::Disabled, QPalette::ButtonText, theme.muted);
  widget->setPalette(palette);
  widget->setAutoFillBackground(true);

  const QString bg = theme.background.name();
  const QString fg = theme.foreground.name();
  const QString accent = theme.accent.name();
  const QString muted = theme.muted.name();
  const QString border = Detail::blend(theme.border, theme.background, 0.55).name();
  const QString well = theme.well.name();
  const QString hover = Detail::blend(theme.foreground, theme.background, 0.08).name();
  const QString selected = Detail::blend(theme.accent, theme.background, 0.12).name();
  const QString selectedHover = Detail::blend(theme.accent, theme.background, 0.2).name();
  const auto px = [&](int n) { return QString::number(rem(theme, n)) + QStringLiteral("px"); };
  const QString radius = px(qBound(0, theme.radius, 24));

  QString css = QStringLiteral("QWidget { background-color: %1; color: %2; } QLabel { background: transparent; }")
                    .arg(bg, fg);
  css += QStringLiteral("QLabel#title { font-size: %1; font-weight: 600; } QLabel#subtitle, QLabel#metadata { color: %2; font-size: %3; } QLabel#status { color: %5; font-size: %4; }")
             .arg(px(15), muted, px(10), px(11), fg);
  css += QStringLiteral("QLabel#key-name { font-size: %1; font-weight: 600; } QLabel#details, QLabel#request-details { color: %2; font-size: %3; } QLabel#step-password, QLabel#step-fingerprint { font-size: %3; } QLabel:disabled { color: %2; }")
             .arg(px(14), muted, px(11));
  css += QStringLiteral("QFrame#keyCard { background-color: %1; border: 1px solid %2; border-radius: %3; }")
             .arg(well, border, radius);
  css += QStringLiteral("QLineEdit { background-color: %1; color: %2; border: 1px solid %3; border-radius: %4; padding: %5 %6; selection-background-color: %7; selection-color: %8; } QLineEdit:focus { border-color: %7; }")
             .arg(well, fg, border, radius, px(7), px(9), accent, selectedText.name());
  css += QStringLiteral("QPushButton { background-color: %1; color: %2; border: 1px solid %3; border-radius: %4; padding: %5 %6; min-height: %7; } QPushButton:hover { background-color: %8; } QPushButton:focus { border-color: %9; }")
             .arg(well, fg, border, radius, px(6), px(11), px(16), hover, accent);
  css += QStringLiteral("QPushButton#consent { background-color: %1; color: %2; border-color: %2; } QPushButton#consent:hover, QPushButton#consent:pressed { background-color: %3; } QPushButton:disabled, QPushButton#consent:disabled { background-color: %4; color: %5; border-color: %6; }")
             .arg(selected, accent, selectedHover, well, muted, border);
  css += QStringLiteral("QPushButton#details-toggle { background: transparent; border: none; color: %1; padding: %2 0; font-size: %3; min-height: 0; } QPushButton#details-toggle:focus { color: %4; }")
             .arg(muted, px(2), px(10), fg);
  css += QStringLiteral("QRadioButton { background: transparent; spacing: %1; padding: %2 0; } QRadioButton:disabled { color: %3; } QRadioButton::indicator { width: %4; height: %4; border: 1px solid %5; border-radius: %6; background-color: %7; } QRadioButton::indicator:checked { border-color: %8; background-color: %8; } QRadioButton::indicator:disabled { border-color: %5; background-color: %7; }")
             .arg(px(7), px(4), muted, px(12), border, px(7), well, accent);
  widget->setStyleSheet(css);
}

} // namespace PromptTheme
