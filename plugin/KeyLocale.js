.pragma library

// UI language only: protocol values, identifiers, paths and user names are never translated.
// Russian is the source catalog; unsupported system languages use English.
function language(localeName) {
  return /^ru(?:[_@.\-]|$)/i.test(String(localeName || "").trim()) ? "ru" : "en"
}

var english = {
  "ключ": "key",
  "ключа": "keys",
  "ключей": "keys",
  "без ограничения": "unlimited",
  " ч": " h",
  " мин": " min",
  " с": " s",
  "Недоступен": "Unavailable",
  "Ожидание": "Waiting",
  "Без пароля": "No passphrase",
  "Закрыт": "Locked",
  "Срок неизвестен": "Duration unknown",
  " д ": " d ",
  " ч ": " h ",
  "Добавлен": "Added",
  "Операция выполняется…": "Operation in progress…",
  "Открыт · срок неизвестен": "Unlocked · duration unknown",
  "Открыт · без ограничения": "Unlocked · unlimited",
  "Открыт до ": "Unlocked until ",
  "Список обновлён": "List refreshed",
  "Пароль установлен; ключ закрыт": "Passphrase set; key locked",
  "Привязка сохранена; ключ закрыт": "Fingerprint linked; key locked",
  "Ключ разблокирован": "Key unlocked",
  "Ключ отозван": "Key revoked",
  "Ключи отозваны": "Keys revoked",
  "Операция отменена": "Operation cancelled",
  "Доступ не подтверждён": "Access denied",
  "Время ожидания истекло": "Request expired",
  "Другая операция ещё выполняется": "Another operation is in progress",
  "После отмены нужно подождать 30 секунд": "Wait 30 seconds after cancelling",
  "Слишком много запросов. Подождите минуту": "Too many requests. Wait a minute",
  "Системный помощник KeyController недоступен": "KeyController system helper is unavailable",
  "Управляемый SSH-агент недоступен": "Managed SSH agent is unavailable",
  "Не удалось открыть защищённое окно. Попробуйте ещё раз": "Could not open the secure window. Try again",
  "Защищённое окно завершилось с ошибкой": "Secure window failed",
  "Помощник не смог завершить запрос": "Helper could not complete the request",
  "Не удалось завершить обмен с защищённым окном": "Could not communicate with the secure window",
  "Нужен активный разблокированный локальный сеанс": "An active, unlocked local session is required",
  "Отпечаток не подтверждён": "Fingerprint not verified",
  "Не удалось проверить защищённое соединение с Hyprland": "Could not verify the secure Hyprland connection",
  "Для защиты ввода нужен kernel.yama.ptrace_scope ≥ 1": "Secure input requires kernel.yama.ptrace_scope ≥ 1",
  "Не удалось включить защиту процесса": "Could not enable process protection",
  "Подтверждение недействительно": "Invalid confirmation",
  "Пароль должен быть не длиннее 1023 байт, без перевода строки": "Passphrase must be at most 1023 bytes, with no line breaks",
  "TPM недоступен. Можно разблокировать ключ паролем": "TPM is unavailable. Unlock with your passphrase",
  "Привязка недоступна. Используйте пароль или повторите привязку": "Fingerprint link is unavailable. Use your passphrase or link again",
  "Пароль не подошёл или файл ключа повреждён": "Incorrect passphrase or damaged key file",
  "Не удалось загрузить ключ": "Could not load the key",
  "Формат не поддерживается; нужен OpenSSH": "Unsupported format; OpenSSH is required",
  "Этот тип ключа не поддерживается": "Unsupported key type",
  "Ссылка ведёт за пределы ~/.ssh": "Link points outside ~/.ssh",
  "У файла несколько жёстких ссылок": "File has multiple hard links",
  "Неверный владелец или слишком открытые права файла": "Incorrect file owner or overly permissive access",
  "Небезопасные права каталога": "Unsafe directory permissions",
  "Файл изменился во время операции; исходник не заменён": "File changed during the operation; original was not replaced",
  "Файл уже зашифрован; последующий шаг не завершён. Обновите список": "File is encrypted, but a later step failed. Refresh the list",
  "Не удалось подтвердить состояние файла после операции. Обновите список": "Could not verify the resulting file. Refresh the list",
  "Файл ключа недоступен. Обновите список": "Key file is unavailable. Refresh the list",
  "Ключ больше не найден. Обновите список": "Key no longer found. Refresh the list",
  "Запрос больше не найден": "Request no longer found",
  "Сначала привяжите отпечаток": "Link a fingerprint first",
  "Введите непустой пароль": "Enter a nonempty passphrase",
  "Пароли не совпадают": "Passphrases do not match",
  "Не удалось завершить операцию": "Could not complete the operation",
  "Помощник не ответил вовремя": "Helper did not respond in time",
  "Настройки применены, но сохранность после сбоя не подтверждена.": "Settings applied, but persistence after a crash is uncertain.",
  "Идёт подготовка ко сну. Повторите после пробуждения.": "Preparing for sleep. Try again after waking.",
  "Несовместимые версии виджета и системного помощника": "Widget and system helper versions are incompatible",
  "Ошибка KeyController: ": "KeyController error: ",
  " · пауза 30 с": " · wait 30 s",
  "Несовместимая версия помощника": "Incompatible helper version",
  "Не удалось связаться с помощником KeyController": "Could not contact the KeyController helper",
  "Помощник KeyController недоступен": "KeyController helper is unavailable",
  "Установите системный пакет keycontroller": "Install the ssh-keys system package",
  "KeyController · Открытие…": "KeyController · Unlocking…",
  "KeyController · Ожидание…": "KeyController · Waiting…",
  "Назад": "Back",
  "Настройки": "Settings",
  "Добавить ключ": "Add key",
  "Настройки ключа": "Key settings",
  "Общие настройки": "General settings",
  "Найдены в ~/.ssh": "Found in ~/.ssh",
  "Обновить": "Refresh",
  "Скрыть сообщение": "Dismiss message",
  "Ожидание…": "Waiting…",
  "Отмена": "Cancel",
  "Общий срок": "Default duration",
  "Наследовать общий срок доступа": "Use the default access duration",
  "Сейчас ": "Currently ",
  "Срок доступа": "Access duration",
  "Применится при следующей разблокировке": "Applies on the next unlock",
  "Отзывать перед сном": "Revoke before sleep",
  "Отзывать все ключи управляемого SSH-агента перед сном": "Revoke all managed SSH agent keys before sleep",
  "Сохранение…": "Saving…",
  "Сохранить": "Save",
  "Есть незашифрованные копии ключа": "Unencrypted copies of this key exist",
  "О ключе": "Key details",
  "Показать путь, отпечаток и состояние ключа": "Show the key path, fingerprint and status",
  "Незашифрованные копии\n": "Unencrypted copies\n",
  "Удалить привязку": "Unlink fingerprint",
  "Отозвать ключ и удалить привязку отпечатка": "Revoke the key and unlink its fingerprint",
  "Есть незашифрованные копии": "Unencrypted copies exist",
  "000 д 00 ч": "000 d 00 h",
  "Отпечаток ⇅": "Fingerprint ⇅",
  "Пароль ⇅": "Passphrase ⇅",
  "Привязать": "Link",
  "Привязать отпечаток; ключ останется закрытым": "Link a fingerprint; the key stays locked",
  "Следующая разблокировка: переключить на пароль": "Next unlock: switch to passphrase",
  "Следующая разблокировка: переключить на отпечаток": "Next unlock: switch to fingerprint",
  "Установить пароль": "Set passphrase",
  "Уже добавлен": "Already added",
  "Открытие…": "Unlocking…",
  "Закрыть": "Lock",
  "Открыть": "Unlock",
  "Отозвать ключ": "Revoke key",
  "Разблокировать ключ": "Unlock key",
  "Сведения и настройки": "Details and settings",
  "Ключи не найдены": "No keys found",
  "Добавьте ключ через +": "Add a key with +",
  "Общий срок · ": "Default duration · ",
  "Настроить общий срок доступа": "Set the default access duration",
  "ч": "h",
  "мин": "min",
  "сек": "sec",
  "15 мин": "15 min",
  "30 мин": "30 min",
  "1 ч": "1 h",
  "Без ограничения": "Unlimited",
  "Срок доступа: ": "Access duration: ",
  "Другое": "Custom",
  "Целое": "Integer",
  "часы": "hours",
  "минуты": "minutes",
  "секунды": "seconds",
  "Единица времени": "Time unit",
  "Введите целое число — срок пока не изменён": "Enter a whole number; duration has not changed",
  "Подготовка к работе": "Getting started",
  "Системный репозиторий": "System repository",
  "Нужна более новая версия": "A newer version is required",
  "Проверка подписи пакета отключена": "Package signature checking is disabled",
  "Нет в подключённых репозиториях": "Not in configured repositories",
  "Установка в терминале…": "Installing in terminal…",
  "Проверка пакетов…": "Checking packages…",
  "Установить пакеты": "Install packages",
  "Не удалось открыть терминал": "Could not open the terminal",
  "Сначала установите Python, затем проверим остальные пакеты": "Install Python first to check the remaining packages",
  "Не удалось проверить пакеты": "Could not check packages",
  "Установите системный пакет keycontroller из выпуска KeyController": "Install the keycontroller system package from a KeyController release",
  "Проверьте репозитории и обновления системы": "Check system repositories and updates",
  "Установка откроется в терминале. Полный список покажет Pacman": "Installation opens in a terminal. Pacman will show the full transaction",
  "Проверить снова": "Check again",
  "Настроить KeyController": "Set up KeyController",
  "Подключить управляемый SSH-агент и инструкции для ИИ": "Connect the managed SSH agent and instructions for AI agents"
}

function text(uiLanguage, source) {
  return language(uiLanguage) === "ru" ? source : (english[source] || source)
}

function keyCount(uiLanguage, count) {
  if (language(uiLanguage) !== "ru") return count + (count === 1 ? " key" : " keys")
  var last = count % 10
  var tail = count % 100
  return count + " " + (last === 1 && tail !== 11 ? "ключ" : last >= 2 && last <= 4 && (tail < 12 || tail > 14) ? "ключа" : "ключей")
}

function keySummary(uiLanguage, count, unlocked) {
  return keyCount(uiLanguage, count) + (language(uiLanguage) === "ru" ? " · открыто " + unlocked : " · " + unlocked + " unlocked")
}

// A metadata refresh may change the language while a notice is already visible.
// Reverse only our catalog text, never paths, caller text or protocol identifiers.
function notice(uiLanguage, current) {
  var suffix = " · пауза 30 с"
  var englishSuffix = english[suffix]
  var hasSuffix = current.endsWith(suffix) || current.endsWith(englishSuffix)
  if (current.endsWith(suffix)) current = current.slice(0, -suffix.length)
  else if (current.endsWith(englishSuffix)) current = current.slice(0, -englishSuffix.length)
  var source = current
  for (var key in english) {
    if (english[key] === current) { source = key; break }
  }
  var prefix = "Ошибка KeyController: "
  if (current.indexOf(english[prefix]) === 0) source = prefix + current.slice(english[prefix].length)
  var result = source.indexOf(prefix) === 0 ? text(uiLanguage, prefix) + source.slice(prefix.length) : text(uiLanguage, source)
  return result + (hasSuffix ? text(uiLanguage, suffix) : "")
}
