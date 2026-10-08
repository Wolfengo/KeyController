#pragma once

#include <QString>
#include <QtGlobal>
#include <cstddef>

// Presentation only. The worker supplies a normalized value from system
// configuration; never change the process locale used by authentication or
// secret-handling tools, and never load user-controlled translation files.
namespace PromptI18n {
enum class Language { English, Russian };
inline Language languageFromEnvironment() {
  return qgetenv("SSH_KEYS_UI_LANGUAGE") == QByteArray("ru")
      ? Language::Russian : Language::English;
}
enum class Message {
  WindowTitle,
  AccessConfirmation,
  Details,
  Hide,
  PasswordStep,
  FingerprintStep,
  KeyPassphrase,
  RepeatPassphrase,
  Cancel,
  Unlock,
  Unlimited,
  Hours,
  Minutes,
  Seconds,
  Done,
  ScannerStarting,
  FingerprintWaiting,
  FingerprintRetry,
  FingerprintVerified,
  KeyLoading,
  PassphraseVerifying,
  BindingSaving,
  BindingVerifying,
  PassphraseSetting,
  WrongPassphrase,
  UnlockFailed,
  FingerprintDenied,
  TpmUnavailable,
  BindingFailed,
  Cancelled,
  OperationFailed,
  KeyLifetime,
  InheritNewLifetime,
  NewLifetime,
  LifetimeExplanation,
  RemoveBinding,
  RemoveBindingTarget,
  RemoveBindingExplanation,
  Program,
  Confirm,
  FingerprintBinding,
  SetPassphrase,
  SshKeyAccess,
  AccessDuration,
  Source,
  FingerprintUnlock,
  PassphraseUnlock,
  Continue,
  EncryptionExplanation,
  Bind,
  BindingExplanation,
  Request,
  Working,
  SetPassphraseButton,
  EnterPassphrase,
  EnterNonemptyPassphrase,
  PassphraseMismatch,
  Count
};
struct Entry { const char *russian; const char *english; };
inline constexpr Entry catalog[] = {
  {"KeyController — подтверждение доступа", "KeyController — access confirmation"},
  {"Подтверждение доступа", "Confirm access"},
  {"Подробнее", "Details"},
  {"Скрыть", "Hide"},
  {"1  Пароль", "1  Passphrase"},
  {"2  Отпечаток", "2  Fingerprint"},
  {"Пароль SSH-ключа", "SSH key passphrase"},
  {"Повторите новый пароль", "Repeat the new passphrase"},
  {"Отмена", "Cancel"},
  {"Разблокировать", "Unlock"},
  {"без ограничения", "unlimited"},
  {" ч", " h"},
  {" мин", " min"},
  {" с", " s"},
  {"Готово", "Done"},
  {"Подключение сканера…", "Starting fingerprint reader…"},
  {"Приложите палец к сканеру", "Touch the fingerprint reader"},
  {"Попробуйте ещё раз", "Try again"},
  {"Отпечаток подтверждён…", "Fingerprint verified…"},
  {"Загрузка ключа…", "Loading key…"},
  {"Проверка пароля…", "Checking passphrase…"},
  {"Сохранение привязки…", "Saving fingerprint link…"},
  {"Проверка привязки…", "Checking fingerprint link…"},
  {"Установка пароля…", "Setting passphrase…"},
  {"Пароль не подошёл или ключ повреждён.", "Incorrect passphrase or invalid key."},
  {"Не удалось загрузить ключ.", "Could not load the key."},
  {"Отпечаток не подтверждён.", "Fingerprint not verified."},
  {"TPM недоступен. Привязка не выполнена.", "TPM unavailable. Fingerprint link was not created."},
  {"Не удалось сохранить привязку.", "Could not save the fingerprint link."},
  {"Операция отменена.", "Operation cancelled."},
  {"Операция не завершена. Подробности — в KeyController.", "Operation incomplete. See KeyController for details."},
  {"Срок доступа к ключу", "Key access duration"},
  {"Новый срок: наследовать общие настройки.", "New duration: inherit general settings."},
  {"Новый срок: ", "New duration: "},
  {"Срок изменится при следующем открытии этого ключа. Текущий доступ сохранит свой срок.", "The new duration applies the next time this key is unlocked. Current access keeps its duration."},
  {"Удаление привязки", "Unlink fingerprint"},
  {"Удалить привязку отпечатка к этому ключу.", "Unlink the fingerprint from this key."},
  {"Ключ будет отозван из SSH-агента. Файл ключа и его пароль сохранятся.", "The key will be removed from the SSH agent. Its file and passphrase will be kept."},
  {"\nПрограмма: ", "\nProgram: "},
  {"Подтвердить", "Confirm"},
  {"Привязка отпечатка", "Link fingerprint"},
  {"Установка пароля", "Set passphrase"},
  {"Доступ к SSH-ключу", "SSH key access"},
  {"\nСрок доступа: ", "\nAccess duration: "},
  {"\nИсточник: ", "\nSource: "},
  {"Разблокировка отпечатком", "Unlock with fingerprint"},
  {"Разблокировка паролем", "Unlock with passphrase"},
  {"Продолжить", "Continue"},
  {"Изменится выбранный файл; публичный ключ сохранится. Старые копии и снимки диска останутся незашифрованными.", "The selected file will change; its public key will stay the same. Existing copies and disk snapshots will remain unencrypted."},
  {"Привязать", "Link"},
  {"После привязки ключ останется закрытым.", "The key will remain locked after linking."},
  {"Запрос: ", "Requested by: "},
  {"Выполняется…", "Working…"},
  {"Установить пароль", "Set passphrase"},
  {"Введите пароль этого SSH-ключа.", "Enter this SSH key’s passphrase."},
  {"Введите непустой пароль SSH-ключа.", "Enter a nonempty SSH key passphrase."},
  {"Пароли не совпадают.", "Passphrases do not match."},
};
static_assert(sizeof(catalog) / sizeof(catalog[0]) == static_cast<std::size_t>(Message::Count));
inline QString translate(Language language, Message message) {
  const auto index = static_cast<std::size_t>(message);
  if (index >= static_cast<std::size_t>(Message::Count)) return {};
  return QString::fromUtf8(language == Language::Russian
      ? catalog[index].russian : catalog[index].english);
}
} // namespace PromptI18n
