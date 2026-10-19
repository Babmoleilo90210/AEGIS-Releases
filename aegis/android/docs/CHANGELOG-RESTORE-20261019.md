# Android 6.0.0 — восстановление 19.10.2026

- Восстановлены source и сборочная цепочка четырёх отдельных APK; прежний потерянный TEST private key не восстанавливался, выпущен новый явно тестовый сертификат.
- Отзыв/выход выполняется обязательной ограниченной security очередью; смена UI epoch отменяет только data work. Lock/exit callback не теряется на pause. `shutdownNow` удаляет и очищает буферы паролей never-started задач.
- Поздний серверный login не может восстановить сессию после lock/logout. Logout не запускает новый Tor в попытке отозвать уже закрытую сессию.
- Почта отправляет и открывает поддерживаемые письма с паролем и FF1 через прежние LetterEnvelope/AutomaticEncryption; новые алгоритмы или oracle проверки FF1 не вводились.
- Обновлён только Android-only pin официального подписанного stable snapshot libsodium1.0.22. Неверный старому SHA архив был отвергнут, новый проверен pinned public key. Desktop pin не изменён.
- Сборка записывает sourceTree и exact binaryArtifactSha256 для общего подписываемого manifest; expected-commit проверяется также после сборки.

Все ограничения и NOT_RUN сохранены в TEST-REPORT и RELEASE-GATES. Подписи владельца и production-публикации не выполнялись.
