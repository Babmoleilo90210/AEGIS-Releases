# Проверки АЕГИС 0.3.0

Дата: 5 октября 2026. Среда: Linux x86_64 container, Java 21.0.12.1, Gradle 9.8.0. Это клиентское обновление; серверные исходники/installer/config/common-protocol сравнены побайтово с выпущенной 0.2.0 и не изменены.

## Выполнено

- 43 JUnit теста: client-core 32, integration 4, common-protocol 4, relay isolation/registration 3; без failures/errors.
- FF1: известный NIST vector, Unicode/пустой/короткий текст, правильный код, несколько неправильных кодов без verifier; AES неправильный пароль/изменение ciphertext; случайные соли/nonces.
- Новый content v3 внутри прежнего E2EE: отправитель и получатель, вложение, отсутствие plaintext/секретов в packet. Старый content v1 читается.
- LiveCode: быстрые изменения, подавление устаревшего UI callback, закрытие view, очистка ожидающих char arrays.
- Tor orchestration: direct 10/45 timeout автоматически закрывает первый экземпляр и создаёт свежий Snowflake; оба отказа запрещают data socket.
- Настоящие Linux Tor 0.4.9.13 и Lyrebird 0.8.1 из bundled Expert Bundle: частный torrc/defaults-torrc/DataDirectory с пробелами, реальная PT-v1 VERSION/CMETHOD регистрация, loopback listeners, автоматический fallback, bootstrap Snowflake до 10% в коротком тесте. Закрытие освобождает собственные порты; другой тестовый Tor остаётся жив. **Tor 100% не подтверждён в этой сетевой среде.**
- Настоящий JavaFX через Monocle: server/login/registration/inbox/compose, пять тем, wrong letter password без внутреннего текста, FF1 ciphertext после правильного AES, неверный/верный код, ввод без кнопки, закрытие/повторное открытие и закрытие по TTL. Скриншоты настоящих контролов находятся в validation03/ui/.
- Два client-core 0.3.0 общались с **неизменённым упакованным relay 0.2.0** в отдельном процессе: регистрация, два направления FF1/AES писем, offline очередь, файл 2 MiB, durable ACK, удаление relay после ACK, replay/dedup, TTL от фактического приёма, отсутствие текста и приватного ключа на relay transport и в SQLite. Принудительный перезапуск процесса relay сохранил пользователей и очередь; повторное открытие обоих клиентских vault сохранило идентичность, контакты и письмо. Это не reboot ОС. Маршрутизация этой проверки — loopback SOCKS harness, **не публичная Tor-сеть**.
- Настоящий профиль создан выпущенными 0.2.0 JAR/runtime, затем открыт 0.3.0: идентичность, ник, контакт и старое E2EE письмо сохранены; backup создан до открытия без перезаписи vault.
- Старые тесты: malformed/oversized packets, signatures, five legacy algorithms, storage, ACK, TTL, P2P и fallback relay, регистрация open/closed.
- Максимальное тело 64 KiB: полный roundtrip прошёл; на этой машине шифрование 5.235 s, FF1 candidate 4.277 s. UI не блокируется; 100 ms — debounce, а не обещание такого времени завершения KDF/FF1.

## Артефакты

Реальные native AEGIS.exe и NSIS Setup EXE, Windows portable ZIP с Java 21 runtime, Tor/DLL/Lyrebird/libsodium; CachyOS AppImage с runtime/Tor/PT; исходный ZIP и SHA-256. Иконка исходного дизайна сохранена, Windows ICO содержит семь размеров. Проверены 212 файлов Windows ZIP, JavaFX win classifier, отсутствие relay JAR, runtime/Tor/PT/native компоненты. В PE launcher найдены семь ICON resources, GROUP_ICON, VERSIONINFO и MANIFEST; launcher и Setup содержат asInvoker. Linux AppImage извлечён, bundled Java 21 запущена, execute bits Tor/Lyrebird 0755 проверены. Lifecycle test выполнен повторно именно извлечённым runtime/JAR из AppImage. Windows launcher использует Job Object, asInvoker; installer — RequestExecutionLevel user и HKCU. Полноценная установка в Windows требует native проверки ниже.

## Не выполнено; не считать пройденным

- Чистая Windows 11 без Java/Tor: запуск AEGIS.exe, установщик/удаление, ярлыки/иконка в shell, ACL, Firewall/Defender/SmartScreen, reboot и живое соединение с пользовательским relay.
- Чистая CachyOS без Java/Tor: native KDE/Wayland/X11, desktop icon integration, reboot.
- Настоящий Windows ↔ Tor ↔ VPS relay ↔ Tor ↔ CachyOS обмен, реальный offline/TTL/file и перезагрузка VPS.
- 100% bootstrap прямого Tor/Snowflake в данном окружении.
- Независимый криптографический аудит, pen test и power-loss durability.

Причина: в доступной среде нет Windows VM, чистой CachyOS/VPS и доступа к пользовательскому .onion. Эти ограничения не заменены mock-утверждениями о native приёмке. Сервер пользователя не изменялся и не перезагружался.

## Приёмка владельцем установки

На двух настоящих ОС установить/распаковать пакеты без глобальной Java/Tor. Использовать существующий relay 0.2.0 без смены конфигурации/identity. Проверить bootstrap, saved onion, старый профиль и backup, вход/открытую регистрацию, двусторонние protected letters, wrong password, live codes, 2 MiB archive, offline ACK/TTL, restart приложений и ОС; при закрытии убедиться, что чужой Tor жив. Проверить отсутствие секретов в connection.log. Отдельно проверить Setup uninstall сохраняет %LOCALAPPDATA%\AEGIS.
