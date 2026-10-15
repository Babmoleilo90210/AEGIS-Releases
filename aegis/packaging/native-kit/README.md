# Native-проверка АЕГИС 1.0.0

Это отдельный тестовый комплект для владельца. Обычный клиент не требует его установки. Тесты работают со встроенным Java21 и библиотеками уже готового клиента. Python/JDK/Gradle не нужны. Administrator, firewall changes, глобальные службы и загрузка данных не требуются.

Windows: распакуйте клиент и этот комплект рядом; откройте `Run-Windows.cmd`. Для установленного клиента автоматически проверяется `%LOCALAPPDATA%\Programs\AEGIS`. Если каталог другой, скрипт предложит указать его. Не отключайте Defender/SmartScreen ради теста.

CachyOS: поместите AppImage рядом с папкой комплекта, дайте ему право запуска и выполните `bash Run-CachyOS.sh`. Можно передать путь к своему AppImage первым аргументом. Извлечение временное, FUSE для теста не требуется. Повторите на KDE Wayland и X11, если оба сеанса доступны.

Проверяются четыре современных шифра, неправильный пароль, nonce, native libsodium E2EE, identity binding, vault reopen, встроенный release public key, отказ unsigned manifest и fail-closed Tor. Реальный DPAPI CurrentUser / Secret Service проверяется с новым случайным тестовым профилем: save/load/replace/clear, отдельный JVM, encrypted resume, AEAD tamper, expiry. Сроки проверяются с управляемыми часами; семь суток ждать не нужно. Это семь суток локального unlock и двенадцать часов существующего relay bearer, не обход ограничения сервера.

GUI-проверки используют настоящий JavaFX toolkit без Monocle: popups, контакты, темы, UI presets, progress, защищённое письмо и FF1. Тестовые окна и снимки содержат только искусственные данные. Снимки временные, реальный рабочий стол не снимается. Отчёт содержит фактический JavaFX output scale; на Windows повторите запуск при 100/125/150/175/200% системного DPI. Скрипт не меняет DPI и настройки рабочего стола.

Результат: `AEGIS-native-Windows-*.json` или `AEGIS-native-Linux-*.json` рядом со скриптом. Только OS/version, SHA256 application JAR, список результатов, elapsed time и screen scale. Пароли, key material, ник, адрес relay, contents/cookies/user profile paths в JSON не включаются. Автоматической отправки нет. Случайные OS-secret records удаляются, тестовые каталоги очищаются. Если provider заблокирован, может потребоваться штатное разблокирование KWallet; пароль АЕГИС тесту не нужен.

`FAIL_OR_UNAVAILABLE` — проверка не прошла или системный provider недоступен. Это не PASS. Комплект всегда оставляет `productionReady=false`, поскольку сам не подтверждает запуск installer, реальные Tor circuits, cross-network доставку, reboot и frozen-AUTH решения. Обычный клиентский профиль не изменяется.

После автоматических тестов проверьте обычным интерфейсом Windows ↔ действующий relay0.2.0 ↔ CachyOS: письмо туда/обратно, offline delivery/ACK, TTL, файл, перезапуск обоих клиентов и reboot VPS. Не вводите пароли или приватные ключи в отчёт. Пользовательские аккаунты тестовый комплект не создаёт, relay не меняет и к сети не подключается.

Сборка комплекта: `./gradlew :client-core:nativeAcceptanceJar :client-ui:nativeAcceptanceGuiJar`; затем `python3 packaging/package-native-kit.py --artifacts <готовые пакеты> --out <отдельный каталог>`.
