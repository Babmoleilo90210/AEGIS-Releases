# АЕГИС 1.1.0 — development candidate

Продолжение выпущенного 1.0.0; protocol 1 сохранён. Новые исходники, реальные тесты и упаковки готовятся отдельно от production. **productionReady=false** до Windows 11/KDE/Tor E2E/reboot и updater acceptance. Production Relay и ключи не изменены; релиз не подписан и не опубликован.

См. CHANGELOG-1.1.0.md, BUILD-1.1.0.md, MIGRATION-1.0-TO-1.1.md, RELAY-0.3-STAGING.md, TEST-REPORT-1.1.0.md.

Runtime-соединения: собственный Tor и Snowflake, relay/P2P onion через localhost onion-only SOCKS, HTTPS обновления к четырём разрешённым GitHub хостам через отдельный localhost SOCKS собственного Tor, SAFECOOKIE Control и loopback P2P service. Прямого fallback нет; в приложении нет telemetry/cloud analytics. Публичные профили и согласия отправляются только через ваш Relay; приватные identity keys, пароль vault и plaintext сообщений остаются на устройстве.

---

Документация прежней версии и происхождение архитектуры:

# АЕГИС 1.0.0

Автономная Единая Гибридная Информационная Система. Клиенты Windows 10/11 x64 и CachyOS x86_64, Java 21. Существующий **Relay 0.2.0 / protocol 1** остаётся без изменений. Новый Debian пакет не выпускается.

Windows: Setup или полный portable ZIP → AEGIS.exe. CachyOS: AppImage. Внутри минимальный Java runtime, официальный Tor, Lyrebird и libsodium. GUI открывается сразу, собственный Tor подключается в фоне. Вставьте выданный onion при первом запуске; затем адрес сохраняется.

Вход — ник и пароль аккаунта. Старый пароль vault нужен один раз при миграции 0.3. Контакт выбирается из списка с поиском и локальным аватаром. Оба участника закрепляют и сверяют отпечатки. Для защищённого письма задаются независимые пароль письма, код FF1 и TTL. До 64 обычных файлов любых типов, суммарно до 16 MiB по стандартной конфигурации. Получатель экспортирует их одним AES-256 ZIP с паролем этого письма.

Новые клиентские функции: компактный список/предпросмотр писем; пять тем и пять пресетов с JSON import/export; локальные PNG/JPEG/WebP аватары; семидневное локальное разблокирование через DPAPI CurrentUser или Secret Service; signed updater с отдельным AEGIS-Updater.exe, встроенным Ed25519 trust key и откатом.

Семидневное локальное разблокирование не продлевает серверную авторизацию: неизменённый relay выдаёт bearer только на 12 часов и забывает его при перезапуске. После этого нужен пароль аккаунта для входа в сеть. Он не сохраняется. Клиентский AEGIS-AUTH-v1 KDF вместо прежнего wire password несовместим с существующими аккаунтами; реализован отдельный vault KDF AEGIS-VAULT-v1, server auth сохранён. Подробности и открытые критерии — SECURITY.md и TEST-REPORT-1.0.0.md.

## Все сетевые соединения

1. Java → **127.0.0.1:19050**: SOCKS5 собственного Tor. Relay и P2P только по onion; DNS-имена передаются SOCKS, а не системному resolver Java.
2. Java → **127.0.0.1:19051**: собственный Tor ControlPort, SAFECOOKIE, bootstrap и публикация onion routing.
3. P2P service слушает только **127.0.0.1:19120**. Tor доставляет ему подписанные encrypted packets. Публичный входящий порт Java не открывается.
4. Обновления: Java → тот же loopback SOCKS → TLS HTTPS к **raw.githubusercontent.com** (Babmoleilo90210/AEGIS-Releases/main/updates/stable.json или beta.json и .sig), **github.com** (только подписанные release URLs). Redirect allowlist: **release-assets.githubusercontent.com**, **objects.githubusercontent.com**. Никакого direct HTTPS fallback, локального DNS для этих запросов или загрузки trust key. Перед parsing JSON проверяются exact bytes и Ed25519. Проверка/скачивание включены по умолчанию и явно выключаются в Настройки → Обновления; установка спрашивается, либо пользователь выбирает установку при закрытии.
5. Встроенный Tor → Tor directory/guard/relay. Только Tor создаёт эти внешние TCP-соединения.
6. При Snowflake Lyrebird → broker/CDN, системный resolver, STUN/WebRTC/bridge из официального tor/snowflake-bridges.txt. Его собственный случайный SOCKS-порт ограничен localhost. PT запускается по абсолютному пути без shell.

Relay Java по-прежнему только слушает localhost. Серверный Tor публикует onion и использует Tor/Snowflake инфраструктуру. Административных функций расшифрования нет. README-SERVER.md относится к неизменённому 0.2.0.

Сборочные scripts обращаются к Gradle/Maven, Azul, официальному Tor bundle, libsodium, LLVM MinGW, AppImage и Ubuntu NSIS **при явной сборке**. Это не рабочие соединения клиента. Скачать зависимости при старте клиент не пытается.

## Зависимости и данные

JCA/Java 21, BC 1.86, Tink 1.23.0, libsodium 1.0.22 — существующая криптография. Zip4j 2.11.6 — локальный AES ZIP. JNA/JNA Platform 5.19.1 — вызовы ОС, в том числе DPAPI. Gson 2.14.0 — строгий bounded JSON. TwelveMonkeys ImageIO WebP 3.14.0 — локальный bounded decoder. У последних трёх нет сетевой роли: OS storage получает только случайный device secret, JSON parser и decoder работают с локальными bytes. Версии сверены с официальными release/docs и закреплены lockfiles/SHA-256 verification metadata; LICENSE/NOTICE внутри JAR сохраняются.

Никаких SaaS, телеметрии, cloud crash reports, рекламы, трекеров, master/developer decryption keys. Release key проверяет дистрибутивы и не расшифровывает сообщения.

Сборка: BUILD-CLIENTS.md. Пользовательские инструкции: README-WINDOWS.md / README-CACHYOS.md. Миграция: MIGRATION-0.3-TO-1.0.md. Проверки, реальные ограничения и owner-side checklist: TEST-REPORT-1.0.0.md. Native Windows/CachyOS и настоящая связь с VPS ещё не подтверждены; **productionReady=false**, публикация и offline-подпись остановлены.

Для проверки готовых пакетов на своих устройствах доступен отдельный `AEGIS-1.0.0-native-acceptance.zip`: Windows — `Run-Windows.cmd`, CachyOS — `bash Run-CachyOS.sh`. Он использует встроенную Java, временный тестовый профиль и локальный JSON-отчёт без автоматической отправки. Сам комплект не заменяет приёмку реального обмена через Tor и существующий relay. Test JARs находятся только в отдельном комплекте и не подключаются к обычному клиенту.
