# Android АЕГИС 6.0.0: проверяемый кандидат разработки

`productionReady=false`. Четыре APK собираются из существующего Java-проекта без изменения desktop-архитектуры. Это функциональные, но неполные Android-приложения. Нативная приёмка Android 13+ ARM64, системный VPN/DNS, Doze и реальный голосовой звонок на Android не проверялись. APK с суффиксом `TEST` подписаны отдельным тестовым сертификатом и не являются production-релизом.

## Реализовано

- **АЕГИС / `org.aegis.core`:** мастер проверки и установки четырёх собственных APK через штатный Package Installer с подтверждением пользователя; проверка действительной APK v2/v3-подписи библиотекой Google apksig 9.4.1, сертификата, версии, ABI и целостности; отдельный ключ устройства, подписанный Identity RPC через существующий onion-only `TorTransport`, подтверждение нового устройства, вход доверенного устройства, выдача конкретных допусков, сверка и отзыв поколения сессии. Публичный ключ Identity закрепляется после независимой проверки владельцем. Tor SOCKS должен предоставляться доверенным работающим провайдером; автоматический Android Tor ещё не встроен.
- **Почта / `org.aegis.mail`:** защищённый импорт прежней identity и проверенных контактов из существующей AEB1/AEB2-копии с исходным Argon2id/AES-GCM; приватная identity остаётся в UID Почты. Настоящие REGISTER6/LOGIN6, протокол-1 STORE/FETCH/ACK через onion SOCKS, исходный подписанный E2EE-формат AEGIS02A, официальная libsodium 1.0.22 через собранный ARM64 JNI, зашифрованный локальный ящик и черновики. ACK отправляется после сохранения пакета и индекса. Поддержана обычная текстовая переписка; дополнительные старые защищённые форматы, интерфейс letter password/FF1, архив, экспорт вложений, P2P-приём и фоновая доставка ещё не перенесены. Текущий Android-лимит пакета 192 КиБ, одновременно 32 неистёкших входящих письма. Это не поддержка вложений 500 МБ.
- Core также содержит настоящий ограниченный режим локальной TCP/DNS-фильтрации: отдельный NETWORK_CONTROL, официальный pinned hev/lwIP, TUN → аутентифицированный локальный SOCKS → protected socket, DNS-правила с NXDOMAIN, запрет остального UDP и приватных назначений. Это обычный TCP через выбранную сеть, **не Tor-VPN**. Общий per-app Tor, Always-on/lockdown и соответствующий release gate остаются незавершёнными. Физические `protect(fd)`, отсутствие утечек и поведение при смене сети требуют Android-приёмки.
- **Глас / `org.aegis.glas`:** выбор микрофона/вывода, громкость, отдельная явная десятисекундная локальная проверка AudioRecord → SpeexDSP → Opus → существующий ограниченный GlasJitterBuffer → AudioTrack. Нативные Opus 1.6.1/SpeexDSP 1.2.1 собраны для ARM64 из тех же проверенных источников, что desktop. Микрофон не открывается до явного действия; при потере окна/блокировке/выходе устройства освобождаются. Нет аудиофайлов или сети в локальной проверке. Реализован отдельный BCJSSE 1.86 TLS1.3-адаптер существующего делегированного v2 wire: точные identity/delegation/context/ALPN, без корневого ключа и без глобальной замены провайдеров. Реальные loopback TLS-соединения с desktop проверены в обеих ролях. Он ещё не соединён с Android сигнализацией/Tor onion listener и защищённым входящим экраном; сетевой звонок не объявляется реализованным. BCJSSE обрабатывает стандартный входящий/автоматический KeyUpdate, публичного ручного API не имеет — неподдерживаемый ручной запрос явно отклоняется.
- **Страж / `org.aegis.strazh`:** локальная потоковая проверка выбранного APK: квоты ZIP, действительные CRC/размеры, traversal/дубли/распаковочные бомбы, apksig, сертификат, manifest/разрешения и ARM64. Файлы никуда не отправляются. Результат не объявляет APK безопасным или свободным от вредоносного кода. Подписанные индикаторы угроз, root/spyware/фишинг и интеграция с VPN ещё не реализованы.
- Во всех четырёх приложениях: отдельные UID без sharedUserId, закрытый backup, Android Keystore AES-GCM, FLAG_SECURE и запрет миниатюр, защита от наложений/obscured touch, системная повторная аутентификация, ограниченные потоки/очереди. Локальная очередь счётчиков зашифрована, дедуплицирована и ограничена.

## Граница IPC

Экспортирован только signature-защищённый Binder сервиса Core и signature-защищённые Activity модулей. На каждой транзакции проверяются реальный kernel UID, ровно один allowlisted package, его UID, текущий сертификат/цепочка и системная signature permission. Для закрытого действия требуется одноразовый 30-секундный challenge, подпись отдельного app key, конкретная операция, серверный capability, точное приложение, ключ доказательства и действительное поколение. Lease максимум 60 секунд, автономный допуск не дольше подписанного срока и 24 часов; monotonic/boot/wall-clock проверки и журнал отозванного поколения. Произвольного RPC/подписания корневым ключом нет. Закрытие Core, отзыв и screen-off закрывают модульные каналы и останавливают захват микрофона. Недоступный сервер не доказывает успешный удалённый отзыв; интерфейс сообщает это отдельно.

## Сборка

Нужны официальный SDK platform 36_r02, build-tools 36.1.0, NDK r29, JDK 21, Python 3 с `cryptography`, gcc/make только для host-тестов. Точные URL, SHA и лицензии перечислены в скриптах и `third-party/DEPENDENCIES.json`. Нативная сборка дополнительно проверяет обе официальные minisign-подписи источника libsodium. Старый mutable-URL SHA не был молча принят: Android использует отдельно аутентифицированный и закреплённый снимок 1.0.22 от 18.10.2026; desktop-артефакты и их pin не менялись.

```bash
python3 android/build-native.py --sdk /path/android-sdk --jdk /path/jdk21 \
  --source /path/libsodium-1.0.22-stable.tar.gz \
  --signature /path/libsodium-1.0.22-stable.tar.gz.minisig --out /path/android-native
python3 android/build-tun.py --sdk /path/android-sdk --jdk /path/jdk21 \
  --source /path/pinned-recursive-hev-git --out /path/android-tun
python3 android/build-audio.py --sdk /path/android-sdk --jdk /path/jdk21 \
  --sources /path/official-audio-archives --out /path/android-audio
python3 android/build.py --sdk /path/android-sdk --jdk /path/jdk21 \
  --native /path/android-native --tun /path/android-tun --audio /path/android-audio \
  --out /path/android-artifacts
```

`build.py --expected-commit FULL_HASH` требует чистый зафиксированный commit. Скрипт проверяет неизменность входных исходников до/после сборки, создаёт четыре unsigned APK и четыре TEST APK, запускает JVM/JNI-тесты, SDK apksigner и точную встроенную apksig, отклоняет реально модифицированный APK, проверяет 16-КиБ ZIP alignment и записывает SHA256SUMS/provenance. `build-native.py --resume` допускает повторное использование только после побайтной проверки исходников кэша по проверенному архиву.

Для API 33 исходные Java-классы криптографии переносятся механически: `HexFormat` заменяется эквивалентным форматированием, `List.getFirst()` на `get(0)` в проверенных непустых списках, `Stream.toList()` на collector. `AutomaticEncryption`, Binary, PacketCodec, алгоритмы, AAD и структуры пакетов сохраняются. Android SodiumBox — только JNI-вызовы официальных libsodium функций, а не реализация шифра. Готовый desktop JNA JAR не содержит Android jnidispatch, поэтому Linux glibc `.so` не использовалась как Android-библиотека.

## Проверки и ограничения

На текущем checkpoint: 31 JVM policy/ZIP, 13 делегирования, 4 реальные loopback SOCKS-handshake проверки, 18 настоящих host JNI/крипто/backup, 13 реальных gateway socket, 6 raw-IP native hev/lwIP и 29 actual Opus/существующего media pipeline с явно синтетическими PCM-устройствами; 31 настоящая BCJSSE↔desktop TLS interop проверка. Итого 145 host-проверок. Отдельно: 7 сценариев с настоящим Identity HTTP + SQLite Relay + Android MailRelay/LOGIN6/REGISTER6/E2EE через локальную SOCKS fixture и 101/101 официальных libsodium host-тестов. Эти сценарии не являются испытанием Tor-сети или двух физических устройств. Все четыре APK проверены SDK apksigner и встроенной apksig 9.4.1; реально изменённый APK отклонён обоими. Три ARM64 ELF (sodium/audio/hev) собраны с LOAD alignment 16384, но на ARM64 не выполнялись. Подробности и точные результаты каждого текущего прогона — в `docs/TEST-REPORT-ANDROID-6.0.0.md` и evidence-checkpoint.

Всегда используйте отдельные тестовые данные. Не заменяйте production-приложение APK с тестовым сертификатом и не удаляйте реальный профиль ради смены сертификата. Production APK signing — отдельный ключ Android, который создаёт и хранит владелец; manifest Ed25519 key для APK не используется. Порядок офлайн-подписи — `docs/OWNER-OFFLINE-SIGNING-ANDROID-6.0.0.md`.
