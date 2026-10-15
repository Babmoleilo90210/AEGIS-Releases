# Отчёт о реализации АЕГИС 2.5.0 — «Взор и Глас»

## Версия, исходники и статус

База: опубликованная кодовая база 2.0.0 Beta, commit `f173b4a1bb5f1e3ed121870aa04a6583833f93e9`; отдельная рабочая ветка `development/aegis-2.5.0`. Все 604 файла source ZIP опубликованного 2.0.0 совпали с Git, SHA-256 опубликованных AppImage/Windows ZIP проверены. Релизы v2.0.0 и v2.0.0-beta.1 содержали одинаковые проверенные assets. Подписанная CI provenance прежнего релиза не предоставлена; независимая воспроизводимость всех старых бинарников не заявляется.

Итоговый source commit/tree и SHA-256 каждого артефакта находятся в BUILD-PROVENANCE-2.5.0.json и SHA256SUMS рядом с пакетами. Сборки выполняются из одного зафиксированного исходного состояния. **productionReady=false. Stable не опубликован.** Это пакет реализации и приёмки с объективными внешними блокерами, а не объявление завершённой нативной сертификации.

## Изученные материалы

Оба предоставленных shared чата восстановлены из доступного HTML и разобраны. Просмотрены 19 локальных PNG, в том числе семь обязательных ориентиров: архив, поиск, профиль, контакты, настройки с красной рамкой/стрелкой вниз и одобренная шапка. Не все исторические attachment pointers доступны как pixels; ограничения и hashes перечислены в `docs/test-results/2.5.0/SOURCE-MATERIALS.md`. Последнее ТЗ 2.5.0 имеет приоритет над ранними назначениями номеров версий.

## Изменённые модули

- client-core: downloader/discovery/preflight/repair браузера, TLS и voice framing, call controller, аудиосистема, optional encrypted voice store, avatar publication journal/cache, навигация и версия updater.
- client-ui: Взор/Глас, общий incoming-call banner, контурные значки, русификация, галерея, архив, popup sizing. JavaFX и Appearance Engine сохранены.
- common-protocol: существующий почтовый протокол сохранён. Production Relay не изменён; серверный модуль остаётся тестовым/унаследованным.
- packaging/tools: native Opus/SpeexDSP build, MinGW/NSIS/AppImage 2.5.0, pinned runtime verification, строгий unsigned manifest generator, native acceptance kit и frozen previous parser fixtures.

## Взор

Одно действие запускает фоновую последовательность: предпосылки → собственная удостоверенная копия либо metadata → официальный package/asc через Tor → pinned OpenPGP → signed internal version/architecture → безопасная установка → изолированный запуск. Прогресс измеряет bytes; неопределённые стадии не получают выдуманных процентов. Отмена закрывает собственные sockets/process job. Повторное открытие использует удостоверенную установку; ошибки не включают fallback.

Linux использует bubblewrap, namespaces, slirp и Xephyr. Windows — официальную Sandbox VM с host-private ownership и disabled clipboard/camera/audio input/printers/vGPU. Home для Взора не поддерживается. Приватные ключи/архив/пароли не монтируются; обычные пользовательские Firefox/Tor Browser profiles не копируются. Browser Tor независим от messenger Tor. URL строго ограничены и не превращаются в shell command. Downloads не запускаются автоматически; импорт в архив явный через существующее шифрование.

Версионный floor основан на удостоверенном пакете, не имени файла. Repair после MAR/изменения executable требует свежего официального удостоверения. Own Browser Data/downloads сохраняются безопасным bounded no-follow переносом, чужой профиль не импортируется. Физическое стирание временной сессии не гарантируется. Полностью захваченный browser broker не ограничен kernel Tor-only firewall; штатная Tor Browser network модель и sandbox требуют настоящих capture/probes. Детали: VZOR-2.5.0.md и модель угроз.

## Глас и криптография

Реализованы настоящие transport/audio code paths, не декоративная заглушка. Peer onion service/подписанный маршрут расширены клиентской операцией 101 на существующем порту 81. Relay используется только через существующий каталог маршрутов, plaintext voice ему не передаётся. UDP, ICE/STUN/TURN/WebRTC и direct fallback отсутствуют.

Существующая Ed25519 identity удостоверяет ограниченное объявление свежего временного сертификата, call ID, ролей и обоих участников. JSSE TLS 1.3 с ECDHE, mutual exact pins и ALPN обеспечивает защищённый канал; подтверждение связывает параметры разговора. Личные ключи identity непосредственно аудио не шифруют и в TLS key manager не передаются. Ключи звонков отделены от писем, session keys не сохраняются. TLS KeyUpdate запрашивается через 10 минут/64 МиБ; полная свежая аутентификация — через час/при reconnect. Сессионные данные очищаются в пределах возможностей JVM/ОС.

Встроены incoming/accept/decline/busy/timeout/reconnect/hangup, проверка сохранённого ключа контакта, блокировка и safety code. Микрофон выключен до согласия и аутентификации и требует явного включения. Открытие раздела не захватывает звук. Локальная проверка микрофона добровольная, максимум 15 секунд, без отправки/записи. Lifecycle гонки отмены, открытия, cleanup и сбоя драйвера исправлены и воспроизводимо проверены.

Opus mono48kHz/20ms и SpeexDSP AEC/NS собраны из официальных pinned источников для Linux/Windows; лицензии включены. Capture/encode/encrypt/send/decode/playback выполняются в ограниченных очередях/потоках. Устаревшие кадры сбрасываются, битрейт и jitter buffer адаптируются. Устройства выбираются явно, mute/gain/volume доступны во время разговора. Необязательная история шифруется существующим vault и отключена по умолчанию. Запись речи, облачная аналитика и распознавание отсутствуют.

Реальное качество Tor, акустика, hotplug/sleep, CPU/RAM длительного разговора и независимая работа двух устройств пока не подтверждены. Нельзя гарантировать защиту от вредоносного ПО на host, физической записи, драйвера или дампа памяти. См. GLAS-CRYPTOGRAPHY-2.5.0.md, GLAS-THREAT-MODEL-2.5.0.md, GLAS-AUDIO-2.5.0-RU.md.

## Интерфейс и профили

Восемь переставляемых разделов, компас/трубка в общем контурном наборе, русские пользовательские подписи и сохранённая шапка. Галерея всех 16 пресетов имеет раздельные preview/name/favorite. Типы архива переведены без смены внутренних значений. Управление архивом разделено на три компактных меню и вложенные панели; поиск/режимы/папки/теги/корзина сохранены. Компактный поиск и пять категорий настроек с содержимым ниже сохранены. Добавлены 92 refinement/settings и 48 Взор/Глас/все разделы настоящих headless screenshots. Исправлены узкие окна200% и доступность кнопок file picker. Эти files входят в evidence; они не выдаются за native screenshots.

Публикация аватара получила crash-safe dirty journal, generation acknowledgement, quota accounting и очистку orphan cache. Identity не меняется. Настоящая Tor-попытка двух аккаунтов заблокирована bootstrap; синхронизация в интернете NOT_RUN. Изменение серверного nickname/Relay не выполнялось; существующая identity и nickname не переименовываются произвольно. Видимость профиля и существующие операции сохранены.

## Проверки, миграция и обновления

Основной JUnit: 367 PASS/1 SKIP/0 FAIL; Python tools:67PASS, Windows packaging policy:1PASS. Подробные наборы и исходные неуспешные прогоны приведены в TEST-REPORT-2.5.0.md. Реальный TLS и native Linux codec tests отделены от искусственных audio/network fixtures. Headless UI не заменяет целевые ОС. В старом resize smoke сохранён PARTIAL_BACKEND_ERROR Monocle. Новый stress-dialog дефект prefHeight при150–200% исправлен horizontal content bias; исходный FAIL сохранён. Доступное profiling-сравнение 3×2 offline JVM записано в docs/test-results/2.5.0-performance/: vault open325→279мс, archive reopen229→236мс, import32MiB672→586мс, fulltext65→61мс, RSSidle198.73→200.82MiB; эти числа не объявляются качеством всего приложения или статистически значимым ускорением.

Перед новой версией создаётся полный проверенный ciphertext snapshot. Добавление safeweb/glas сохраняет порядок, ключи/письма/архив/темы; операции идемпотентны. Проверены прерванный/повреждённый backup и повторное открытие. Нативные upgrade paths 1.5.0/2.0.0 и rollback остаются NOT_RUN.

Unsigned manifest generator отвергает несовпадающие version/tag/URL и проверяет реальные размеры/хеши assets. Frozen old parser tests воспроизводят ограничения 1.5.0/2.0.0; Ed25519/SHA-256/anti-rollback не ослаблены. Проверка manifest не называется updater E2E. Production signing key и feeds не изменены.

## Объективные блокеры и оставшаяся приёмка

1. Windows 11/CachyOS KDE Wayland/X11 отсутствуют: нативные GUI/Sandbox/audio/install/update/rollback NOT_RUN.
2. Внешний Tor bootstrap Direct0%/Snowflake10% не завершился: настоящий удалённый Глас, профили/аватары, updater через Tor BLOCKED/NOT_RUN.
3. Official Tor Browser endpoint вернул SiteUnavailable: vendor archive/pin/install/launch/HTTPS/onion/MAR и реальные leak tests NOT_RUN.
4. Нет двух физических устройств в разных сетях и аудиоустройств: реальный разговор,60мин,акустика,hotplug/CPU/RAM/combinedload NOT_RUN.
5. Владелец не предоставлял offline Ed25519 signature, и она не запрашивалась для выполнения разработки. Stable publish после gates требует отдельного разрешения.

Именно эти условия сохраняют productionReady=false. Результаты, которые ещё не получены, не заменены фиктивными логами, mock-проверками или сгенерированными изображениями.

## Пакеты, установка и подпись

Подготовлены Windows Setup/portable, CachyOS AppImage, source/client-source ZIP, native acceptance ZIP, документация, SHA256SUMS, unsigned metadata и provenance. Их фактическое наличие/хеши подтверждаются внешним inventory в пакете; если packaging verification не прошёл, соответствующий файл не объявляется проверенным. В комплекте нет owner private signing key, пользовательских паролей/архивов и production secrets.

Установка: README-WINDOWS.md и README-CACHYOS.md. Миграция: MIGRATION-1.5.0-TO-2.5.0.md и MIGRATION-2.0.0-TO-2.5.0.md. Подпись: OWNER-OFFLINE-SIGNING-2.5.0.md. Публикация Stable и изменение updates/stable.json(.sig) в этой работе не выполняются.

Дополнительная проверка комплектной Java воспроизвела отсутствие русских locale data в унаследованном JRE: октябрь отображался как Oct. Включены проверенные Java21runtimes с jdk.localedata: Linux jlink en,ru из vendorSHA-проверенного Temurin JDK, Windows официальный Temurin JREZIP с проверкой двух vendorSHAисточников. Фактическое Linux форматирование русского месяца/дня/даты и десятичной запятой прошло; Windows проверены vendorfiles/modules/PE, нативное форматирование NOT_RUN. Закреплены все441runtimefileSHA и лицензии; неизвестные/изменённые файлы и внешние ссылки packager отвергает. Источники и before/after: docs/test-results/2.5.0-java-locale/. Приватные ключи/криптоалгоритмы не менялись.


## Финальный review исходящей очереди голоса

Исправлены два подтверждённых дефекта: потеря сигнала congestion при drop-oldest и отсутствие local TTL для накопленных frames. Очередь12frames/250ms, fresh-check перед write после KeyUpdate, очистка payload.10 новых детерминированных тестов; итоговый полный Java-прогон378found/377PASS/1WindowsDPAPI SKIP/0FAIL/errors: docs/test-results/2.5.0-final-voice-review/. Все5headlessUIпроб повторены на конечных sharedJAR,148реальныхPNG в final-package-verification/postreview-ui/ итогового пакета. Старые performance числа остаются измерениями прежнего JAR; byte comparison подтвердил неизменность storage/search workload classes. Протокол и TLS не менялись.
