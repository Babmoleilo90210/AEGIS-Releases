# АЕГИС 1.2.0 — новый lifecycle release candidate

**productionReady=false.** Friends/receipts/disappearing теперь реализованы клиентским E2EE путём без production Relay изменений. Новые файлы и формат подробно описаны в LIFECYCLE-1.2.0.md. Для открытых disappearing писем действует conservative early expiry после reboot ОС/неопределённого guard; это не утверждение точного межзагрузочного времени.

## Текущие результаты

Локальный Java21 прогон: client-core 121 PASS + 1 Linux DPAPI SKIP, common 4 PASS, Relay 3 PASS, integration 11 PASS; всего **139 PASS, 1 SKIP, 0 FAIL**. Семь новых security/clock/storage тестов и четыре lifecycle TCP/SOCKS/SQLite интеграции проверяют настоящие шифрование, Ed25519, persistence, packet framing и database. Synthetic SOCKS не является Tor.

Отдельные actual JavaFX MessengerSmoke и Lifecycle120Smoke PASS: password/FF1 сами не дают read receipt, explicit final reveal отображает body, один Stage. Полный 9-suite CI и проверки exact новых артефактов ниже будут дополнены после выполнения. Новый LifecycleTorProbe предназначен для настоящего встроенного Tor, трёх временных onion services и двух staging аккаунтов; его статус до запуска PENDING, не PASS.

Protocol/common, Relay, основные cipher algorithms и pinned updater key сохранены. 36 из прежних 38 protected files byte-identical; LocalStore и PlainMessage изменены отдельно для encrypted sidecars/clock floor и memory-only attachment copy, прежние форматы/codecs/алгоритмы не заменялись. Новые device keys не заменяют account identity. Ни independent security audit, ни Windows11/CachyOS acceptance не объявляются.

Windows11, CachyOS KDE Wayland/X11, различные физические сети и полный owner-signed 1.1.5→1.2.0 install/restart/rollback: **NOT_RUN**. Private key не использован; main/production feed/VPS/onion/релизы не менялись. Новый manifest надо подписывать заново для новых бинарников после приёмки.

## История предыдущего частичного кандидата

Следующий отчёт относится только к прежним бинарникам/CI b8cbeff (не к изменённым lifecycle binaries). Он сохраняется для воспроизводимости, его прежние BLOCKED решения заменены client-only реализацией и не являются текущим состоянием.

# АЕГИС 1.2.0 — проверенный клиентский кандидат

**productionReady=false.** Завершена независимая клиентская фаза; это не полный Stable 1.2.0. Friends на Relay 0.2.0, доставка подписанных delivery/read events отправителю и исчезновение после отображения требуют утверждения архитектуры. Production VPS, onion identity, ключи, main update feed и опубликованные Release не изменялись. Независимый security audit не проводился.

## Сборка и исходники

База — фактически опубликованная 1.1.5 Stable, source SHA-256 `9a564f5bb0638a55d1378d2601e5f8949012a725409a19792c6dd7630c74efd9`. Build commit `b8cbeff6902c9f7db7a284f6ba7c590fc42203bc`; [CI run 38228975781](https://github.com/Babmoleilo90210/AEGIS-Releases/actions/runs/38228975781). Финальные бинарники соответствуют этому прогону. Setup, portable и AppImage содержат Java21/Tor/Snowflake/libsodium; глобальные Java/Tor Browser не нужны. Клиентские JAR Windows/Linux побайтово одинаковы. В клиенте отсутствует Relay JAR. ICO/PE version 1.2.0.0, icon 16–256, ASLR/NX/asInvoker и payload SHA проверены.

Отдельно подтверждено побайтовое совпадение 38 защищённых исходных файлов с 1.1.5: common-protocol, Relay, crypto, LocalStore и TorHttpsClient. Pinned Ed25519 SPKI сохранён. SHA256SUMS и unsigned manifest заново сформированы после финализации документов; подпись не создана. Старые подписи нельзя переносить на этот manifest.

## JUnit и JavaFX

| Модуль | PASS | SKIP | FAIL |
| --- | ---: | ---: | ---: |
| client-core | 114 | 1 | 0 |
| common-protocol | 4 | 0 | 0 |
| integration-tests | 7 | 0 | 0 |
| relay-server | 3 | 0 | 0 |

Итого **128 PASS, 1 SKIP, 0 FAIL**. SKIP — nativeDpapiCurrentUserRoundTrip на Linux; в Windows Server проверка DPAPI выполнена отдельно. 16 release/security tests PASS. Восемь headless JavaFX suites PASS: ClientUiRegressionSmoke, Aegis11UiSmoke, SingleWindowSmoke, DarkGreenThemeSmoke, MessengerSmoke, Appearance115Smoke, AppearancePerformanceSmoke, Stability120Smoke. Они проверяют реальные JavaFX объекты/CSS, 22 сохранённых оформления, single window, draft retention, typed system update events, пять реальных TTF семейств с кириллическим coverage, preview/cancel, bootstrap card, avatar zoom/Escape и bounded geometry. Это не физическое DPI испытание.

Фактические JUnit XML, logs, безопасные synthetic screenshots и исходные измерения находятся в evidence/screenshots. Никакой реальный пользовательский профиль или Tor private state не вложен.

## Совместимость без production изменений

1.1.5 и 1.2.0 прошли четыре сочетания с независимо запущенными Relay 0.2.0/0.3.0: обычная E2EE почта, FF1/letter password, файлы, offline очередь, ACK, дедупликация, TTL, reopen vault и restart Relay. SOCKS harness синтетический — не настоящий Tor. Старый Relay собран из SHA-pinned опубликованного 1.0.0 source; это не скачанный production бинарник. Staging Relay 0.3 source уже присутствует в базе 1.1.5 и не изменялся.

Реальная временная SQLite БД прошла 0.2→0.3→0.2: users/password hashes/public keys, queued ciphertext, TTL и receipts сохраняются; старый Relay после rollback доставляет почту. Это лабораторная проверка существующей миграции, не развёртывание новой lifecycle схемы.

## Проверки точных пакетов

Windows runner — Windows Server 2025, а не Windows 11. Linux runner — Ubuntu 24.04, а не CachyOS. Изолированные тестовые профили/аккаунты и owned процессы; production feed только read-only через Tor.

| Среда | Проверка | Результат |
| --- | --- | --- |
| windows | packaged_runtime_native_cryptography_DPAPI_and_JavaFX | PASS |
| windows | real_NSIS_silent_install_with_isolated_profile | PASS |
| windows | real_AEGIS_EXE_no_global_Java_loopback_Tor_own_shutdown | PASS |
| windows | BUG11_real_embedded_Tor_TLS_production_Ed25519_old_feed | PASS |
| windows | published_110_verifier_stable_schema_exact_120_packages_fixture | PASS |
| windows | published_110_real_Tor_production_signature_download_resume_SHA256 | PASS |
| windows | candidate_120_real_Tor_production_signature_download_resume_SHA256 | PASS |
| windows | candidate_120_real_Snowflake_signature_download_resume_SHA256 | PASS |
| windows | published_111_verifier_stable_schema_exact_120_packages_fixture | PASS |
| windows | published_115_verifier_stable_schema_exact_120_packages_fixture | PASS |
| linux-tor | BUG11_real_embedded_Tor_TLS_production_Ed25519_old_feed | PASS |
| linux-tor | published_110_verifier_stable_schema_exact_120_packages_fixture | PASS |
| linux-tor | published_110_real_Tor_production_signature_download_resume_SHA256 | PASS |
| linux-tor | candidate_120_real_Tor_production_signature_download_resume_SHA256 | PASS |
| linux-tor | candidate_120_real_Snowflake_signature_download_resume_SHA256 | PASS |
| linux-tor | published_111_verifier_stable_schema_exact_120_packages_fixture | PASS |
| linux-tor | published_115_verifier_stable_schema_exact_120_packages_fixture | PASS |

Old 1.1.0/1.1.1/1.1.5 verifier fixture использует временный in-memory Ed25519 test key, который production verifier обязан отвергать. Проверяются schema, exact package/hash, прогресс и READY_TO_INSTALL; это **не** owner-signed установка новой версии. Real network probes используют настоящий pinned production key и SHA-pinned опубликованный source 1.1.5, проверяют TLS, Tor bootstrap, progress, interrupted download/resume и SHA; файл не устанавливается. Проверка старого production feed клиентом 1.2.0 не подменяет полный updater E2E.

## Измерения

Одинаковая нагрузка: Monocle/software 1280×900, 30 переключений шести прежних тем, тот же Java21 worker. Median/P95: 1.1.5 — 15/79 ms; 1.2.0 — 17/71 ms. Heap после GC: 31202448/30550344 bytes. Один прогон содержит шум; он не доказывает поведение DPI или latency на устройстве владельца. PERFORMANCE-1.2.0.json содержит исходные значения.

## Исправленные причины и открытые ограничения

- TorConnection/EmbeddedTor: один start, защита concurrent close, реальный bootstrap, Direct/Snowflake/Relay состояния без преждевременного FAILED, более терпеливые ограниченные stall timeouts. Availability fail closed; отсутствует clearnet fallback.
- ClientSession/LocalFeatures/MessengerApp: block имеет приоритет, отзыв остаётся локально при offline, ошибка профиля не блокирует friend sync. На старом Relay подтверждённый Friends не симулируется.
- BundledFonts/AppearanceEngine/AppearanceView: лицензированные Noto Sans, Inter, Roboto, PT Sans и DejaVu Sans, проверка реального coverage и JavaFX family до выбора. Typography preview/apply/cancel и старые presets сохранены.
- ResponsiveGeometry/AvatarView/AvatarViewer/MessengerApp: отступы sidebar и ограниченная адаптация, крупный аватар и zoom/Escape в одном Stage; чужой/скрытый профиль не получает право редактирования.
- UpdateInstaller/UpdaterMain/Windows updater: helper исключает UI/JavaFX из classpath, AWT headless, безопасные phase codes; основной Stage оформлен до показа. Источник белого окна на настоящем KDE не воспроизведён — BUG-17 не объявляется нативно закрытым.
- UpdateService: ошибка публикуется после записи диагностики; close/cancellation/ожидание собственных задач исправляют воспроизведённую гонку temp-profile cleanup. Ed25519/SHA/anti-rollback не отключались.
- ClientUpgrade: полный snapshot до новых sidecars/Tor, version marker с повторной проверкой. Старые письма не получают read события/новые сроки. Открытый draft базы 1.1.5 только в RAM; прежний install guard сохраняется.

Обнаруженные неудачные прогоны сохранены: stale test version fixtures, реальная updater close race, timeout официального apt mirror, неверный baseline Relay в compatibility harness, устаревшее ожидание DemoTorNetworkProbe и старый Snowflake 1.1.0/Linux fallback. Assertion/cipher/signature защиты не отключались; исторический FAIL не становится PASS задним числом.

## NOT_RUN / обязательные решения

Все 87 native rows Windows11/CachyOS Wayland/X11 остаются NOT_RUN до владельческой приёмки, включая DPI100/125/150/200, реальные два аккаунта через staging/production, интернет-loss/recovery, миграцию настоящего профиля, white window, reboot, owner-signed 1.1.5→1.2 install/restart и аварийный rollback. Native acceptance ZIP пересобран из exact source/client и находится отдельно от production classpath.

FR-01/02, MSG-03..06, EXP-01..07 заблокированы решением из RELAY-LIFECYCLE-PROPOSAL-1.2.0.md: минимальный event/lease transport, метаданные, одно активное устройство либо online coordination, fail closed при clock/state rollback, явный final display для FF1 без добавления correctness oracle. Не подменяем существующий max7d TTL-after-delivery таймером-after-read на30d. Production signing/publication не разрешены.

Доступный planning share изучен только до1.1.5; отсутствующие материалы1.2.0 не объявляются прочитанными. Work Prompt обрывается на DoD пункте4; оставшиеся утверждённые требования владельцу следует передать отдельно.
