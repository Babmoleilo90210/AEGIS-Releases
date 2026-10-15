# Результаты испытаний АЕГИС 2.5.0

Дата: 15 октября 2026 года. Среда: Ubuntu 24.04 x86_64, JDK 21.0.12.1+1; JavaFX Monocle headless. **productionReady=false.** Windows 11, CachyOS KDE Wayland/X11, физические аудиоустройства и второй физический компьютер в другой сети недоступны.

## Автоматические проверки

| Набор | Результат | Граница доказательства |
| --- | --- | --- |
| common-protocol | 4 PASS | Реальный локальный Java 21 |
| client-core | 346 PASS, 1 SKIP | Windows DPAPI пропущен на Linux |
| relay-server | 3 PASS | Изолированная JVM без клиентской криптографии |
| integration-tests | 14 PASS | Локальные тестовые Relay/PeerServer и временные профили |
| tools | 67 PASS | Python manifest, updater installer policy, staging и native registry |
| Windows packaging policy | 1 PASS | Статическая/fixture-проверка; не Windows execution |

Итого основной JUnit: 368 найдено, **367 PASS, 1 SKIP, 0 FAIL**. XML в `docs/test-results/2.5.0/full-java/`. Последняя сборка из итогового commit и контрольные суммы записываются в BUILD-PROVENANCE-2.5.0.json рядом с артефактами. Поднаборы ниже входят в общий JUnit и не прибавляются повторно.

- 69 browser download/install/preflight/repair checks: настоящий OpenPGP с одноразовыми fixture-ключами, XZ/TAR/HTTP/SOCKS fixtures, traversal, links, подпись, версия, antirollback, cancellation, crash recovery. Это не официальный Tor Browser.
- 17 TLS tests: настоящий JSSE TLS 1.3, mutual pins/ALPN, identity/call/role binding, неверные сертификаты, TLS 1.2 rejection, record tamper через TCP proxy, KeyUpdate, absence известного plaintext на wire.
- 20 voice controller tests: настоящее loopback TLS/PeerServer с искусственными аудиоустройствами; accept/auth gate, bounded queues, busy, reconnect, blocked/key-changed contacts, runtime device failure, совместная доставка зашифрованного письма и cleanup.
- 4 независимых hostile-peer tests и 5 microphone ownership tests, в том числе 200 воспроизводимых гонок. Искусственные handles не выдаются за физический микрофон.
- 11 audio tests: настоящий Linux Opus/SpeexDSP, codec roundtrip, synthetic echo/noise/PLC/buffers и искусственные Java Sound seams. Захват/воспроизведение настоящего устройства не проводились.
- 20 update security tests и 5 old-parser compatibility executions; подписи fixture проверяются отдельным тестовым ключом. Закреплённый ключ production не заменялся.
- Avatar publication/cache/crash-journal и migration tests выполняются локально с временными хранилищами. Они не подтверждают Tor/Relay доставку между удалёнными аккаунтами.

Первый полный прогон был неуспешен: устаревшие тестовые версии 2.1.0 стали ниже CURRENT=2.5.0, две проверки ожидали семь разделов, один migration fixture не содержал обязательный state.vault. Тестовые данные исправлены под новую версию; anti-rollback не ослаблен. Исходный журнал не скрыт: `docs/test-results/2.5.0-manifest-followup/root-first-run-client-core.xml`.

## Интерфейс

Interface250RefinementSmoke проверяет восемь вариантов 800×600 (две темы × 100/125/150/200%), 16 карточек галереи, отсутствие наложения избранного, одинаковые кнопки, archive types, 11 вложенных панелей управления, настоящий второй/третий popup и размещение контента настроек ниже категорий. Optional CPU metric корректно даёт UNAVAILABLE без jdk.management.

VzorGlas250Smoke проверяет реальные JavaFX-узлы Взора/Гласа, маленькое окно, масштаб, раскрываемые панели, safe invalid URL, русский manual picker и отсутствие автоматического микрофона. Выявленные переполнения Взора/Гласа и clipping общих файловых диалогов при 200% исправлены; повторный прогон дал PASS_HEADLESS, 48 снимков, все восемь разделов и проверку экранных границ кнопок. Окончательные результаты и снимки — в `docs/test-results/2.5.0-vzor-glas-ui/`.

Старый Interface200Smoke выполнил функциональные assertions, но Monocle resize выдал `Too small int buffer`. Результат **PARTIAL_BACKEND_ERROR**, а не чистый PASS. Исправленный текущий smoke проверяется отдельно. Ни один headless screenshot не объявляется снимком Windows 11/CachyOS.

После изменения общего диалога выполнен отдельный UI-only compile; Core/common/Relay не изменены. Общий stress-smoke с24wrappedLabel выявил ошибку измерения высоты при150–200%; horizontal content bias устранил недоступность нижних кнопок. Сохранён исходный FAIL, финальные четыре связанные UI-smoke прошли чисто на свежем release JAR в docs/test-results/2.5.0-shared-ui/.

## Реальные сетевые попытки

В этот сеанс запущен свежий bundled Tor, без SOCKS mock. Tor Direct остановился на 0%, Snowflake на 10%; bootstrap failure. `docs/test-results/2.5.0/tor-profiles/RESULTS.json` фиксирует BLOCKED и семь последующих profile/avatar сценариев NOT_RUN. Новые удалённые тестовые аккаунты не были выданы за созданные.

Официальный endpoint Tor Browser в этой среде вернул HTML SiteUnavailable вместо metadata/package. Полная цепочка official package + asc + production pin + install + real browser launch не выполнена. Локальные TLS/HTTP fixtures её не заменяют.

| Обязательное испытание | Статус |
| --- | --- |
| Windows 11 x64 native | NOT_RUN |
| CachyOS KDE Wayland native | NOT_RUN |
| CachyOS KDE X11 native | NOT_RUN |
| Official Tor Browser real launch/HTTPS/onion/MAR | NOT_RUN |
| Native sandbox filesystem/clipboard/IPC probes | NOT_RUN |
| DNS/WebRTC/real-IP/direct-connection capture | NOT_RUN |
| Два физических устройства, разные сети, настоящий Глас | NOT_RUN |
| Разговор не менее 60 минут, sleep/hotplug/device acoustics | NOT_RUN |
| Удалённая синхронизация аватаров через Tor/Relay | BLOCKED |
| 1.5.0/2.0.0 updater E2E через Tor, установка/перезапуск/rollback | NOT_RUN |

## Миграция и регрессии

Проверены навигация 6/7→8, сохранение восьмисекционного порядка, ciphertext snapshots, identity, письма и отдельный зашифрованный архив, идемпотентность и отказ при повреждённом прерванном backup. Это реальные операции временных файлов/хранилищ. Нативные обновления установленного продукта с настоящими предыдущими версиями остаются NOT_RUN.

Регрессии E2EE/FF1/letter password/archive/receipts/P2P/profile caches проверены имеющимися автоматическими наборами. Direct/Snowflake/Relay и доставка на удалённый компьютер требуют отдельной сетевой приёмки. Подпись manifest, проверка parser и успешный local installer fixture не объявляются updater E2E.

Отдельный финальный Взор/Глас smoke также повторён на конечном JAR без override:48PNG, clean PASS_HEADLESS. Первая попытка с default virtual-screen Monocle дала BufferOverflowException при1280×850; результат помечен PARTIAL_BACKEND_ERROR. Повтор с явно достаточной headless.geometry1920×1200 прошёл, без изменения production source. Логи обеих попыток сохранены.

## Производительность

В UI evidence сохраняются реальные локальные длительности создания/layout/render, операций архива и поиска, heap/CPU sample. При отсутствии optional module CPU честно UNAVAILABLE. Нативные startup/login/Tor/archive/combined-browser-voice-mail и сравнение с 2.0.0 не измерены; baseline regression conclusion не сделан для всего приложения. Отдельно выполнены 3×2 независимых JVM с одинаковым offline vault/archive workload: медианы vault open325→279мс, archive reopen229→236мс, import32MiB672→586мс, full-text65→61мс; RSSidle198.73→200.82MiB. Это описательные значения контейнера, не доказательство ускорения продукта. Исходные JSON/runner/input SHA и эквивалентность Core classes находятся в docs/test-results/2.5.0-performance/. Linux native acceptance CLI проверил pins/codec/device enumeration, обнаружил 0 аудиоустройств. Он не открывал микрофон.

Критические непройденные проверки перечислены в RELEASE-GATES-2.5.0.json; BROWSER/VOICE matrix — FINAL-VERIFICATION-2.5.0.json. До их завершения `productionReady=false`.

Дополнительная проверка комплектной Java воспроизвела отсутствие русских locale data в унаследованном JRE: октябрь отображался как Oct. Включены проверенные Java21runtimes с jdk.localedata: Linux jlink en,ru из vendorSHA-проверенного Temurin JDK, Windows официальный Temurin JREZIP с проверкой двух vendorSHAисточников. Фактическое Linux форматирование русского месяца/дня/даты и десятичной запятой прошло; Windows проверены vendorfiles/modules/PE, нативное форматирование NOT_RUN. Закреплены все441runtimefileSHA и лицензии; неизвестные/изменённые файлы и внешние ссылки packager отвергает. Источники и before/after: docs/test-results/2.5.0-java-locale/. Приватные ключи/криптоалгоритмы не менялись.


## Финальный review исходящей очереди голоса

Исправлены два подтверждённых дефекта: потеря сигнала congestion при drop-oldest и отсутствие local TTL для накопленных frames. Очередь12frames/250ms, fresh-check перед write после KeyUpdate, очистка payload.10 новых детерминированных тестов; итоговый полный Java-прогон378found/377PASS/1WindowsDPAPI SKIP/0FAIL/errors: docs/test-results/2.5.0-final-voice-review/. Все5headlessUIпроб повторены на конечных sharedJAR,148реальныхPNG в final-package-verification/postreview-ui/ итогового пакета. Старые performance числа остаются измерениями прежнего JAR; byte comparison подтвердил неизменность storage/search workload classes. Протокол и TLS не менялись.
