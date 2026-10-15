# Проверки АЕГИС2.0.0

Текущий полный Java21 прогон: **258 found,257 PASS,1 skipped,0 failures/errors**. Код: `0a8efa98c1307ae2dc88c00d6b3208cdb260282b`. Native/Stable готовность из этого не следует; `productionReady=false`.

| Модуль | Найдено | PASS | Skipped | Ошибки |
|---|---:|---:|---:|---:|
| common-protocol |4|4|0|0|
| client-core |237|236|1|0|
| relay-server |3|3|0|0|
| integration-tests |14|14|0|0|

Пропущен Windows DPAPI CurrentUser на Linux. Итоговые XML, полный clean-retry log и RESULTS.json: `docs/test-results/2.0.0-followup/full-current/`. Первая неполная попытка сохранена как first-incomplete-build.log и не считается PASS. Исторические totals171/170 перенесены в previousAutomaticTests; с новыми выборочными тестами не складываются.

Новое покрытие: pinned OpenPGP17 (реальные RSA3072 fixture signatures+реальный Tor publickey); bounded TAR/XZ installer10; guarded download snapshot14; controller/Sessions/Linux27; Windows backend policy6; profile/cache/search/migration13. Это unit/policy/локальная интеграция, не фактический Tor Browser launch. Process-backed adapter явно тестирует cleanup policy в build namespace, не native descendant enumeration.

Python suite40 PASS: release-manifest16, installer19, staging5. Подписи fixtures не используют private key владельца. SHA/CRC восьми настоящих runtime dependencies проверены отдельно. Клиентские пакеты проходят независимую структурную проверку после сборки; факт cross-compilation не равен Windows11 PASS.

Interface200Smoke, SettingsResponsive200Smoke и SafeWeb200Smoke прошли на реальных JavaFX Scene с искусственными данными:16 пресетов, архив/навигация/настройки/профиль,800×600,100/125/150/200%,две темы,два режима и реальные controls Safe Web, отсутствие overlap, прокрутка, picker cancellation и URL rejection. Cached snapshot остаётся отзывчивым при занятом manager monitor. Матрица/логи/48 снимков — current-gui.json/current-gui/screenshots. SafeWeb200Smoke повторно прошёл на финальных JAR после backend fixes. Ни одного сгенерированного изображения за screenshot не выдано.

Реальный Tor PublicProfileTorProbe выполнен дважды: Direct0%, Snowflake10%, затем BLOCKED/bootstrap stall/SNOWFLAKE_BROKER_ERROR. Все семь wire-сценариев профиля через onion остались NOT_RUN. Локальный PublicDataTest с двумя аккаунтами/SQLite/подписями/SOCKS harness прошёл, но это отдельное доказательство. Production Relay не изменялся.

| Обязательная внешняя проверка | Факт |
|---|---|
| Windows11x64 desktop/native |NOT_RUN|
| CachyOS KDE Wayland |NOT_RUN|
| CachyOS KDE X11 |NOT_RUN|
| Официальный browser+asc install/actualversion |NOT_RUN: download blockedHTML|
| HTTPS/onion/DNS/WebRTC/packet capture |NOT_RUN|
| Native key/archive/clipboard sentinels |NOT_RUN|
| Native browser/VM lifecycle/crash/tempcleanup |NOT_RUN|
| Official Tor Browser MAR update |NOT_RUN|
|1.5→2.0 signed updater install/restart/rollback |NOT_RUN|
| Windows Home/другие builds |Не покрыты WSB24H2+ backend|
| Nickname rename |BLOCKED_SERVER_APPROVAL|

Подробные границы каждого SW-01…20/UI-01…26 — FINAL-VERIFICATION-2.0.0.json. Невыполненные обязательные пункты не переведены в PASS. Stable не опубликован, production feed и pinned owner public key не изменены.
