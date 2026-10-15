# Глас 2.5.0 — независимый обзор интеграции

Проверена рабочая реализация на базе `f173b4a1` в `development/aegis-2.5.0`, 15 октября 2026 года. Область: `VoiceCallService`, `VoiceFrames`, `VoiceHistory`, `VoiceTls`, `PeerServer`, маршрутизация voice в `NetworkService`/`TorTransport`/`ClientSession`, media boundary и `GlasView`/`VzorView`. Обзор выполнялся отдельно от разработчика voice controller; изменения его файлов передавались ему для исправления. Интеграция microphone lifetime в `GlasView` затем выполнена по отдельному поручению владельца общей разработки.

## Найденные и исправленные дефекты

| Finding | Риск и исходный путь | Исправление и актуальное место | Доказательство |
|---|---|---|---|
| GR-01 | Аутентифицированный вызываемый контакт мог посылать повторные RINGING. Каждый frame вызывал publish и новый `Platform.runLater`; bounded audio queues не ограничивали FX events | `VoiceCallService.java:209`: единственный WAITING→RINGING; duplicate no-op. `:206`: дополнительно 250 frames/s. `GlasView.java:58`: coalesced FX refresh | Настоящий TLS malicious-callee test. Прежнее выражение в отдельной временной копии:20 notifications на 20 duplicates, assertion FAIL. Текущий код: PASS |
| GR-02 | Повреждение необязательного `voice-v1.vault` передавало исключение через конструктор VoiceCallService в ClientSession и мешало открыть также неповреждённые письма/архив | `VoiceCallService.java:63–66,91–96`: исходный файл сохраняется, выключается только voice, для восстановления требуется явная очистка истории | Исправление выполнено разработчиком controller; его regression suite проверяет scope recovery. Это не восстановление повреждённых записей |
| GR-03 | `disposed` переиспользовался после scene reattach/new start: позднее завершение старого open могло заменить handle нового теста и оставить capture до timeout | `GlasTestOwnership.java:17–58`; `GlasView.java:96–107,119–120`: монотонная generation, atomic claim/stop/retire, callbacks проверяют token и владение | 5 deterministic lifetime tests, включая blocked old open→stop→new open, shutdown-during-open и 200 concurrent claim/stop |
| GR-04 | Stop теста помещал close в общий executor; последующий `shutdownNow` либо заполненная bounded device queue могли отбросить закрытие уже отсоединённого handle | `GlasView.java:33–37,124–130,139`: global slot до подтверждённого close, независимый cleanup executor 1/queue 1, shutdown только после освобождения slot, ожидающие opens дренируются и не могут заявить устаревшее владение | Проверка lifetime helper и compile Java 21. Driver/реальный capture shutdown остаётся нативным gate |
| GR-05 | Проверка микрофона могла продолжаться после начала/принятия разговора; повторные клики enable в ожидании открытия давали неочевидный toggle | `GlasView.java:44–46,58,62–68,116,122`: отмена на call actions, busy notification, scene leave, logout/close; pending desired state для mic button, hangup доступен | Проверка фактических code paths; реальное устройство/нативный UI отдельно NOT_RUN |

Номера строк относятся к состоянию обзора и могут сдвигаться при последующей сборке. GR-01 — availability/OOM path от аутентифицированного peer, GR-02 — локальная availability regression, GR-03/04/05 — управление согласием и lifetime локального захвата. Они не описываются как доказанная кража identity keys или обход TLS.

## Проверенные защитные свойства

- Incoming проходит проверку известного полного identity key, подписи, адресата, роли и TTL до ringing. TLS требует взаимный точный certificate pin и подтверждает call context внутри канала. Неизвестный ключ не становится контактом.
- Media создаётся после ACCEPT/READY; AUDIO до согласия отвергается. Микрофон закрыт по умолчанию и после reconnect. Данные микрофонного теста не передаются в сеть.
- Fresh reconnect использует новые Offers/сертификаты/SSLContext с прежней pinned identity. Контакт со сменившимся ключом не принимается автоматически. TTL seen-call cache и возрастающий audio sequence дают дополнительные application bounds поверх JSSE record nonces.
- Максимальные размеры проверяются до allocation; сообщения не используют Java serialization, URL, команды или пути. Native Opus decoder получает ограниченный mono 20 ms frame. Время разговора вычисляется локально, а не из hostile timestamps.
- Voice outbound route требует identity-signed актуальный onion route и loopback SOCKS. Нет voice STORE/Relay/direct/UDP/ICE fallback. TLS socket test сам по себе это сетевое свойство не доказывает.
- Отдельные preface/voice/mail workers, лимиты handshakes и очередей, deadlines и raw-first socket close ограничивают зависания и рост памяти. Защита от любого DoS public onion endpoint не заявляется.
- История opt-in и зашифрована существующим локальным vault. Она не содержит аудио, маршрут, сетевые адреса, пароли и traffic secrets. Выключение не удаляет старые записи: предусмотрена отдельная очистка.
- Старый peer operation rejection проверяется через отключённое voice extension при сохранении обычной доставки зашифрованного письма. Это совместимость wire handlers, а не запуск старого установщика.

## Фактические тесты обзора

`VoiceSecurityReviewTest`: 4/4 PASS, 0 skipped, настоящий JSSE TLS через loopback. Сценарии: другой recipient, повтор завершённого callId с новым сертификатом, повтор принятого audio sequence, flood повторных RINGING. XML: `docs/test-results/2.5.0-voice-security-review/TEST-junit-jupiter.xml`.

`GlasTestOwnershipTest`: 5/5 PASS, 0 skipped; реальные concurrent threads и controllable blocked-open seam, искусственные close-counted handles. XML: `docs/test-results/2.5.0-microphone-ownership/TEST-junit-jupiter.xml`. Эти handles не выдаются за аппаратный звук. `GlasView` с интеграцией helper скомпилирован Java 21; `git diff --check` прошёл.

Ранее отдельно выполнен `VoiceTlsTest`: 17/17 PASS с настоящими TLS sockets, KeyUpdate и повреждением реального ciphertext relay. Суммы остальных controller/media/полной сборки берутся из основного отчёта; старые XML не выдаются за повторный прогон новых исходников.

## Остаточные ограничения и gates

Сетевой MITM/auth bypass, передача до согласия и повтор audio frame в проверенных сценариях не обнаружены; абсолютной безопасности или полного независимого аудита это не означает. Требуются нативные Windows 11/CachyOS KDE Wayland/X11, реальные микрофон/динамик/device switch/unplug, Tor/onion traces, долгий 10/60 min lifecycle, updater E2E/rollback и итоговая release verification. Для них в этом обзоре стоит `NOT_RUN`, а не PASS.

Экран, память endpoint, глобальная Tor traffic correlation и запись голосового потока собеседником остаются явными границами модели. Документ `GLAS-THREAT-MODEL-2.5.0.md` приводит первичные источники Microsoft, XDG Desktop Portal, Tor Project, RFC и JSSE и не обещает универсальный запрет capture/доступа ОС. Механизмы обхода антивируса/EDR или сокрытия процесса не вводились.

`productionReady=false` до выполнения обязательных внешних gates. Этот обзор не разрешает Stable, не меняет production Relay/feed и не использует release-signing private key.
