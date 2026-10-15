# Маршрут писем АЕГИС 1.5.0

Базовый commit бинарников 1.2.0: `70f80c27c13321d3ad8f7c8d7fa630862c56c56d`. Итоговые бинарники 1.5.0: `f9ac41ab9a7aca659e23df88f020a84618af77a1`. Production Relay и protocol 1 не изменены.

## Фактическая архитектура

Online клиент создаёт ephemeral Tor onion через SAFECOOKIE/ADD_ONION. Java PeerServer слушает только `127.0.0.1`, onion virtual port — 81. Root identity подписывает Route с короткой lease около 90 секунд. Relay PUBLISH/FIND получает необходимые routing/account metadata. NetworkService DELIVER передаёт E2EE packet через onion-only SOCKS непосредственно peer onion; PeerServer подписывает ACK с digest пакета. STORE — ciphertext fallback на Relay.

Прямой P2P в исходной архитектуре существует. Использование Tor само по себе не доказывает такой маршрут. При P2P Relay видит координационные метаданные; успешный direct packet не передаётся через STORE. Подтверждения — отдельные подписанные E2EE control packets, они также могут использовать Relay fallback.

Аудит нашёл безусловный FIND перед DELIVER и закрытие живого PeerServer/Control при неудаче PUBLISH. Клиентское исправление добавляет краткий cache проверенного root-signed Route, сохраняет lease/key checks и оставляет живой peer при недоступном Relay. При потере или перезапуске самого Tor peer/control пересоздаются. После истечения lease доступность прямого маршрута без Relay не гарантируется. Новых серверных операций, публичных IP или криптографических identity не введено.

## Реально выполнено

1. `DeliveryTest.cachedRootSignedRouteWorksAfterRelayStopsWithoutPayloadOrDuplicate`: отдельные LocalStore/identity/PeerServer, остановленный Relay listener, два отправления одного packet → проверенные P2P ACK, ровно одно письмо, ноль новых Relay payload. Это TCP с **synthetic SOCKS**, отдельно от проверки Tor.
2. Run **38534308413**, окончательные JAR из run **38532085562**: **PASS через настоящий встроенный Tor**. Два client-core экземпляра, один Tor-процесс, один Linux-хост, три ephemeral onion services. RESULT и REAL-TOR.log: `evidence/platform/final-AEGIS-1.5.0-real-onion-staging-evidence/`.
3. Подписанные capabilities и ACK/read проверены криптографически. Во время отключения Relay прошли защищённое письмо с letter password/FF1, повторная отправка без дубликата и прямое read receipt. Отдельно прошли прямое вложение, исчезающее письмо и реальное ожидание 60 секунд. Получатель офлайн использовал ciphertext Relay queue; после возвращения доставка и ACK прошли. Отзыв взаимного контакта проверен.

| Сценарий | Зафиксированный маршрут / результат | Два физических устройства |
|---|---|---|
| P2P-01 — оба online | Прямой Tor DELIVER и подписанный ACK: PASS на staging | NOT_RUN |
| P2P-02 — Relay остановлен после координации | Прямой Tor по действительному Route, Relay не мог принимать payload: PASS | NOT_RUN |
| P2P-03 — получатель offline | Tor → Relay STORE ciphertext: PASS | NOT_RUN |
| P2P-04 — возвращение получателя | Tor → Relay FETCH / durable ACK / dedup: PASS | NOT_RUN |
| P2P-05 — разные сети | Нет доступной физической топологии | NOT_RUN |
| P2P-06 — разные OS | Linux staging не подтверждает Windows ↔ CachyOS | NOT_RUN |
| P2P-07 — вложение | Прямой Tor: PASS на staging | NOT_RUN |
| P2P-08 — letter password / FF1 | Прямой Tor: PASS на staging | NOT_RUN |
| P2P-09 — delivery/read | Signed peer ACK и display event: PASS на staging | NOT_RUN |
| P2P-10 — исчезновение | Прямой Tor, настоящий 60-секундный срок: PASS на staging | NOT_RUN |

Проверка одного Tor-процесса с несколькими onion services не равна проверке двух пользовательских компьютеров в разных сетях. Скрипт создаёт отдельные тестовые аккаунты и disposable Relay 0.2.0, не использует production VPS. Не записывает plaintext, пароли или private keys в отчёт.

## Неудачные попытки и повторная проверка

Первый Linux job окончательной сборки столкнулся с временной недоступностью свежего Relay onion descriptor и завершился `FAIL_OR_UNAVAILABLE`. Журнал сохранён. Отдельный тест ожидал готовность descriptor ограниченными unauthenticated probes и прошёл **на тех же бинарниках**. Более ранний fixture после restart Relay не учитывал инвалидизацию сеанса; теперь повторно авторизуется. Старые доказательства не заменяют итоговый run.

## Индикация и оставшаяся приёмка

Маршрут хранится в зашифрованном sidecar по подтверждённому событию: исходящий direct — проверенный peer ACK, входящий direct — PeerServer, Relay — authenticated STORE/FETCH. В технических сведениях показано «Прямое соединение Tor» либо «Через Relay». Историческим и неподтверждённым письмам маршрут не выдумывается.

Для полной приёмки нужны Windows 11 ↔ CachyOS на двух устройствах/сетях, независимые Tor directories, временное отключение Relay, обрыв direct ACK и восстановление, вложение и защищённое исчезающее письмо. Сохранять только operation counts, message IDs и публичный маршрут. Native kit и `NATIVE-ACCEPTANCE-1.5.0.md` содержат сценарии. До этого `productionReady=false`. Независимый аудит безопасности не проводился.
