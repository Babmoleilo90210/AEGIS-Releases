# Проверка маршрута писем АЕГИС 1.5.0

Фактическая архитектура 1.2: каждый online клиент создаёт ephemeral Tor onion через SAFECOOKIE ADD_ONION. Java PeerServer слушает127.0.0.1; virtual onionport81. Rootidentity подписывает Route с короткой lease90с; Relay FIND/PUBLISH использует routing/account metadata. NetworkService DELIVER передаёт E2EE packet через mail-only Tor SOCKS непосредственно peeronion; peer подписывает ACK с packetdigest. STORE — ciphertext fallback на Relay. Использование Tor само по себе не доказательство P2P.

Найдено две клиентские зависимости от Relay: unconditional FIND перед DELIVER и закрытие PeerServer/Control при ошибке PUBLISH. Исправления сохраняют короткий root-signed route cache/expiry/key pin и не закрывают живой peer при directory outage. Новых serveroperations/onion identity/ports/publicIP не добавлено. Дольше текущей lease без Relay доступность маршрута не гарантируется.

Доказано автоматическим реальным TCP/SOCKS-framing тестом DeliveryTest.cachedRootSignedRouteWorksAfterRelayStopsWithoutPayloadOrDuplicate: отдельные LocalStore/identity/PeerServer, Relay listener остановлен, два отправления samepacket получают signed P2P_ACK, mailbox ровно1, Relaypacketcount0, после координации не увеличились relayBytes. Это **локальный synthetic SOCKS**, не реальный Tor. Базовый тест проверяет lostACK/fallback/TTLdedup и отсутствиеplaintext Relay.

LifecycleTorProbe дополнен actual bundled Tor staging: two client-core instances, три ephemeral onionservices, signed capabilities, direct mail/read, Relaystoppeddirectprotectedletter/FF1/read/dedup, attachment/expiringdirect, offlinecipherfallback/ACK/reappear. Только disposable accounts/database; stdout содержит технические события, ciphertext/privatekeys/body не сохраняются в evidence. Итог actualTor статуса приводится в TEST-REPORT/evidence после запуска. Один Torprocess/одна Linuxhost не доказывают передачу между двумя пользовательскими устройствами.

| Сценарий | Фактически доступное доказательство | Native owner |
|---|---|---|
| P2P-01 | signed DELIVER/ACK, local framing; actualTor staging result отдельно | NOT_RUN |
| P2P-02 | Relay listener stopped, no Relaybytes, signed cache+ACK; actualTor отдельно | NOT_RUN |
| P2P-03/04 | ciphertext STORE→FETCH→durable ACK и dedup вintegration | NOT_RUN |
| P2P-05/06 | разная physicalnetwork/OS недоступна в текущем worker | NOT_RUN |
| P2P-07/08 | attachment/E2EE/manualprotection tests; actualTor scripted | NOT_RUN |
| P2P-09/10 | signed receipt/display event+expiry integration, actualelapsedexpiry отдельно | NOT_RUN |

Route evidence сохраняется AEAD sidecar и показывается в технических сведениях письма. Неизвестный/historical route не выдумывается. Для отправленного directletter подтверждение — проверенный peerACK; для входящего — принятие PeerServer; для Relay — authenticated STORE/FETCH. Relay при P2P участвует в координации/PUBLISH/FIND и может видеть metadata, но успешный directpacket не STORE. Control receipts тоже E2EE, могутfallbackRelay. Не независимый security audit.
