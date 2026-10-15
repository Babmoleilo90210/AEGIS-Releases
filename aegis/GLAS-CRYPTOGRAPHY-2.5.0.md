# Глас 2.5.0 — криптографическая спецификация до реализации

База: `f173b4a1`, ветка `development/aegis-2.5.0`. Этот документ составлен до добавления классов голосового TLS-транспорта. Владелец архитектуры подтвердил схему: существующая Ed25519 identity подписывает привязку временного TLS-сертификата; медиаканал использует стандартный JSSE TLS 1.3.

## 1. Результат аудита существующих ключей

`client-core/.../crypto/Identity.java` хранит Ed25519 пару JCA: публичный ключ в X.509 SubjectPublicKeyInfo DER, секретный в PKCS#8. Уже существуют `sign(byte[])`, `verify(...)` и `userId = SHA-256(publicKey DER)`. Это **не** долгосрочная X25519 identity. `SodiumBox` преобразует Ed25519 в X25519 только для существующего sealed-box wrapping ключей писем.

Глас не меняет identity, не вызывает эти преобразования для аудио, не использует пароль аккаунта, letter password, FF1, recovery key или release-signing key. Долгосрочный identity private key служит только подписи публичного объявления временного сертификата; JSSE его не получает.

## 2. Стандартный медиаканал

- Только TLS 1.3 JSSE из Java 21, с взаимным предъявлением сертификатов.
- Разрешены AEAD-наборы `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, если они поддерживаются runtime. TLS 1.2, anonymous/null suites и plaintext fallback запрещены.
- ALPN: ровно `aegis-glas/1`. Несогласованный протокол завершает соединение.
- Ключи обмена и traffic secrets, AEAD nonce, sequence number, проверка целостности TLS records и KeyUpdate реализует JSSE по RFC 8446. Приложение не реализует DH, HKDF, AEAD, nonce derivation или собственный AKE.
- TLS-контекст создаётся заново для каждой попытки вызова. `Pending` допускает только одну попытку handshake. Контекст и временный ключ не используются в другом вызове, с другим контактом или для reconnect. Нет 0-RTT, внешних PSK и повторного использования resumption sessions между вызовами.
- Perfect forward secrecy обеспечивается новым TLS 1.3 ephemeral (EC)DHE, а не долгосрочным identity key. После завершения ссылки на временные ключи освобождаются; гарантированное обнуление всех внутренних копий ключей JVM/JSSE не заявляется.

`VoiceTls` принимает уже подключённый `Socket`. Он не создаёт TCP-соединения, не разрешает имена, не слушает внешние адреса и не имеет direct fallback. Caller/controller обязан создать onion-соединение через существующий Tor SOCKS и предъявить известную identity контакта. Сам по себе TLS поверх переданного сокета не является доказательством Tor-only.

## 3. Временный сертификат и identity binding

На каждую попытку генерируются новая Ed25519 пара для TLS и короткоживущий self-signed X.509v3 сертификат. Сертификат строится стандартными ASN.1 X.509 структурами существующего Bouncy Castle `bcprov:1.86`, подпись создаётся JCA Ed25519. Новая криптографическая зависимость не нужна. Параметры алгоритма Ed25519 в AlgorithmIdentifier отсутствуют согласно RFC 8410. Subject не содержит nickname, секретов или идентификаторов сессий.

Локальная существующая `Identity.sign` подписывает `Offer` с отдельным доменом `AEGIS/GLAS/CERT-BINDING/v1`. Каноническая бинарная запись включает:

1. Версию и фиксированный ALPN.
2. Случайный 128-битный `callId` UUID и роль `CALLER`/`CALLEE`.
3. Упорядоченные `callerId` и `calleeId`, вычисленные из известных публичных identity ключей обеих сторон.
4. Время создания и expiry объявления; допустимое окно — 120 секунд, небольшой clock skew ограничен.
5. Публичный Ed25519 identity ключ отправителя, полный DER временного сертификата и SHA-256 сертификата, связанный с ним канонической записью.

Подпись — Ed25519, 64 байта. DER identity key должен иметь точный поддерживаемый Ed25519 формат. Сертификат и объявление ограничены по длине; Java serialization, произвольные URL, пути, классы или команды отсутствуют.

Получатель сначала находит контакт по непривилегированному публичному идентификатору, затем проверяет подпись **уже известным ключом контакта**, ожидаемого адресата, роли, `callId`, версию и срок. Самопредъявленный ключ не создаёт доверия. Неизвестный контакт не получает звонок на экран и доступ к микрофону. Подписанные объявления могут идти открыто внутри Tor до TLS; они не содержат аудио. Поиск контакта, ограничение частоты и защита от ringing spam находятся в controller.

После проверки объявлений каждый TrustManager принимает ровно один сертификат, байт-в-байт совпадающий с DER из подписанного объявления противоположной стороны. Он дополнительно проверяет validity, Ed25519, self signature, digitalSignature usage и отсутствие CA-привилегий. Общесистемный CA store и hostname/PKIX fallback не применяются. TLS CertificateVerify доказывает владение временным private key, соответствующим объявленному сертификату.

Перед передачей управления аудиопротоколу внутри установленного TLS стороны обмениваются фиксированным хэшем контекста обоих упорядоченных объявлений. Несовпадение роли, идентичностей, call ID или certificate pair прекращает канал. Это подтверждение контекста приложения поверх TLS; оно не создаёт новые медиаключи и не заменяет стандартный TLS handshake.

Связывание обоих адресатов и ролей обязательно: одной подписи над чужим fingerprint недостаточно для защиты от identity misbinding/unknown-key-share. Схема использует принцип аутентифицированной привязки сертификата к идентичности, описанный для RTC в RFC 8827; Глас не заявляет совместимость с WebRTC/DTLS-SRTP.

## 4. Replay, reconnect и frames

Перехваченные TLS records нельзя перенести в другую новую TLS-сессию: ключи, transcript и sequence numbers различны. Повтор signed Offer сам по себе не доказывает владение временным TLS private key. Controller дополнительно хранит ограниченный TTL-кэш принятых call IDs/объявлений, предотвращает повторный ringing и разрешает reconnect только для существующего согласованного вызова. Reconnect создаёт новую `Pending`, новый сертификат и новый TLS-контекст; старый поток не переиспользуется.

Приложение не принимает аудио до взаимной аутентификации и явного ответа пользователя. Форматы `RING`, `ACCEPT`, `AUDIO`, `HANGUP`, codec negotiation, максимальные frame lengths и счётчики находятся в отдельном ограниченном voice wire протоколе. TLS record bound не заменяет пределы длины и количества сообщений приложения. Голосовые frames не сохраняются на диск автоматически.

## 5. Rekey и длительность

JSSE выполняет стандартный TLS 1.3 KeyUpdate по собственным лимитам `jdk.tls.keyLimits` (Oracle документирует default 2^37 байт для AES/GCM и ChaCha20-Poly1305). Библиотека не меняет глобальные security properties приложения.

Для явного обновления предусмотрен `VoiceTls.requestKeyUpdate(SSLSocket)`: только на уже согласованном TLS 1.3 в поддерживаемом SunJSSE. В поставляемом OpenJDK 21 вызов `SSLSocket.startHandshake()` на таком соединении запускает стандартный post-handshake KeyUpdate; это проверено по исходникам поставляемого JDK (`SSLSocketImpl`, `TransportContext`, `PostHandshakeContext`, `SSLHandshake`). Свой key-update packet не создаётся.

Controller должен запрашивать KeyUpdate по своему лимиту длительности/объёма, а на 60-минутной границе выполнить новую попытку с новым временным сертификатом и полным TLS handshake либо завершить вызов, если обновление не состоялось. Одно успешное согласование не доказывает выполнение этого lifecycle-требования в UI/controller.

## 6. Код для ручной проверки

`shortCode(Offer caller, Offer callee)` — короткое представление SHA-256 контекста проверенной пары сертификатов, ordered identities и callId. Обе стороны получают одинаковое значение после успешного TLS context confirmation. Это код проверки certificate pair, **не** TLS exporter, не пароль и не дополнительный ключ шифрования. Полные fingerprint контактов остаются основным способом проверки identity. JSSE Java 21 не предоставляет используемый здесь публичный exporter API; его наличие не выдумывается.

## 7. Согласованный API

Пакет `org.securemail.client.voice`, класс `VoiceTls`:

```java
Pending create(Identity local, UUID callId, Role localRole, byte[] expectedPeerPublicKey);
Offer Pending.offer();
void Offer.write(DataOutput output);
Offer read(DataInput input);
void Offer.verify(byte[] expectedRemoteKey, byte[] expectedLocalKey,
                  UUID expectedCallId, Role expectedRemoteRole, long nowMillis);
SSLSocket Pending.handshake(Socket connected, Offer remote,
                            byte[] expectedRemoteKey, boolean clientMode);
void requestKeyUpdate(SSLSocket socket);
String shortCode(Offer caller, Offer callee);
```

`Pending` закрывается после неиспользованной попытки/сбоя; живой возвращённый `SSLSocket` принадлежит controller. Роли фиксированы: TLS client = CALLER, TLS server = CALLEE. Получение сокета из браузера Safe Web не предусмотрено. Секретный identity key и аудиоключи не возвращаются API.

## 8. План доказательных испытаний

При составлении спецификации до реализации все пункты имели статус `NOT_RUN`. Ниже — программа испытаний настоящих TLS-соединений между отдельными сокетами:

- Многокадровый duplex, TLS 1.3, ALPN и взаимные ожидаемые сертификаты.
- Reject: неверная contact identity, подмена сертификата/подписи, роль, другой callId, адресат, истёкший/future Offer, oversized поля и unsupported version.
- Новый временный ключ/сертификат у другой попытки; повтор `Pending` запрещён.
- Невозможность вывести plaintext media при handshake failure, удалённый TLS 1.2 и неправильный ALPN.
- Реальная передача после стандартного KeyUpdate.
- Проверка одинакового кода обоими участниками и изменения при смене callId/сертификата.

Loopback TLS-тесты доказывают криптографическую интеграцию JSSE. Они не считаются Tor P2P, тестом DNS/IP утечек, нативным аудиотестом или испытанием Windows/CachyOS.

### Выполнено после реализации

`VoiceTls.java` и `VoiceTlsTest.java` скомпилированы Java 21 без новых зависимостей. **17/17 JUnit-тестов прошли**, ошибок и пропусков нет. Отчёт: `docs/test-results/2.5.0-voice-tls/TEST-junit-jupiter.xml`.

Выполнены реальные взаимные TLS 1.3 handshakes через loopback, duplex application records, post-handshake KeyUpdate в обе стороны, точные certificate pins и ALPN. Отдельный настоящий TCP relay после handshake изменил байт шифротекста: JSSE отверг повреждённую запись; известный маркер аудио отсутствовал в захваченных сетевых байтах. Отрицательные проверки охватывают подмену известной identity, другого адресата, call ID/роль, подпись/сертификат, TTL/будущее время, oversized/truncated/unsupported/trailing wire data, повтор `Pending`, другую фактически предъявленную TLS certificate, TLS 1.2 и неправильный ALPN.

Это проверка библиотечной интеграции с JSSE на Linux в доступной среде. Она не означает выполнения приёмки Tor/onion, Relay, реальных микрофонов/динамиков, Windows 11 или CachyOS KDE. Этим сценариям сохраняется `NOT_RUN` до собственных реальных испытаний. Лимиты frames, replay cache и периодический lifecycle/reconnect проверяются отдельно в voice controller/media tests.

## Первичные источники

- RFC 8446, TLS 1.3, разделы 4.4, 4.6.3, 5, 7 и 8: <https://datatracker.ietf.org/doc/html/rfc8446>.
- Oracle Java 21 JSSE Reference Guide, custom trust/key managers, ALPN и key limits: <https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html>.
- Oracle `SSLSocket`: <https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/net/ssl/SSLSocket.html>.
- RFC 8410, Ed25519 X.509 AlgorithmIdentifier: <https://www.rfc-editor.org/rfc/rfc8410.html>.
- RFC 8827, fingerprint identity binding и ограничения signalling: <https://www.rfc-editor.org/rfc/rfc8827.html>.
- Bouncy Castle Java 1.86, официальные ASN.1/X.509 API: <https://www.bouncycastle.org/download/bouncy-castle-java/>.
