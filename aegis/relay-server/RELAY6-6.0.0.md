# Relay6: общая сессия АЕГИС и совместимость Почты

Режим включается только отдельным `org.securemail.relay.RelayMain600` / `bin/aegis-relay6`. Старый RelayMain, конструктор RelayServer(config,store,clock), заголовок protocolVersion=1, операции 1–15, формат mailbox и криптография писем сохраняются. Production Relay этим исходным кодом не изменён и не развёрнут.

## Установка оператором

Пример из установленного relay-server distribution; параметры относятся к тестовой конфигурации. Используйте отдельный service UID, каталог 0700, ключи/конфигурацию 0600 и проверенные абсолютные пути базы/конфигурации. Сохраните резервную копию прежней базы и конфигурации до переключения сервиса.

```sh
bin/aegis-relay6 init --home /var/lib/aegis-relay6 --config /etc/aegis/relay6.properties --identity-public /etc/aegis/identity-public.x509 --identity-fingerprint IDENTITY_SHA256 --identity-port 19120
bin/aegis-relay6 inspect --home /var/lib/aegis-relay6
```

Init создаёт отдельный Ed25519 service key, `service-public.x509` и `service-public.txt` (base64url X509). Он не читает ключи аккаунтов или release-signing key. Закреплённый Identity fingerprint проверяется до записи ключа. Повторный init и символические пути отклоняются; незавершённый init требует явного операторского разбора, замена рабочего ключа автоматически не выполняется.

На Identity оператор отдельно разрешает **только публичный** ключ Relay и сверяет его SHA-256 независимым способом:

```sh
aegis-admin service relay allow --home /var/lib/aegis-identity --public /var/lib/aegis-relay6/service-public.txt --fingerprint RELAY_SERVICE_SHA256
bin/aegis-relay6 serve --home /var/lib/aegis-relay6
```

Allowlist имеет единственное назначение `RELAY_MANAGED_QUERY`. Relay может получить подписанный `{managed:boolean}` о конкретном accountId; это не публичный API каталога аккаунтов. Identity и Relay используют разные private keys и разные базы. Соединение между службами — literal 127.0.0.1 с Ed25519 pin, nonce и SHA точного запроса/ответа; redirect/DNS/proxy исключены. Полный HTTP deadline — 6 секунд, заголовки/тело/параллелизм ограничены, duplicate length/chunked/content encoding отклоняются.

## LOGIN6 и REGISTER6

Поле `Binary.text` = int длины UTF8 + байты; `Binary.bytes` = int длины + байты. Общий заголовок и прежние поля не изменены.

| Операция | Поля после header, byte operation, text пустого token |
|---|---|
| LOGIN6 = 16 | nickname, passwordBytes, capabilityWire, long time, nonce, appSignatureBytes |
| REGISTER6 = 17 | nickname, passwordBytes, accountPublicKey44, capabilityWire, long time, nonce, appSignatureBytes |

Nickname нормализуется прежним Limits.nickname. Password по-прежнему проверяет Relay через прежний Argon2id; в каноническом proof подписывается только SHA-256 пароля. Приватный root не передаётся Core или Relay.

LOGIN6 canonical: `MailSessionProtocol600.login(SHA256(RelayServicePublicKey),accountId,nickname,passwordBytes)`; домен `AEGIS-MAIL-LOGIN/v1`. Proof: `IdentityProtocol.requestDigest(cap,"mail.read",SHA256(canonical),time,nonce)`, подпись отдельным Mail app key. REGISTER6 использует `registration(...,accountPublicKey44)`, отдельный `AEGIS-MAIL-REGISTER/v1` и действие `mail.send`. Для регистрации требуются MAIL_READ и MAIL_SEND. Root public key должен совпасть с подписанным Identity accountPublicKey и accountId.

Ответ LOGIN6 совпадает со старым LOGIN: header, status int, при 0 — token64hex, UserInfo. REGISTER6 отвечает как прежний REGISTER: header, status, UserInfo; затем клиент выполняет LOGIN6. Все nonce в Identity одноразовые; изменение nickname/password hash/Relay audience/app/account/device/generation исключает повторное применение proof. Подпись OpenPGP браузера и release Ed25519 к этому механизму не относятся.

`IdentityRelayCredentials600` сохраняет конструктор `(relayPublicKey,identityPublicKey,capabilityWire,appPrivateKey)`; добавлен `writeRegistrationProof`. Когда NetworkService настроен этим объектом, автоматического отката к LOGIN/REGISTER нет.

## Проверка каждой операции и передачи

Сессия Relay хранит capability binding. До обработки каждого запроса выполняется live Identity isActive (или положительная monotonic cache максимум 250 мс, отсчитанная от начала RPC). Длительный RPC не продлевает кэш. Недоступность Identity, неправильная подпись, отзыв устройства, generation или capability закрывают доступ; офлайн-разрешения для Relay нет. STORE/PROFILE_PUT/CONTACT_PUT требуют MAIL_SEND, CONTACT_GET — CONTACTS_READ, остальные mailbox операции — MAIL_READ. Свежая проверка повторяется после входного большого packet, после Argon2 регистрации и перед SQL commit регистрации/STORE.

FETCH проверяется до ответа и на каждом блоке не больше 64 KiB. При отзыве передача закрывается без подстановки второго протокольного ответа в ciphertext. Кэш, уже отправленные байты и буферы ОС означают ограниченный интервал отзыва, а не мгновенное удаление данных. FETCH не удаляет mailbox; удаление требует прежнего подписанного ACK.

Published onion route привязан к capability и проверяется заново перед FIND. В Mail6 свежий FIND выполняется перед новым исходящим P2P; старый подписанный route из локального кэша не служит обходом проверки отправляющей сессии.

## Миграция и границы

После регистрации accountId в Identity6 его старые LOGIN и ранее выданные legacy bearer отклоняются. Такой аккаунт должен использовать LOGIN6; пароль/identity/accountId не меняются. Не зарегистрированные в Identity6 аккаунты 5.x сохраняют операции прежнего протокола и обмен письмами с 6.x. Не выдавайте эту совместимость за поддержку нового Identity6-входа старыми бинарниками.

Старые клиенты и уже запущенные старые P2P listeners с ранее полученным route невозможно удалённо превратить в новый протокол. Уже сохранённые/расшифрованные данные, старые root keys и открытые потоки не стираются изменением server generation. Этот gate подтверждает серверную сессию Relay6 и новый исходящий путь Mail6; полное принудительное применение ко всем старым direct P2P endpoint требует отдельной приёмки. Нативный Tor, Windows/CachyOS и два физических устройства должны быть проверены отдельно. `productionReady=false` до всех обязательных release gates.

## Воспроизведение проверок

`relay-server/tools/test-relay600.py` компилирует настоящие Identity/Relay/NetworkService/LocalStore зависимости и запускает TCP/SOCKS/HTTP тесты. SOCKS harness направляет синтетические onion-имена только в loopback fixture: это не Tor-приёмка. Отдельный процесс компилирует Relay только с production dependency set и выполняет неизменённый IsolationTest: client crypto, BouncyCastle и Tink в этом runtime отсутствуют. Реальные логи, source SHA и JUnit XML сохраняются в test-results; sourceStable проверяется до/после прогона.
