# Identity 6.0.0 — контракт реализации

`org.securemail.ecosystem.protocol.IdentityProtocol` — общий JCA Ed25519/SHA-256 двоичный кодек без зависимости от UI, SQL, Gson или Android SDK. Только фиксированные домены: регистрация, одобрение устройства, восстановление, вход, выдача capability, proof-of-possession запроса и Owner Bootstrap. Никакого API произвольного подписания чужими ключами.

`org.securemail.identity.IdentityStore`: отдельная SQLite, постоянный accountId = SHA256(X509 Ed25519 root public key); root private остаётся только в Почте. Первая регистрация подтверждается root + device; последующее устройство требует действующего доверенного устройства с повторной аутентификацией либо root + отдельного recovery key. Session generation увеличивается атомарно; новая сессия отзывает все старые capabilities. App capabilities привязаны к account/device/app/proof key/generation/service/expiry/scopes. Максимальный offline lease 24 часа, закрытые материалы не получают офлайн-разрешение по умолчанию.

Публичные Java методы: `register`, `login`, `challengeDevice`, `approveDevice`, `recoverDevice`, `issueCapability`, `authorize`, `revoke`, `stepUp`, `ownerChallenge`, `bootstrapOwner`, `profile`. DTO — вложенные типы IdentityProtocol. `IdentityHttpServer` предоставляет POST /identity/v1 с ограниченным JSON и подписанными ответами, только loopback за отдельным onion service. Никакой автоматической регистрации ключей через CommunityAuth.

Приложения: AEGIS, MAIL, GLAS, LIBRARY, STRAZH, NETWORK. Scope enum — закрытый список конкретных разрешений. Capability не разрешает расшифровывать письма либо экспортировать identity key. В клиентском IPC нужны дополнительные проверки UID/certificate/package; серверная capability их не заменяет.

`aegis-admin owner bootstrap --account-id ID --challenge FILE` выдаёт одноразовое публичное challenge для уже зарегистрированного аккаунта. Тот же вызов с `--proof FILE` принимает только подпись точного Owner Bootstrap challenge корневой account identity. Приватный ключ CLI не запрашивает/не читает. Назначение singleton атомарно и записывается в HMAC-журнал.

Интеграционный статус: новый сервер не обеспечивает отзыв старых клиентов Relay/Community до явного подключения там session gate. Полное межкомпонентное применение, Android IPC, Tor, нативная приёмка и офлайн-guard на реальных устройствах — отдельные release gates.

## Итоговые операции HTTP

Верхний объект строго `{operation,nonce,data}`. Все бинарные поля — base64url без padding. Ответ `{ok,data,serverTime}` либо `{ok:false,error:{code,message},serverTime}`; заголовок `AEGIS-Signature` подписывает `IdentityProtocol.response(audience,outerNonce,exactRequest,exactResponse)`.

| operation | Точные поля data |
| --- | --- |
| register | accountKey, deviceKey, recoveryKey, nickname, time, nonce, accountProof, deviceProof |
| login | accountId, deviceId, time, nonce, proof |
| challengeDevice | accountId, deviceKey, time, nonce, proof |
| approveDevice | accountId, deviceId, generation, challenge, proof |
| recoverDevice | accountId, challenge, accountProof, recoveryProof |
| issueCapability | accountId, deviceId, generation, appId, proofKey, capabilities, ttl, time, nonce, deviceProof, appProof |
| authorize | capability, action, body, time, nonce, proof |
| authorizeDigest | capability, action, bodySha256, time, nonce, proof |
| isActive | capability |
| profile / stepUpChallenge / revoke | capability, time, nonce, proof |
| stepUp | accountId, deviceId, generation, challenge, accountProof, deviceProof |
| firstDelegateChallenge | capability, targetAccountId, roleName, time, nonce, proof |
| firstDelegateComplete | challenge, ownerRootProof, ownerDeviceProof, targetRootProof, targetDeviceProof |
| criticalRequest | capability, operation, payload, time, nonce, proof |
| criticalApprove | capability, requestId, time, nonce, proof |
| criticalConsume | capability, requestId, operation, payload, time, nonce, proof |
| administratorAssign | capability, requestId, targetAccountId, roleName, time, nonce, proof |
| administratorRevoke / sensitiveRecoveryApprove | capability, requestId, targetAccountId, time, nonce, proof |

`profile` и `stepUpChallenge`: AEGIS ACCOUNT_READ и app PoP для action `account.read` с **пустым body**; `revoke` — SESSION_MANAGE, action `session.manage`, пустой body. Root/device `stepUp` подтверждают точный `IdentityProtocol.stepUp` из возвращённых challenge/expiry.

`authorizeDigest` — отдельный фиксированный домен APPLICATION-REQUEST-DIGEST, не совместимый с подстановкой обычной `request` подписи. Каждый сервис сам вычисляет SHA фактических байтов операции. Успешный signed context дополнительно содержит **accountPublicKey** (44B X509Ed25519 base64url) и nickname из Identity SQL; принимающий сервис проверяет SHA256(publicKey)==accountId и не назначает роли на основании nickname/значков. `isActive` не выдаёт этих сведений.

Реализовано узкое первое назначение дополнительного администратора (подробно README): один существующий target, выбранное владельцем имя роли, 120 секунд, обе exact device/generation, четыре подписи root/device двух разных аккаунтов, вечный one-use flag, атомарность и аудит. Последующие назначения/отзывы требуют двух текущих ADMIN и свежего step-up. Галочка владельца не выдаётся делегату. При восстановлении аккаунта все операции LIBRARY временно запрещены до `sensitiveRecoveryApprove` с двумя администраторами. Релизы утверждает только владелец.

Первоначальный codec использует DataOutputStream UTF/long/фиксированные bytes и сортированные scope names; точным источником формата служит `IdentityProtocol`. Существующий capability wire в процессе добавления административных helper-методов не менялся. Общий codec и OfflineLeaseGuard компилируются `--release 8`; сервер требует JDK 21.

## Relay: защищённая проверка управляемого аккаунта

`IdentityProtocol.managedAccountQuery(String audience, String serviceId, String accountId, long time, String nonce)` использует домен `AEGIS-IDENTITY-RELAY-MANAGED-ACCOUNT/v1`; `serviceId = SHA256(X509 Ed25519 serviceKey)`. `POST /identity/v1`, operation `managedAccount`, exact data `{serviceKey,accountId,time,nonce,proof}`. Ключ/подпись — canonical base64url, `accountId` hex64, время ±60 с, nonce32 одноразовый. Подпись отдельным ключом Relay проверяется по операторскому allowlist с единственным purpose `RELAY_MANAGED_QUERY`. Ответ data содержит только `{managed:boolean}`, подписан обычным `IdentityProtocol.response` с точными исходными байтами запроса. Ключи аккаунта/устройства/приложения не могут быть одновременно ключами доверенного Relay.

Локальное разрешение: `aegis-admin service relay allow --home DIR --public FILE --fingerprint SHA256`; файл содержит только base64url публичного X509 ключа. Отзыв: `aegis-admin service relay revoke --home DIR --fingerprint SHA256`. Это отдельная операторская операция, не HTTP API и не полномочие клиента.

`managed=true` означает регистрацию Identity6 с доказательством владения старым account root и новым устройством. Relay6 должен отклонить старый LOGIN и ранее выданный legacy bearer для такого аккаунта и принимать LOGIN6 с live capability+app proof. Старые не переведённые в Identity6 аккаунты сохраняют прежний протокол. Проверка перед каждой операцией; отказ Identity закрывает доступ. Реальная интеграция Relay принадлежит отдельному модулю, не объявляется завершённой только этим API. Allowlist до 64 ключей, общий HTTP лимит 6000/мин, общий бюджет проверок isActive/isStepUpActive/managedAccount 4000/мин; защищённые данные не выдаются при исчерпании бюджета. Краткий кэш ≤250 мс означает такой же ограниченный интервал распределённого отзыва.

## Owner administration

Финальный расширенный контракт: [OWNER-ADMINISTRATION-6.0.0.md](OWNER-ADMINISTRATION-6.0.0.md). Добавлены shared immutable DTO OwnerBootstrap/FirstDelegation/OwnerTransfer, строгие codec и фиксированные Mail purposes. Bootstrap completion остаётся только operator CLI; inspect не выдаёт административных полномочий. Owner transfer требует четырёх типизированных root/device proofs, свежего step-up двух участников и существующего2ADMIN critical permit; consume/Owner switch/двойной session revoke атомарны. Имена RPC/fields и proof domains приведены в документе.

## Новое устройство без capability

`deviceRecoveryInspect` и фиксированный Mail `PURPOSE_DEVICE_RECOVERY` описаны в [DEVICE-RECOVERY-6.0.0.md](DEVICE-RECOVERY-6.0.0.md). Сервер возвращает только известные challenge поля после точного new-device proof, без recovery public key/ролей/сессии. `recoverDevice` и sensitive2ADMIN ограничения не изменены. Финальные локальные результаты: Identity77/77, Mail codecs7/7, 0 skip, sharedJava8/sourceStable PASS; соответствующие evidence в test-results/6.0.0-device-recovery и6.0.0-mail-recovery.
