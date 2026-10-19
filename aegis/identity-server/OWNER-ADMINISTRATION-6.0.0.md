# Владелец: первоначальное назначение, делегирование, передача и восстановление

Это дополнение к контракту Identity 6.0.0. Оно реализует фиксированные Ed25519 операции существующего протокола; новые шифры, пользовательские identity или release keys не создаются. Root private key находится только в Почте. Core подписывает своим отдельным device key. Сервер хранит public keys и проверяет точные доказательства. Операторский CLI не принимает приватные ключи пользователя.

## Первоначальный владелец

Оператор на сервере создаёт challenge только существующему аккаунту:

```sh
aegis-admin owner bootstrap --home /var/lib/aegis-identity \
  --account-id ACCOUNT_ID --challenge /private-transfer/bootstrap.json
```

В JSON сохраняются прежние `audience`, `accountId`, `challenge`, `expiresAt`, `proofBytes` и дополнительный `bootstrap` с теми же каноническими байтами. `IdentityProtocol.decodeOwnerBootstrap(...)` возвращает immutable DTO. Его `ownerBootstrapBytes(...)` точно совпадает с прежним wire форматом. Сам по себе public code не назначает владельца.

Пользователь вводит public code в Core и открывает отдельное подтверждение Почты `PURPOSE_OWNER_BOOTSTRAP`. Mail использует действующий AEGIS `ACCOUNT_READ` capability и app proof для `ownerBootstrapInspect`, проверяет подписанный pinned Identity ответ и точное равенство DTO. После свежей аутентификации локальной identity, сверки своего account ID, срока и fingerprint оператора пользователь явно подтверждает назначение. Подписывается только `ownerBootstrapBytes`; произвольного payload-to-sign API нет.

Core получает только публичный результат и формирует файл строго такого вида:

```json
{"audience":"SERVICE_SHA256","accountId":"ACCOUNT_SHA256","challenge":"NONCE43","signature":"BASE64URL_ROOT_SIGNATURE"}
```

Оператор выполняет:

```sh
aegis-admin owner bootstrap --home /var/lib/aegis-identity \
  --account-id ACCOUNT_ID --proof /private-transfer/bootstrap-proof.json
```

Назначение атомарно, singleton/one-use проверяются в SQLite, событие входит в HMAC audit. Кандидат с незавершённым sensitive recovery не допускается. `ownerBootstrapComplete` HTTP RPC отсутствует. Повторное назначение, reset/force/nickname обхода нет. После изменения роли старый capability с прежним authority snapshot становится недействителен; требуется новый вход/выдача capability.

## Первый независимый администратор

Первое назначение является явно ограниченной начальной процедурой, поскольку двух уже действующих администраторов ещё нет. Требуются два разных существующих аккаунта и четыре root/device доказательства. Владелец со свежим ADMIN создаёт `firstDelegateChallenge`, указывает точное имя роли. В challenge входят service audience, оба account/device/generation, имя роли, nonce и срок 120 секунд. Вечный `first_delegate_used` не сбрасывается при отзыве всех делегатов.

`IdentityProtocol.FirstDelegation`/`decodeFirstDelegation` представляют прежние `firstDelegateConsent` bytes без изменения wire. Фиксированное подтверждение Почты — `PURPOSE_FIRST_DELEGATE`, роли `OWNER_APPROVE`/`DELEGATE_ACCEPT`. До unlock Mail вызывает `firstDelegateInspect`, проверяет подпись сервиса, канонические поля и свою сторону. После свежего unlock и явного согласия Mail выдаёт root proof только для `firstDelegationBytes`. Device proofs создаются отдельно в соответствующих Core. В результате передаются только четыре публичных подписи, а не private keys.

`firstDelegateComplete` повторно проверяет текущие сессии, оригинальный Owner ADMIN, срок, четыре подписи, отсутствие прежнего делегата и one-use flag. Назначается выбранная именованная роль ADMIN, а не Owner badge. Повторная начальная процедура запрещена даже после удаления всех делегатов. Следующие назначения и отзывы требуют обычного `criticalRequest`/`criticalApprove`/`administratorAssign`/`administratorRevoke` с двумя текущими независимыми ADMIN.

Операторский резервный маршрут также использует только публичные файлы:

```sh
aegis-admin owner first-delegate --home /var/lib/aegis-identity \
  --request /private-transfer/delegate-request.json \
  --challenge /private-transfer/delegate-challenge.json
aegis-admin owner first-delegate --home /var/lib/aegis-identity \
  --proof /private-transfer/delegate-proofs.json
```

Первый request имеет ту же схему, что RPC `firstDelegateChallenge`; файл proofs — ту же, что `firstDelegateComplete`. CLI не заменяет Mail consent и не позволяет подпись чужим ключом.

## Передача владельца

`OwnerTransfer` фиксирует audience/challenge, старый и новый account/device/generation, текущий `authorityEpoch`, expiresAt ≤120 секунд. Протокол:

1. Текущий Owner с ADMIN и свежим step-up создаёт `ownerTransferChallenge` для другого существующего активного аккаунта. Одновременно разрешён один действующий challenge; expired/used записи удаляются, storage ограничен.
2. Обе стороны проходят свежий root/device step-up. Почта каждой стороны через `PURPOSE_OWNER_TRANSFER` подписывает свой отдельный `ownerTransferConsent(t, OWNER_APPROVE)` или `(..., SUCCESSOR_ACCEPT)`. Core device proof подписывает тот же фиксированный consent своей стороны. Перестановка ролей, account/device/generation или байтов запрещена.
3. Старый Owner создаёт обычный critical request с `operation=owner.transfer`, `payload=ownerTransferBytes(t)`. Другой текущий ADMIN подтверждает его. Новый владелец может быть обычным User; если он не ADMIN, подтверждение обеспечивает третий уполномоченный аккаунт.
4. `ownerTransferComplete` в одной `BEGIN IMMEDIATE` транзакции проверяет четыре подписи, обе свежие сессии, sensitive flags, неизменность authority epoch, оригинальный Owner capability и действующий двухсторонний critical permit. Consume permit, one-use challenge, смена singleton Owner, отзыв обоих поколений/tokens/step-up и HMAC audit коммитятся вместе.

После успеха старый владелец становится User. Его Identity delegated admin row удаляется, persistent `former_owner_user` блокирует неявное возвращение администрирования через внешний trusted/legacy callback. Новому владельцу также убирается дублирующая Identity delegated row. Позднее явное назначение старому владельцу новой именованной роли допускается только через обычное одобренное двумя ADMIN действие. Остальные администраторы и организационные membership/roles не удаляются. Корневые public/private keys обоих аккаунтов остаются прежними. Обе стороны обязаны заново войти.

Epoch увеличивается при Owner Bootstrap, первом делегате, назначении/отзыве Identity administrator и передаче владения. Изменение полномочий во время подтверждения делает старый transfer непригодным. Неудачные доказательства не расходуют approved permit, поскольку проверка/consume входят в одну SQL транзакцию. Гонки двух подключений дают только один успешный commit.

Резервный операторский маршрут:

```sh
aegis-admin owner transfer --home /var/lib/aegis-identity \
  --request /private-transfer/transfer-request.json \
  --challenge /private-transfer/transfer-challenge.json
aegis-admin owner transfer --home /var/lib/aegis-identity \
  --proof /private-transfer/transfer-proofs.json
```

Форматы файлов совпадают с `ownerTransferChallenge`/`ownerTransferComplete`. Request/proof уже должны содержать действующие app proofs; CLI не генерирует их и не получает app/root private key пользователя.

## RPC и критический permit

Каждый RPC — существующий подписанный `/identity/v1` envelope с outer nonce и точным request hash. Данные:

| RPC | data |
|---|---|
| ownerBootstrapInspect | capability, challenge, time, nonce, proof |
| firstDelegateInspect | capability, challenge, time, nonce, proof |
| ownerTransferChallenge | capability, targetAccountId, time, nonce, proof |
| ownerTransferInspect | capability, challenge, time, nonce, proof |
| ownerTransferComplete | capability, challenge, requestId, ownerRootProof, ownerDeviceProof, targetRootProof, targetDeviceProof, time, nonce, proof |

Inspect proof: `requestDigest(cap, "account.read", SHA256(ownerBootstrapInspection/firstDelegationInspection/ownerTransferInspection(audience,challenge,time,nonce)),time,nonce)`. Inspect применяется только к exact активному участнику; nonce одноразовый. Mail не повторяет его после unlock. Перед подписью повторно проверяется signed `isActive`, собственная identity и срок; итоговая серверная операция повторно проверяет все изменяемые ограничения. Изменение epoch во время unlock приводит к отказу completion, а не расширению полномочий.

Ответы inspect: Bootstrap — `{bootstrap,challenge,expiresAt,accountId,audience}`; FirstDelegate — `{delegation,challenge,expiresAt}`; Transfer — `{transfer,challenge,expiresAt,ownerAccountId,targetAccountId,authorityEpoch}`. `bootstrap/delegation/transfer` содержат канонический base64url binary DTO. Они не содержат ключей сессий.

`criticalRequest` возвращает `{requestId,operation,payloadSha256,expiresAt}`. Запрос подписывает `criticalApproval(audience,initiator,operation,requestNonce,payload,time+300000)` внутри обычного ADMIN requestDigest. Approve/consume используют выданные `requestId` и `expiresAt` вместо начального nonce/time. Для передачи exact payload — только `ownerTransferBytes(t)`. SHA-256 или имя пользователя без полного совпадения server payload недостаточны.

## Восстановление владельца

Владелец использует ту же подтверждённую процедуру `recoverDevice`: прежний account root + отдельный зарегистрированный recovery key подтверждают новое устройство. Старые устройства/сессии отзываются, sensitive recovery flag блокирует ADMIN и все Library операции. Для снятия ограничения требуется `sensitiveRecoveryApprove` с двумя другими текущими ADMIN над точным account ID. Владелец с pending recovery сам не входит в этот quorum.

Для устойчивости следует заранее создать как минимум двух независимых дополнительных администраторов через обычную одобренную процедуру. Если quorum или корневое/recovery подтверждение потеряны, административное восстановление BLOCKED. Скрытого повторного Bootstrap, принудительного перевыпуска identity, reset флага, привилегированного nickname или обхода двух подтверждений нет. Полная копия/откат серверного диска требует внешнего доверенного audit checkpoint; локальный HMAC не доказывает защиту от полного rollback всей машины.

Локальные JCA/SQLite/HTTP/CLI и codecs тесты не заменяют packaged/native/Tor/physical приёмку. Production, release-signing key и Stable feed этим изменением не затрагиваются.

Фактические локальные результаты: 69/69 Identity тестов, 0 skip, shared codec `--release 8` PASS, sourceStable=true; дополнительные Mail administration codecs — 5/5, 0 skip, sourceStable=true. Доказательства: `test-results/6.0.0-owner-administration` и `test-results/6.0.0-mail-administration`. Эти числа не включают независимые UI/общие тесты других модулей.
