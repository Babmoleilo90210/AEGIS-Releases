# Восстановление на новом устройстве без действующего capability

Новый Core ещё не имеет account/device capability. Для проверки задания он доказывает владение только своим новым отдельным device key. Это не даёт прав читать аккаунт или автоматически регистрировать устройство.

`IdentityProtocol.DeviceRecovery(audience,accountId,newDevicePublic,challenge,expiresAt)` — immutable публичный DTO. `newDevicePublic()` возвращает копию. `deviceRecoveryBytes(dto)` точно совпадает с существующим `IdentityProtocol.recovery(audience,accountId,challenge,newDevicePublic,expiresAt)`; формат root/recovery proof не изменён. `decodeDeviceRecovery` проверяет domain, размеры, canonical encoding и отсутствие лишних байтов.

После существующего `challengeDevice` Core подписывает своим **новым device key** только `deviceRecoveryInspection(dto,time,nonce)`. В фиксированный domain входят service audience, account ID, challenge, полный new device public key, expiry, время и nonce. Запрос `deviceRecoveryInspect`:

```json
{"recovery":"BASE64URL_CANONICAL_DEVICE_RECOVERY","time":123,"nonce":"NONCE43","proof":"BASE64URL_NEW_DEVICE_SIGNATURE"}
```

Это data обычного подписанного Identity HTTP envelope. Сервер проверяет свежесть времени, подпись новым ключом, точное совпадение с живым неиспользованным DEVICE challenge, account/key/expiry/service binding и одноразовый nonce. Ответ содержит **только уже известные поля задания**: `recovery`, `accountId`, `challenge`, `expiresAt`, `audience`, `deviceKey`. Зарегистрированные account/recovery public keys, роль, статус восстановления, сессия и generation не раскрываются. Подпись сервиса связана с exact request/outer nonce и проверяется закреплённым публичным ключом.

Mail использует отдельный `PURPOSE_DEVICE_RECOVERY`. `MailPairing600.DeviceRecoveryRequest` содержит DTO/time/nonce/deviceProof и проверяет new-device proof; capability отсутствует. До unlock Mail получает и проверяет signed `deviceRecoveryInspect`, сравнивает точные канонические байты, сервис, account, новый ключ и срок. После явного согласия пользователь разблокирует прежнюю Mail identity либо восстанавливает её из защищённой backup в отдельную приватную проверочную копию. Корневой ключ должен удовлетворять `SHA256(X509 public)==accountId`.

Отдельный существующий recovery key загружается из Mail sidecar либо импортируется из `.aer6` только внутри Mail. `.aer6` зашифрован и аутентифицирован с expectedAccount AAD. Во время восстановления нельзя создавать новый recovery key через `loadOrCreate`: он не будет соответствовать зарегистрированному ключу. Корневой и recovery ключи различны. Mail после свежей аутентификации подписывает `deviceRecoveryBytes` обоими ключами и возвращает Core только DTO, два public key и два фиксированных proof. Это публичный `DeviceRecoveryResult`; приватные ключи и пароли не передаются Core.

`MailPairingBroker600.beginDeviceRecovery(dto,time,nonce,deviceProof)` проверяет exact DTO, audience/expiry и обе подписи результата. Зарегистрированный recovery public key намеренно не раскрывается неизвестному устройству. Поэтому ошибочный или устаревший `.aer6` может пройти локальную проверку целостности, но будет отклонён существующим серверным `recoverDevice`, который проверяет обе подписи против **зарегистрированных** ключей до изменения данных.

Окончательный запрос остался прежним: `{accountId,challenge,accountProof,recoveryProof}`. Только его успех доверяет новому устройству, отзывает прежние устройства/tokens/generation и устанавливает `sensitiveRecoveryPending=true`. После нового входа ADMIN и все Library операции остаются запрещены до настоящего двухстороннего `sensitiveRecoveryApprove`; восстановленный Owner не может сам составлять quorum. Потеря recovery key/quorum блокирует соответствующий маршрут. Force/reset, повторный Bootstrap и скрытый обход отсутствуют.

Локальные испытания используют настоящий JCA Ed25519, SQLite, две конкурентные SQL связи и подписанный loopback HTTP: публичность ответа, отсутствие auto-enrollment, replay, изменённые account/service/key/expiry, неправильный ключ, несовместимый signature domain, expiry/clock rollback, consumed challenge, ошибочный recovery файл и последующее правильное восстановление. Они не заменяют нативный запуск Mail/Core, Tor, защищённое системное хранилище или испытания на физических устройствах.
