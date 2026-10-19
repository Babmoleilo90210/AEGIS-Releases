# Сообщества/Вестник: Identity Gateway 6.0

Новый loopback origin `/community/v6` использует существующие OrgAdminService, ContentService, AgentService и SQLite. Root identity private key, пароли Почты и TOTP в Core не передаются. Старый `/api/v1`, CommunityMain 5 и протокол Relay не заменяются.

`CommunityClient600(onion, port, communityPublicKey, identityPublicKey, capabilityWire, appProofPrivateKey, TorTransport)` предоставляет `call(action, JsonObject)` и `close`. Production constructor использует только прежний onion-only TorTransport; тестовый Connector находится в package-private API. Клиенту нужен AEGIS ACCOUNT_READ; для глобального администрирования — дополнительно ADMIN после повторного подтверждения root/device в Почте. Для свежей capability Core создаёт новый клиент через свой SessionAuthority. UI password/OTP в Core не нужен: делегированное подтверждение выполняет Почта.

Подписываются фиксированные `CommunityWire600.operation` с target service audience, action и точными байтами argsJson. Внешний JSON содержит только action/argsJson/authorization/criticalProof/nonce. Приложение подписывает Identity requestDigest от этой операции; separate server пересчитывает digest и отправляет его с app PoP в закреплённую Identity через literal loopback. Публичный key/nickname зеркалируются только из подписанного ответа Identity и при SHA256(publicKey)==accountId. Поля клиента actor/owner/isAdmin/clearance не принимаются как авторизация.

Ответ Community подписан отдельным ключом, nonce и SHA обоих точных тел. Нет fallback к legacy root signing или clearnet. HTTP ограничен 8 MiB, рабочими потоками/очередью и deadline 30 секунд. Роль проверяется в исходном ACL при каждом действии; generation/срок/права Identity повторно проверяются перед возвратом и перед SQL commit. Внутренний кэш boolean recheck максимум 250 мс, принудительные проверки перед commit его обходят. Это ограниченная распределённая задержка отзыва, не обещание мгновенного стирания данных.

## Скоуп сервера

`TrustedContext600` создаётся только Gateway после проверенного app PoP и Identity signature. ThreadLocal устанавливается в try/finally и снимается при любых исключениях; вложенный контекст запрещён. `AccessControl` в таком запросе читает administrative status только из проверенной Identity capability. Старые global_admins и nickname не превращают нового пользователя в администратора. Без контекста AccessControl продолжает прежнее поведение 5.0.

`withServerAuthority` — внутренний Java API для Library Controller: callback создаётся из private authenticated evidence, сначала и в конце повторно проверяется. Это не HTTP/Binder/пользовательский setter роли. Контроллер Библиотеки ограничивает собственный action набор и app capability; глобальная роль пользователя не превращает LIBRARY app key в Core ADMIN capability. Закрытые политики membership/clearance/read остаются в прежнем ResourcePolicy; к E2EE Почте такой контекст отношения не имеет.

Для повторной аутентификации используются подписанный `stepUpUntil` и текущий `Identity.isStepUpActive`, а не имитация TOTP. В data `stepUp` клиент 6.0 удаляет. Перегрузка requireStepUp(actor, data) выбирает новый проверенный контекст либо полностью прежний legacy механизм.

## Два независимых подтверждения

Старый UI admin.critical.request/approve/list поддерживается без новых клиентских root keys. Клиент автоматически добавляет **второй типизированный app proof** для Identity criticalRequest/Approve/Consume. Локальный UUID связывается с Identity request nonce, kind, точным canonical payload и сроком. Второй участник должен быть другим действующим ADMIN, свежим step-up; Identity повторно проверяет обоих и потребляет permit один раз.

Перед изменением Community SQL Identity потребляет permit; scoped executeCritical повторно сравнивает UUID/kind/payload и проверяет обе текущие сессии. SQL-изменение и локальная отметка EXECUTED атомарны. **Если после Identity consume происходит сбой SQL/связи, permit не возвращается: требуется новый запрос.** Это явный безопасный режим отказа между двумя БД, а не распределённая атомарная транзакция. Подмена payload, self-approval, replay или смена generation прекращают операцию.

Identity administrators назначаются через отдельный протокол Identity; legacy admin.administrators и factor/stepup RPC запрещены. LIBRARY/agent.library RPC запрещены в Core — используются отдельные приложения. `AGENT_WORK` нельзя назначить пользовательской роли через Gateway до отдельного onboarding служебных identities; прежние worker endpoint/процесс остаются отдельными.

## Подготовка оператора

```sh
java -cp 'lib/*' org.securemail.community.gateway600.CommunityMain600 --init PRIVATE_DIR \
  --identity-public VERIFIED_IDENTITY_PUBLIC_FILE --identity-fingerprint SHA256 \
  --identity-port 19120 --port 38160
java -cp 'lib/*' org.securemail.community.gateway600.CommunityMain600 --serve PRIVATE_DIR
```

Создаются собственный service key и ключ Community audit. В свежей БД нет заранее созданных пользовательских ролей или global_admins. Владелец определяется живой Identity. Старая структура Community DB сохранена; INITIALIZED маркирует формат для отдельного Library adapter, а INITIALIZED600 — новый способ инициализации. Продакшен не меняется и старые данные автоматически не копируются.

Тест `GatewayIntegration600Test` запускает реальный HTTP Identity/Gateway, производственный клиент и SQL: Owner/пользователь, одобрение организации, публикация новостей, два администратора, наследование/назначение/отзыв ролей, смена generation, app/service binding, очистка контекста, canonical Unicode/64-bit числа и реальный operator Main. Connector использует обычный loopback как тестовый стенд: это не проверка Tor, Windows/CachyOS или production E2E.

Глобальная единственная сессия на старом endpoint 5.0 автоматически не обеспечена этим Gateway. Мигрированные аккаунты требуют отдельного managed-account gate в старых серверных endpoints; старые немигрированные клиенты сохраняют прежнюю совместимость. Полный UI разрешений allow/deny и production role bridge оцениваются отдельно по фактическим тестам.

## Наследование и явный запрет (6.0)

`admin.roles.create/update` принимает optional `deniedPermissions: string[]` (до 128 проверенных имён разрешений), список ролей возвращает explicit `deniedPermissions`. Запрет побеждает разрешения из родительских и параллельно назначенных ролей. UPDATE без поля сохраняет действующие запреты для совместимости с 5.x; пустой массив явно очищает их. Старые роли без запретов сохраняют прежнее поведение.

Снятие запрета через изменение, удаление или отзыв роли не может повысить права инициатора: сервер проверяет его исходные полномочия до изменения графа и откатывает превышение. Глобальные изменения по-прежнему требуют двух независимых действующих ADMIN. Серверный administrative override не открывает закрытые ResourcePolicy: минимальный уровень, членство, allowlist и требуемые права чтения проверяются явно, включая Owner.

Семейство `admin.roles.*` подписывает `account.read`: конкретная организация и полномочия проверяются AdminService в той же SQL-транзакции, после серверно подтверждённого step-up. Это позволяет обычному владельцу организации использовать конструктор своих ролей. Глобальные изменения дополнительно требуют действующего ADMIN и реального двухстороннего permit; перенос scope или self-escalation не даёт административного доступа.

Отрицательные назначения `role_restrictions` сохраняются после обычного выхода/удаления участника из организации: повторное вступление в OPEN не снимает запрет. Все положительные назначения при выходе удаляются и не восстанавливаются. Ограничение действует только в исходном scope (глобальный запрет сохраняет глобальную область), а не на другие организации. Явный уполномоченный `admin.roles.revoke` удаляет отрицательное назначение; удаление роли очищает его по FK. Изменение родительской роли инвалидирует epoch также для сохранённых ограничений, даже когда участник временно вышел.
