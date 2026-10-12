# АЕГИС 1.2.0 — отдельное предложение Friends / receipts / исчезающие письма

**Требуется отдельное архитектурное утверждение владельца.** Это reviewable ТЗ, не изменение production Relay. Никакие новые серверные операции пока не включены. Протокол основного заголовка остаётся 1; legacy REGISTER/LOGIN/FIND/STORE/FETCH/ACK не меняются.

## Почему клиентского изменения недостаточно

Production Relay 0.2.0 не поддерживает существующий CONTACT_PUT/GET путь. Локальные списки A и B неизвестны другой стороне, поэтому текущая реализация не может автоматически заявлять взаимную дружбу. В исходниках уже существует staging pair assertions модель, пригодная для повторного использования.

При offline доставке ACK получателя проверяется сервером и уничтожает ciphertext, но подпись/time не сохраняются для отправителя. Таблица receipts — replay tombstones, не read notifications. Создать «Прочитано» из исчезновения очереди нельзя.

Legacy пакет допускает TTL максимум 7 суток и привязывает expiry к доставке. Таймер до 30 суток после отображения требует отдельного capability-negotiated пути. Старые клиенты/старые письма сохраняют прежний путь и правила.

## Альтернатива без расширения Relay

Транспорт protocol 1 передаёт opaque ciphertext, поэтому в принципе можно добавить клиентские signed in-band события в E2EE payload обычного STORE. Это не запрещено математически и не требует передачи полного списка контактов. В текущей базе такого пути нет: PlainMessage.decode допускает только версии 1/3/4/5, без внутреннего control типа; старый клиент покажет текстовый control JSON как письмо либо отвергнет новый payload. Capability получателя на Relay 0.2.0 неизвестна; управляемые 30-дневные сроки конфликтуют с LocalStore received+legacyTTL. Потребуются отдельно спроектированные handshake, durable outbox, защита от event/mail recursion и negotiation до передачи новому клиенту.

В текущем решении выбрано минимальное Relay capability/event расширение для review: оно позволяет отличать control данные, выдавать исходный ACK отправителю и не показывать старым клиентам служебные письма. Клиентское in-band решение — возможная альтернативная архитектура, а не уже реализованная функция; при выборе владельцем его следует отдельно проверять на старых клиентах и offline очередях. Нельзя обосновывать статус Friends только наличием локального контакта.

## Минимальное совместимое расширение

1. Capability negotiation: оставить биты profiles/friends, добавить отдельные lifecycle/expiring возможности и информацию о возможности клиента-получателя. Не дописывать поля в старый FIND ответ, который заканчивается Binary.end; использовать новые операции.
2. Friends: подписанные ContactAssertion для конкретной пары, active/revision/owner/target, replay floor. Сервер получает только направленные заявления о добавленной/удалённой паре, а не полный список контактов. Отзыв/block снимают статус; письма не удаляются. Старый Relay — честное состояние unsupported/pending.
3. Durable lifecycle события: уникальный eventId, messageId, packetDigest, senderId/recipientId, вид DELIVERED или DISPLAYED, deviceId если выбран multi-device, timestamp/revision и Ed25519 подпись origin identity. Подпись проверяется получателем события по закреплённому ключу контакта. DISPLAYED означает только показ клиентом, не факт человеческого прочтения.
4. ACK хранит исходное подписанное подтверждение и адресованную отправителю event запись. Новые событие put/fetch/ack операции разрешены только участникам письма и их аутентифицированной сессии. Событие удаляется после durable acceptance отправителем; повторная выдача безопасна. P2P использует тот же eventId/digest и пересылает события через Relay при офлайн-отправителе.
5. Для expiring новый distinct packet/lifecycle envelope, явно отделённый от legacy delivery TTL. Не изменять старый PacketCodec или max TTL глобально. Capability-gated новый STORE/FETCH/DELIVER путь, bounds/quotas/replay/выбор политики подписаны; E2EE остаётся существующим стандартным алгоритмом. Recipient старой версии не получает такой пакет.
6. Содержимое/вложения, letter password и FF1 остаются только внутри E2EE payload. Event outbox/history/lifecycle state клиента — внутри защищённого локального состояния существующим vault AEAD; отдельная версия sidecar, backup, rekey и rollback обязательны. Не создавать plaintext staging.

## Метаданные Relay

Новые минимальные данные: связанная пара participant IDs, message/event ID, digest, event kind, подпись, delivery/display time, policy duration, capability/version, device/lease ID при выборе этого режима. Эти поля раскрывают граф взаимодействий и техническое событие отображения. Message body, имя/содержимое файла и секреты не передаются. TTL/квоты событий ограничены конфигурацией, глобального admin read/export API нет.

## Требующее решения владельца исчезновение и устройства

**Вариант A — один активный получатель исчезающего письма (рекомендуемый первый шаг).** Capability содержит receiver lease/device. Обычные письма продолжают работать на старых клиентах. На активном устройстве первый успешный показ сохраняет один signed DISPLAYED event и deadline; sender offline не задерживает timer. Monotonic elapsed + durable high-water защищают работающий процесс; при подозрении на откат часов/повреждение/старый backup после перезапуска expiring content закрывается до безопасного восстановления. Второе устройство не может открыть тот же expiring пакет без согласованного переноса lease. Lease не меняет существующие identity keys.

**Вариант B — несколько получателей с согласованным lease/read state.** Перед первым открытием нужна онлайн-координация, что ограничивает offline opening. Недоступный/скомпрометированный Relay может препятствовать доступу, но не читает ciphertext. Без этой координации нельзя обещать общий deadline на разъединённых устройствах. Локальные неподконтрольные копии, экспорт/скриншоты остаются вне гарантий.

Для обоих вариантов исчезновение удаляет только управляемое expiring content/attachment cache, оставляет защищённый tombstone «Письмо исчезло» без plaintext, не переделывает старые письма. При отключённых ordinary read receipts перед открытием expiring требуется in-window согласие на обязательный DISPLAYED event либо отказ от открытия.

## Миграция SQLite и staging

Сначала отдельный staging Relay, копия схемы без production пользовательских данных. Новые таблицы consent/events/capabilities/lifecycle с SQL schema version и transaction; existing users/mailbox/receipts и onion identity сохраняются. Повторная migration идемпотентна, есть ciphertext/SQLite online-backup и rollback на предыдущий бинарник/совместимую схему. Никаких запросов на live VPS.

Проверки: old client 1.1.5 ↔ new Relay обычная почта; new client ↔ old Relay обычная почта/unsupported lifecycle; два реальных staging аккаунта mutual/offline/revoke/block; durable event before ACK, forged signature, wrong party/digest, replay/duplicate/order/time regression; first display only after protected letter password+ручной FF1 и явное отображение результата (см. ограничение отсутствия oracle ниже); ordinary receipts off; expiring mandatory consent; 1мин/30д bounds, старые письма без новых таймеров, offline sender, restart/crash/corrupt sidecar/backup restore/attachments purge/tombstone; multi-device lease conflict; Windows/CachyOS updater snapshot/rekey/rollback.

## Что необходимо утвердить

- Само минимальное расширение Relay и раскрываемые метаданные (только staging разработка, не production deployment).
- Вариант A либо B и fail-closed поведение при невозможности доказать elapsed time после offline restart/backup rollback.
- Версионированное локальное lifecycle состояние с existing AEAD, без изменения identity keys и шифров старых писем.

До этого FEAT-15/16 и подтверждённый Friends на старом production Relay не считаются реализованными. Независимые клиентские bug fixes не требуют этого решения.

## FF1: согласование события прочтения

Существующий LetterEnvelope.VERSION=3 прямо запрещает проверку корректности второго кода: candidate всегда вычисляется и может быть plaintext или hex. Не считаем initial ciphertext/каждый live-keystroke прочтением. Рекомендуемое совместимое решение — после ввода секрета отдельное действие «Показать результат» и подписанное событие DISPLAYED только после отображения конечного candidate; статус не доказывает правильность FF1 и человеческое чтение. Это сохраняет криптографию/старые письма. Если требуется именно криптографическое доказательство правильного FF1, понадобится отдельно утверждённый новый защищённый envelope, который меняет нынешнее отсутствие correctness oracle; молча это не добавляется.
