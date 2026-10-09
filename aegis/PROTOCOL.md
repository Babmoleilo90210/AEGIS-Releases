# Wire protocol v1

Протокол двоичный, big-endian, поверх одного TCP-соединения на запрос через Tor SOCKS5. HTTP, JSON, Java native serialization и динамические имена классов не используются. Endpoint обязан быть onion v3; Java не делает его DNS resolution. Tor обеспечивает аутентификацию onion endpoint и транспортное шифрование; дополнительного TLS на loopback нет.

## Примитивы

- `int`: 4 знаковых байта, `long`: 8; длины всегда проверяются **до** выделения массива.
- `bytes`: int length + ровно length байт; отрицательные и чрезмерные длины отвергаются.
- `text`: такой же length + UTF-8; некорректный UTF-8 отвергается.
- `boolean`: 0 или 1 при записи; считывается Java DataInput.
- Заголовок: int magic `0x534d3031`, int version `1`. Другие версии не принимаются.
- Обязательная полная передача каждого поля. EOF/timeout не является успешным запросом или ACK.

## Запрос и ответ

Запрос: header, unsigned byte operation, text sessionToken (до 64 байт), затем поля операции. Для REGISTER/LOGIN/DELIVER token пуст. Ответ: header, int status (0 успешно, 1 отказ), затем результат. При отказе нет отражения входных данных или stack trace.

| Код | Операция | Поля запроса после token | Успешный ответ |
|---:|---|---|---|
| 1 | REGISTER | nickname ≤32; password bytes ≤4096; Ed25519 public DER 44 | UserInfo |
| 2 | LOGIN | nickname; password bytes | session token 64 hex + UserInfo |
| 3 | FIND | exact nickname | UserInfo, возможный Route |
| 4 | PUBLISH | Route | Пусто |
| 5 | STORE | EncryptedPacket | Пусто; принято в очередь или уже известно |
| 6 | FETCH | Нет | boolean exists; один EncryptedPacket при true |
| 7 | ACK | Receipt | Пусто; атомарное удаление ciphertext |
| 8 | LOGOUT | Нет | Пусто; session и route удалены |
| 9 | DELIVER | EncryptedPacket | Receipt; только P2P endpoint |
| 10 | DELETE | messageId | Пусто; удаление пакета только из собственной очереди |

Сервер удаляет копию после **ACK**, истечения delivery TTL либо явного DELETE от авторизованного получателя. DELETE сохраняет минимальный receipt до delivery deadline, чтобы повторный STORE не восстановил удалённое письмо. Чужую очередь DELETE не изменяет и её наличие не раскрывает. Это транспортная операция клиентского API `deletePending(messageId)`; кнопки массового удаления очереди в GUI нет. Административного API чтения/экспорта переписки нет.

Служебные команды cleanup/stats/health/version выполняются локальным CLI. Они не являются wire-операциями. Максимум 3 пользователя по умолчанию; регистрация закрыта до явного включения. Только разрешённые ники. Пароль аккаунта проходит Argon2id, его bytes не сохраняются. Токен 256 бит случайности существует в RAM клиента; relay хранит SHA-256 токена и срок сессии. LOGIN заменяет предыдущую сессию этого аккаунта.

## EncryptedPacket

Точный порядок записи:

1. Header (magic/version).
2. text messageId (36; канонический UUID).
3. text senderId (64 hex SHA-256 публичного ключа).
4. text senderNickname (3–32 ASCII, нижний регистр).
5. text recipientId (64 hex).
6. long createdAt (Unix milliseconds).
7. long deliveryDeadline (Unix milliseconds).
8. long ttlAfterDelivery (секунды, 1…604800).
9. int algorithm: 1 AES-GCM, 2 XChaCha, 3 ChaCha, 4 Camellia-GCM, 5 Enigma.
10. bytes salt (ровно 16, либо 0 для Enigma).
11. bytes senderPublicKey (ровно 44 байта, X.509 DER Ed25519).
12. bytes nonce (12/24/12/12/0 соответственно).
13. bytes ciphertext (AEAD ciphertext || 16-byte authentication tag; Enigma — ASCII).
14. bytes signature (ровно 64 байта Ed25519).

Пункты 1–11 — AEAD AAD. Подпись: Ed25519(SHA-256(канонические пункты 1–13)). Ключ сообщения **не имеет поля** в пакете. В wire v1 параметры Argon2id фиксированы, а не передаются от атакующего.

Время создания должно быть не более чем на 5 минут в будущем. Signed deliveryDeadline позже создания, максимум через 7 суток. Relay ограничивает хранение своим maxMessageAge и signed deadline. Новая упаковка старого письма с прежним messageId и другим digest отвергается.

По умолчанию максимум ciphertext = `maxFileSize + 128 KiB`; жёсткий предел файла 100 МиБ. В 128 КиБ входят ограниченный текст, имя, структура и AEAD tag; этот запас не делает разрешённым файл больше настроенного лимита при локальном расшифровании. Sender/client enforcement определяет лимит исходного файла, receiver независимо проверяет decoded длину. Relay не может проверить внутренний формат файла без расшифровки.

## Зашифрованный внутренний payload

Для современных алгоритмов: int contentVersion=1, bytes UTF-8 text (≤65536), text filename (≤800 UTF-8 байт и ≤200 Java символов), bytes file (≤maxFileSize). Пустое имя означает отсутствие вложения. Разрешены конечные расширения `.txt`, `.zip`, `.7z`, `.tar`, `.tar.gz`; пути, разделители и управляющие символы запрещены. Ничего автоматически не распаковывается.

Enigma обрабатывает только строку A–Z/пробелы напрямую, без вложения. Сигнатура подтверждает автора ciphertext, но не подтверждает правильность введённого исторического ключа.

## ACK / Receipt

text messageId; bytes packetDigest (32, SHA-256 unsigned packet); long firstDeliveredAt; bytes signature (64). Подпись покрывает length-prefixed ASCII domain `secure-mail/ack/v1`, messageId, digest и firstDeliveredAt.

ACK создаётся только после durable local write. Сервер сопоставляет authenticated recipientId и проверяет его Ed25519 signature и digest. DELETE и запись квитанции происходят в одной транзакции. Повторный ACK принят идемпотентно. Повторный STORE идентичного пакета после ACK не воскрешает сообщение до истечения signed deadline.

Если P2P ACK потерян, отправитель использует relay с тем же packet/ID; получатель возвращает прежнее firstDeliveredAt. Новое самостоятельное нажатие отправки после ошибки создаёт новое письмо: без постоянного outbox невозможно узнать исход неизвестной доставки. При неоднозначной ошибке проверьте получение у собеседника перед повторной отправкой.

## UserInfo / Route

UserInfo: text userId; text nickname; bytes publicKey; boolean hasRoute; Route при наличии.

Route: text userId; text onionAddress (62 ASCII символа); int virtualPort; long expiresAt; bytes signature. Подписывается domain `secure-mail/route/v1`, ID, onion, порт и expiry. Relay принимает срок до 120 секунд вперёд; клиент публикует 90 секунд. UI не требует ручного onion-адреса собеседника.

Изменение ключа в каталоге никогда не обновляет контакт автоматически. При первом контакте нужен независимый fingerprint check.

## Ограничения обслуживания

12 попыток регистрации/входа в минуту глобально, 8 за 15 минут на разрешённый ник. Счётчики ограничены allowlist, не растут от произвольных ников. Они обнуляются при перезапуске relay — это локальная защита, не гарантия против DoS. Обработка большого пакета сериализована. Сокеты имеют inactivity timeout 30 секунд и общий deadline 5 минут; ответ должен быть полностью прочитан перед признанием успеха.

## Совместимое расширение содержимого 0.2.0

Magic/version/operation codes, EncryptedPacket, UserInfo, signatures, ACK и пределы protocol 1 не менялись. Сервер 0.1.0 может переносить 0.2.0 E2EE, потому что не интерпретирует ciphertext.

Обычный E2EE-пакет использует внешний algorithm AES_256_GCM. Salt16 начинается ASCII `AEGIS02A`; следующие 8 bytes случайны. В этом режиме salt не является Argon2-солью. Ciphertext field: int 0x4145324b, 80-byte libsodium sealed AES key для recipient, 80-byte sealed AES key для sender, затем AES-GCM ciphertext с tag16. Nonce12 и AAD берутся из существующего envelope. Ed25519 signature связывает весь контейнер. Расшифровка обычного чата требует клиента 0.2.0; клиент 0.1.0 это содержимое не понимает.

Ответы по-прежнему начинаются прежним header и int status. 0 — success, 1 — generic rejection. Новые необязательные причины: 2 registration closed, 3 nickname not allowed, 4 nickname occupied, 5 user capacity, 6 incorrect credentials, 7 rate limit. Старый клиент уже отклоняет любой nonzero status и не читает дополнительного payload, поэтому это обратно совместимо. Клиент 0.2 поддерживает generic status1 старого сервера без попытки угадать точную причину.

Новой операции для receipt отправителю нет. Offline ACK удаляет relay-копию и не доставляет отправителю подтверждение; GUI этого не выдумывает. DELETE удаляет собственную очередь получателя; «Удалить у меня» в чате удаляет локальную копию и не обещает remote delete.


## Клиентское содержимое v3 (0.3.0)

Внутри неизменённого E2EE-converter AE2K: int32(3), UTF-8 subject (<=1024 bytes), bytes LetterEnvelope (<=65792), UTF-8 filename, bytes file. Content v1 продолжает читаться. Это не wire protocol upgrade: relay и common-protocol не изменены. Старый клиент 0.2 не понимает content v3. Новый слой тела описан в CRYPTO-0.3.0.md; файл защищён только существующим E2EE.

## Клиентское содержимое 1.0.0 (wire всё ещё protocol 1)

Opaque E2EE plaintext content v4: int32=4; UTF8 subject (bounded1024 bytes); length-prefixed AES/FF1 letter envelope (<=LetterEnvelope.MAX_BYTES); int32 attachment count0..64; для каждого UTF8 basename<=800 bytes и length-prefixed file bytes. Сумма file bytes<=client maxFileSize. Указанные overhead не меняют Limits.PAYLOAD_OVERHEAD. Имена уникальны без учёта регистра и проверяются на traversal, absolute paths, Windows devices/ADS.

Versions1/3 читаются прежним decoder layout; новые письма v4 требуют клиента1.0. Relay не анализирует content. AUTH/REGISTER, crypto packet, подписи, ACK/TTL, outer wire header и common-protocol не менялись. ZIP формируется только локально после приёма, в протокол не включён.

## Backward-compatible extension 1.1.0 / optional Relay 0.3.0

Wire VERSION остаётся 1. Операции 1–10 и layout существующих пакетов не изменены.

| ID | Операция | Назначение |
|---|---|---|
| 11 | CAPABILITIES | Authenticated битовая маска: 1 profiles, 2 signed contact assertions |
| 12 | PROFILE_PUT | Только собственный подписанный Ed25519 профиль; monotonic revision |
| 13 | PROFILE_GET | Точный nickname; signed public profile либо отсутствие |
| 14 | CONTACT_PUT | Собственное подписанное согласие owner/target/active/revision |
| 15 | CONTACT_GET | Только пара requester/target, две подписанные стороны |

Old Relay unsupported operation → capabilities 0, базовая авторизация/почта продолжают работать. Профиль не заменяет pinned identity. Скрытый профиль публикует подписанный tombstone без about/avatar. Relay видит публичные данные, но никогда letter plaintext или message keys.

Внутри E2EE payload legacy content 1/3/4 продолжает читаться. Content 5 добавляет subject/text, необязательный manual letter envelope, несколько файлов и encrypted MailContext (thread/parent/digest/original card). Расширенный контент адресуется получателю с проверенным подписанным профилем 1.1; обычные одиночные письма сохраняют legacy формат. Клиент 1.0 не читает content 5; ограничения downgrade той же identity описаны в MIGRATION-1.0-TO-1.1.md.
