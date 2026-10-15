# Криптография 0.2.0

## Обычный чат

PlainMessage v1 содержит UTF-8 text, filename, file bytes. Ключ AES-256 (32 байта) генерируется SecureRandom на сообщение; nonce GCM — 12 случайных байт. AAD — существующий PacketCodec.associatedData, tag — 128 бит. Стандартный libsodium `crypto_box_seal` упаковывает AES-ключ для получателя и отправителя. Sealed boxes используют X25519, XSalsa20-Poly1305 и стандартную схему nonce libsodium. Полный внешний пакет подписан Ed25519.

Для совместимости с identity 0.1 используется стандартное `crypto_sign_ed25519_pk_to_curve25519` / `sk_to_curve25519` libsodium. Схему выбрали потому, что существующий protocol 1 хранит один Ed25519 public key и не поддерживает публикацию отдельного encryption key. Приватный ключ никогда не покидает client-core. Это расширение содержимого ciphertext, не новый relay protocol.

JNA — только FFI к поставленной libsodium по абсолютному пути `native/libsodium.{dll,so}`. В сети JNA/libsodium ничего не отправляют. Самостоятельно реализованных шифров для современной защиты нет. Долговременный ключ используется повторно; forward secrecy/ratchet отсутствуют.

## Ручной шифратор и письма 0.1

Сохранены AES-256-GCM (JCA), XChaCha20-Poly1305 (Tink), ChaCha20-Poly1305 (JCA), Camellia-256-GCM (Bouncy Castle) и исторический Enigma. Для четырёх современных вариантов пароль → Argon2id v19 (64 MiB, t=3, p=1, 32 bytes), random salt16 и nonce соответствующей длины. Enigma не считается конфиденциальной защитой; рядом отображается предупреждение.

Ручной encrypted packet копируется как `AEGIS-MANUAL:<base64>` и может передаваться внутри обычного E2EE. Пароль шифратора не отправляется автоматически.

## Vault и backup

Формат state.vault v1 не менялся. Argon2id-параметры те же, ciphertext AES-GCM, random salt16/nonce12. AAD state/v1 отделяет state от mail/v1 и sent/v1. Backup — magic AEB1 + salt + уже зашифрованный state.vault; нового master/recovery key нет.

Публичные сведения: https://doc.libsodium.org/public-key_cryptography/sealed_boxes и https://doc.libsodium.org/advanced/ed25519-curve25519 . Для новых независимых протоколов обычно предпочтительны отдельные signing/encryption keys; здесь сохранение существующей identity — осознанное ограничение совместимости.
