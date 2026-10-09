# Relay 0.3.0: только staging

Production 0.2.0 не обновлён. Wire protocol 1 и операции 1–10 сохраняются.

Добавлены authenticated optional операции CAPABILITIES (11), PROFILE_PUT (12), PROFILE_GET (13), CONTACT_PUT (14), CONTACT_GET (15). Поля public profile подписаны identity владельца; запись запрещена от другого аккаунта, при неверной подписи, меньшей ревизии и конфликте одинаковой ревизии. CONTACT_GET показывает только пару согласий с текущим авторизованным пользователем.

Миграция SQLite аддитивна и транзакционна: public_profiles, contact_assertions, schema_migrations. users/mailbox/receipts и account hashing не переименовываются и не переписываются. Старый Relay игнорирует новые таблицы при rollback; полный backup БД перед staging upgrade обязателен.

В staging сначала использовать отдельную БД и onion, не production identity. Инсталлятор/upgrade из пакета требует явного действия администратора; в этой разработке он на VPS не запускался. Не выполнять full-upgrade, изменения GRUB, DNS или открытие порта 19110. Права `/etc/aegis` root:aegis-relay 750 и config 640 сохраняются, API только 127.0.0.1. Existing onion-service private key не выводится и не заменяется.

Публичные данные — явно разрешённые nickname, «О себе» и нормализованный аватар. Relay видит их и граф подписанных согласий; сообщения и attachment payload остаются ciphertext, private identity/message passwords ему не передаются. При старом Relay capabilities=0, клиент сохраняет базовую почту и отключает public sync/friends.
