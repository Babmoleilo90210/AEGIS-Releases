# Приватность

Нет телеметрии, аналитики, рекламы, trackers, облачных crash reports, hidden commands или backdoors. Все возможные сетевые направления перечислены в README.md.

Фоновая проверка и загрузка обновлений — явно включённая настройка, отключаемая пользователем; выполняется только через собственный Tor к allowlisted GitHub hosts. GitHub получает GET публичных release ресурсов, Tor exit и User-Agent AEGIS, без ника, писем, vault, паролей или приватных ключей. Release public key встроен, а не скачивается. Установка требует действия пользователя либо выбранного им режима «при закрытии».

Relay видит аккаунты, публичные ключи, маршруты onion, время, размеры и внешние поля пакетов; sender содержится в подписанном packet, отдельная колонка не добавлена. Имя и содержимое файла находятся внутри E2EE. Существующая AUTH protocol1 передаёт account password relay через Tor для server Argon2id; производные vault keys, letter passwords и приватные identity keys не передаются.

Локально сохраняются encrypted identity/contacts/messages/avatars, конфигурация, UI presets, Tor state, публичные signed update records и технические журналы. OS storage получает только случайный device key. Resume envelope защищён этим ключом и не содержит account password. Ключ/пароль письма и FF1 не запоминаются.

Plaintext отображается только в RAM; аватар decoder не создаёт disk image cache. Backup и encrypted ZIP экспорт требуют действия пользователя. Экспортированные файлы, clipboard, screenshots, системные backup/swap и чужие программы находятся вне TTL приложения.

Tor stdout/stderr не сохраняется; connection.log ограничен и содержит allowlist событий, без cookie, bridge payload, passwords или содержимого письма. Diagnostics показывает адрес своего relay и версии. Private key владельца release не запрашивается, не копируется и не входит в проект.

Tor/Lyrebird создают необходимые внешние соединения, Snowflake использует broker/CDN/STUN/WebRTC и системный resolver. ISP может видеть Tor/обходной транспорт, сильный противник может сопоставлять traffic. VPN не требуется и не даёт абсолютной анонимности.
