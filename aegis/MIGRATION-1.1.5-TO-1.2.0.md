# Переход 1.1.5 → 1.2.0 (клиентский кандидат)

Не удаляйте профиль и не создавайте новые identity keys. Сохраняются ciphertext письма/вложения, contacts, сессии ОС, Tor state, themes/presets/layouts, update preferences/floors/cache/events.

При старте до Tor/новых sidecars создаётся полный ProfileSnapshot и marker upgrade-1.2.0-backup-location. Повторный старт проверяет прежний snapshot вместо копирования заново. При отсутствии существующего vault новый аккаунт не получает фиктивную миграцию. Формат vault/старых писем и сроки legacy TTL не меняются; старым письмам не присваиваются новые read статусы.

Отдельный updater backup выполняется при закрытом клиенте/Tor перед заменой бинарников; rollback восстанавливает прежние бинарники и совместимый ciphertext/settings snapshot. Snapshot identity-only недостаточен. Используйте тестовую копию профиля для updater/rollback приёмки. Открытые черновики базы 1.1.5 находятся только в памяти, установка с ними запрещена прежним guard; это ограничение не скрывается миграцией.

Новые lifecycle события/after-read expiry пока не активированы: необходимо отдельно согласовать архитектуру из RELAY-LIFECYCLE-PROPOSAL-1.2.0.md. Физический rollback Windows11/CachyOS NOT_RUN до приёмки.

## Lifecycle sidecars

Новый зашифрованный каталог data/lifecycle хранит events/outbox/device key и отдельные disappearing ciphertext. Account identity и старый vault формат сохранены. Полный backup профиля включает эти sidecars; identity-only backup их не заменяет. Device expiry ledger лежит рядом с каталогом приложения, вне rollback snapshots, и не откатывается к старой копии. На другом устройстве/при потере ledger уже открытые disappearing письма недоступны; ordinary mail остаётся доступна. Reboot ОС консервативно закрывает открытое disappearing письмо раньше срока. Это описано в LIFECYCLE-1.2.0.md.
