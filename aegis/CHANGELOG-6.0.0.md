# АЕГИС 6.0.0 — «Экосистема»

Кандидат для проверки владельцем. Фактическая готовность, sourceCommit и тестовые результаты указаны в итоговом комплекте; имя6.0.0 само по себе не присваивает Stable.

- Core/Почта/Глас/Взор/Библиотека разделены по ключам и жизненному циклу.
- Добавлены Identity, узкие app/device capabilities, атомарное поколение, отзыв, доверенные устройства и восстановление.
- Восстановлены Owner Bootstrap, первая независимая делегация, передача владельца и реальные двухадминистраторские операции с проверкой сохранённого permit и независимого кворума.
- Подключены Community, News, уведомления, защищённый Library connector и отдельный служебный News Worker6.
- В настольную Почту встроены потоковые зашифрованные вложения до500МиБ, resume/квоты/TTL и прежний password/FF1.
- Созданы четыре Android приложения с разными UID, Binder-проверками, Tor, native media, TUN TCP/DNS forwarding, APK analysis и подтверждаемой установкой.
- Исправлены Android logout/late login/microphone/cleanup races, очистка Core PasswordField и поздних UI callbacks, приватные пути Взора, runtime installation leases и Core-only Windows rollback.
- Android libsodium1.0.22 source archive обновлён по подлинной официальной minisign подписи после изменения stable archive; изменение и точные новые pins документированы. Настольный криптографический формат сохранён.

Ограничения включают незавершённый полный Android desktop-parity набор, отдельные native/VPN/Doze/Tor/двухустройственные испытания и подтверждение владельца. Полный перечень — release gates и отчёты. Production Relay/feed/ключи владельца не изменены.
