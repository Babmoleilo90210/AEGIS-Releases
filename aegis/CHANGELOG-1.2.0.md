# АЕГИС 1.2.0 — Stability, Reliability & Message Lifecycle candidate

productionReady=false до Windows 11/CachyOS приёмки и полного owner-signed updater/restart/rollback. Stable не публиковался.

- Friends для двух новых клиентов через подписанные E2EE assertions без обновления Relay 0.2.0. Ожидание при отсутствии подтверждения, устойчивый отзыв, приоритет блокировки; переписка сохраняется.
- Четыре достоверных статуса: отправлено, принято Relay, доставлено на устройство, отображено получателем («Прочитано»). Encrypted retry queues, packet digest/root-signature binding, deduplication и application ACK.
- Read receipts обычных писем можно выключить. Дополнительная защита требует ручных letter password/FF1 и явного показа результата; disappearing требует согласия на receipt.
- Исчезающие письма на одно проверенное устройство: 1 минута–30 дней, timer после отображения, отсутствующий plaintext preview, удаление ciphertext/вложений и tombstone. Перезапуск приложения сохраняет timer; reboot ОС/неопределённый guard закрывает уже открытое письмо раньше срока (documented fail-closed restriction).
- Встроенная Tor bootstrap/Direct/Snowflake карточка, самостоятельная Relay-проверка, защита повторного запуска и close/reconnect race.
- Адаптивные отступы/максимизация с сохранённым пользовательским scale, всеми прежними темами и макетами.
- Пять распространяемых локальных семейств с кириллицей: Noto Sans, Inter, Roboto, PT Sans, DejaVu Sans; проверяемые TTF/glyph coverage, preview/apply/cancel.
- Крупный профильный аватар и встроенный zoom/Escape; чужой аватар не изменяется.
- Updater helper без JavaFX/видимого пустого Stage; проверка Ed25519/SHA-256, полное резервирование и безопасный shutdown сохранены. Нативная KDE ошибка пока отдельно подтверждается владельцем.
- Исправлено массовое удаление обычной почты при переводе часов назад: сохранена верхняя отметка, сроки не продлеваются.
- Полный backup до первого запуска новой версии; encrypted lifecycle sidecars и device key сохраняются, profile rollback не откатывает expiry guard.

Protocol 1, account identity keys, основные криптоалгоритмы, FF1, legacy TTL, production Relay/onion и pinned release public key сохранены. Новых SaaS/telemetry/clearnet fallback нет. Новые peer connections ограничены подписанным onion port 81 через прежний Tor transport. LIFECYCLE-1.2.0.md описывает формат и ограничения.

Автоматические, actual Tor staging и нативные результаты разделены в отчёте. Windows Server/Ubuntu/headless не заменяют Windows 11/CachyOS. Постоянные encrypted drafts отсутствовали в базе 1.1.5; текущий draft сохраняется в памяти при изменениях UI и блокирует установку обновления, пока не завершён.
