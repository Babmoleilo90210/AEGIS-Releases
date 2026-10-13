# АЕГИС 1.2.0 — принятое client-only решение

После поручения владельца искать обходной путь реализован E2EE lifecycle transport через существующий protocol 1. Production Relay 0.2.0 не обновляется. Подробный формат, metadata и ограничения — LIFECYCLE-1.2.0.md.

- Relay получает прежние зашифрованные пакеты/ACK; новые операции серверу не нужны.
- Signed peer capabilities проверяются через onion virtual port 81; virtual port 80 остаётся доступен. Клиенты 1.1.5 продолжают обычную почту.
- Friends и receipt events — локально подписанные E2EE события на пару пользователей, не полный contact list.
- Disappearing body привязан к одному device key; timer и durable guard отдельны от legacy delivery TTL.
- Открытые disappearing письма fail closed после reboot ОС/утраты достоверного guard. Это явно описанное ограничение доступности, требующее нативной приёмки.

Никаких production server schema migrations, новых server metadata tables, onion-key replacements или deployment команд этот пакет не выполняет. Первоначальный вариант server receipt/capability extension не используется. При необходимости строгих deadline через reboot/мульти-device semantics потребуется отдельное архитектурное согласование; текущий клиент не обещает невозможного.
