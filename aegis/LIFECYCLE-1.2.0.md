# АЕГИС 1.2.0 — клиентская lifecycle-архитектура

Реализован путь без обновления production Relay. Protocol 1, существующая E2EE и account identity остаются прежними. Никаких дополнительных SaaS нет.

## Возможности и транспорт

Новый клиент публикует существующий подписанный Route с onion virtual port 81. Tor одновременно направляет virtual ports 80 и 81 в один ограниченный localhost PeerServer. Старые клиенты могут отправлять обычные письма на этот Route. На новом клиентском endpoint имеется только дополнительный read-only capability probe (код 100), с 32-байтным challenge и Ed25519-подписью существующего account key. Этот код не добавляется Relay и не открывает прямой IP-порт.

Capability содержит account public key, отдельный локальный device public key, срок и feature flags. Device private key создаётся локально и сохраняется только в AES-GCM encrypted lifecycle sidecar существующего vault. Account key не заменяется. Приватные ключи и message plaintext не передаются Relay или Tor. Новый режим включается только после проверки подписи и возможностей собеседника. После первой успешной проверки cached capability позволяет offline-доставку в пределах срока; без неё отображается ожидание совместимого клиента.

CONSENT, DELIVERED, DISPLAYED и application ACK передаются внутри прежнего AutomaticEncryption/PlainMessage version 1. Это не административные команды и не системные письма updater. Relay хранит обычный ciphertext. Семантический event ID, участники, digest конкретного пакета, timestamp и подпись проверяются. Durable encrypted retry queue сохраняется до application ACK; повторная передача использует прежний packet/message ID, а после delivery deadline создаёт новый внешний ciphertext для того же idempotent event. Технический relay ACK по-прежнему выдаётся только после сохранения ciphertext и состояния.

## Friends

Для каждой пары используются уже существующие подписанные ContactAssertion. Полный список контактов серверу не отправляется. Взаимная дружба требует проверенного локального контакта, двух актуальных подписанных active assertions и отсутствия блокировки. Одностороннее добавление означает ожидание. Отзыв после удаления контакта сохраняет информацию, необходимую для доставки signed revoke; переписка не удаляется. Блокировка имеет приоритет. Существующий серверный путь Relay 0.3 остаётся для совместимых старых клиентов, но для двух новых клиентов он не требуется.

## Четыре статуса

«Отправлено» — encrypted пакет сохранён в локальной retry queue перед сетевой попыткой. «Принято Relay» — успешный ответ STORE. «Доставлено на устройство» — проверенный P2P Receipt или signed DELIVERED, сформированный после durable приёма. «Прочитано» — signed DISPLAYED после отображения body JavaFX. Открытие списка, ввод letter password и ввод FF1 не создают read event. Для защищённого письма есть явное «Показать результат»: FF1 не получает нового correctness oracle. Статус не доказывает, что человек прочёл текст.

Обычные read receipts можно отключить. Для исчезающего письма требуется отдельное согласие перед открытием, если настройка выключена. События сохраняются encrypted и повторяются после восстановления сети. Старым письмам не добавляются вымышленные статусы задним числом.

## Исчезающие письма

Срок: 1 минута–30 дней; готовые 5 минут, 1 час, 1 день, 7/30 дней. Настоящее содержимое и вложения шифруются существующей E2EE для одного account-signed device key. Затем inner ciphertext помещается в прежний version-1 carrier, зашифрованный для account key. Старый получатель видит инструкцию и ciphertext, но его account key не открывает inner body. Inner/outer signatures и участники проверяются. Не меняются crypto algorithms, FF1, letter password или protocol version.

Новый encrypted mailbox sidecar сохраняет эти письма отдельно от legacy delivery-TTL mail. Список не расшифровывает inner body и не создаёт plaintext snippet. После фактического показа стартует durable timer; DISPLAYED доставляется отправителю даже если он был офлайн. Countdown uses OS boot elapsed time including suspend plus a persisted high-water value. Linux: boot_id и /proc/uptime. Windows: local WMI LastBootUpTime (bounded query) и GetTickCount64. Сетевая синхронизация часов отсутствует.

**Консервативное ограничение:** после reboot ОС или при недостоверном/утраченном ledger уже открытое исчезающее письмо становится недоступным раньше выбранного срока. Это fail-closed, а не доказательство точного elapsed времени через reboot. Перезапуск самого АЕГИС в пределах одного boot сохраняет отсчёт. Нативное поведение Windows 11/KDE ещё требует приёмки. Непрочитанные письма не получают таймер от простого просмотра списка или открытия password/FF1 формы. Graceful закрытие такой формы сохраняет unread состояние. Прерванный/неоднозначный reveal (например, закрытие между подготовкой body и render-подтверждением) fail closed для данного disappearing письма, без вымышленного read receipt. Письмо адресовано одному устройству; перенос полного vault на другое устройство не отменяет guard.

Guard ledger хранится в соседнем каталоге aegis-lifecycle-guards (вне updater/profile rollback snapshots), имеет owner-only ACL/POSIX и AES-GCM с существующим vault key. Старый профильный backup не откатывает этот ledger и не восстанавливает истёкшее письмо. Missing/corrupt ledger блокирует только disappearing content. Ledger не защищает от скомпрометированной ОС, ручного извлечения ключей или сознательного изменения программы получателем.

При истечении срока удаляются управляемые encrypted content/outbox копии; остаётся metadata-only «Письмо исчезло». Plaintext не stage-ится на диск. Экспортированные файлы, clipboard, скриншоты, фотографии и явно созданные новые пересылки не являются удаляемыми копиями исходного письма. Автоматических plaintext attachments/cache нет. Существующие обычные TTL и письма не изменяются.

## Миграция и тестирование

ClientUpgrade создаёт прежний полный backup затрагиваемого vault/settings/Tor state. Новая state-v1.enc атомарна, encrypted, bounded; old state.vault/features-v1.vault/mail форматы сохранены. Rekey-copy поддерживает lifecycle sidecars. Identity-only backup не является полным backup профиля/device ledger. При clock rollback обычные письма теперь сохраняются с верхней отметкой времени, вместо прежнего массового удаления.

JUnit и real TCP/SOCKS/SQLite проверки отделены от actual Tor staging и от нативной приёмки. LifecycleTorProbe создаёт отдельный временный Relay, два throwaway аккаунта и три ephemeral onion services; production не меняется. Один компьютер/один Tor не доказывают разные физические сети. Полные Windows 11, CachyOS Wayland/X11 и owner-signed installer/restart/rollback остаются обязательными.

API/reference sources: Microsoft GetTickCount64/windows-time и Win32_OperatingSystem LastBootUpTime; JNA 5.19.1 WbemcliUtil.WmiQuery.execute(int) (официальный исходник). Новых Java-зависимостей нет.
