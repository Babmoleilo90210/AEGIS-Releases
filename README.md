# АЕГИС 1.2.0 — Stability & Message Lifecycle

**АЕГИС (Автономная Единая Гибридная Информационная Система)** — клиент приватной переписки и защищённых писем для Windows x64 и CachyOS x86_64. Использует встроенные Java и Tor, собственный Relay, локальное зашифрованное хранилище и дополнительные уровни защиты отдельных писем.

**Последний опубликованный Stable Release:** [v1.2.0](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/tag/v1.2.0) (13 октября 2026).

> **Статус проверки:** релиз опубликован как Stable, однако `productionReady=false` по отчёту сборщика: обязательные нативные испытания Windows 11, CachyOS KDE Wayland/X11 и полный owner-signed updater/restart/rollback ещё не завершены. Независимый аудит безопасности не проводился. Публикация не означает подтверждения всех критериев готовности.

## Скачать

| Платформа | Файл |
| --- | --- |
| Windows x64 — установщик | [AEGIS-Setup-1.2.0-x64.exe](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/AEGIS-Setup-1.2.0-x64.exe) |
| Windows x64 — portable | [AEGIS-1.2.0-Windows-x64.zip](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/AEGIS-1.2.0-Windows-x64.zip) |
| CachyOS x86_64 | [AEGIS-1.2.0-CachyOS-x86_64.AppImage](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/AEGIS-1.2.0-CachyOS-x86_64.AppImage) |
| Контрольные суммы | [SHA256SUMS](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/SHA256SUMS) |
| Исходники и отчёты | [GitHub Release v1.2.0](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/tag/v1.2.0) |

## Установка

**Windows:** запустите Setup EXE под обычной учётной записью. Для portable-версии распакуйте *весь* ZIP и запустите `AEGIS.exe`. Java и Tor Browser отдельно устанавливать не требуется.

**CachyOS KDE (Wayland/X11):** скачайте AppImage и выполните:

```bash
chmod +x AEGIS-1.2.0-CachyOS-x86_64.AppImage
./AEGIS-1.2.0-CachyOS-x86_64.AppImage
```

Для ярлыка KDE используйте `~/.local/share/applications/aegis.desktop` с абсолютным путём к AppImage. Если используется встроенный updater, сохраняйте путь установки, который ожидает updater, и не удаляйте пользовательский профиль при обновлении.

## Что нового в 1.2.0

- **Friends:** взаимные подтверждения добавления в контакты, предварительный статус при ожидании синхронизации и обработка отзыва/блокировки.
- **Доставка и прочтение:** различаются отправка, приём Relay, подтверждение доставки на устройство и подтверждённое отображение содержимого получателем. Обычные receipts можно отключить.
- **Исчезающие письма:** срок от 1 минуты до 30 дней; отсчёт после подтверждённого отображения, удаление управляемого содержимого и запись об истечении срока.
- **Tor:** встроенная карточка подключения, реальный bootstrap, Direct/Snowflake fallback и более корректное отображение ошибок.
- **Интерфейс:** адаптивные панели и максимизация, пять семейств шрифтов с кириллицей, полноразмерный просмотр аватаров.
- **Updater:** доработана изоляция вспомогательного процесса, чтобы не появлялось лишнее белое окно.
- **Совместимость:** по отчёту сборщика сохранены существующий Relay 0.2.0, protocol 1, шифрование и пользовательские настройки.

Подробнее: [CHANGELOG-1.2.0.md](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/CHANGELOG-1.2.0.md) и [TEST-REPORT-1.2.0.md](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/TEST-REPORT-1.2.0.md).

## Обновления внутри приложения

В разделе **Настройки → Обновления** клиент Stable-канала получает `updates/stable.json` и `updates/stable.json.sig` через Tor, проверяет Ed25519, версию, совместимость, размер и SHA-256 загружаемого артефакта. После проверки установка требует подтверждения пользователя.

GitHub используется для распространения, **не является корнем доверия**. Закреплённый публичный ключ находится в [updates/release-public.pem](https://github.com/Babmoleilo90210/AEGIS-Releases/blob/main/updates/release-public.pem).

[Текущий Stable manifest](https://github.com/Babmoleilo90210/AEGIS-Releases/blob/main/updates/stable.json) указывает на 1.2.0. Это позволяет совместимым клиентам обнаружить обновление; успешная установка и rollback на каждой платформе должны быть проверены отдельно.

Перед обновлением рекомендуется сделать резервную копию профиля и завершить незаконченные черновики.

## Проверки и ограничения

По [отчёту сборщика](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/TEST-REPORT-1.2.0.md):

- 141 JUnit PASS, 1 SKIP; 16 release/security PASS; 9 headless JavaFX suites PASS.
- Windows Server 2025: 10 проверок; Ubuntu: 8 проверок; Linux staging с Tor и тестовыми аккаунтами — PASS.
- **Ещё не подтверждены:** Windows 11, CachyOS KDE Wayland и X11, обмен между разными физическими сетями, реальный owner-signed updater с установкой/перезапуском/откатом.
- После перезагрузки ОС исчезающее письмо может стать недоступным раньше заданного срока — консервативная мера при недостоверном времени устройства.
- Скриншоты, экспортированные файлы и копии вне АЕГИС нельзя гарантированно удалить.
- Черновики по-прежнему хранятся в памяти и блокируют установку обновления, пока не завершены или не отменены.
- Независимого security audit нет; не заявляется эквивалентность Signal.

## Безопасность публикации

**Не загружайте** в репозиторий приватный Ed25519 release key, пароли, letter passwords, FF1 codes, приватные identity keys, Tor onion-service keys, production-базы или пользовательские профили.

Production Relay и onion identity не изменяются при публикации клиентского обновления. Новые бинарники и подписанные manifest должны соответствовать опубликованным SHA-256.
