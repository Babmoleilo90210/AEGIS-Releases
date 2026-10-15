# АЕГИС 1.5.0 — Personal Encrypted Archive

**АЕГИС (Автономная Единая Гибридная Информационная Система)** — настольный клиент защищённой переписки и писем для Windows x64 и CachyOS x86_64 со встроенными Java и Tor, локальным зашифрованным хранилищем и собственным Relay.

**Последний опубликованный GitHub Stable Release:** [v1.5.0](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/tag/v1.5.0) (15 октября 2026).

> **Внимание:** релиз опубликован как Stable по решению владельца, но отчёт сборщика содержит `productionReady=false`. Нативные испытания Windows 11, CachyOS KDE Wayland/X11, P2P между двумя физическими сетями и полный owner-signed updater/restart/rollback не завершены. Независимый аудит безопасности не проводился. Статус публикации не следует трактовать как подтверждение production-готовности.

## Скачать

| Платформа | Файл |
| --- | --- |
| Windows x64 — установщик | [AEGIS-Setup-1.5.0-x64.exe](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.5.0/AEGIS-Setup-1.5.0-x64.exe) |
| Windows x64 — portable | [AEGIS-1.5.0-Windows-x64.zip](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.5.0/AEGIS-1.5.0-Windows-x64.zip) |
| CachyOS x86_64 — AppImage | [AEGIS-1.5.0-CachyOS-x86_64.AppImage](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.5.0/AEGIS-1.5.0-CachyOS-x86_64.AppImage) |
| Контрольные суммы | [SHA256SUMS](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.5.0/SHA256SUMS) |
| Исходники, инструкции и отчёты | [Все вложения релиза](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/tag/v1.5.0) |

## Установка

**Windows:** запустите Setup EXE либо распакуйте *весь* portable ZIP и запустите `AEGIS.exe`. Отдельная установка Java и Tor Browser не требуется.

**CachyOS KDE (Wayland/X11):**

```bash
chmod +x AEGIS-1.5.0-CachyOS-x86_64.AppImage
./AEGIS-1.5.0-CachyOS-x86_64.AppImage
```

Работайте под обычной учётной записью, не запускайте клиент от root. Перед обновлением сохраните резервную копию пользовательского профиля и закройте незавершённые черновики.

## Что нового в 1.5.0

- **Личный зашифрованный архив:** письма, вложения и файлы, отдельный пароль, возможность recovery key, блокировка, офлайн-доступ.
- **Организация архива:** папки, теги, избранное, поиск, просмотр изображений, текста и PDF, корзина, предупреждения о дубликатах.
- **Резервные копии архива:** зашифрованный экспорт, восстановление и миграция данных.
- **Главное окно:** согласованная навигация, обновлённые настройки и компактная верхняя панель; убран пользовательский раздел «Друзья», сохранены контакты.
- **Соединение:** автоматическое подключение Tor и статусы соединения внутри главного окна.
- **Письма:** единая настройка исчезновения и дополнительные улучшения редактора.
- **P2P:** проведены испытания onion-маршрута в среде одного Linux-хоста; прямая передача между двумя физическими устройствами/сетями ещё не подтверждена.

Подробности: [CHANGELOG 1.5.0](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.5.0/CHANGELOG-1.5.0.md), [документация архива](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.5.0/ARCHIVE-1.5.0.md), [P2P-отчёт](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.5.0/P2P-VERIFICATION-1.5.0.md).

## Обновления внутри АЕГИС

Клиент Stable-канала проверяет подписанные файлы `updates/stable.json` и `updates/stable.json.sig` через Tor. Применяются проверка Ed25519, ограничений версии, размера и SHA-256 артефакта. Подтверждение установки остаётся за пользователем.

GitHub служит для распространения, но не является корнем криптографического доверия; закреплённый публичный ключ расположен в [updates/release-public.pem](https://github.com/Babmoleilo90210/AEGIS-Releases/blob/main/updates/release-public.pem).

Публикация Release и активация [Stable feed](https://github.com/Babmoleilo90210/AEGIS-Releases/blob/main/updates/stable.json) — **разные действия**. Доступность конкретной версии внутри приложения зависит от опубликованной подписанной пары manifest и подписи.

## Ограничения и результаты испытаний

Подробные фактические статусы указаны в [RELEASE-GATES-1.5.0.json](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.5.0/RELEASE-GATES-1.5.0.json) и [TEST-REPORT-1.5.0.md](https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.5.0/TEST-REPORT-1.5.0.md).

По отчёту: 165 JUnit PASS, 1 SKIP; 16 release/security PASS; 6 JavaFX suite PASS; 22 проверки архива на Windows Server и 22 на Ubuntu. Это **не заменяет** обязательную нативную приёмку и полный сценарий автоматического обновления с откатом. Не заявляется независимая проверка безопасности или абсолютная защита от скомпрометированной ОС.

## Безопасность репозитория

Никогда не публикуйте приватные release-signing keys, пароли аккаунтов, letter passwords, FF1 codes, identity private keys, приватные Tor onion-service keys или производственные пользовательские данные. Production Relay и onion identity не должны изменяться публикацией клиентской сборки.
