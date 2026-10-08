# АЕГИС 1.0.0

Автономная Единая Гибридная Информационная Система. Клиенты для Windows 10/11 x64 и CachyOS x86_64; существующий Relay 0.2.0 / protocol 1 сохраняется.

**Статус: кандидат для финальной приёмки, release ещё не опубликован.** Windows ZIP, Setup, CachyOS AppImage, исходники и SHA-256 подготовлены. Реальная native/E2E-приёмка и offline-подпись владельца пока не завершены. Ссылки на файлы релиза начнут работать после публикации v1.0.0; сейчас доступна документация.

- [Установка на Windows](docs/README-WINDOWS.md)
- [Установка на CachyOS](docs/README-CACHYOS.md)
- [Что нового в 1.0.0](CHANGELOG-1.0.0.md)
- [Статус подготовки и проверки](RELEASE-STATUS-1.0.0.md)
- [Все релизы](https://github.com/Babmoleilo90210/AEGIS-Releases/releases)

## Что добавлено

Подписанные обновления через собственный Tor с откатом; отдельный Windows updater; компактный интерфейс писем; локальные зашифрованные аватары; пять пресетов и JSON import/export; семидневное локальное разблокирование через защищённое хранилище ОС. Серверный вход ограничен прежними 12 часами и сбрасывается при перезапуске relay; пароль аккаунта не сохраняется.

Сохранены защищённые письма, FF1, вложения, AES-256 ZIP, TTL, миграция старого хранилища и совместимость с текущим relay. Новый сервер устанавливать не нужно.

## Политика распространения

# AEGIS Releases

Official binary releases and signed update manifests for AEGIS.

This repository is intended for distribution only. It must never contain:
- private release-signing keys;
- account passwords;
- letter passwords or FF1 codes;
- private identity keys;
- Tor onion-service private keys;
- production database backups.

## Update channels

Signed manifests will live under `updates/`:
- `updates/stable.json` + `updates/stable.json.sig`
- `updates/beta.json` + `updates/beta.json.sig`

Release binaries will be published as GitHub Release assets.

The AEGIS clients must verify the embedded Ed25519 release public key before trusting any update manifest.
