# АЕГИС 1.0.0

Автономная Единая Гибридная Информационная Система. Клиент для Windows 10/11 x64 и CachyOS x86_64.

**Обычная установка:** на Windows скачайте Setup EXE и откройте его; на CachyOS скачайте AppImage, разрешите выполнение и запустите. Java и Tor уже включены. После запуска вставьте выданный владельцем сервера `.onion`, создайте аккаунт или войдите.

Обычный пользователь не выполняет offline-подпись и команды подготовки релиза. Финальная offline-подпись manifest выполняется владельцем после приёмки. Автоматическая проверка и загрузка обновлений на новом профиле выключены по умолчанию. Ручная установка не зависит от update manifest.

- [Как установить на Windows](docs/README-WINDOWS.md)
- [Как запустить на CachyOS](docs/README-CACHYOS.md)
- [Что нового в 1.0.0](CHANGELOG-1.0.0.md)
- [Статус сборок и проверок](RELEASE-STATUS-1.0.0.md)

Для владельца: [финальная приёмка и offline-подпись](docs/OWNER-ACCEPTANCE-AND-SIGNING.md).

GitHub Release assets пока не загружены; файлы предоставлены владельцу в итоговом сообщении. Постоянные ссылки в гайдах начнут работать после загрузки Release. Native Windows/CachyOS и реальный VPS/Tor/reboot пока не подтверждены; результаты сборки и автоматических тестов доступны в отчёте.

Клиенты сохраняют совместимость с Relay 0.2.0 / protocol 1. Переустанавливать сервер не нужно.

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
