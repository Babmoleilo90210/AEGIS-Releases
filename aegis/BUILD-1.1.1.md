# Сборка 1.1.1 Demo

Исходная база: опубликованный v1.1.0, commit 5d9e303bf8114dfbe1f6c0cbb2720eb9d3382549. Код не создаётся заново.

Java 21 JDK, Python 3.11+, GCC MinGW x64, NSIS, squashfs-tools. На Windows/CachyOS конечному пользователю они не нужны. Используются неизменённые официальные runtime/Tor/libsodium из SHA-pinned пакетов 1.0.0; их происхождение и версии записаны в BUILD-PROVENANCE.json/BUILD-INPUTS.json. Новых библиотек и сетевых endpoints в клиент не добавлено.

С полного source ZIP:

```bash
cd aegis
python3 tools/build-demo.py --jdk /путь/к/jdk-21 --work /путь/к/build-inputs --out /путь/к/unsigned-demo
```

Сборка явно скачивает SHA-pinned inputs/Maven test dependencies, компилирует все модули Java 21, запускает JUnit/release/security/JavaFX и compatibility checks, собирает client JARs/native launchers/NSIS/AppImage/source ZIP. Relay нужен только для регрессионных тестов и не выпускается/не развёртывается.

GitHub CI: .github/workflows/aegis111-demo.yml, development/aegis-1.1.1-demo; результат — Actions artifacts, не Release. Источник входит в ZIP вместе с build scripts.

Unsigned updates/beta.json создаётся после вычисления SHA256SUMS. tools/sign-release-manifest запускается только владельцем офлайн. После подписи запрещены пересборка и изменение JSON/бинарных файлов: потребуется новый manifest и новая подпись.

Нативный E2E не заменяется зелёной CI-сборкой. Порядок приёмки и точные команды — DEMO-UPDATER-TEST-RU.md.
