# Native acceptance kit — АЕГИС 2.5.0 «Взор и Глас»

Это отдельный комплект проверок для владельца. Его создание и нулевой exit code отдельного fixture не означают, что вся нативная приёмка пройдена. При поставке kit значения Windows 11, CachyOS KDE Wayland/X11, реальные Tor Browser/onion, два физических устройства и updater E2E остаются **NOT_RUN**. `productionReady=false` до закрытия обязательных gates в `NATIVE-ACCEPTANCE-2.5.0.md`.

Тестовые JAR не находятся в `app/` и не заменяют pinned verifier или production public key. Комплект собирается `tools/package-native250.py` из точного `AEGIS-2.5.0-client-source.zip` и `AEGIS-2.5.0-Windows-x64.zip`; `TESTED-ARTIFACTS.json` содержит SHA-256 этих входов и трёх общих application JAR. Старые `SafeWeb200Smoke`/`Interface200Smoke` в текущий UI kit не входят. Повторная упаковка сохраняет предыдущий каталог kit под отдельным именем, чтобы не удалить отчёты владельца.

## Запуск

Распакуйте portable Windows ZIP рядом с каталогом `native-acceptance`. Все команды принимают каталог установленного/portable АЕГИС первым аргументом; Java/JDK/Python/Gradle для запуска готовых JAR не нужны.

```bat
Run-Windows.cmd "C:\AEGIS-Test\AEGIS"
Run-Appearance-Windows.cmd "C:\AEGIS-Test\AEGIS"
Run-Voice-Windows.cmd "C:\AEGIS-Test\AEGIS"
```

Для CachyOS передайте исполняемый AppImage или уже распакованный AppDir с `runtime`, `app`, `native`. AppImage извлекается во временный каталог, который удаляется при завершении; профиль владельца не открывается.

```bash
bash Run-CachyOS.sh /path/to/AEGIS-2.5.0-CachyOS-x86_64.AppImage
bash Run-Appearance-CachyOS.sh /path/to/AEGIS-2.5.0-CachyOS-x86_64.AppImage
bash Run-Voice-CachyOS.sh /path/to/AEGIS-2.5.0-CachyOS-x86_64.AppImage
```

Повторите графические проверки отдельно в KDE Wayland и X11 и сохраните edition/build/kernel, compositor, масштаб ОС, SHA-256 приложения и наблюдения. Наличие установленного Sandbox, Xephyr или аудиодрайвера не является PASS реальной операции. Windows Server и Linux headless не заменяют целевые стенды. Взор требует Windows 11 24H2+ Pro/Enterprise/Education с актуальным Microsoft Sandbox CLI; Home этим backend не поддерживается. На CachyOS нужны системные bubblewrap, slirp4netns, Xephyr и X11/Xwayland. Глас от Windows Sandbox не зависит.

## Что запускают команды

- `Run-Windows` / `Run-CachyOS`: `NativeAcceptanceMain` проверяет совпадение общих application JAR, crypto/vault/expiry guard/OS credentials и базовые синтетические JavaFX сцены. Результат JSON сохраняется рядом с kit. Он относится только к реально выполненным локальным строкам, а не к голосовому звонку, браузерному трафику или updater E2E.
- `Run-Appearance`: текущий `Interface250RefinementSmoke`, сохранённый компонентный `SettingsResponsive200Smoke`, затем текущий `VzorGlas250Smoke`. Это реальные JavaFX controls, искусственный зашифрованный архив, масштаб 100/125/150/200%, светлые/тёмные темы, popup/embedded panel и compact/advanced Взор/Глас. Старое имя SettingsResponsive200 отражает происхождение проверки настроек, а не запуск браузерной приёмки версии 2.0. Эти fixture не открывают официальный Tor Browser, сеть или микрофон.
- `Run-Voice`: `VoiceNativeAcceptanceMain` по умолчанию проверяет фактические pinned Opus/Speex-библиотеки, перечисляет устройства и выполняет синтетический codec fixture. Захват, воспроизведение и сеть не открываются.

Только для явного локального измерения уровня микрофона добавьте второй аргумент `--test-microphone` к `Run-Voice`. Захват длится до 15 секунд; тест не записывает, не воспроизводит и не передаёт звук. Для явного выбора device ID используйте документированный Java CLI из `NATIVE-ACCEPTANCE-2.5.0.md`. Обёртка не принимает произвольные дополнительные параметры. Отчёт может содержать личные имена Bluetooth/USB устройств: проверьте их перед передачей. Никакие отчёты автоматически не отправляются.

```bash
bash Run-Voice-CachyOS.sh /path/to/AppDir --test-microphone
```

## Доказательства и ограничения

Сохраняются JSON `AEGIS-native-*`, `AEGIS-voice-local-*`, настоящие synthetic screenshots и компонентные измерения в `build/`. Точные пути текущих UI smoke: `build/ui250-refinement-screenshots`, `build/ui250-refinement-performance.json`, `build/vzor-glas250-screenshots` (дополнительный SettingsResponsive использует свой исторический каталог). Снимок искусственной сцены не является доказательством Tor-only, запуска официального браузера, физического аудио или работы между двумя компьютерами. Исключение/FAIL_OR_UNAVAILABLE не становится PASS.

Fixture микрофона по умолчанию не запускается. Даже при успехе явной локальной проверки `nativeVoiceAcceptance`, `twoPhysicalMachinesOnDifferentNetworks`, `sixtyMinuteOnionCall`, реальный playback/speech quality остаются NOT_RUN. Их проводят по подробному протоколу, включая ≥60 минут реального onion-звонка между двумя физическими компьютерами в разных внешних сетях.

`fixtures/manifest-compatibility/` содержит точные v1.5.0/v2.0.0 parser source snapshots и provenance с SHA-256, unsigned generator и test source. Снимок v1.5.0 использует явно обозначенные вспомогательные JsonData/SemVersion из базы 2.0, потому что дерево 1.5.0 их не содержало; это не полная сборка исторического приложения. Файлы не включены в production/native runtime classpath. Проверка парсеров и временные test-only подписи не являются owner подписью и не доказывают скачивание/установку/перезапуск/rollback. Для повторного JUnit запуска этих sources нужны отдельный JDK21, Python 3 и проверенные test dependencies из полной исходной сборки.

Если при упаковке передан `--staging-deps`, каталог `staging/` содержит disposable Relay и два operator probe, скомпилированные из того же source ZIP. Команды `Run-Lifecycle-CachyOS.sh` и `Run-Public-Profiles-CachyOS.sh` используют настоящий комплектный Tor и временные аккаунты/onion/database на одном устройстве. Они не обращаются к production Relay/feed/аккаунтам; relay JAR не добавляется в `app/`. Bootstrap failure оставляет зависимые сценарии NOT_RUN. Этот стенд не заменяет двухмашинную приёмку Гласа и проверку официального Tor Browser.

Сверьте `SHA256SUMS` kit и SHA-256 release artifacts перед испытаниями. Приватные release-signing keys для kit не требуются. Не отключайте Defender/firewall и не открывайте рабочий профиль ради получения PASS. Полный протокол: `NATIVE-ACCEPTANCE-2.5.0.md`; границы безопасности Взора: `VZOR-THREAT-MODEL-2.5.0.md`; архитектура Гласа: `GLAS-2.5.0.md` и `GLAS-CRYPTOGRAPHY-2.5.0.md`.
