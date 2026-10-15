# Сборка АЕГИС 2.5.0

Исходная база: `f173b4a1bb5f1e3ed121870aa04a6583833f93e9`, ветка разработки опубликованного 2.0.0 Beta. Source ZIP релиза имеет SHA-256 `ade6108509ac837d9781ff3f03ebfe0bd9c917b332bbf221de0ed9ca28c90633`; все 604 его файла совпали с Git. Проверены SHA-256 AppImage и Windows ZIP. Это сравнение опубликованных артефактов и исходников, не независимое воспроизводимое доказательство всей старой сборки. Криптографически подписанная CI provenance старого релиза не предоставлена.

Обычная сборка: `./gradlew build`, Java 21, зависимости из Gradle verification metadata. В данной среде использован явный offline fallback `tools/build-local.py` с проверенными JAR из опубликованной сборки и отдельно проверенными JUnit/server dependencies. Он компилирует все четыре модуля и запускает JUnit в раздельных JVM; test-only server не попадает в client distribution.

```sh
python3 tools/build-local.py --jdk /path/to/jdk21 --deps /path/to/base/app --deps /path/to/test-deps --native-root /path/to/voice-linux
python3 tools/stage-candidate.py --linux-base /path/to/base/AppDir --windows-base /path/to/base/AEGIS --build build/local-java21 --deps /path/to/base/app --out client-ui/build/stage
python3 packaging/build-voice-native.py --help
python3 packaging/package-clients.py --help
python3 packaging/verify_client_release.py --help
python3 packaging/archive-clients.py /path/to/artifacts
python3 tools/package-native250.py --help
```

Packager требует явные проверенные Linux/Windows base runtimes, оба voice-native набора, MinGW, NSIS, AppImage Type 2 runtime и mksquashfs. Ничего не скачивается неявно. Windows launcher/maintenance/updater пересобираются из сохранённого C source; NSIS включает полный проверенный payload. AppImage проверяется фактическим извлечением и сравнением payload, не одним exit code packager.

Аудио: pinned официальные Opus 1.6.1 и SpeexDSP 1.2.1. Исходники, лицензии, SHA-256 и компиляторы описаны в `packaging/native-kit/voice-runtime-provenance.json` и GLAS-AUDIO-2.5.0-RU.md. Linux ELF и Windows DLL собираются из тех же исходников, зависимости ограничены. Runtime загружает только библиотеки с совпадающими embedded pins.

JDK сборки: Eclipse Temurin OpenJDK 21.0.12.1+1, официальный архив Adoptium с SHA-256 `ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94`. Exact release source/provenance и фактические инструменты записываются рядом с артефактами в BUILD-PROVENANCE-2.5.0.json. Все бинарники и source ZIP относятся к одному зафиксированному исходному commit; окончательный hash берётся из этого файла, чтобы не создавать самоссылочный commit в собственном содержимом.

Кросс-компиляция Windows и Ubuntu extraction не считаются нативной приёмкой Windows 11/CachyOS KDE. Подпись и публикация отделены от сборки.

Для текущего packager обязательны --java-linux и --java-windows: точные runtimeиз packaging/native-kit/java-runtime-provenance-2.5.0.json. Старый English-onlyruntimeиз2.0больше не копируется. Linux jlinkкоманда и WindowsofficialvendorZIP+SHA перечислены в docs/test-results/2.5.0-java-locale/. Все legacybuild-{archive,visual,stability,demo,candidates}.py относятся к прежним поколениям и не являются командой выпуска2.5. Используйте описанную явную последовательность build-local → stage-candidate → package-clients → verify → source/native archive; packager--help показывает полный набор обязательных проверенных входов.
