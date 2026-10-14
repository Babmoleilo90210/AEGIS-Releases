# Сборка АЕГИС 1.5.0

Java21 JDK. Gradle wrapper/locks/verification используются обычной сборкой `./gradlew build`; разные Windows/Linux JavaFX native JAR остаются раздельными. Альтернативный `tools/build-local.py` принимает явно переданные проверенные JDK/deps и ничего не скачивает.

Для полной упаковки на Linux нужны gcc-mingw-w64-x86-64, NSIS и squashfs-tools. Только build worker, не пользовательский компьютер/VPS. `python3 tools/build-archive.py --jdk /path/jdk21 --work /path/inputs --out /path/candidates` скачивает SHA-pinned published1.2.0 runtime/Tor/libsodium/JavaFX, зависимости, компилирует, запускает JUnit/JavaFX tests, собирает launchers/Setup/ZIP/AppImage, source ZIP и kit. No signing/publication.

База binaries70f80c27c13321d3ad8f7c8d7fa630862c56c56d; final1.2 source overlay8dd290af025921c16c40798f71b7958878524faf. Published1.2 source SHA25693c816760d3f688214a3a37e67483e9ec89233e5f671d28bb8f5b49f7f370324. Runtime21/Tor/lyrebird и E2EE зависимости сохраняются. Новые PDFBox/pdfbox-io/FontBox3.0.8 и CommonsLogging1.3.5 разрешены только клиенту/PDF helper. Их SHA закреплены в build script; Apache PDFBox SHA512 проверена при получении.

Fonts NotoSans/Inter/Roboto/PTSans/DejaVuSans и лицензии унаследованы из проверенного1.2.0 исходника. Иконка — прежний подготовленный icon.ico/PNG владельца, не заменяется.

CI branch development/aegis-1.5.0 производит unsigned artifacts и evidence с contents:read. Реальные Tor staging/Windows Server checks выполняются отдельно от candidate packaging. Ни один workflow не имеет Release/feed signing шагов. Все команды имеют timeout; сетевые ошибки становятся FAIL/NOT_RUN, а не бесконечным повтором.
