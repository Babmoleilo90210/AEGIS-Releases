# Зависимости и сетевые компоненты

Версии зафиксированы в Gradle, lockfiles и `gradle/verification-metadata.xml` (SHA-256). Выбор сверялся с официальными документацией и Maven-артефактами в сентябре 2026 года. Исходный набор 0.1.0 дополнен для 0.2.0, а не обещание отсутствия будущих уязвимостей. Обновления выполняет человек после проверки release notes и повторного запуска тестов.

## Дополнение клиента 2.0.0: локальная установка Tor Browser

| Артефакт | Версия | Назначение | Лицензия |
|---|---|---|---|
| bcpg-jdk18on, bcutil-jdk18on | 1.86 | Проверка официальной detached OpenPGP подписи Tor Browser с закреплённым публичным fingerprint; приватные ключи не принимаются | Bouncy Castle MIT-подобная |
| commons-compress | 1.28.0 | Ограниченный разбор официального TAR после проверки подписи | Apache-2.0 |
| xz | 1.12 | Потоковая XZ-декомпрессия с лимитом памяти | 0BSD |
| commons-io | 2.20.0 | Транзитивные локальные stream API Commons Compress | Apache-2.0 |
| commons-lang3 | 3.18.0 | Транзитивные локальные API Commons Compress | Apache-2.0 |
| commons-codec | 1.19.0 | Транзитивные локальные API Commons Compress | Apache-2.0 |

Прежний bcprov-jdk18on 1.86 сохраняется. Новые библиотеки не выполняют собственную загрузку пакетов; установщик принимает явно выбранные локальные файлы и проверяет их до распаковки. Точные SHA-256 официальных Maven Central JAR/POM закреплены в verification metadata; `packaging/client_runtime.py` и offline `tools/stage-candidate.py` требуют тот же полный runtime набор в Windows и Linux. JUnit, Monocle и серверные зависимости не включаются.

META-INF LICENSE/NOTICE новых BC/Commons JAR сохраняются в JAR и извлекаются в каталог licenses дистрибутива. XZ 1.12 не содержит такого файла внутри JAR; его официальный POM объявляет 0BSD. Полный upstream COPYING из тега v1.12 и сведения об источнике/hash сохранены в `resources/licenses/xz-1.12-COPYING` и `xz-1.12-NOTICE.txt`. Официальные исходники: https://github.com/bcgit/bc-java ; https://commons.apache.org/proper/commons-compress/ ; https://tukaani.org/xz/java.html . Это описание библиотек установщика, а не заявление о завершённой нативной приёмке Tor Browser.

## Рабочие приложения

| Компонент | Версия | Где и зачем | Получаемые данные |
|---|---|---|---|
| Java / OpenJDK | 21 LTS | Оба приложения: JVM, стандартные AES-GCM, ChaCha20-Poly1305, Ed25519, sockets | Данные своего процесса; внешнего сервиса нет |
| OpenJFX | 21.0.12 | Только клиент: base, graphics, controls; нативный desktop GUI | Локальный текст интерфейса; WebView отсутствует |
| Bouncy Castle bcprov-jdk18on | 1.86 | Только клиент: Argon2id и Camellia-GCM | Пароль/ключ/содержимое только в RAM клиента |
| Google Tink | 1.23.0 | Только клиент: готовая XChaCha20-Poly1305 | Ключ, plaintext, AAD локально; Cloud API не используется |
| Password4j | 1.8.4 | Только relay: Argon2id паролей аккаунтов | Пароль аккаунта в RAM; соль и hash в SQLite |
| Xerial SQLite JDBC | 3.53.4.0 | Только relay: встроенная SQLite | Аккаунты, публичные идентификаторы, ciphertext, квитанции |
| SLF4J API + nop | 2.0.17 | Relay: отключённый logging backend для библиотек | Без вывода параметров библиотек |
| Tor | Системный поддерживаемый пакет | Отдельный процесс клиента и VPS | Сетевые метаданные/зашифрованные потоки; ControlPort локальный |

JavaFX выбран вместо Compose Desktop: приложение остаётся на Java без дополнительного Kotlin/Skia стека; для компактных форм достаточно стандартных контролов. Java 21 позволяет использовать стабильную ветку JavaFX 21 и распространённый Linux runtime. Java 25 также LTS, но миграция не обязательна для этих функций; выбран и проверен baseline Java 21. Версия исправлений JDK должна поддерживаться вашим дистрибутивом.

Системный Tor намеренно не скачивается и не обновляется из Java. Пользователь явно устанавливает его и включает выделенный service по инструкции. Onion адреса клиентов создаются автоматически через стандартный Tor Control protocol; стороннего каталога адресов нет.

## Транзитивные runtime JAR

Кроме собственных модулей и прямых зависимостей, клиентская поставка содержит:

| Артефакт | Версия | Причина |
|---|---|---|
| gson | 2.13.2 | Зависимость Tink; сетевой протокол АЕГИС не использует JSON |
| protobuf-java | 4.33.6 | Типы/служебный формат библиотеки Tink; не SaaS |
| error_prone_annotations | 2.41.0 | Аннотации зависимостей |
| jsr305 | 3.0.2 | Аннотации зависимостей |
| javafx-base, javafx-graphics без classifier | 21.0.12 | Служебные Maven JAR; Linux implementation присутствует отдельно |

У relay нет BC, Tink, client-core или JavaFX. `:relay-server:verifyIsolation` проверяет эту границу в Gradle; тест `IsolationTest` проверяет недоступность клиентской криптографии в relay classpath. JDK имеет общие криптографические API, однако ни ключей писем, ни операции их расшифрования у relay нет.

## Только разработка и тесты

- Gradle 9.8.0 и настоящий Wrapper. ZIP Gradle проверяется фиксированным SHA-256. Gradle не нужен для запуска готовых приложений.
- JUnit BOM/Jupiter 5.13.4; JUnit Platform 1.13.4; opentest4j 1.3.0; apiguardian-api 1.1.2. Не входят в client/relay distributions.
- TestFX `openjfx-monocle` 21.0.2 — только `smokeRuntimeClasspath`, для запуска JavaFX без дисплея (`uiSmoke -PheadlessSmoke`). Не входит в приложение, не обрабатывает настоящую переписку, не создаёт внешних соединений.
- Для форматирования исходников при подготовке использован google-java-format 1.24.0; он не является зависимостью проекта или runtime.

Проверить фактическое дерево: `./gradlew :client-ui:dependencies --configuration runtimeClasspath` и аналогично для relay. Полный набор для каждой конфигурации записан в `gradle.lockfile` соответствующего модуля. JAR-зависимости не создают собственных сетевых вызовов в используемых здесь API; аудит этой версии не равнозначен полному независимому аудиту всего upstream-кода.

## Источники и лицензии

- [OpenJDK](https://openjdk.org/projects/jdk/21/) и [OpenJFX](https://openjfx.io/) — GPLv2 с Classpath Exception; [исходники JavaFX](https://github.com/openjdk/jfx).
- [Bouncy Castle](https://www.bouncycastle.org/download/bouncy-castle-java/) — собственная MIT-подобная [лицензия](https://www.bouncycastle.org/licence.html); [GCM API](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/modes/GCMBlockCipher.html).
- [Tink](https://github.com/tink-crypto/tink-java), [Password4j](https://github.com/Password4j/password4j), [SQLite JDBC](https://github.com/xerial/sqlite-jdbc), [Gson](https://github.com/google/gson) — Apache-2.0; встроенная SQLite public domain.
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf) — BSD-3-Clause; [SLF4J](https://www.slf4j.org/license.html) — MIT. Error Prone — Apache-2.0; jsr305 — BSD-3-Clause.
- [Gradle](https://gradle.org/) — Apache-2.0; [JUnit](https://junit.org/) — EPL-2.0; [Monocle](https://github.com/TestFX/Monocle) — GPLv2 с Classpath Exception.
- [Tor](https://www.torproject.org/) — отдельный системный компонент; его лицензии поставляются дистрибутивом.

Лицензии и NOTICE, включённые авторами в JAR, сохраняются в бинарной поставке. При распространении модифицированных сторонних компонентов отдельно проверьте их требования. Все соединения приложений и инструментов установки перечислены в README; скрытого API обновления или загрузки данных нет.

## Дополнения и уточнения 0.2.0

- Java 21 runtime: Azul Zulu OpenJDK 21.0.12.1, jlink, GPLv2 + Classpath Exception; legal notices сохранены внутри runtime.
- JNA 5.19.1: локальная FFI к libsodium; LGPL-2.1-or-later / Apache-2.0 dual license. https://github.com/java-native-access/jna
- libsodium 1.0.22 stable: стандартные sealed boxes и преобразование Ed25519/X25519; ISC, LICENSE включён. https://doc.libsodium.org/
- Tor теперь **включён в клиент**, а не требует отдельной установки. Expert Bundle 15.0.24 / Tor 0.4.9.13 и его Lyrebird: https://download.torproject.org/tor/ . Bundle содержит upstream notices. Неиспользуемые conjure-client/tor-gencert не поставляются.
- Windows JavaFX classifier win и Linux classifier linux: 21.0.12. Maven placeholder JAR без classifier не нужны новой staging-конфигурации.
- LLVM-MinGW 20260922 и AppImage tooling используются только при сборке. Launcher не использует упаковщики или obfuscators.

Время проверки поставляемых версий: 2–3 октября 2026. Архив libsodium stable сверён официальной minisign-подписью 3 октября; его SHA-256 закреплён заново после изменения upstream tarball. Авторитетные upstream URL и точные hashes сохранены в packaging/fetch-dependencies.py и BUILD-INPUTS.json бинарных пакетов. Клиентские JAR не инициируют независимые соединения; сетевые действия выполняют явно описанные TorTransport/TorControl и Tor/PT.

Client 1.0.0: Zip4j 2.11.6, Apache2.0, https://github.com/srikanth-lingala/zip4j/releases/tag/v2.11.6 . Проверено2026-10-07. Только локальный AES ZIP stream; сеть/telemetry отсутствуют. Лицензия включена в resources/licenses/zip4j-LICENSE. Все прежние server dependencies заморожены.

## Клиент 1.0.0: добавленные зависимости

JNA Platform 5.19.1: DPAPI CurrentUser и Windows process APIs, локальные OS вызовы. Gson 2.14.0: строгий bounded update/preset JSON. TwelveMonkeys ImageIO WebP 3.14.0: pure Java decoder локальных аватаров с ограниченными dimensions; связанные modules common-lang/common-io/common-image/imageio-core/imageio-metadata той же версии. У этих зависимостей нет сетевой роли и пользовательские bytes внешним сервисам не отправляются. Существующая JNA 5.19.1 сохранена. JavaFX 21.0.12, Zip4j 2.11.6, BC 1.86, Tink 1.23.0, libsodium 1.0.22 не менялись.

Official references: https://github.com/java-native-access/jna/releases/tag/5.19.1 ; https://github.com/google/gson/releases/tag/gson-parent-2.14.0 ; https://github.com/haraldk/TwelveMonkeys/releases/tag/3.14.0 ; https://gnome.pages.gitlab.gnome.org/libsecret/ . Версии проверены перед включением; binaries закреплены Gradle verification SHA-256. LICENSE/NOTICE в исходных JAR остаются внутри пакетов. Linux libsecret — компонент desktop OS; при его отсутствии remember-login fail-closed, базовый password login не отключается.
