# Android 6.0.0: испытания текущего checkpoint

Дата: 18.10.2026. Linux x86-64, JDK 21, SDK 36/build-tools 36.1.0, NDK r29; это не Android-устройство. `productionReady=false`.

| Проверка | Статус | Реальное доказательство |
|---|---|---|
| UID/пакет/сертификат, поколения, время, ZIP-квоты/CRC | PASS | 31 production-policy JVM-тест |
| Типизированное делегирование, чужой app key/authority, replay/time/TTL, duplicate JSON/scope, generic signing | PASS | 13 production AppGrantProposal тестов |
| Onion-domain в реальном SOCKS handshake, отказ без fallback, внешние SOCKS/clearnet denied | PASS | 4 socket-теста существующего TorTransport; loopback fixture, не Tor |
| Настоящее JNI/libsodium и исходное E2EE, неправильные ключи/подпись, AEB1/AEB2/пароль/account | PASS | 18 host-тестов; ARM64 не выполнялся |
| Credentialed gateway, запрет UDP/закрытых IP/домена, двусторонние TCP bytes | PASS | 13 настоящих host socket-тестов |
| Нативный hev/lwIP, raw IP, DNS NXDOMAIN/virtual mapping, non-DNS UDP drop, TCP/SOCKS/echo, protect hook, stop | PASS | 6 actual native-engine host-тестов через AF_UNIX socketpair; это не Android TUN/protect |
| Opus/SpeexDSP encode/decode/PLC/битрейт/DSP, packet bounds, native handle limits, существующий media lifecycle/jitter/mute/switch/close | PASS | 29 actual host JNI/pipeline проверок; синтетические PCM-устройства явно обозначены |
| Android-only BCJSSE 1.86 ↔ неизменённый desktop SunJSSE, TLS1.3/ALPN v2 в обеих ролях, duplex, KeyUpdate, exact comparison code, wrong root/key/context/expiry, tamper/replay/cert substitution/downgrade | PASS | 31 настоящий loopback interop тест; global Security provider registry не изменён |
| Android MailRelay REGISTER6/LOGIN6/E2EE/FETCH/ACK с действительными Identity HTTP + SQLite Relay | PASS_LOCAL | 7 integration-сценариев; локальная SOCKS fixture, не реальный Tor |
| Официальная libsodium 1.0.22 host suite | PASS | 101/101 upstream, x86-64 |
| ARM64 sodium/audio/hev native build, ABI/LOAD 16384 | PASS | NDK compile/link + llvm-readelf; только структурная проверка ELF |
| Java→DEX→APK четырёх приложений | PASS | Официальные javac, D8, aapt2, zipalign, apksigner |
| Одинаковый тестовый сертификат и actual APK verify | PASS | Четыре SDK apksigner + четыре точной встроенной Google apksig 9.4.1 |
| Реально изменённый APK | PASS | SDK apksigner и встроенная apksig отклонили |
| Owner public APK verifier | PASS | 11 Python tests: actual SDK signed/tampered APK + 10 помеченных adversarial parser fixtures; ключи не читаются |
| Android install/PackageInstaller, Binder spoof/cert lineage, FLAG_SECURE/overlays/биометрия | NOT_RUN | Нет устройства, USB, KVM или эмулятора |
| OS VPN/protect(fd), DNS/WebRTC/IPv6 leaks, kill switch, смена сети | NOT_RUN | Нужна Android-приёмка; host forwarding не доказывает свойства ОС |
| Полный per-app Tor VPN, Always-on/lockdown | BLOCKED | Реализован только ограниченный локальный TCP/DNS mode; manifest не заявляет Always-on |
| Реальная Mail доставка через Tor/staging Relay на двух устройствах | NOT_RUN | Local integration не заменяет испытание |
| Android голосовой звонок/сигнализация/onion listener/защищённый входящий экран | BLOCKED | Codec и TLS адаптеры реализованы; сквозная Android сессия не подключена |
| AudioRecord/AudioTrack, hardware AEC, маршруты устройств | NOT_RUN | Код собран; физического аудиоустройства нет |
| Doze/App Standby/уведомления/батарея | NOT_RUN | Нужны Android-устройства |
| Полная Mail миграция/архив/старые letter password/FF1 GUI/P2P/background/500МБ вложения | BLOCKED | Реализованы узкий защищённый импорт identity/контактов и текстовая Mail; пакет максимум 192 КиБ |
| Owner APK signing/rotation/updater E2E | NOT_RUN | Ключ владельца не получался/не использовался |

145 host-тестов включены в ANDROID-JVM-TESTS-6.0.0.log; 7 actual-service integration и upstream suites учитываются отдельно. Тесты не выданы за нативную Android приёмку. Реальные логи и source/artifact SHA находятся в evidence-checkpoint. Тестовые сертификаты не являются доверенными production сертификатами.

Во время разработки raw-IP тест выявил double-free pbuf при слишком раннем освобождении UDP-пакета. Drop исправлен установкой штатного одноразового lwIP receive callback; весь native-engine/gateway прогон повторён. Первая libsodium upstream suite обнаружила недостающий execute bit скомпилированного тестового ELF; восстановлен только режим compiled ELF и повторена вся suite, итог 101 PASS/0 FAIL.

BCJSSE источник 1.86 проверен: публичный JSSE startHandshake после установки канала отклоняет повторную renegotiation. Адаптер не использует reflection/собственный rekey. Проверен standard peer-initiated KeyUpdate и ответ BCJSSE. Периодический ручной Android rekey не объявляется реализованным; это отдельный gate интеграции звонка. Предупреждения BCJSSE о неподдерживаемых SHA1 disabledAlgorithms из JDK не отменяют ограничения адаптера: только TLS1.3 AEAD suites и exact Ed25519 certificate/delegation pin.

Источник official SDK/JAR/NDK/Opus/Speex/hev и лицензии закреплены в third-party и native provenance. Источник libsodium — отдельно аутентифицированный signed snapshot 18.10.2026; desktop pin не менялся. Ни один секрет владельца не использован.
