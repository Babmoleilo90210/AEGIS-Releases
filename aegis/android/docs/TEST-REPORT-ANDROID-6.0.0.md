# Android 6.0.0: восстановление и проверки 19.10.2026

`productionReady=false`. Тестовая среда: Linux x86-64, JDK21.0.12.1+1, официальный SDK36/build-tools36.1, NDKr29. Это не Android-устройство.

| Проверка | Фактический результат |
|---|---|
| Production policy / AppGrantProposal / SOCKS | 31 + 13 + 4 PASS_LOCAL |
| JNI/libsodium/E2EE/AEB1/AEB2/password/FF1 | 22 PASS_LOCAL |
| Gateway / native raw-IP hev-lwIP | 13 + 6 PASS_LOCAL |
| Voice handoff / Tor policy / lifecycle | 21 + 14 + 16 PASS_LOCAL |
| Opus/SpeexDSP pipeline / BCJSSE-desktop TLS1.3 | 29 + 31 PASS_LOCAL |
| Android Mail adapter + настоящие Identity HTTP/SQLite Relay | 7 PASS_LOCAL |
| Android Glas controller + реальные Identity/signaling HTTP/SQL/TLS/JNI Opus | 12 PASS_LOCAL |
| Upstream libsodium / Opus host suites | 101/101 + 16/16 PASS_LOCAL |
| ARM64 sodium/audio/hev | Собраны ELF с 16-КиБ LOAD alignment; ARM64 execution NOT_RUN |
| Четыре unsigned + четыре TEST APK | Реально собраны, SDK и embedded apksig проверили; изменённый APK отклонён |
| Android install/Binder/биометрия/FLAG_SECURE/overlays/VPN leaks/mic/Doze | NOT_RUN |
| Два физических устройства, разные сети, публичный Tor | NOT_RUN |

В основных 200 host-проверках повторные прогоны не суммируются. Mail и Glas используют явно синтетические loopback SOCKS/onion и PCM fixtures; фактические HTTP/SQL/криптографические компоненты не заменены mock. Аудио-warning playback-frame/xrun в синтетическом прогоне сохранён в полном логе; пригодность физической аудиосистемы не заявляется.

Изменения после восстановления: обязательный выход и отзыв исполняются отдельной ограниченной очередью независимо от Activity pause/destroy; блокировка/выход инвалидируют поздний Identity login; data callback не восстанавливает старую страницу; очередь удалённых password tasks очищает массивы при отмене/закрытии. Добавлены реальная отправка и чтение поддерживаемых letter-password/FF1 писем существующим LetterEnvelope, без нового шифра и без oracle правильности FF1.

Доказательства — `evidence-restored19`. DIAGNOSTIC provenance описывает промежуточную сборку с неизменными непосредственными inputs. Итоговые APK требуют повторного `build.py --expected-commit` после общего frozen commit.

Полные блокеры перечислены в RELEASE-GATES-ANDROID-6.0.0.json: архив/P2P/500МиБ UI/полная миграция Android, защищённый фоновый входящий вызов, фоновая Tor-доставка уведомлений, Communities/News/Library UI, автоматический установщик сторонних приложений, подписанные базы угроз и полный per-app Tor/Always-on/lockdown ещё не завершены. Эти функции не объявлены реализованными.
