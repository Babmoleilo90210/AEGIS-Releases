# АЕГИС 1.2.0 — итоговый отчёт release candidate

**productionReady=false.** Реализован client-only lifecycle без изменений production Relay 0.2.0/protocol 1. Обязательная Windows 11/CachyOS и owner-signed updater/restart/rollback приёмка остаётся владельцу. Приватный release key не использован, Stable не опубликован, production feed/VPS/onion identity не менялись. Independent security audit не проводился.

## Реализовано

- Signed peer capabilities и взаимные ContactAssertion для Friends, ожидание неподтверждённого контакта, durable отзыв/блокировка без удаления переписки.
- Encrypted retry queues и четыре статуса, основанные на реальном STORE, durable delivery ACK и recipient-signed display event. Root identity/message digest binding и idempotence; ordinary receipts можно выключить.
- Device-bound disappearing content/attachments: 1 минута–30 дней, countdown после показа, отсутствие plaintext preview, ciphertext deletion и metadata-only tombstone.
- Password/FF1 ввод не является read event; финальный reveal внутри одного окна. Hidden/minimized body не подтверждается. Нераскрытое protected письмо сохраняется после app restart. Неоднозначный прерванный reveal fail closed без вымышленного read.
- Tor card/reconnect, sidebar/maximize, пять Cyrillic TTF семейств, большой avatar/zoom/Escape, updater helper isolation, backup/migration и прежние темы/макеты сохранены.
- Backwards clock больше не удаляет всю обычную почту: persistent high-water time сохраняет deadlines.

## Фактически выполненные проверки

Build commit `70f80c27c13321d3ad8f7c8d7fa630862c56c56d`, [CI run 38356575633](https://github.com/Babmoleilo90210/AEGIS-Releases/actions/runs/38356575633). Exact binaries: Windows Setup/portable, CachyOS AppImage, matching client/common JARs. Java21/Tor/Snowflake/libsodium внутри; Relay JAR в приложение не включён.

| Проверка | Результат |
|---|---|
| JUnit | 141 PASS, 1 SKIP, 0 FAIL |
| Release/security | 16 PASS |
| Actual headless JavaFX | 9 suites PASS |
| Windows Server exact-package checks | 10 PASS |
| Ubuntu exact-package/Tor checks | 8 PASS |
| Linux actual Tor staging | PASS: two disposable identities, signed capabilities, Friends, P2P, offline Relay, read receipt, file, real 60-second expiry, revoke |
| Previous 1.1.0/1.1.1/1.1.5 verifier fixture | PASS for exact new artifact size/SHA/schema with ephemeral test signature; production verifier rejects that key |
| Actual Direct/Snowflake HTTPS | PASS: TLS/default truststore, production Ed25519, interrupted/resumed SHA-pinned source download |
| Windows 11 / CachyOS KDE Wayland / X11 | NOT_RUN |
| Different physical networks | NOT_RUN |
| Owner-signed update install/restart/rollback | NOT_RUN |

Linux DPAPI JUnit skip is expected; Windows Server DPAPI and device boot-clock/guard checks ran. Windows Server is not Windows 11. Monocle is not native KDE. One Tor process/one temporary Linux Relay is not a cross-network test. Native kit carries explicit NOT_RUN cases; the owner must fill evidence.

## Ограничения

Opened disappearing letters fail closed after OS reboot, missing/corrupt device guard or ambiguous reveal; they may disappear earlier than the selected duration. App restart on the same boot retains countdown. This is a documented availability tradeoff, not an assertion of trusted elapsed time across reboot. Recipient device binding and a ledger outside profile rollback prevent resetting a timer through normal old-profile restore. Hostile OS/modified recipient, screenshots, clipboard, manual extraction and exported copies remain outside deletion guarantees.

FF1 version 3 has no correctness oracle. Manual reveal acknowledges a displayed candidate, not proof that the human supplied the right FF1 code or understood the text. Account identity and cipher algorithms remain unchanged; a separate locally generated device key is encrypted in lifecycle state. Legacy vault/common protocol/Relay formats remain intact. 36 protected files are byte-identical; reviewed LocalStore/PlainMessage changes are listed separately. Identity-only backup is not full profile/device-state backup. Drafts remain RAM-only as in the baseline and block update installation until finished/discarded.

The staging kit is Linux-only because the existing Debian Relay uses POSIX filesystem permissions. Windows clients communicate with a separate Linux Relay; no Windows-specific Relay rewrite was performed.

## Устранённые ошибки проверок

Initial runs exposed old clock/onion test fixtures omitted from the source overlay, a native-kit Path name error, omitted nested staging JARs and a Windows port-readiness race. They were corrected and subsequent exact-package results are included. The first final Linux attempt exhausted three bounded signed probes while a cold onion descriptor was unavailable; it is recorded as FAIL_OR_UNAVAILABLE in evidence/packaged-linux-attempt1. Exactly one CI job rerun, using identical binaries, passed actual staging in 264.54 seconds. The earlier failure is preserved and is not rewritten to PASS. Current test logs/JSON/XML are in evidence; synthetic screenshots are separate from real user data.

## Дальше

Follow NATIVE-ACCEPTANCE-1.2.0.md, LIFECYCLE-1.2.0.md and OWNER-OFFLINE-SIGNING-1.2.0.md. Every changed binary/source/checksum requires regenerated manifest and a new owner signature. The included stable and beta-test inputs are unsigned; they must not be installed/published as a completed Stable until the mandatory gates pass.
