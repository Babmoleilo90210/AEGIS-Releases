# Отчёт испытаний АЕГИС 1.5.0

14.10.2026. productionReady=false. Реальные результаты CI и последние локальные XML/log находятся в evidence. Этот документ не объявляет native PASS на недоступных системах.

Локально Java21: common4PASS; client-core143PASS/1SKIP (WindowsDPAPI наLinux); Relay3PASS; integration13PASS. Всего163PASS/1SKIP. Включены20 новых archivecrypto/storage/document/security tests и managedarchive snapshot restore. Security release Python tests — см. exact log/count в evidence.

JavaFX Monocle: Archive150Smoke PASS (actual create/import/preview/search/lock, three views/zones, responsive window, encryptedprefs, oneStage, draft); Appearance115Smoke PASS (22presets,16new, preview/apply/cancel/persistence/layouts/logicalscale100/125/150/200/systemevents with ephemeralEd25519). Скриншоты — actualJavaFX rendering syntheticprofile, неGeneratedIllustrations/неWindows11/KDE.

Проверены: неправильный пароль/recovery; passwordchangeobjectsunchanged; randomsalt/nonce/tamperedwrapper; swappedcipherobjects; folderdepth/cycle; indexcorruption/rebuild; knownrollback+preparedguard crashside; copy/merge/encryptedbackups/tamper; explicitexport/closedgate; importcancel/noorphan; localPDF child actualrender/text/noactivecontent; PDF malformedreject; migration snapshot с missingrestoredcontainer; Relaystopped cachedroute noRelaypayload/duplicates; ordinarymail/lifecycle/Ed25519/Tor-only regressions.

Automatic vs native matrix фиксируется отдельно по ARC-01–40,UI-01–30,P2P-01–10,SEC-01–20. PASS filesystemtest не заменяет Explorer/Dolphin/NTFSnative. Native Windows11, CachyOSWayland, CachyOSX11, twophysicalnetworks, exactownerSigned120→150install/restart/rollback — NOT_RUN. Productionrelay/feed/identity/signingprivatekey не использованы/не изменены.

CI Ubuntu structuralpackaging, CI WindowsServer packagedruntime/launcher/Setup/UI и realTorDirect/Snowflake/prodfeedread-only/staging должны оцениваться по приложеннымRESULTS, не предполагаются успешными заранее. ОшибкаTor изограниченнойсети — NOT_RUN/FAIL_OR_UNAVAILABLE, а неPASS. Ownerprivate signature необходима для финальногоE2E; ephemeralfixture проверяетschema/hash/package/state отдельно.

Известныеограничения: automaticarchivebackuponlyunlocked/running; recovery/oldbackup сохраняют старуюзащиту; firstdevice freshness невозможно доказать безanchor; JavaGCmemorywipebest-effort; PDF192MiB12s неOSsandbox; maxpreviewtext2MB/PDF20MB512pages/image64MP; explicitexportplaintextpartialcrash; physicalpowerlossnotrun; inheriteddisappearingpolicyconservativeonOSreboot. Всё это вынесено вARCHIVE/THREAT_MODEL.
