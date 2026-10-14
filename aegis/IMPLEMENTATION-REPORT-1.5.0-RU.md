# Реализация АЕГИС 1.5.0 — отчёт владельцу

База опубликованного1.2.0: binaries70f80c27c13321d3ad8f7c8d7fa630862c56c56d, sourceoverlay8dd290af025921c16c40798f71b7958878524faf. Аудит и изменения — development/aegis-1.5.0. Exact sourcecommit/hash финального кандидата указан вBUILD-PROVENANCE.json/SHA256SUMS. Нельзя объявлять независимый securityaudit: его не было.

## Реализовано

Независимое archivecore (ArchiveCrypto/EncryptedArchive/ArchiveBackup/ArchiveDocuments/PdfWorkerMain/ArchiveEntry), отдельныйpassword/optionalrecovery/DEKwrap, file/index/catalogAEAD, privateACL/POSIX, lock/autolock, import/export/folders/tags/favorite/search/filters/sort/trash/quota/dedup, encryptedbackup/schedule/restore/merge/repaircopy, localtext/image/PDFpreview. ArchiveView выполняетheavyoperationsотдельноотFX, не пересоздаёт сеть/криптографию письма приthemechange. Опасныеоперации требуютinlineconfirm; noextraStage.

MessengerApp/MailViewer: new6sectionnavigation/compactheader/mailcompose/settingscategories/noFriendsUI/nopopuptoasts; one retention selector сохраняет разныеwireTTL/lifecycle semantics; archiveaction gated onreveal+disappearingwarning; autoTor и inline accountreauth/allowedoffline. ThemeManager/AppearanceEngine/16presets/legacygreen/fonts/layouts сохранены; Appearance navigation безопасносопоставлена.

NetworkService/ClientSession: boundedroot-signedroutecache, preservePeer/ControlonRelayPUBLISHfailure, nofalseP2Pack, existingRelayfallback/packetIDdedup; technicalrouteAEADsidecar. No productionRelay/protocol1/serveroperation/identity/cryptochanges. Plaintext never goesNetworkService.

LocalStore/ProfileSnapshot/ClientUpgrade: encryptedUIprefs/routeevidence, rekeypreservation, managedarchives snapshotrestore включаяотсутствующийrestoredsibling, per-versionfullbackup beforemigration, updater waitsarchiveworker. Archiveсоздаётся пустым только пользователем. Исчезающихtimersbackfill нет.

## Проверки и доказательства

TEST-REPORT-1.5.0.md иevidence содержатexactJUnit/JavaFX/releasechecks; screenshots — реальноеrendering syntheticdata. P2P-VERIFICATION-1.5.0.md разделяетsyntheticlocalSOCKS, actualTorstaging и NOT_RUNnative/crossnetwork. Cryptotests неsecuritycertification. WindowsServerCI неWindows11; Ubuntu неCachyOSKDE.

## Необходимая приёмка

NativeWindows11/KDEWayland/X11/DPI/reboot/ExplorerDolphin/OSACL, tworealdeviceP2P и exactownerSignedupdater120→150/install/restart/rollback остаютсяотдельнымиgate. Privatekey остаётсявладельцу; manifestunsigned. ProductionReady=false покахотьmandatorycriterionнепроверен. Пакетcandidateготовитсядляэтихиспытаний, Stableнепубликуетсясамостоятельно.

## Ограничения

ПеречисленывARCHIVE/THREAT_MODEL: strictpreviewlimits; autbackupтолькоприunlockedrunning; mergepartialdurableoncancel; nofreshnessproofnewdevice; JavaGCwipebest-effort; explicitplaintextfileexport; powerlossnativepending; noSSDphysicalerase; privateACLнеадминистраторзащита; PDFworkerresourceisolationнеOSsandbox. Сторонниекопии/backupнеуничтожаютсяpurge. Externalcontainers/backupfoldersmigrationнетронуты, ихкопииделаютсяархивнымbackup.

## Передача

Итог: SetupEXE/portableZIP/AppImage/source/client-source/nativekit, reports/acceptance/SHA256/unsignedstable+beta+publickey/offlinesigningguide. Exactbinaries/hash/manifest должныбытьоднойсборкой. ПередofflineподписьювладелецпроверяеттестыиSHA, затемподписываетточныебайты. КомандаподписиGitHubuploadнеделает. Publicationтолькопослеотдельногоразрешения.
