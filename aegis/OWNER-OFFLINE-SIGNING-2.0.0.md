# Офлайн-подпись владельцем

productionReady=false. Этот development candidate нельзя публиковать как Stable или подписывать для production feed до закрытия RELEASE-GATES-2.0.0.json.

Приватный Ed25519 release key остаётся у владельца. Он не использовался и не запрашивался. Pinned public key не менялся. updates/stable.json и .sig не менялись.

После завершения разработки: Build → Tests → SHA-256 → manifest → offline Ed25519 signature владельца → verification → отдельно разрешённый GitHub Release → signed feed. Подпись должна быть над точными байтами финального manifest. Пересборка или изменение артефактов требует новых hash/manifest/signature. Используйте существующий owner signing workflow 1.5.0 как форматный образец; не подписывайте черновик или перечень блокировок.

Updater E2E требует отдельного тестового канала с корректно подписанными артефактами, установки, перезапуска, проверки профиля/архива/тем и принудительно воспроизводимого rollback. Проверка manifest отдельно не считается E2E. Production Stable feed для испытаний запрещён.
