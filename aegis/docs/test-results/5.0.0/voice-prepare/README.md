# Целевая проверка разрешений входящего Гласа до TLS

Реальный прогон `VoiceCallServiceTest`: 20/20 успешных, 0 пропущенных. Java 21 пересобрала все текущие common-protocol/client-core исходники; `RESULTS.json` содержит SHA-256 и подтверждение неизменности source input во время проверки. XML и журналы сохранены рядом. Это отдельный source cut, а не финальный общий прогон релизного commit.

Новые проверки блокируют `prepare` на bounded incoming handshake worker и доказывают, что до свежего проверенного организационного решения не возвращается ответный offer/TLS и не открываются аудиоустройства. После разрешения выполняются настоящие identity-bound mutual JSSE TLS, принятие вызова и передача тестового аудиокадра. `prepare` вызывается один раз; audio/tick используют только cache-only `authorize`. Неизвестный, заблокированный, явно запрещённый контакт и выключенный incoming master switch не вызывают подготовку. IOException подготовки закрывает raw соединение без offer, TLS, media или приватной причины отказа.

Остальные реальные state-controller тесты сохраняют consent, мьют, replay, key replacement, reconnect, bounded deadlines, совместимый обмен письмом во время звонка и освобождение устройств. Loopback connectors и синтетические media-device seams прямо обозначены; это не Tor, реальный микрофон, акустические испытания, Windows/CachyOS или два физических устройства. `productionReady=false`.

Воспроизведение требует проверенные Java 21, JAR из INPUTS-SHA256.json и базовые комплектные native files. Скрипт очищает только собственные classes/tests/XML внутри output:

```sh
python3 reproduce.py --repo /path/to/aegis/aegis --inputs-root /path/to/verified-inputs --output /path/to/new-voice-results
```
