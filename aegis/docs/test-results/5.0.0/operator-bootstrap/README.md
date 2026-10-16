# Проверка первоначальной регистрации worker

Воспроизводимый внешний fixture использует production WorkerCoordinatorClient/CommunityHttpServer/SQLite и две независимые тестовые identity с TOTP. Меняется только Tor TCP connector на loopback. Это не настоящий Tor, не нативная приёмка и не production deployment. Секреты генерируются временно; в журнал попадают только результаты проверок.

Сопоставьте SHA трёх используемых production JAR с RESULTS.json. Под Java 21 JDK, используя распакованные серверный и worker-пакеты:

```sh
mkdir test-classes test-state
javac --release 21 -cp "/path/to/community-server/lib/*:/path/to/news-worker/lib/*" -d test-classes WorkerBootstrapProof.java
java -cp "test-classes:/path/to/community-server/lib/*:/path/to/news-worker/lib/*" org.securemail.worker.WorkerBootstrapProof test-state
```

Используйте отдельный тестовый каталог. После проверки удалите созданный внутри test-state каталог proof-*, содержащий временную SQLite; не включайте его в diagnostics или релиз. Исходный выполненный прогон и его финальные JAR SHA перечислены в RESULTS.json; временное состояние выполненного прогона уже удалено. Этот отдельный fixture не суммируется повторно с 622 JUnit-тестами.
