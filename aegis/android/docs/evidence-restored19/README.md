# Восстановленный Android: реальные проверки 19.10.2026

`productionReady=false`. JVM/JNI/SQL/HTTP/TLS проверки выполнены на Linux x86-64. ARM64 ELF собраны; на Android они не исполнялись. Ни Android Binder, ни FLAG_SECURE, ни Tor-сеть, ни физические микрофоны этим прогоном не проверены.

200 проверок в ANDROID-JVM-TESTS.log: 31 policy + 13 delegation + 4 SOCKS + 22 mail crypto + 13 gateway + 6 native TUN + 21 voice handoff + 14 Tor policy + 16 lifecycle + 29 media + 31 BCJSSE↔SunJSSE. Дополнительно 7 Mail и 12 Glas actual local integration. Не складывайте их с повторными прогонами тех же сценариев.

DIAGNOSTIC-* относится к фактически собранным четырём unsigned и четырём TEST APK из промежуточного рабочего дерева. Состав непосредственных исходников неизменен за весь прогон, но это ещё не финальный общий commit. Новый финальный provenance обязан создаваться после заморозки общего commit и `build.py --expected-commit`. Старые файлы evidence-checkpoint относятся к 18.10 и сохранены как история, не доказательство новых APK.

Входы SDK и зависимости повторно получены из официальных источников с прежними SHA256. Исключение — изменяемый официальный stable-архив libsodium; старый SHA отклонён, обе minisign-подписи нового архива проверены закреплённым официальным ключом. Новый Android-only SHA, версия, commit, отличие от upstream release tag и сравнение 537 crypto/test-файлов с текущим stable сохранены в LIBSODIUM-REPIN-20261019.json. Старый архив отсутствует; сравнение его полного дерева не заявлено. Desktop pin не изменён.
