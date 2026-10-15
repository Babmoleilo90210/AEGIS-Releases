# Модель угроз личного архива1.5.0

Независимый security audit не проводился. Цель: украденный/скопированный закрытый контейнер и обычный доступ через файловый менеджер не раскрывают содержимое без отдельного секрета. Ограничения процесса/GC/SSD/полного администратора описаны ниже.

| ID | Угроза и предусмотренная защита/ограничение |
|---|---|
| SEC-01 | Offline password brute force: Argon2id64MiB,t3,p1, независимая соль; слабый пароль остаётся уязвимым. |
| SEC-02 | Копирование контейнера: только encrypted wrappers/каталог/UUID/объекты; без пароля/recovery недоступен. |
| SEC-03 | Подмена: AEAD с archive/object/type AAD, UUID, SHA/размер; переставленные объекты не проходят проверку. |
| SEC-04 | Повреждение metadata: fail closed; ремонт только копии из previous/AEAD descriptors, не обещает восстановить разрушенный ciphertext. |
| SEC-05 | Уникальные nonce12 через SecureRandom; Tink Streaming AEAD самостоятельно управляет segment nonce/HKDF. Не пользовательские алгоритмы. |
| SEC-06 | Индекс/импорт/backup/PDF без document plaintext temp; явный export имеет приватный partial в выбранной папке. Crash может оставить partial. |
| SEC-07 | Нет payload/key/password logs; helper stderr discard; безопасные ошибки в UI. Имена/путь выбранного файла могут показываться самому пользователю. |
| SEC-08 | requestLock немедленно запрещает доступ/устаревший результат; close обнуляет DEK/recovery arrays, очищает UI/metadata/query. GC/render/native копии не гарантированно стерты. |
| SEC-09 | PDFBox3.0.8 только memory input, headless дочерний JVM192МБ/12с, ограничение20МБ/512pages/text2МБ/preview4MP; без JavaScript/URL load. Это ресурсная изоляция, не полноценный OS sandbox против уязвимости decoder. |
| SEC-10 | JPG/PNG/WebP magic+decoder, source64MP/preview4MP; MemoryCacheImageInputStream, без disk image cache. |
| SEC-11 | Backup framing bounded/allowlist/anti-traversal/symlink reject, nested folders bound12, entries20k, file1ГБ/limit100ГБ. |
| SEC-12 | Внешняя streamingAEAD и authenticated header, полный tag/hash перед restore atomic rename; подмена backup отвергается. |
| SEC-13 | External encrypted revision/hash anchor и prepare/commit; локальный rollback отвергается. На новом устройстве без прежнего anchor свежесть недоказуема. Полный snapshot ОС/anchor rollback не предотвращается. |
| SEC-14 | Export после подтверждения создаёт ordinary plaintext, перестаёт защищаться контейнером; не обещается уничтожение чужих копий. |
| SEC-15 | External Desktop.open только после предупреждения/экспорта; сторонняя программа может кэшировать/выполнять содержимое. |
| SEC-16 | Linux700/600, NTFS owner-only ACL; NTFS/POSIX необходимы для рабочей папки, encrypted backup допустим на съёмном носителе. |
| SEC-17 | Администратор/debugger/keylogger/вредоносная ОС читают unlocked process; шифрование at-rest не предотвращает. |
| SEC-18 | Password change заменяет только AEAD wrapper атомарно с prepared guard; исходные objects unchanged. Старые backup сохраняют старый пароль. |
| SEC-19 | Recovery32 — самостоятельный секрет, компрометация даёт доступ; rotation/disable защищает текущую wrapper, не ранее сохранённые копии. |
| SEC-20 | Ciphertext staging, file force + atomic rename + prepared guard. Linux fsync directory; Java Windows directory fsync отсутствует. Физическое отключение питания на native пока NOT_RUN. |

Архив не добавляет сетевых destinations, keys не попадают Relay/Tor. При наличии malware с полным доступом plaintext/password capture возможны. Точные обязательные native/OS/перенос/питание испытания перечислены в acceptance kit. PASS unit/synthetic filesystem tests не независимая сертификация.

Смена пароля/recovery перезащищает тот же DEK и не отзывает уже извлечённый DEK. Знающий старый секрет и имеющий старую wrapper/backup может извлечь DEK; при его компрометации требуется новый пустой архив с новым случайным ключом и явный перенос.
