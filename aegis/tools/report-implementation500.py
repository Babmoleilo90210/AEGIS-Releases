#!/usr/bin/env python3
"""Generate truthful frozen-source provenance and the Russian owner report.

No signing, deployment, publication, readiness promotion or test execution.
Run after report-release500.py and actual client/server/native packaging.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BASE = '699a3260fa456a40d4d16d3b711c957b088f9ab3'
BINARIES = ('AEGIS-Setup-5.0.0-x64.exe', 'AEGIS-5.0.0-Windows-x64.zip', 'AEGIS-5.0.0-CachyOS-x86_64.AppImage')

def sha(p):
    if p.is_symlink() or not p.is_file():
        raise ValueError('Missing/unsafe artifact: ' + p.name)
    with p.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], timeout=60).decode().strip()

def write(out, name, value):
    if (out/name).is_symlink():
        raise ValueError('Output symlink forbidden')
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    (out/name).write_text(text, encoding='utf-8')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    args = parser.parse_args()
    out = args.artifacts.resolve()
    if not re.fullmatch('[0-9a-f]{40}', args.expected_commit) or git('rev-parse', 'HEAD') != args.expected_commit:
        raise ValueError('Wrong exact frozen source commit')
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Commit source/evidence before generating final provenance')
    identity = json.loads((out/'SOURCE-COMMIT-5.0.0.json').read_text('utf-8'))
    if identity.get('sourceCommit') != args.expected_commit or identity.get('baseCommit') != BASE:
        raise ValueError('Source archive identity mismatch')
    final = json.loads((out/'FINAL-VERIFICATION-5.0.0.json').read_text('utf-8'))
    if final.get('sourceCommit') != args.expected_commit or final.get('productionReady') is not False:
        raise ValueError('This generator only reports an unapproved owner candidate')
    binary = {name:sha(out/name) for name in BINARIES}
    with zipfile.ZipFile(out/BINARIES[1]) as z:
        names = [n for n in z.namelist() if n.endswith('/BUILD-INPUTS.json')]
        if len(names) != 1:
            raise ValueError('Ambiguous client build provenance')
        inputs = json.loads(z.read(names[0]))
    if inputs.get('sourceCommit') != args.expected_commit:
        raise ValueError('Windows package built from another source')
    jar_dir = ROOT/'build/local-java21'
    jars = {p.name:sha(p) for p in sorted(jar_dir.glob('*.jar')) if p.name in {
        'common-protocol.jar','client-core.jar','client-ui.jar','relay-server.jar','community-server.jar','news-worker.jar'}}
    if len(jars) != 6:
        raise ValueError('All six production module JARs are required')
    changed = git('diff', '--stat', BASE, args.expected_commit)
    audit_path = ROOT/'docs/test-results/5.0.0/source-audit/RESULTS.json'
    source_audit = json.loads(audit_path.read_text('utf-8'))
    top = Path(git('rev-parse', '--show-toplevel'))
    protected = {}
    for name in ('updates/stable.json','updates/stable.json.sig','updates/release-public.pem','aegis/updates/release-public.pem'):
        original = git('rev-parse', BASE+':'+name)
        if git('hash-object', str(top/name)) != original:
            raise ValueError('Protected production feed or pinned release key changed: '+name)
        protected[name] = {'unchangedFromBase':True,'sha256':sha(top/name)}
    write(out, 'SOURCE-PROVENANCE-5.0.0.json', {
        **identity, 'baseVersion':'2.5.0', 'basePublishedAsPrerelease':True,
        'baseSourceArchiveSha256':source_audit['sourceZipSha256'],
        'baseComparedFiles':source_audit['sourceArchiveComparedFiles'],
        'baseMismatches':source_audit['mismatches'],
        'sourceAuditSha256':sha(audit_path),
        'protectedProductionFiles':protected,
        'sourceArtifactsSha256':{n:sha(out/n) for n in ('AEGIS-5.0.0-source.zip','AEGIS-5.0.0-client-source.zip')},
        'sourceArchives':'Exact frozen Git payloads, modes and inserted source identity; verified by assemble-release500.py',
        'ownerPrivateKeyUsed':False, 'productionRelayChanged':False, 'stableFeedChanged':False})
    write(out, 'BUILD-PROVENANCE-5.0.0.json', {
        **identity, 'version':'5.0.0', 'packageKind':'UNSIGNED_OWNER_ACCEPTANCE_CANDIDATE',
        'productionReady':False, 'binaryArtifactSha256':binary, 'moduleJarSha256':jars,
        'javaCompiler':'Eclipse Temurin 21.0.12.1+1',
        'jdkArchiveSha256':'ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94',
        'gradle':'9.8.0', 'gradleArchiveSha256':'bafd5ce9cfaea0fbccfdc8439a1ac42fbd4cd9c89dc9a988228d8a2639a58e6c',
        'buildCommands':['gradle --no-daemon --max-workers=1 test :client-ui:jar :community-server:jar :news-worker:jar :relay-server:jar --continue --rerun-tasks',
                         'tools/stage-candidate500.py; packaging/package-clients500.py --expected-commit EXACT_COMMIT',
                         'tools/package-community500.py; tools/package-native500.py; tools/assemble-release500.py'],
        'clientBuildInputs':inputs,
        'reproducibility':'Gradle JAR order/timestamps are deterministic; native package inputs and hashes are pinned. Full independent machine reproducibility is not asserted.',
        'nativeAcceptance':'NOT_RUN', 'nativeWindowsExecution':'NOT_RUN',
        'ownerPrivateKeyUsed':False, 'publicationPerformed':False, 'productionRelayOrFeedChanged':False})
    hashes = '\n'.join('- `' + digest + '  ' + name + '`' for name,digest in binary.items())
    report = f'''# АЕГИС 5.0.0 — отчёт о реализации

Статус: кандидат для приёмки владельцем. **productionReady=false**. Пакет не опубликован как Stable, production Relay и Stable feed не изменены, приватный release-signing key не использовался. Обязательная приёмка именно этих бинарников ещё не подтверждена.

## Исходная база и итог

База: точные опубликованные исходники 2.5.0 «Взор и Глас», commit `{BASE}`. Сам релиз v2.5.0 опубликован как тестовый prerelease; этот отчёт не переименовывает его в проверенный Stable. Проверено побайтовое совпадение 1210 файлов исходного архива, расхождений нет. Две shared-истории получены и декодированы; реальные пользовательские изображения навигации, контактов, поиска, профиля, настроек и дефектов архива/Взора изучены. Приватные исходные истории в публичный пакет не включены.

Итоговый commit: `{args.expected_commit}`. Дерево: `{identity['sourceTree']}`. Все платформенные клиентские пакеты используют одни и те же Gradle JAR приложения. Файлы исходников проверяются относительно точного дерева Git. SOURCE-PROVENANCE и BUILD-PROVENANCE содержат привязку к commit и SHA входов/выходов.

## Реализованные модули

- **common-protocol:** строгая спецификация подписанных запросов/ответов общей системы, отделённая от прежнего протокола писем. Ed25519, SHA-256, одноразовый nonce, service audience, identity и хеш точного запроса связывают ответ с вызвавшим пользователем.
- **client-core:** Tor-only клиент общего сервера, ограниченные HTTP/JSON, отзыв/epoch, отдельный шифрованный кэш, интеграция организационных голосовых разрешений, миграция навигации и схемы голосовых правил. Существующие identity и ключи архива не меняются.
- **client-ui:** три блока навигации, шесть категорий настроек, организации, новости, календарь, библиотека-граф и встроенное администрирование. Верхняя панель, контакты, письма, 16 пресетов и макеты сохранены.
- **community-server:** отдельный Java21/SQLite сервер полномочий, организаций, новостей, мероприятий, библиотеки, вложений, уведомлений, аудита и центрального координатора ИИ. Производственный почтовый Relay не превращён в универсальный сервер.
- **news-worker:** отдельный ограниченный узел сбора публичных источников, с подписями, арендой заданий, повтором, очередью и бюджетом. Он не читает письма, личный архив, закрытую библиотеку или административные секреты.
- **Сборка и приёмка:** изолированные клиентские и серверные пакеты, Windows Setup/Portable, AppImage, комплект нативных сценариев, точные исходники, evidence, проверки структуры и unsigned manifest.

## Организации и полномочия

Заявки содержат назначение, описание, необязательный нормализованный город и эмблему. Публикация организации в каталоге требует решения уполномоченной администрации. Есть свободное вступление, заявки, приглашения, состав, должности, удаление участника и отзыв роли. Организация содержит главную, новости, события, состав, библиотеку и управление; групповые чаты не добавлены.

Глобальные и организационные роли создаются конструктором, образуют проверяемый DAG наследования и действуют только в своей области. Уровень допуска отделён от прав чтения/изменения/публикации/модерации/удаления/управления. Сервер проверяет делегирование и права при каждой операции. NEWS_GLOBAL_PUBLISH нельзя выдать себе организационной ролью. Подтверждение личности, должности и внутренний допуск независимы; пользователь не присваивает себе официальный значок.

Административный интерфейс встроен в настройки. Начальные полномочия выдаются отдельной операторской процедурой двум проверенным криптографическим identity, не nickname. Для защищённых операций нужны повторная авторизация существующим Relay и серверный TOTP. Критические запросы имеют неизменяемый payload, срок и подтверждаются другим администратором; инициатор не подтверждает себя. Аудит имеет цепочку SHA и HMAC с отдельным от SQLite ключом.

## Новости, события и ИИ

Реализованы всеобщая, городская и организационная ленты, ручной выбор города, создание/редактирование/модерация/публикация/отзыв, источники и история исправлений, реакции, опросы, вложения. Мероприятия имеют ограничение мест, регистрацию, перенос/отмену, уведомления и месячный календарь. Географический охват отделён от ACL. IP-геолокация не используется.

Центральный координатор управляет городами, разрешёнными источниками, расписанием 15–30 минут, работниками, бюджетами и политикой. Реальные адаптеры RSS/Atom и HTML получают только публичные разрешённые страницы с ограничениями, TLS, SSRF-защитой и robots policy. Работник выполняет анализ; центральный сервер независимо получает подтверждения и формирует собственный редакционный текст перед публикацией. Выход модели не является полномочием. Две перепечатки не считаются двумя независимыми источниками; группы происхождения задаются политикой. Сомнительные, противоречивые и особо важные сообщения направляются редактору.

Поддержаны Ollama и OpenAI-compatible API, модель/провайдер выбираются администрацией. Конкретная production-модель и реальные платные API в этой среде **не настроены и не испытаны**. Их названия не выдумываются. Автоматические тесты используют явно обозначенные локальные HTTP-источники и модели; это проверка протокола и политики, не доказательство достоверности реальных новостей. API-ключи не включены в пакет. Отсутствие центральной модели/бюджета/подтверждения не обходится публикацией без проверки.

## Общая библиотека

Общая библиотека отделена от личного архива. Сервер хранит материалы и ACL; это доверенная серверная система, а не E2EE-хранилище. Доступ проверяется для документа, вложений, поиска, графа, версий, экспорта, уведомлений и предложений связей. Страницы ограничены; граф загружается постепенно, недоступные узлы и связи не выдаются.

JavaFX-граф поддерживает дерево, масштаб, перемещение, перетаскивание, выбор, подсветку, фильтры, просмотр и режим списка. Markdown — канонический формат; визуальный редактор блоков сохраняет содержимое при переключении. HTML/JavaScript не исполняется. Сохранение использует версию, чтобы не затереть конкурентные правки. История и восстановление ограничены страницами.

ИИ-связи формируются только для доступных материалов через разрешённую локальную модель; закрытые материалы не передаются внешнему новостному API. Доступ проверяется повторно после анализа и при выдаче результата. Постоянная связь требует разрешённого подтверждения редактора. Кэш клиента ограничен 3MiB/100 материалов/5 минут, зашифрован существующим vault, очищается при выходе/изменении доверия/отказе доступа. Уже просмотренные данные нельзя гарантированно стереть на чужом отключённом устройстве.

## Взор и Глас

Взор сохраняет официальный Tor Browser, проверку OpenPGP закреплённым ключом, атомарную установку и независимый Tor-контекст. Подготовка CachyOS выполняет только разрешённые пакетные операции через Polkit; Windows использует проверенный системный DISM/UAC. Приложение целиком не запускается администратором. Ошибка изоляции блокирует запуск с конкретной диагностикой. Windows Home без проверенной альтернативы штатному Windows Sandbox не заявлен поддерживаемым для Взора.

Глас сохраняет аутентифицированный TLS1.3 поверх onion/Tor-only TCP, существующие identity и Opus. Добавлены независимые входящие/исходящие режимы, выбранные контакты, запреты и явно включаемые организационные исключения. Отказ неизвестным/заблокированным и явный локальный запрет имеют приоритет. Проверка серверного исключения идёт на ограниченном рабочем потоке до защищённой сессии. Захват/воспроизведение не начинаются до согласия и аутентификации; запись разговоров не создаётся. Реальные звонки и задержка между физическими устройствами в этой среде не измерялись.

## Исправленные дефекты и безопасность

Исправлены обрезанные подписи MenuButton архива, размеры и padding, наложение избранного в галерее, компоновка настроек/Взора, навигация и календарные даты при 200%. Действия контакта перенесены в компактное меню. Входные файлы/изображения/JSON ограничены, недоверенный активный HTML не выполняется, секреты не включаются в диагностические отчёты.

При интеграции дополнительно исправлены подмена ответа другого actor с тем же nonce, гонки выхода/сохранения кэша, несогласованный authorization epoch, rekey большого кэша, округление чисел/огромные экспоненты JSON, rollback счётчика неудачных TOTP и доверие неподтверждённым предложениям рабочего узла. Итоги дополнительного аудита ролей и комплектного Tor/OpenSSL отражены в SECURITY-AUDIT и приложенных test-results; незакрытые высокие риски блокируют Stable.

Сохранены шифры и форматы прежних данных. Обычная переписка на долговременных sealed-box identity **не имеет Forward Secrecy**; FS голосовой TLS не является FS всей программы. Enigma — прежний исторический режим с предупреждением. Полная компрометация ОС/драйвера/микрофона/памяти и физическая запись не устраняются Tor или E2EE. Отдельного runtime hash pin перед JNA-load libsodium нет; есть проверка комплектных входов. Аудит без внешнего неизменяемого checkpoint не доказывает отсутствие восстановления целого старого корректного снимка БД.

## Испытания и пределы результата

Точный результат общего прогона, названия проверок и SHA отчётов приведены в TEST-REPORT и FINAL-VERIFICATION. Там разделены JUnit, локальные интеграционные стенды, JavaFX Monocle, структурные проверки пакетов и обязательная нативная приёмка. Реальные PNG находятся в evidence; это снимки JavaFX приложения, а не генерация изображений и не доказательство Windows/CachyOS.

Локальные интеграционные проверки используют настоящие SQLite, Ed25519, зашифрованные vault, HTTP-сервер и SOCKS-стенд, два тестовых identity, ACL/отзыв/граф/кэш/миграцию. SOCKS-стенд не является Tor. Нагрузочные результаты относятся к указанному in-process стенду с 100/1000/3000 материалов; они не являются SLA сети или production-сервера.

В этой среде отсутствуют Windows11, CachyOS KDE Wayland/X11, два физических устройства/две сети и production-сервер общей системы. Их проверки — NOT_RUN. Полный положительный updater E2E с подписью закреплённого ключа владельца, установкой/перезапуском/rollback также NOT_RUN. Старые сведения владельца о тестах 2.5.0 не переносятся на новые бинарники 5.0.0. Реальный сбор production-новостей и установленная модель требуют отдельной приёмки.

## Установка, миграция и подпись

Клиент: README-WINDOWS и README-CACHYOS. Оператор отдельного сервера: COMMUNITY-SERVER и SERVER-DEPLOYMENT-PROPOSAL. Server/worker ZIP не развёртываются автоматически на production Relay; сервер требует JDK21, двух независимых администраторов, защищённых служебных ключей и onion service. Проверенный адрес и публичный ключ сервиса задаются в клиенте; фиксированный чужой или выдуманный сервер не подставляется.

Перед открытием прежнего профиля создаётся проверяемый шифрованный snapshot; marker записывается атомарно после проверки. Миграция идемпотентна, сохраняет аккаунты, identity, письма, вложения, архив, recovery key, Tor, Взор/Глас, темы и пользовательские макеты. Повреждённая копия не объявляется успехом. Восстановление и откат испытываются только на отдельных копиях; детали — MIGRATION-2.5.0-TO-5.0.0.

Сначала проверить SHA256SUMS. Владелец выполняет финальную приёмку точных файлов, затем офлайн подписывает окончательный manifest по OWNER-OFFLINE-SIGNING. Имена/tag/URL согласованы с v5.0.0 и проверками старых SignedManifest; Ed25519/SHA256/anti-rollback не ослаблены. Ни наличие unsigned manifest, ни сборка не разрешают публикацию Stable.

SHA-256 трёх бинарных артефактов:

{hashes}

Остальные контрольные суммы находятся в SHA256SUMS; хеш самого owner ZIP выводится отдельно, чтобы не создавать циклическую сумму. Любое изменение бинарника требует новых сумм и нового manifest.

## Незавершённые обязательные условия

Нативная приёмка трёх окружений; реальные Tor/DNS/WebRTC/изоляция; звонки и синхронизация двух физических устройств; развёртывание и приёмка отдельной общей системы/ИИ; updater E2E/rollback; финальное подтверждение владельца. Эти условия удерживают **productionReady=false**. Пакет является пригодным для дальнейшей приёмки кандидатом, а не объявлением выполненного Stable.

## Изменения дерева

```text
{changed}
```
'''
    write(out, 'IMPLEMENTATION-REPORT-5.0.0-RU.md', report)
    write(out, 'START-HERE-5.0.0-RU.md', f'''# АЕГИС 5.0.0 — приёмочный комплект

**productionReady=false. Это кандидат для проверки владельцем.** Commit `{args.expected_commit}`.

1. Проверить SHA256SUMS перед запуском.
2. Клиент Windows: AEGIS-Setup-5.0.0-x64.exe или Portable ZIP. CachyOS: AppImage. Инструкции и ограничения редакций Windows находятся в README-WINDOWS/README-CACHYOS.
3. Новые организации, новости и библиотека требуют отдельного community-server. Server/worker ZIP и операторское ТЗ включены; production Relay не изменён. Не создавайте фиктивный адрес сервера или доверие nickname.
4. TEST-REPORT, NATIVE-ACCEPTANCE, RELEASE-GATES и FINAL-VERIFICATION показывают выполненные и невыполненные проверки. Нативный комплект содержит сценарии и пустые результаты NOT_RUN для заполнения реальными доказательствами.
5. После полной приёмки владелец подписывает точный unsigned manifest офлайн. Публикация GitHub/Stable feed автоматически не выполняется.

Подробный русский отчёт — IMPLEMENTATION-REPORT-5.0.0-RU.md.
''')
    print('Generated frozen source/build provenance and Russian owner report; productionReady remains false.')

if __name__ == '__main__':
    main()
