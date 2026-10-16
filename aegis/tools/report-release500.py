#!/usr/bin/env python3
"""Inventory real Gradle JUnit XML and prepare conservative 5.0.0 acceptance reports.

No network, signing, test execution, production mutation or readiness override exists.
Capture a clean committed source receipt BEFORE the final --rerun-tasks invocation;
generate then rejects changed source, stale/malformed XML or mismatched commits.
"""
from __future__ import annotations
import argparse
import collections
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile

VERSION = '5.0.0'
MODULES = ('common-protocol', 'client-core', 'client-ui', 'relay-server',
           'integration-tests', 'community-server', 'news-worker')
REQUIRED_TEST_MODULES = tuple(m for m in MODULES if m != 'client-ui')
FORCED_MANUAL = {'NATIVE', 'PHYSICAL', 'UPDATER'}
MATRIX_FILE = Path(__file__).with_name('release500-matrix.json')
MAX_XML = 16 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')


def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError('Output symlink is forbidden: ' + str(path))
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.part')
    try:
        with temporary.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def git(project, *arguments):
    return subprocess.check_output(['git', '-C', str(project), *arguments], stderr=subprocess.PIPE, timeout=60)


def source_state(project, expected=None):
    top = Path(git(project, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
    commit = git(project, 'rev-parse', 'HEAD').decode().strip()
    if not re.fullmatch('[0-9a-f]{40}', commit) or expected is not None and commit != expected:
        raise ValueError('HEAD differs from the frozen source commit')
    if git(top, 'status', '--porcelain', '--untracked-files=all').strip():
        raise ValueError('Commit and freeze every source/evidence change before capture/generate')
    files = {}
    for raw in git(top, 'ls-tree', '-r', '-z', '--full-tree', commit).split(b'\0'):
        if not raw:
            continue
        metadata, raw_name = raw.split(b'\t', 1)
        mode, kind, oid = metadata.decode('ascii').split()
        name = raw_name.decode('utf-8')
        p = top / name
        if kind != 'blob' or mode not in ('100644', '100755') or not p.is_file() or p.is_symlink():
            raise ValueError('Frozen source must contain regular tracked files only: ' + name)
        sha, blob = hashlib.sha256(), hashlib.sha1(b'blob ' + str(p.stat().st_size).encode('ascii') + b'\0')
        with p.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                sha.update(chunk)
                blob.update(chunk)
        if blob.hexdigest() != oid:
            raise ValueError('Tracked file differs from committed blob (even if status hides it): ' + name)
        files[name] = sha.hexdigest()
    if not files or git(top, 'status', '--porcelain', '--untracked-files=all').strip():
        raise ValueError('Source changed while its receipt was captured')
    return {'sourceCommit': commit,
            'sourceTree': git(project, 'rev-parse', 'HEAD^{tree}').decode().strip(),
            'sourceFilesSha256': files,
            'sourceFilesDigest': digest(encoded(files))}


def outside_repository(project, target):
    top = Path(git(project, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
    resolved = target.resolve()
    if resolved == top or top in resolved.parents:
        raise ValueError('Post-freeze receipts/reports must be written outside the Git repository')
    return resolved


def xml_paths(project):
    return [(m, p) for m in MODULES for p in sorted((project / m / 'build/test-results/test').glob('TEST-*.xml'))]


def capture(project, receipt, command):
    if not isinstance(command, str) or not command.strip() or len(command) > 8192 or '\0' in command:
        raise ValueError('A bounded nonempty reproducible test command is required')
    receipt = outside_repository(project, receipt)
    if receipt.exists():
        raise ValueError('Receipt already exists; use a new file for the new final test run')
    captured_ns = time.time_ns()
    state = source_state(project)
    document = {'schema': 1, 'version': VERSION, 'kind': 'SOURCE_BEFORE_FINAL_TESTS',
                'capturedAt': now_iso(), 'capturedAtNs': captured_ns,
                'testCommand': command, **state,
                'previousXmlSha256': {str(p.relative_to(project)): file_sha(p) for _, p in xml_paths(project)},
                'acceptanceClaim': False, 'productionReady': False}
    atomic(receipt, encoded(document))
    return document


def parse_suite(project, module, path):
    if path.is_symlink() or path.stat().st_size > MAX_XML:
        raise ValueError('Oversized/symlink JUnit XML: ' + str(path))
    raw = path.read_bytes()
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise ValueError('DTD/entity declarations are forbidden in JUnit XML')
    root = ET.fromstring(raw)
    if root.tag != 'testsuite':
        raise ValueError('Expected one Gradle testsuite: ' + str(path))
    counts = {}
    for key in ('tests', 'failures', 'errors', 'skipped'):
        value = root.get(key, '')
        if not re.fullmatch('[0-9]{1,8}', value):
            raise ValueError('Invalid JUnit count ' + key)
        counts[key] = int(value)
    if sum(counts[k] for k in ('failures', 'errors', 'skipped')) > counts['tests']:
        raise ValueError('Inconsistent JUnit counters')
    duration = float(root.get('time', '0'))
    if not math.isfinite(duration) or not 0 <= duration <= 7 * 86400:
        raise ValueError('Invalid JUnit duration')
    cases = []
    actual = collections.Counter()
    occurrences = collections.Counter()
    for item in root.findall('testcase'):
        cls, name = item.get('classname'), item.get('name')
        if not cls or not name or len(cls) > 512 or len(name) > 8192:
            raise ValueError('Invalid JUnit test identity')
        key = (cls, name)
        occurrences[key] += 1
        kinds = [k for k in ('failure', 'error', 'skipped') if item.find(k) is not None]
        if len(kinds) > 1:
            raise ValueError('Ambiguous JUnit testcase outcome')
        status = 'FAIL' if kinds and kinds[0] != 'skipped' else 'NOT_RUN' if kinds else 'PASS'
        if kinds:
            actual[{'failure': 'failures', 'error': 'errors', 'skipped': 'skipped'}[kinds[0]]] += 1
        cases.append({'classname': cls, 'name': name, 'occurrence': occurrences[key], 'status': status})
    if len(cases) != counts['tests'] or any(actual[k] != counts[k] for k in ('failures', 'errors', 'skipped')):
        raise ValueError('JUnit testcase outcomes contradict declared suite counters')
    for case in cases:
        case['ambiguousDisplayName'] = occurrences[(case['classname'], case['name'])] > 1
    counts['passed'] = counts['tests'] - counts['failures'] - counts['errors'] - counts['skipped']
    return {'module': module, 'path': str(path.relative_to(project)), 'sha256': digest(raw),
            'suite': root.get('name'), 'timestamp': root.get('timestamp'),
            'durationSeconds': duration, **counts, 'testcases': cases}


def scoped_evidence(project):
    records = []
    base = project / 'docs/test-results/5.0.0'
    if base.exists():
        for path in sorted(base.rglob('*RESULTS.json')):
            if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
                continue
            try:
                source = json.loads(path.read_text('utf-8'))
            except (ValueError, UnicodeError):
                continue
            record = {'path': str(path.relative_to(project)), 'sha256': file_sha(path),
                      'countedIntoGradleTotals': False,
                      'scope': 'Исторический отдельный source cut; не переносится на новый commit автоматически'}
            for key in ('status', 'recordedAt', 'testsFound', 'testsPassed', 'failures', 'errors', 'skipped', 'sourceChangedDuringRun', 'productionReady'):
                if key in source and isinstance(source[key], (str, int, float, bool)):
                    record[key] = source[key]
            records.append(record)
    return records


def inventory(project):
    suites = [parse_suite(project, module, path) for module, path in xml_paths(project)]
    by_module = []
    for module in MODULES:
        selected = [s for s in suites if s['module'] == module]
        totals = {k: sum(s[k] for s in selected) for k in ('tests', 'passed', 'failures', 'errors', 'skipped')}
        status = 'FAIL' if totals['failures'] or totals['errors'] else 'BLOCKED' if totals['skipped'] else 'PASS' if totals['tests'] else 'NOT_RUN'
        by_module.append({'module': module, 'status': status, **totals, 'suiteCount': len(selected),
                          'scope': 'Gradle JUnit; не нативная приёмка',
                          'note': 'Нет JUnit XML; это не PASS' if not selected else ''})
    suite_keys = [(s['module'], s['suite']) for s in suites]
    if len(set(suite_keys)) != len(suite_keys):
        raise ValueError('The same suite occurs in multiple XML files; refusing double counting')
    return {'schema': 1, 'version': VERSION, 'generatedAt': now_iso(), 'sourceCommit': None,
            'sourceBinding': 'UNVERIFIED_INVENTORY_ONLY', 'productionReady': False,
            'totals': {k: sum(m[k] for m in by_module) for k in ('tests', 'passed', 'failures', 'errors', 'skipped')},
            'modules': by_module, 'suites': suites, 'scopedEvidence': scoped_evidence(project),
            'previousOwner250AcceptanceInherited': False}


def requirements(inv, definition=None):
    definition = definition or json.loads(MATRIX_FILE.read_text('utf-8'))
    tests = collections.defaultdict(list)
    for suite in inv['suites']:
        for case in suite['testcases']:
            tests[(suite['module'], case['classname'], case['name'])].append({**case, 'module': suite['module'], 'evidence': suite['path'], 'xmlSha256': suite['sha256']})
    rows, seen = [], set()
    def resolve(ref):
        key = (ref['module'], ref['classname'], ref['name'])
        found = tests.get(key, [])
        if len(found) == 1:
            return found[0]
        return {**ref, 'status': 'NOT_RUN', 'reason': 'Неоднозначное parameterized display name; точного сопоставления нет' if found else 'Точный test case отсутствует в текущем Gradle XML'}
    for spec in definition['requirements']:
        identity = spec['id']
        if identity in seen or not re.fullmatch('[A-Z0-9-]+', identity):
            raise ValueError('Missing/duplicate/invalid requirement identity')
        seen.add(identity)
        mapped = [resolve(ref) for ref in spec.get('tests', [])]
        if spec['group'] in FORCED_MANUAL:
            status, reason = 'NOT_RUN', 'Нет фактической приёмки 5.0.0 в обязательной среде; старое сообщение владельца о 2.5.0 не переносится'
        elif not mapped:
            status, reason = 'NOT_RUN', 'Нет полного точного сопоставления; связанные тесты показываются только как частичное доказательство'
        elif any(t['status'] == 'FAIL' for t in mapped):
            status, reason = 'FAIL', 'Точный сопоставленный автоматический тест завершился ошибкой'
        elif any(t['status'] != 'PASS' for t in mapped):
            status, reason = 'NOT_RUN', 'Один или несколько точных сопоставленных тестов отсутствуют/пропущены'
        else:
            status, reason = 'PASS', 'Только явно указанная локальная автоматическая область; не production/native acceptance'
        row = {k: v for k, v in spec.items() if k not in ('tests', 'relatedTests')}
        row.update(status=status, reason=reason, automatedEvidence=mapped,
                   relatedEvidence=[resolve(ref) for ref in spec.get('relatedTests', [])],
                   matching='EXACT_MODULE_CLASS_TESTCASE', releaseWideAcceptance=False)
        rows.append(row)
    return {'schema': 1, 'version': VERSION, 'sourceCommit': inv['sourceCommit'],
            'policy': definition['policy'], 'previousOwner250AcceptanceInherited': False,
            'productionReady': False, 'requirements': rows,
            'summary': {g: dict(collections.Counter(r['status'] for r in rows if r['group'] == g)) for g in sorted({r['group'] for r in rows})}}


def verify_receipt(project, path, expected_commit, inv):
    raw = path.read_bytes()
    receipt = json.loads(raw)
    if receipt.get('schema') != 1 or receipt.get('version') != VERSION or receipt.get('kind') != 'SOURCE_BEFORE_FINAL_TESTS':
        raise ValueError('Invalid before-tests source receipt')
    state = source_state(project, expected_commit)
    if any(receipt.get(k) != state[k] for k in ('sourceCommit', 'sourceTree', 'sourceFilesDigest', 'sourceFilesSha256')):
        raise ValueError('Source differs from the before-tests receipt')
    started = receipt.get('capturedAtNs')
    if not isinstance(started, int) or started <= 0 or started > time.time_ns():
        raise ValueError('Invalid receipt start time')
    missing = set(REQUIRED_TEST_MODULES) - {s['module'] for s in inv['suites'] if s['tests']}
    if missing:
        raise ValueError('Final Gradle XML missing for required modules: ' + ', '.join(sorted(missing)))
    before = receipt.get('previousXmlSha256', {})
    for suite in inv['suites']:
        p = project / suite['path']
        try:
            when = dt.datetime.fromisoformat(suite['timestamp'].replace('Z', '+00:00'))
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError('Final Gradle suite requires a valid timezone timestamp') from error
        if when.tzinfo is None or int(when.timestamp() * 1e9) < started or when > dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1) or p.stat().st_mtime_ns < started or before.get(suite['path']) == suite['sha256']:
            raise ValueError('Stale/unrerun Gradle XML after source freeze: ' + suite['path'])
    inv.update(sourceCommit=state['sourceCommit'], sourceTree=state['sourceTree'],
               sourceBinding='VERIFIED_UNCHANGED_SOURCE_BEFORE_AND_AFTER_FINAL_GRADLE',
               testedSourceReceiptSha256=digest(raw), testedSourceFilesDigest=state['sourceFilesDigest'],
               testCommand=receipt['testCommand'])
    return receipt


GATE_TITLES = '''Все критические функции реализованы|Организации одобряются администрацией|Глобальные и организационные роли|Наследование без повышения привилегий|Серверные уровни доступа|Закрытые материалы не раскрываются|Защищённая система подтверждения|Региональные новости|Полномочия всеобщих объявлений|Реальный сбор новостей ИИ|Проверки автопубликации|Редакционная проверка сомнительных/важных|Библиотека с реальными документами|Визуальный редактор и Markdown|Личный архив отдельно|Исправлены известные дефекты 2.5.0|Взор устанавливается и изолирован|Глас сохраняет защищённую связь|Разрешения звонков|Аудит безопасности|Нет блокирующих critical/high уязвимостей|Обязательные автоматические тесты|Обязательные интеграционные тесты|Windows 11 native|CachyOS KDE Wayland native|CachyOS KDE X11 native|Два физических устройства/две сети|Полная миграция|Updater E2E|Rollback|Релизные артефакты|Контрольные суммы|Manifest для офлайн-подписи|Финальная приёмка владельцем'''.split('|')


def release_gates(inv, matrix):
    mandatory = []
    total = inv['totals']
    integration = next(m for m in inv['modules'] if m['module'] == 'integration-tests')
    for number, title in enumerate(GATE_TITLES, 1):
        status, note = 'NOT_RUN', 'JUnit inventory сам по себе не доказывает полную готовность этого release gate; нужны отдельные фактические доказательства'
        if number == 22:
            status = 'FAIL' if total['failures'] or total['errors'] else 'BLOCKED' if total['skipped'] else 'PASS' if total['tests'] else 'NOT_RUN'
            note = 'Точные финальные Gradle XML; пропущенные проверки не объявляются PASS'
        if number == 23:
            status = integration['status']
            note = 'Только реальные локальные Java integration tests, включая production client/HTTP/SQLite; не физические устройства или настоящий Tor'
        mandatory.append({'id': f'GATE-{number:02}', 'title': title, 'status': status,
                          'scope': note, 'evidence': ['JUNIT-INVENTORY-5.0.0.json', 'requirements-matrix.json']})
    return {'schema': 1, 'version': VERSION, 'sourceCommit': inv['sourceCommit'],
            'testedSourceReceiptSha256': inv['testedSourceReceiptSha256'],
            'mandatory': mandatory, 'productionReady': False,
            'publicationAuthorized': False, 'readinessOverrideAvailable': False,
            'unperformedTestsNeverPromotedByPreviousOwnerReport': True}


def report(inv, matrix, gates):
    total = inv['totals']
    text = ['# Испытания АЕГИС 5.0.0', '',
            'Итоговый статус: **productionReady=false**. Пакет предназначен для дальнейшей приёмки владельцем; этот отчёт не объявляет его завершённым Stable.', '',
            f'Исходный commit: `{inv["sourceCommit"]}`. SHA-256 source receipt: `{inv["testedSourceReceiptSha256"]}`.',
            'Чистый зафиксированный Git tree и SHA всех tracked файлов совпали до и после финального прогона. Все учтённые Gradle XML созданы после receipt; старые и scoped прогоны не суммируются повторно.', '',
            f'JUnit: {total["tests"]} найдено, {total["passed"]} PASS, {total["failures"]} failures, {total["errors"]} errors, {total["skipped"]} skipped. Сборка сама по себе не считается тестом.', '',
            '| Модуль | Тесты | PASS | Failures | Errors | Skipped | Статус |',
            '|---|---:|---:|---:|---:|---:|---|']
    for m in inv['modules']:
        text.append(f'| {m["module"]} | {m["tests"]} | {m["passed"]} | {m["failures"]} | {m["errors"]} | {m["skipped"]} | {m["status"]} |')
    text += ['', 'Модуль client-ui не содержит Gradle JUnit XML; нативные/визуальные проверки фиксируются отдельно. Причины skipped не подменяются успешным результатом.', '',
             '## Матрица требований', '',
             'В `requirements-matrix.json` перечислены все 224 запрошенных сценария. PASS появляется только при точном совпадении module/class/testcase и только в указанной локальной области. Частичные и близкие тесты не закрывают требование. Нативная приёмка, два устройства и полный updater E2E всегда остаются NOT_RUN до отдельного фактического прогона.', '',
             '| Группа | PASS локально | FAIL | BLOCKED | NOT_RUN |', '|---|---:|---:|---:|---:|']
    for group, counts in matrix['summary'].items():
        text.append('| ' + group + ' | ' + ' | '.join(str(counts.get(k, 0)) for k in ('PASS', 'FAIL', 'BLOCKED', 'NOT_RUN')) + ' |')
    text += ['', '## Область и ограничения', '',
             '- SQL/API tests используют настоящие SQLite, подписи и контролируемые тестовые аккаунты. SOCKS loopback fixture не является Tor.',
             '- Source/model fixtures и локальные HTTP tests не доказывают качество реальной ИИ-модели, сбор публичных новостей или production deployment.',
             '- JSSE/native codec tests не являются реальным микрофоном, акустическим испытанием или звонком на двух физических устройствах.',
             '- Нативные Windows 11, CachyOS KDE Wayland и X11, настоящие Tor/DNS/WebRTC captures, физические устройства, полная установка/updater/rollback точных бинарников и финальная приёмка владельцем в этом прогоне не выполнены.',
             '- Сообщение владельца о предыдущих проверках 2.5.0 не переносится на код и бинарники 5.0.0.',
             '- Этот генератор не подписывает manifest, не использует приватный release key, не изменяет Relay/feed и не публикует GitHub Release.', '',
             '## Воспроизведение', '', 'Команда фактического тестового прогона из receipt:', '', '```text', inv['testCommand'], '```', '',
             'После нового capture нужно заново выполнить все Gradle test tasks с `--rerun-tasks`; затем `generate` проверяет commit, source SHA и свежесть XML. При любом изменении исходников нужен новый commit/receipt/прогон.', '',
             'Архив `AEGIS-5.0.0-final-test-evidence.zip` содержит receipt, inventory, матрицу и копии XML без stdout/stderr/stacktrace payload. SHA исходных XML и SHA очищенных копий перечислены отдельно. Необработанные данные из журналов в этот архив не экспортируются.', '']
    return '\n'.join(text).encode('utf-8')


def sanitized_xml(path, expected_sha=None):
    raw = path.read_bytes()
    if expected_sha is not None and digest(raw) != expected_sha:
        raise ValueError("JUnit XML changed after inventory: " + str(path))
    root = ET.fromstring(raw)
    for parent in root.iter():
        for child in list(parent):
            if child.tag in ('system-out', 'system-err', 'properties'):
                parent.remove(child)
            elif child.tag in ('failure', 'error', 'skipped'):
                child.text = None
                child.attrib.clear()
                for grandchild in list(child):
                    child.remove(grandchild)
    root.attrib.pop('hostname', None)
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)


def write_reports(project, output, receipt_path, inv, matrix):
    gates = release_gates(inv, matrix)
    final = {'schema': 1, 'version': VERSION, 'sourceCommit': inv['sourceCommit'],
             'sourceTree': inv['sourceTree'], 'testedSourceReceiptSha256': inv['testedSourceReceiptSha256'],
             'testedSourceFilesDigest': inv['testedSourceFilesDigest'],
             'status': 'UNSIGNED_OWNER_ACCEPTANCE_CANDIDATE', 'productionReady': False,
             'junit': inv['totals'], 'sourceBinding': inv['sourceBinding'],
             'pendingMandatory': [g['id'] for g in gates['mandatory'] if g['status'] != 'PASS'],
             'nativeAcceptance': 'NOT_RUN', 'physicalTwoNetworkAcceptance': 'NOT_RUN',
             'realTorLeakAcceptance': 'NOT_RUN', 'updaterEndToEnd': 'NOT_RUN', 'rollback': 'NOT_RUN',
             'ownerFinalAcceptance': 'NOT_RUN', 'previousOwner250AcceptanceInherited': False,
             'publicationAuthorized': False, 'signatureGenerated': False,
             'productionInfrastructureChangedByGenerator': False,
             'evidence': ['JUNIT-INVENTORY-5.0.0.json', 'requirements-matrix.json', 'TESTED-SOURCE-RECEIPT-5.0.0.json', 'AEGIS-5.0.0-final-test-evidence.zip']}
    files = {'JUNIT-INVENTORY-5.0.0.json': encoded(inv), 'requirements-matrix.json': encoded(matrix),
             'RELEASE-GATES-5.0.0.json': encoded(gates), 'FINAL-VERIFICATION-5.0.0.json': encoded(final),
             'TEST-REPORT-5.0.0.md': report(inv, matrix, gates),
             'TESTED-SOURCE-RECEIPT-5.0.0.json': receipt_path.read_bytes()}
    if file_sha(receipt_path) != inv["testedSourceReceiptSha256"]:
        raise ValueError("Source receipt changed after verification")
    output.mkdir(parents=True, exist_ok=True)
    zipped = output / 'AEGIS-5.0.0-final-test-evidence.zip'
    if zipped.is_symlink():
        raise ValueError('Output archive symlink forbidden')
    temporary = zipped.with_name('.' + uuid.uuid4().hex + '.zip.part')
    hashes = []
    try:
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(files.items()):
                archive.writestr(name, data)
                hashes.append(digest(data) + '  ' + name)
            for suite in inv['suites']:
                name = 'gradle/' + suite['module'] + '/' + Path(suite['path']).name
                data = sanitized_xml(project / suite['path'], suite['sha256'])
                archive.writestr(name, data)
                hashes.append(digest(data) + '  ' + name)
            archive.writestr('SHA256SUMS', '\n'.join(hashes) + '\n')
        state = source_state(project, inv['sourceCommit'])
        if state['sourceFilesDigest'] != inv['testedSourceFilesDigest'] or file_sha(receipt_path) != inv['testedSourceReceiptSha256']:
            raise ValueError('Source/receipt changed while final reports were generated')
        if any(file_sha(project / suite['path']) != suite['sha256'] for suite in inv['suites']):
            raise ValueError('JUnit XML changed while final reports were generated')
        for name, data in files.items():
            atomic(output / name, data)
        os.replace(temporary, zipped)
    finally:
        temporary.unlink(missing_ok=True)
    return final


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='mode', required=True)
    for mode in ('inventory', 'capture', 'generate'):
        p = subs.add_parser(mode)
        p.add_argument('--repo', type=Path, required=True)
        if mode == 'capture':
            p.add_argument('--receipt', type=Path, required=True)
            p.add_argument('--command', required=True)
        else:
            p.add_argument('--output', type=Path, required=True)
        if mode == 'generate':
            p.add_argument('--receipt', type=Path, required=True)
            p.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    try:
        project = args.repo.resolve()
        if args.mode == 'capture':
            document = capture(project, args.receipt, args.command)
            print(json.dumps({'captured': True, 'sourceCommit': document['sourceCommit'], 'productionReady': False}))
        else:
            inv = inventory(project)
            if args.mode == 'inventory':
                matrix = requirements(inv)
                atomic(args.output / 'JUNIT-INVENTORY-5.0.0.json', encoded(inv))
                atomic(args.output / 'requirements-matrix.json', encoded(matrix))
                print(json.dumps({'sourceCommit': None, 'totals': inv['totals'], 'productionReady': False}))
            else:
                output = outside_repository(project, args.output)
                verify_receipt(project, args.receipt, args.source_commit, inv)
                final = write_reports(project, output, args.receipt, inv, requirements(inv))
                print(json.dumps(final, ensure_ascii=False))
    except (ValueError, OSError, ET.ParseError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Report rejected: ' + str(error) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
