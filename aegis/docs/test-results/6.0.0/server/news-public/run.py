#!/usr/bin/env python3
"""Explicit opt-in live-source run; no credentials, production paths or publication."""
import argparse
import datetime
import hashlib
import json
import pathlib
import platform
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--jdk', required=True, type=pathlib.Path)
p.add_argument('--dependencies', required=True, type=pathlib.Path)
p.add_argument('--output', required=True, type=pathlib.Path)
p.add_argument('--feed', default='https://www.debian.org/News/news')
a = p.parse_args()
repo = pathlib.Path(__file__).resolve().parents[5]
sources = sorted(path for module in ('common-protocol', 'identity-server', 'community-server', 'news-worker')
                 for path in (repo / module / 'src/main/java').rglob('*.java'))
sources.append(pathlib.Path(__file__).with_name('NewsPublicSourceSmoke600.java'))
deps = [a.dependencies / x for x in ('gson-2.14.0.jar', 'error_prone_annotations-2.48.0.jar',
        'sqlite-jdbc-3.53.4.0.jar', 'slf4j-api-2.0.17.jar', 'slf4j-nop-2.0.17.jar')]
if any(not x.is_file() for x in deps):
    raise SystemExit('Exact pinned runtime JAR missing')
a.output.mkdir(parents=True, exist_ok=False)
classes = a.output / 'classes'
classes.mkdir()
digest = lambda x: hashlib.sha256(x.read_bytes()).hexdigest()
before = {str(x.relative_to(repo)): digest(x) for x in sources}
classpath = ':'.join(map(str, deps))
command = [str(a.jdk / 'bin/javac'), '-encoding', 'UTF-8', '-cp', classpath, '-d', str(classes)] + list(map(str, sources))
with (a.output / 'compile.log').open('w') as log:
    subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=90)
run = [str(a.jdk / 'bin/java'), '-Xms32m', '-Xmx96m', '-XX:+DisableAttachMechanism',
       '-XX:-HeapDumpOnOutOfMemoryError', '-cp', str(classes) + ':' + classpath,
       'org.securemail.worker.NewsPublicSourceSmoke600', str(a.output / 'live'), a.feed]
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
with (a.output / 'run.log').open('w') as log:
    result = subprocess.run(run, stdout=log, stderr=subprocess.STDOUT, timeout=120)
receipt = {'startedAt': started, 'completedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'host': platform.platform(), 'javaCommand': run, 'exitCode': result.returncode,
           'sourceBefore': before, 'sourceUnchanged': before == {str(x.relative_to(repo)): digest(x) for x in sources},
           'dependencies': {x.name: digest(x) for x in deps},
           'scope': 'Fresh javac; actual public source and actual SQLite; no public Tor, model output, deployment or notification'}
(a.output / 'RUN.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({'exitCode': result.returncode, 'sourceUnchanged': receipt['sourceUnchanged'], 'output': str(a.output)}))
raise SystemExit(result.returncode)
