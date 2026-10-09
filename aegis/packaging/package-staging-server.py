#!/usr/bin/env python3
"""Package optional protocol-1 Relay 0.3.0 for staging, without installing it."""
import argparse,pathlib,shutil,subprocess,zipfile
p=argparse.ArgumentParser();p.add_argument('--jdk',required=True,type=pathlib.Path);p.add_argument('--deps',required=True,type=pathlib.Path);p.add_argument('--base-app',required=True,type=pathlib.Path);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];out=a.out.resolve();server=out/'stage/AEGIS-server';server.mkdir(parents=True,exist_ok=True)
shutil.copytree(root/'packaging/server',server,dirs_exist_ok=True);relay=server/'relay';lib=relay/'lib';lib.mkdir(parents=True,exist_ok=True)
for module,version in [('common-protocol','0.2.0'),('relay-server','0.3.0')]:shutil.copy2(root/'build/local-java21'/(module+'.jar'),lib/(module+'-'+version+'.jar'))
for jar in a.deps.glob('*.jar'):
    if jar.name.startswith(('password4j-','sqlite-jdbc-','slf4j-')):shutil.copy2(jar,lib/jar.name)
runtime=relay/'runtime'
if runtime.exists():shutil.rmtree(runtime)
subprocess.run([a.jdk.resolve()/'bin/jlink','--module-path',a.jdk.resolve()/'jmods','--add-modules','java.base,java.logging,java.management,java.naming,java.sql,jdk.crypto.ec,jdk.unsupported,jdk.charsets','--strip-debug','--no-header-files','--no-man-pages','--compress=zip-6','--output',runtime],check=True,timeout=120)
(relay/'bin').mkdir(exist_ok=True);launcher=relay/'bin/relay-server'
launcher.write_text('''#!/bin/sh
set -eu
app_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS
exec "$app_dir/runtime/bin/java" -Xms32m -Xmx256m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -XX:ErrorFile=/dev/null -cp "$app_dir/lib/*" org.securemail.relay.RelayMain "$@"
''');launcher.chmod(0o755)
for name in ['README-SERVER.md','RELAY-0.3-STAGING.md','SECURITY.md','PROTOCOL.md','RELEASE-GATES-1.1.0.json']:shutil.copy2(root/name,server/name)
shutil.copy2(root/'config/relay.properties',server/'relay.properties');tor=server/'tor';tor.mkdir(exist_ok=True)
shutil.copy2(a.base_app/'tor/pluggable_transports/lyrebird',tor/'lyrebird');(tor/'lyrebird').chmod(0o755)
shutil.copy2(a.base_app/'tor/snowflake-bridges.txt',tor/'snowflake-bridges.txt');shutil.copytree(a.base_app/'tor/licenses',tor/'licenses',dirs_exist_ok=True)
for script in server.glob('*.sh'):script.chmod(0o755)
(server/'aegis-server.py').chmod(0o755)
subprocess.run([launcher,'version',server/'relay.properties'],check=True,timeout=15)
if any(j.name.startswith(('client-','bcprov-','tink-','javafx-')) for j in lib.iterdir()):raise ValueError('Client crypto in relay package')
with zipfile.ZipFile(out/'AEGIS-0.3.0-server-debian13-staging.zip','w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
    for file in sorted(server.rglob('*')):
        if file.is_file() and '__pycache__' not in file.parts:archive.write(file,pathlib.Path('AEGIS-server')/file.relative_to(server))
print('Optional staging Relay 0.3.0 / protocol 1 packaged; not installed or deployed.')
