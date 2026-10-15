#!/usr/bin/env python3
"""Package owner-side native checks; no build, network, signing or publication."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--artifacts', type=Path, required=True)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
out = args.out.resolve(); out.mkdir(parents=True, exist_ok=True)
target = out / 'AEGIS-1.0.0-native-acceptance'; target.mkdir(exist_ok=True)
def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()
for src, name in [(root/'client-core/build/libs/aegis-native-tests.jar','aegis-native-tests.jar'),
                  (root/'client-ui/build/libs/aegis-ui-tests.jar','aegis-ui-tests.jar')]:
    if not src.is_file(): raise RuntimeError('Build native acceptance JAR tasks first')
    shutil.copy2(src, target/name)
for file in (root/'packaging/native-kit').iterdir():
    if file.is_file():
        if file.suffix == '.cmd':
            (target/file.name).write_bytes(('\r\n'.join(file.read_text('utf-8').splitlines())+'\r\n').encode('utf-8'))
        else: shutil.copy2(file,target/file.name)
(target/'Run-CachyOS.sh').chmod(0o755)
assets = args.artifacts.resolve()
metadata = {'version':'1.0.0','productionClientClasspathModified':False,'applicationArtifacts':[]}
metadata['applicationJarSha256'] = {
    name: digest(assets/'stage/AEGIS.AppDir/app'/name)
    for name in ['client-core-1.0.0.jar','client-ui-1.0.0.jar','common-protocol-0.2.0.jar']
}
for name in ['AEGIS-1.0.0-Windows-x64.zip','AEGIS-Setup-1.0.0-x64.exe','AEGIS-1.0.0-CachyOS-x86_64.AppImage']:
    file=assets/name
    metadata['applicationArtifacts'].append({'fileName':name,'size':file.stat().st_size,'sha256':digest(file)})
(target/'TESTED-ARTIFACTS.json').write_text(json.dumps(metadata,indent=2)+'\n')
names = ['aegis-native-tests.jar','aegis-ui-tests.jar','README.md','Run-Windows.cmd','Run-CachyOS.sh','TESTED-ARTIFACTS.json']
files=sorted(target/name for name in names)
(target/'SHA256SUMS').write_text(''.join(digest(file)+'  '+file.name+'\n' for file in files))
archive=out/'AEGIS-1.0.0-native-acceptance.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as zipped:
    for file in sorted([*files,target/'SHA256SUMS']):
        zipped.write(file,Path(target.name)/file.name)
with zipfile.ZipFile(archive) as zipped:
    if zipped.testzip() is not None:raise RuntimeError('Native kit ZIP CRC failed')
print(json.dumps({'file':archive.name,'size':archive.stat().st_size,'sha256':digest(archive),'nativeAcceptanceExecuted':False},indent=2))
