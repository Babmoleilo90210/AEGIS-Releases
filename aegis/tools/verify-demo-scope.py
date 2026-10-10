#!/usr/bin/env python3
"""Verify the minimal demo delta against the exact published 1.1.0 source ZIP."""
import argparse,hashlib,json,zipfile
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--baseline',required=True,type=Path);p.add_argument('--report',required=True,type=Path);a=p.parse_args()
root=Path(__file__).resolve().parents[1]
with a.baseline.open('rb') as stream:
    if hashlib.file_digest(stream,'sha256').hexdigest()!='5297d563d3f3f492bab8b2d47435011173e704d67a4e37e2e117d38da93bb0b8':raise ValueError('Published source SHA mismatch')
allowed={'client-core/src/main/java/org/securemail/client/update/SignedManifest.java','client-core/src/main/java/org/securemail/client/storage/UpdateSupport.java','client-ui/src/main/java/org/securemail/ui/ThemeManager.java','client-ui/src/main/resources/org/securemail/ui/messenger.css'}
frozen={};version_only=[]
with zipfile.ZipFile(a.baseline) as archive:
    if archive.testzip():raise ValueError('Published source CRC failed')
    previous={name.removeprefix('aegis/'):archive.read(name) for name in archive.namelist() if not name.endswith('/') and name.startswith('aegis/')}
    def protected(name):
        return name.startswith(('common-protocol/','relay-server/','deployment/','client-core/src/main/','client-ui/src/main/')) or name in {'config/relay.properties','config/client.properties'}
    for name,data in previous.items():
        if not protected(name):continue
        target=root/name
        if not target.is_file() or target.is_symlink():raise ValueError('Protected source missing: '+name)
        current=target.read_bytes()
        if name not in allowed:
            if current!=data:raise ValueError('Unexpected demo change: '+name)
            frozen[name]=hashlib.sha256(current).hexdigest()
        elif name.startswith('client-core/'):
            if current!=data.replace(b'1.1.0',b'1.1.1'):raise ValueError('Only version metadata may change here: '+name)
            version_only.append(name)
    for module in ['common-protocol','relay-server','client-core/src/main','client-ui/src/main']:
        for path in (root/module).rglob('*'):
            if path.is_file() and path.relative_to(root).as_posix() not in previous:raise ValueError('Unexpected new production source: '+str(path))
report={'result':'PASS','baselineVersion':'1.1.0','baselineSourceSha256':'5297d563d3f3f492bab8b2d47435011173e704d67a4e37e2e117d38da93bb0b8','version':'1.1.1','frozenProductionFiles':len(frozen),'versionOnlyClientCore':version_only,'uiChanges':sorted(allowed-set(version_only)),'pinnedEd25519KeyChanged':False,'E2EEChanged':False,'relayChanged':False,'protocolChanged':False,'vaultFormatChanged':False,'frozenFileSha256':frozen}
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n')
print('Minimal demo scope PASS; '+str(len(frozen))+' protected source files byte-identical to published 1.1.0.')
