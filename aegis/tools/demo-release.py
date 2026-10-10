#!/usr/bin/env python3
"""Write only the unsigned Beta manifest for the exact demo artifacts. No network/signing."""
import argparse,json
from pathlib import Path
from release_manifest import PUBLIC_KEY,REPOSITORY,sha256,parse_manifest,verify_assets

def prepare(root):
    root=Path(root).resolve();version='1.1.1'
    def asset(name):
        p=root/name
        if p.is_symlink() or not p.is_file():raise ValueError('Missing or unsafe artifact: '+name)
        return {'fileName':name,'size':p.stat().st_size,'sha256':sha256(p),'url':f'https://github.com/{REPOSITORY}/releases/download/v{version}/{name}'}
    artifacts=[{**asset(name),'platform':platform,'kind':kind} for name,platform,kind in [
        ('AEGIS-Setup-1.1.1-x64.exe','windows-x64','installer'),
        ('AEGIS-1.1.1-Windows-x64.zip','windows-x64','portable'),
        ('AEGIS-1.1.1-CachyOS-x86_64.AppImage','cachyos-x86_64','appimage'),
        ('AEGIS-1.1.1-client-source.zip','source','source')]]
    document={'schemaVersion':1,'application':'AEGIS','channel':'beta','version':version,'tag':'v'+version,'repository':REPOSITORY,'protocolVersion':1,'relayCompatibility':['0.2.0'],'artifacts':artifacts,'checksums':asset('SHA256SUMS'),'changelog':asset('CHANGELOG-1.1.1.md'),'minimumSupported':'1.1.0','updatePolicy':'optional','announcement':{'title':'АЕГИС 1.1.1 Demo','summary':'Новый пресет «Тёмно-зелёная». Добровольное испытание подписанного автообновления через Tor.','showAsLetter':True},'releaseNotes':{'publishedAt':'2026-10-10T00:00:00Z','type':'Feature','text':(root/'CHANGELOG-1.1.1.md').read_text('utf-8')}}
    exact=(json.dumps(document,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    parse_manifest(exact,'1.1.0');verify_assets(document,root)
    updates=root/'updates';updates.mkdir(exist_ok=True)
    target=updates/'beta.json'
    if (updates/'beta.json.sig').exists():raise ValueError('Do not rewrite an already signed manifest')
    target.write_bytes(exact);(updates/'release-public.pem').write_bytes(PUBLIC_KEY)
    (root/'SIGNING-INPUT-SHA256').write_text(sha256(target)+'  updates/beta.json\n',encoding='ascii')
    print('Unsigned Beta 1.1.1 ready; stable feed untouched; no signature created.')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifacts',required=True,type=Path)
    prepare(p.parse_args().artifacts)
