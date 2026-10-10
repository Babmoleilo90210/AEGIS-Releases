#!/usr/bin/env python3
"""Write an unsigned Stable candidate manifest for the exact 1.1.5 artifacts. No network/signing."""
import argparse,json
from pathlib import Path
from release_manifest import PUBLIC_KEY,REPOSITORY,sha256,parse_manifest,verify_assets

def prepare(root):
    root=Path(root).resolve();version='1.1.5'
    def asset(name):
        p=root/name
        if p.is_symlink() or not p.is_file():raise ValueError('Missing or unsafe artifact: '+name)
        return {'fileName':name,'size':p.stat().st_size,'sha256':sha256(p),'url':f'https://github.com/{REPOSITORY}/releases/download/v{version}/{name}'}
    artifacts=[{**asset(name),'platform':platform,'kind':kind} for name,platform,kind in [
        ('AEGIS-Setup-1.1.5-x64.exe','windows-x64','installer'),
        ('AEGIS-1.1.5-Windows-x64.zip','windows-x64','portable'),
        ('AEGIS-1.1.5-CachyOS-x86_64.AppImage','cachyos-x86_64','appimage'),
        ('AEGIS-1.1.5-client-source.zip','source','source')]]
    document={'schemaVersion':1,'application':'AEGIS','channel':'stable','version':version,'tag':'v'+version,'repository':REPOSITORY,'protocolVersion':1,'relayCompatibility':['0.2.0'],'artifacts':artifacts,'checksums':asset('SHA256SUMS'),'changelog':asset('CHANGELOG-1.1.5.md'),'minimumSupported':'1.1.0','updatePolicy':'optional','announcement':{'title':'АЕГИС 1.1.5 Visual Experience','summary':'Оформление, макеты почтового центра и локальная системная история обновлений.','showAsLetter':True},'releaseNotes':{'publishedAt':'2026-10-10T00:00:00Z','type':'Feature','text':(root/'CHANGELOG-1.1.5.md').read_text('utf-8')}}
    exact=(json.dumps(document,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    parse_manifest(exact,'1.1.0');verify_assets(document,root)
    updates=root/'updates';updates.mkdir(exist_ok=True)
    target=updates/'stable.json'
    if (updates/'stable.json.sig').exists():raise ValueError('Do not rewrite an already signed manifest')
    target.write_bytes(exact);(updates/'release-public.pem').write_bytes(PUBLIC_KEY)
    (root/'SIGNING-INPUT-SHA256').write_text(sha256(target)+'  updates/stable.json\n',encoding='ascii')
    print('Unsigned candidate 1.1.5 ready; production feed untouched; no signature created.')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifacts',required=True,type=Path)
    prepare(p.parse_args().artifacts)
