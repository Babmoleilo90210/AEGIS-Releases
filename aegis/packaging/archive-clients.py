#!/usr/bin/env python3
"""Archive only exact committed project files; never package a dirty source tree."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile

root=Path(__file__).resolve().parents[1]
out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=True)
def git(*arguments):
    return subprocess.check_output(['git','-C',str(root),*arguments])
repository=Path(git('rev-parse','--show-toplevel').decode().strip())
prefix=root.relative_to(repository).as_posix()+'/'
commit=git('rev-parse','HEAD').decode().strip()
if git('status','--porcelain','--untracked-files=all','--','.').strip():
    raise SystemExit('Refusing source archive: commit all intended source/evidence changes first')
entries=[]
for raw in git('ls-tree','-r','-z','--full-tree',commit,'--',prefix).split(b'\0'):
    if not raw:continue
    meta,name=raw.split(b'\t',1);mode,kind,blob=meta.decode().split();path=name.decode('utf-8')
    if kind!='blob' or mode not in ('100644','100755') or not path.startswith(prefix):
        raise SystemExit('Unsupported committed source entry')
    relative=path[len(prefix):]
    if relative in ['updates/stable.json','updates/stable.json.sig','updates/beta.json','updates/beta.json.sig']:continue
    file=root/relative
    if file.is_symlink() or not file.is_file():raise SystemExit('Unsafe source file: '+relative)
    content=file.read_bytes()
    if hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()!=blob:
        raise SystemExit('Working file differs from committed bytes: '+relative)
    entries.append((relative,mode,content,hashlib.sha256(content).hexdigest()))
if not entries:raise SystemExit('No committed source files')
metadata={'version':'2.5.0','commit':commit,'repositoryTree':git('rev-parse','HEAD^{tree}').decode().strip(),
          'files':{name:digest for name,mode,content,digest in entries},
          'scope':'exact committed inner Java project; production update feeds excluded; no .git or build outputs'}
temporary=out/'.AEGIS-2.5.0-client-source.zip.part'
with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
    for name,mode,content,digest in entries:
        info=zipfile.ZipInfo('aegis/'+name,(2026,10,15,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
        info.external_attr=(0o100755 if mode=='100755' else 0o100644)<<16
        archive.writestr(info,content)
    archive.writestr('SOURCE-COMMIT-2.5.0.json',json.dumps(metadata,ensure_ascii=False,indent=2)+'\n')
with zipfile.ZipFile(temporary) as checked:
    if checked.testzip() is not None:raise SystemExit('Source ZIP integrity failure')
temporary.replace(out/'AEGIS-2.5.0-client-source.zip')
shutil.copy2(out/'AEGIS-2.5.0-client-source.zip',out/'AEGIS-2.5.0-source.zip')
names=['AEGIS-2.5.0-Windows-x64.zip','AEGIS-Setup-2.5.0-x64.exe','AEGIS-2.5.0-CachyOS-x86_64.AppImage','AEGIS-2.5.0-client-source.zip','AEGIS-2.5.0-source.zip']
def digest(file):
    with file.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
(out/'SHA256SUMS').write_text(''.join(digest(out/name)+'  '+name+'\n' for name in names))
print('Archived',len(entries),'committed files from',commit)
