#!/usr/bin/env python3
from pathlib import Path
import sys,zipfile,hashlib
root=Path(__file__).resolve().parents[1];out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=True)
temporary=out/'.AEGIS-2.0.0-client-source.zip.part'
with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
 for file in sorted(root.rglob('*')):
  if file.is_file() and not any(part in ['build','dist','.gradle','.git','.build-inputs','.native-test','__pycache__','validation10','validation-final','validation-simple'] for part in file.relative_to(root).parts) and file.relative_to(root).as_posix() not in ['updates/stable.json','updates/stable.json.sig','updates/beta.json','updates/beta.json.sig']:
   archive.write(file,Path('aegis')/file.relative_to(root))
with zipfile.ZipFile(temporary) as checked:assert checked.testzip() is None
temporary.replace(out/'AEGIS-2.0.0-client-source.zip')
import shutil
shutil.copy2(out/'AEGIS-2.0.0-client-source.zip',out/'AEGIS-2.0.0-source.zip')
names=['AEGIS-2.0.0-Windows-x64.zip','AEGIS-Setup-2.0.0-x64.exe','AEGIS-2.0.0-CachyOS-x86_64.AppImage','AEGIS-2.0.0-client-source.zip']
def digest(file):
 with file.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
(out/'SHA256SUMS').write_text(''.join(digest(out/name)+'  '+name+'\n' for name in names))

