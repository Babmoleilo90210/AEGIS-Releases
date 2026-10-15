#!/usr/bin/env python3
from pathlib import Path
import sys,zipfile,hashlib
root=Path(__file__).resolve().parents[1];out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(out/'AEGIS-0.2.0-source.zip','w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted(root.rglob('*')):
  if p.is_file() and not any(part in p.relative_to(root).parts for part in ['build','.gradle','.native-test','.build-inputs','dist','__pycache__']):z.write(p,Path('aegis')/p.relative_to(root))
files=[out/n for n in ['AEGIS-0.2.0-Windows-x64.zip','AEGIS-0.2.0-CachyOS-x86_64.AppImage','AEGIS-0.2.0-server-debian13.zip','AEGIS-0.2.0-source.zip']]
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files))
