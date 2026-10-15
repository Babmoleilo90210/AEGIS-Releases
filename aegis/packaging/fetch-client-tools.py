#!/usr/bin/env python3
"""Explicit pinned build downloads, never part of client execution."""
import pathlib,urllib.request,hashlib,subprocess,sys
root=pathlib.Path(sys.argv[1]).resolve();root.mkdir(parents=True,exist_ok=True)
items=[
 ('appimagetool-x86_64.AppImage','https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage','95cbe7cce9717fce90c484e34052ee7c7f1d7635b33c12525b4776826a7d29b6'),
 ('runtime-x86_64','https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64','156f4bdbde9c52d01814600013e0a273f0118dc2de98975f3c8c63427ec79074'),
 ('nsis_amd64.deb','https://archive.ubuntu.com/ubuntu/pool/universe/n/nsis/nsis_3.09-4ubuntu1_amd64.deb','9e061bef1a8b611aeb2ea76d9a3bd7722b960ca1a9dff8e38d2ab51e5a8f5e5b'),
 ('nsis-common_all.deb','https://archive.ubuntu.com/ubuntu/pool/universe/n/nsis/nsis-common_3.09-4ubuntu1_all.deb','49471b9debdee4751ebb4caf6b705cc4c678eebfaecefbe56362258893f85859')]
for name,url,digest in items:
 path=root/name
 if not path.exists():
  with urllib.request.urlopen(url,timeout=120) as response,path.open('wb') as out:
   while data:=response.read(1048576):out.write(data)
 if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('Refuse unverified tool: '+name)
 if name.endswith('.deb'):subprocess.run(['dpkg-deb','-x',str(path),str(root/'nsis')],check=True)
 else:path.chmod(0o755)
print('Build tools verified')

