#!/usr/bin/env python3
"""Explicit build-time downloads only; no application updater. Pinned release inputs."""
import urllib.request,hashlib,concurrent.futures,pathlib,json,sys
r=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '.build-inputs').resolve();r.mkdir(parents=True,exist_ok=True)
base='https://ftp.acc.umu.se/mirror/torproject.org/dist/torbrowser/15.0.24/'
items=[
('jdk-linux.tar.gz','https://cdn.azul.com/zulu/bin/zulu21.52.203-ca-jdk21.0.12.1-linux_x64.tar.gz','db0c11e13b545e64d520b4821f4ca38ea9bc1c515924eb1e7f48435df101f183'),
('jdk-win.zip','https://cdn.azul.com/zulu/bin/zulu21.52.203-ca-jdk21.0.12.1-win_x64.zip','ebfe6ccb94a1a7c8743ed270c6a96dbb22f5abc48b2cc4785dbf067e02dbed22'),
('mingw.tar.xz','https://github.com/mstorsjo/llvm-mingw/releases/download/20260922/llvm-mingw-20260922-ucrt-ubuntu-22.04-x86_64.tar.xz','bb7bb7654b33d5aa8712acb837c963b2e0c56352560c76105270a3268c665c21'),
('sodium-src.tar.gz','https://download.libsodium.org/libsodium/releases/libsodium-1.0.22-stable.tar.gz','4ed1a1353a0cc2426a25a63fbd9d69bb53fa293a50f3b2e59300ef951f096a31'),
('sodium-win.tar.gz','https://download.libsodium.org/libsodium/releases/libsodium-1.0.22-stable-mingw.tar.gz','2dbb9fdb0882ec44a328b1f6a8fccbfa0bb0d0f5b1034f135e15827acaf6dba7')]
for platform,sha in [('windows','e9dc6ccc93cd6afa507193f4de284d6424233ff5102155cd2c94b259e8a22b65'),('linux','8e012ec6815d7899cb64011582e2dade88e74119c6661068a2a3252de0ccd7f2')]:
 name=f'tor-expert-bundle-{platform}-x86_64-15.0.24.tar.gz';items.append((name,base+name,sha))
items.extend([('appimagetool-x86_64.AppImage', 'https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage', '95cbe7cce9717fce90c484e34052ee7c7f1d7635b33c12525b4776826a7d29b6'), ('runtime-x86_64', 'https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64', '156f4bdbde9c52d01814600013e0a273f0118dc2de98975f3c8c63427ec79074')])
def fetch(item):
 name,url,expected=item;p=r/name
 if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:
  req=urllib.request.Request(url,headers={'User-Agent':'AEGIS-build/0.2.0'})
  with urllib.request.urlopen(req,timeout=180) as resp,open(str(p)+'.part','wb') as o:
   while data:=resp.read(1024*1024):o.write(data)
  pathlib.Path(str(p)+'.part').replace(p)
 actual=hashlib.sha256(p.read_bytes()).hexdigest()
 if actual!=expected:raise ValueError(name+' checksum mismatch; do not use this file')
 print('VERIFIED',name,p.stat().st_size,flush=True);return {'file':name,'url':url,'sha256':actual}
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:manifest=list(ex.map(fetch,items))
(r/'manifest.json').write_text(json.dumps(manifest,indent=2))
