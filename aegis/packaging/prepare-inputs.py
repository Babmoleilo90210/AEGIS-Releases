#!/usr/bin/env python3
import pathlib,tarfile,zipfile,subprocess,shutil,os,sys
root=pathlib.Path(__file__).resolve().parents[1];cache=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else root/'.build-inputs').resolve();out=cache/'assets';out.mkdir(parents=True,exist_ok=True)
for name,folder in [('jdk-linux.tar.gz','jdk-linux'),('mingw.tar.xz','mingw'),('sodium-src.tar.gz','sodium-src'),('sodium-win.tar.gz','sodium-win'),('tor-expert-bundle-windows-x86_64-15.0.24.tar.gz','tor-win'),('tor-expert-bundle-linux-x86_64-15.0.24.tar.gz','tor-linux')]:
 if not (out/folder).exists():
  with tarfile.open(cache/name) as t:t.extractall(out/folder,filter='data')
if not (out/'jdk-win').exists():
 with zipfile.ZipFile(cache/'jdk-win.zip') as z:z.extractall(out/'jdk-win')
src=next((out/'sodium-src').glob('*'));prefix=out/'sodium-install'
if not (prefix/'lib/libsodium.so').exists():
 subprocess.run(['./configure','--disable-static','--prefix='+str(prefix)],cwd=src,check=True);subprocess.run(['make','-j2'],cwd=src,check=True);subprocess.run(['make','check','-j2'],cwd=src,check=True);subprocess.run(['make','install'],cwd=src,check=True)
target=root/'.native-test/native';target.mkdir(parents=True,exist_ok=True);shutil.copy2(prefix/'lib/libsodium.so',target/'libsodium.so')
print('Inputs ready',flush=True)
