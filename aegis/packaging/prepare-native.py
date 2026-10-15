#!/usr/bin/env python3
"""Gradle test prerequisite: pinned libsodium only. No runtime download/update."""
from pathlib import Path
import os,urllib.request,hashlib,tarfile,subprocess,shutil
root=Path(__file__).resolve().parents[1];cache=root/'.build-inputs/native';cache.mkdir(parents=True,exist_ok=True);windows=os.name=='nt'
name='libsodium-1.0.22-stable-mingw.tar.gz' if windows else 'libsodium-1.0.22-stable.tar.gz'
expected='2dbb9fdb0882ec44a328b1f6a8fccbfa0bb0d0f5b1034f135e15827acaf6dba7' if windows else '4ed1a1353a0cc2426a25a63fbd9d69bb53fa293a50f3b2e59300ef951f096a31'
archive=cache/name
if not archive.exists():
 with urllib.request.urlopen('https://download.libsodium.org/libsodium/releases/'+name,timeout=180) as r:archive.write_bytes(r.read())
if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:raise ValueError('libsodium checksum mismatch; refuse build')
with tarfile.open(archive) as t:t.extractall(cache,filter='data')
target=root/'.native-test/native';target.mkdir(parents=True,exist_ok=True)
if windows:shutil.copy2(cache/'libsodium-win64/bin/libsodium-26.dll',target/'libsodium.dll')
else:
 src=cache/'libsodium-stable';subprocess.run(['./configure','--disable-static'],cwd=src,check=True);subprocess.run(['make','-j2'],cwd=src,check=True);subprocess.run(['make','check','-j2'],cwd=src,check=True);shutil.copy2(src/'src/libsodium/.libs/libsodium.so',target/'libsodium.so')
