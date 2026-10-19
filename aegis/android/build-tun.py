#!/usr/bin/env python3
"""Build pinned reviewed hev/lwIP ARM64 with protect, DNS deny and TCP-only restrictions."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess
HERE=pathlib.Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--sdk',required=True,type=pathlib.Path);p.add_argument('--source',required=True,type=pathlib.Path);p.add_argument('--out',required=True,type=pathlib.Path);p.add_argument('--jdk',required=True,type=pathlib.Path);a=p.parse_args();src=a.source.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True);pins=json.loads((HERE/'third-party/HEV-SOURCES.json').read_text())
 if sha(a.sdk/'android-ndk-r29-linux.zip')!='4abbbcdc842f3d4879206e9695d52709603e52dd68d3c1fff04b3b5e7a308ecf':raise SystemExit('NDK archive mismatch')
 for name,commit in pins['commits'].items():
  if subprocess.check_output(['git','rev-parse','HEAD'],cwd=src/name,text=True).strip()!=commit:raise SystemExit('Upstream source commit mismatch')
 files=subprocess.check_output(['git','ls-files','--recurse-submodules','-z'],cwd=src).decode().strip('\0').split('\0');digest=hashlib.sha256();work=HERE/'build/tun-work';shutil.rmtree(work,ignore_errors=True);work.mkdir(parents=True);dest=work/'source'
 for name in sorted(files):
  p=src/name
  if not p.is_file():continue
  data=p.read_bytes();digest.update(name.encode()+b'\0'+data+b'\0');target=dest/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);target.chmod(p.stat().st_mode&0o777)
 if digest.hexdigest()!=pins['trackedSourceCompositeSha256']:raise SystemExit('Upstream tracked source hash mismatch')
 patches={}
 def patch(name,old,new):
  f=dest/name;s=f.read_text();assert s.count(old)==1,(name,old);f.write_text(s.replace(old,new));patches[name]=sha(f)
 # Native engine sockets must be protected before connecting, no exception fallback.
 patch('src/hev-socks5-session.c','#include "hev-utils.h"','#include "hev-utils.h"\n#include "aegis_tun_bridge.h"')
 patch('src/hev-socks5-session.c','    srv = hev_config_get_socks5_server ();\n    mark = srv->mark;','    if (!aegis_protect_fd (fd)) return -1;\n    srv = hev_config_get_socks5_server ();\n    mark = srv->mark;')
 patch('src/hev-socks5-session.c','        LOG_D ("%p socks5 client auth %s:%s", self, srv->user, srv->pass);','        /* AEGIS: never log local gateway credentials. */')
 patch('src/hev-socks5-tunnel.c','static void\nudp_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,','static void\naegis_drop_udp (void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)\n{\n    (void)arg; (void)addr; (void)port;\n    if (p) pbuf_free (p);\n    udp_recv (pcb, NULL, NULL);\n    udp_remove (pcb);\n}\n\nstatic void\nudp_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,')
 # No UDP egress at all in this constrained mode; only local mapped DNS is processed.
 patch('src/hev-socks5-tunnel.c','    udp = hev_socks5_session_udp_new (pcb, &mutex);','    udp_recv (pcb, aegis_drop_udp, NULL);\n    return; /* The upstream lwIP accept callback retains p until the installed receiver. */\n\n    udp = hev_socks5_session_udp_new (pcb, &mutex);')
 patch('src/hev-mapped-dns.c','#include "hev-logger.h"','#include "hev-logger.h"\n#include "aegis_tun_bridge.h"')
 patch('src/hev-mapped-dns.c','    node = hev_mapped_dns_node_alloc (name);','    if (self->use >= self->max) return -1; /* Never reassign a cached virtual address. */\n    node = hev_mapped_dns_node_alloc (name);')
 patch('src/hev-mapped-dns.c','            idx = hev_mapped_dns_find (self, (char *)&rb[ipo[ipn] + 1]);','            if (!aegis_domain_allowed ((char *)&rb[ipo[ipn] + 1])) {\n                shdr->fl = htons ((shdr->fl | 0x8000 | ((shdr->fl & 0x100) >> 1)) & ~0xf | 3);\n                shdr->an = 0; return qlen;\n            }\n            idx = hev_mapped_dns_find (self, (char *)&rb[ipo[ipn] + 1]);')
 (dest/'src/hev-jni.c').write_text('/* AEGIS uses its reviewed explicit JNI bridge, not upstream launcher registration. */\n');patches['src/hev-jni.c']=sha(dest/'src/hev-jni.c')
 for name in ['aegis_tun_bridge.c','aegis_tun_bridge.h']:shutil.copy2(HERE/'native'/name,dest/'src'/name)
 mk=dest/'Android.mk';text=mk.read_text();mk.write_text(text.split('# Standalone executable build')[0]);patches['Android.mk']=sha(mk)
 app=dest/'Application.mk';app.write_text(app.read_text().replace('APP_ABI := armeabi-v7a arm64-v8a x86 x86_64','APP_ABI := arm64-v8a').replace('APP_PLATFORM := android-29','APP_PLATFORM := android-33').replace('APP_CFLAGS := -O3','APP_CFLAGS := -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2'));patches['Application.mk']=sha(app)
 cmd=[str(a.sdk.resolve()/'android-ndk-r29/ndk-build'),'NDK_PROJECT_PATH='+str(dest),'APP_BUILD_SCRIPT='+str(mk),'NDK_APPLICATION_MK='+str(app),'NDK_OUT='+str(work/'obj'),'NDK_LIBS_OUT='+str(out/'lib'),'REV_ID='+pins['commits']['.'],'-j4'];env=os.environ.copy();env['SOURCE_DATE_EPOCH']='1792280091'
 with (out/'TUN-BUILD.log').open('w')as log:r=subprocess.run(cmd,cwd=dest,env=env,stdout=log,stderr=subprocess.STDOUT)
 if r.returncode:raise SystemExit('Native TUN build failed; see TUN-BUILD.log')
 lib=out/'lib/arm64-v8a/libhev-socks5-tunnel.so';readelf=a.sdk.resolve()/'android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf';elf=subprocess.check_output([str(readelf),'-h','-l','-d',str(lib)],text=True);assert 'AArch64'in elf
 for line in elf.splitlines():
  if line.strip().startswith('LOAD'):assert int(line.split()[-1],16)>=16384
 (out/'TUN-ELF.txt').write_text(elf)
 shutil.copy2(HERE/'test/native/tun_fixture.c',dest/'src/aegis_host_fixture.c')
 hostflags='-I'+str(a.jdk.resolve()/'include')+' -I'+str(a.jdk.resolve()/'include/linux')+' -fPIC -Wno-parentheses'
 with (out/'TUN-HOST-BUILD.log').open('w')as log:hostrun=subprocess.run(['make','shared','-j4','CFLAGS='+hostflags,'REV_ID='+pins['commits']['.']],cwd=dest,env=env,stdout=log,stderr=subprocess.STDOUT)
 if hostrun.returncode:raise SystemExit('Native TUN host fixture build failed; see TUN-HOST-BUILD.log')
 host=out/'host';host.mkdir(exist_ok=True)
 for f in [dest/'bin/libhev-socks5-tunnel.so',dest/'third-part/yaml/bin/libyaml.so',dest/'third-part/lwip/bin/liblwip.so',dest/'third-part/hev-task-system/bin/libhev-task-system.so']:shutil.copy2(f,host/f.name)
 report={'productionReady':False,'source':pins,'sourcePatchesSha256':patches,'bridgeSha256':sha(HERE/'native/aegis_tun_bridge.c'),'librarySha256':sha(lib),'minimumApi':33,'udp':'Only local mapped DNS; other UDP dropped before any relay','routing':'Local direct TCP forwarding gateway, not implemented Tor per-app mode','protectFdHookImplemented':True,'loadSegmentAlignment':16384,'nativeExecution':'NOT_RUN','command':cmd};(out/'TUN-PROVENANCE.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
