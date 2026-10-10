#!/usr/bin/env python3
"""Verify that visual changes do not modify protocol, Relay, crypto or vault identity format."""
import argparse,hashlib,json,pathlib,zipfile
p=argparse.ArgumentParser();p.add_argument('--baseline',type=pathlib.Path,required=True);p.add_argument('--report',type=pathlib.Path,required=True);a=p.parse_args();root=pathlib.Path(__file__).resolve().parents[1]
protected=('common-protocol/src/','relay-server/src/','client-core/src/main/java/org/securemail/client/crypto/')
special={'client-core/src/main/java/org/securemail/client/storage/LocalStore.java','client-core/src/main/java/org/securemail/client/net/NetworkService.java'}
results=[]
with zipfile.ZipFile(a.baseline) as z:
 for n in z.namelist():
  if not n.startswith('aegis/') or n.endswith('/'):continue
  rel=n[6:]
  if not rel.startswith(protected) and rel not in special:continue
  current=root/rel;valid=current.is_file() and hashlib.sha256(z.read(n)).digest()==hashlib.sha256(current.read_bytes()).digest();results.append({'path':rel,'unchanged':valid})
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps({'baseline':'1.1.1','protectedComponents':results,'passed':all(r['unchanged'] for r in results)},indent=2)+'\n');assert results and all(r['unchanged'] for r in results),'Protected component changed'
print('Protected protocol, Relay, client crypto and vault files unchanged:',len(results))
