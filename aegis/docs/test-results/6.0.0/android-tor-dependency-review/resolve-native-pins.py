from pathlib import Path
import urllib.request,json,hashlib,datetime,concurrent.futures
root=Path('/workspace/scratch/aa629f360927/audit600/android/tor-dependency-review600');receipts=[];pins={x['path'].split('/')[-1]:x['sha']for x in json.loads((root/'upstream/SUBMODULE-PINS.json').read_text())['pins']}
def get(name,url):
 record={'name':name,'url':url}
 try:
  with urllib.request.urlopen(url,timeout=25)as r:raw=r.read(8*1024*1024);(root/name).write_bytes(raw);record.update(status=r.status,sha256=hashlib.sha256(raw).hexdigest());receipts.append(record);return json.loads(raw)
 except Exception as e:record['error']=repr(e);receipts.append(record);return None
resolved=[]
for component,file in [('libevent','native-ref-libevent.json'),('openssl','native-ref-openssl-3.5.9.json'),('zlib','native-ref-zlib.json'),('zstd','native-ref-zstd.json')]:
 ref=json.loads((root/file).read_text());obj=ref['object']
 if obj['type']=='tag':tag=get('native-tag-'+component+'.json',obj['url']);obj=tag['object']
 resolved.append({'component':component,'sourceGitlink':pins[component],'officialTagCommit':obj['sha'],'match':pins[component]==obj['sha']})
(root/'NATIVE-PIN-MATCHES.json').write_text(json.dumps(resolved,indent=2)+'\n');print(json.dumps(resolved,indent=2))
# Full source LICENSE is already downloaded from exact Tor gitlink; identify any further license material.
for component,repo in [('openssl','openssl/openssl'),('libevent','libevent/libevent'),('zlib','madler/zlib'),('zstd','facebook/zstd')]:
 tree=get('native-pinned-'+component+'-tree.json','https://api.github.com/repos/'+repo+'/git/trees/'+pins[component]+'?recursive=1')
 if tree:
  files=[e['path']for e in tree['tree']if e['type']=='blob'and any(t in e['path'].split('/')[-1].upper()for t in ['LICENSE','NOTICE','COPYING'])];(root/('native-'+component+'-license-paths.json')).write_text(json.dumps(files,indent=2)+'\n')
(root/'NATIVE-PIN-FETCH-RECEIPTS.json').write_text(json.dumps({'when':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sources':receipts},indent=2)+'\n')
