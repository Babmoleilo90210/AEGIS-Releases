from pathlib import Path
import urllib.request,hashlib,json,datetime,concurrent.futures
root=Path('/workspace/scratch/aa629f360927/audit600/android/tor-dependency-review600');receipts=[]
def fetch(name,url):
 p=root/name;p.parent.mkdir(exist_ok=True,parents=True);record={'name':name,'url':url}
 try:
  with urllib.request.urlopen(url,timeout=25)as response:data=response.read(8*1024*1024);p.write_bytes(data);record.update(status=response.status,finalUrl=response.url,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
 except Exception as e:record['error']=repr(e)
 receipts.append(record);return json.loads(p.read_text())if name.endswith('.json')and p.exists()and record.get('status')==200 else None
ref=fetch('upstream/tag-0.4.9.14.json','https://api.github.com/repos/guardianproject/tor-android/git/ref/tags/0.4.9.14')
if ref:
 obj=ref['object']
 if obj['type']=='tag':tag=fetch('upstream/annotated-tag.json',obj['url']);commit=tag['object']['sha']
 else:commit=obj['sha']
 info=fetch('upstream/commit.json','https://api.github.com/repos/guardianproject/tor-android/commits/'+commit)
 tree=fetch('upstream/tree.json','https://api.github.com/repos/guardianproject/tor-android/git/trees/'+commit+'?recursive=1');pins=[e for e in tree['tree']if e['mode']=='160000'];(root/'upstream/SUBMODULE-PINS.json').write_text(json.dumps({'tag':'0.4.9.14','commit':commit,'pins':pins},indent=2)+'\n')
 with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:list(pool.map(lambda file:fetch('upstream/'+file.replace('/','_'),'https://raw.githubusercontent.com/guardianproject/tor-android/'+commit+'/'+file),['README.md','.gitmodules','LICENSE','external/Makefile','tor-android-binary/src/main/java/org/torproject/jni/TorService.java']))
items={
 'licenses/Tor-0.4.9.14-LICENSE.txt':'https://raw.githubusercontent.com/torproject/tor/tor-0.4.9.14/LICENSE',
 'licenses/libevent-2.1.13-LICENSE.txt':'https://raw.githubusercontent.com/libevent/libevent/release-2.1.13-stable/LICENSE',
 'licenses/OpenSSL-3.5.7-LICENSE.txt':'https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.7/LICENSE.txt',
 'licenses/zlib-1.3.2-LICENSE.txt':'https://raw.githubusercontent.com/madler/zlib/v1.3.2/LICENSE',
 'licenses/zstd-1.5.7-LICENSE.txt':'https://raw.githubusercontent.com/facebook/zstd/v1.5.7/LICENSE',
 'licenses/zstd-1.5.7-COPYING.txt':'https://raw.githubusercontent.com/facebook/zstd/v1.5.7/COPYING',
 'licenses/androidx-localbroadcastmanager-LICENSE.txt':'https://raw.githubusercontent.com/androidx/androidx/androidx-main/LICENSE.txt',
 'native-ref-libevent.json':'https://api.github.com/repos/libevent/libevent/git/ref/tags/release-2.1.13-stable',
 'native-ref-openssl.json':'https://api.github.com/repos/openssl/openssl/git/ref/tags/openssl-3.5.7',
 'native-ref-zlib.json':'https://api.github.com/repos/madler/zlib/git/ref/tags/v1.3.2',
 'native-ref-zstd.json':'https://api.github.com/repos/facebook/zstd/git/ref/tags/v1.5.7'}
with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:list(pool.map(lambda item:fetch(*item),items.items()))
(root/'SOURCE-LICENSE-FETCH-RECEIPTS.json').write_text(json.dumps({'when':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sources':receipts},indent=2)+'\n');print(json.dumps(receipts,indent=2))
