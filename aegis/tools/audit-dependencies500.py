#!/usr/bin/env python3
"""Exact-version OSV Maven audit of actual product JARs and committed runtime pins.

Only public package coordinates leave this tool. Failed/partial queries are NOT_RUN,
never interpreted as an empty vulnerability set. This is not a native/JRE audit.
"""
from __future__ import annotations
import argparse, datetime, hashlib, json, pathlib, re, urllib.error, urllib.parse, urllib.request, zipfile

GROUPS = {
 'bcpg-jdk18on':'org.bouncycastle','bcprov-jdk18on':'org.bouncycastle','bcutil-jdk18on':'org.bouncycastle',
 'gson':'com.google.code.gson','jna':'net.java.dev.jna','jna-platform':'net.java.dev.jna',
 'zip4j':'net.lingala.zip4j','tink':'com.google.crypto.tink','protobuf-java':'com.google.protobuf',
 'pdfbox':'org.apache.pdfbox','pdfbox-io':'org.apache.pdfbox','fontbox':'org.apache.pdfbox',
 'commons-compress':'org.apache.commons','commons-lang3':'org.apache.commons','commons-io':'commons-io',
 'commons-codec':'commons-codec','commons-logging':'commons-logging','xz':'org.tukaani',
 'jsr305':'com.google.code.findbugs','error_prone_annotations':'com.google.errorprone',
 'imageio-core':'com.twelvemonkeys.imageio','imageio-metadata':'com.twelvemonkeys.imageio','imageio-webp':'com.twelvemonkeys.imageio',
 'common-image':'com.twelvemonkeys.common','common-lang':'com.twelvemonkeys.common','common-io':'com.twelvemonkeys.common',
 'javafx-base':'org.openjfx','javafx-controls':'org.openjfx','javafx-graphics':'org.openjfx',
 'password4j':'com.password4j','sqlite-jdbc':'org.xerial','slf4j-api':'org.slf4j','slf4j-nop':'org.slf4j',
}
EXCLUDED=('junit-','openjfx-monocle-','client-core-','client-ui-','common-protocol-','relay-server-','community-server-','news-worker-')
MAX_RESPONSE=4*1024*1024

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()

def coordinates(path):
 """Prefer the JAR's matching Maven identity; only known filename mappings are fallback."""
 if path.name.startswith(EXCLUDED):return None
 with zipfile.ZipFile(path) as archive:
  for info in archive.infolist():
   if re.fullmatch(r'META-INF/maven/[^/]+/[^/]+/pom.properties',info.filename) and info.file_size<=16384:
    values={}
    for line in archive.read(info).decode('ISO-8859-1').splitlines():
     if '=' in line and not line.lstrip().startswith('#'):
      k,v=line.split('=',1);values[k.strip()]=v.strip()
    if all(values.get(k) for k in ['groupId','artifactId','version']) and path.name.startswith(values['artifactId']+'-'+values['version']):
     return (values['groupId'],values['artifactId'],values['version'],'pom.properties')
 for artifact in sorted(GROUPS,key=len,reverse=True):
  match=re.fullmatch(re.escape(artifact)+r'-(\d[0-9A-Za-z.+_-]*?)(?:-(linux|win|mac|windows|linux-aarch64|mac-aarch64))?\.jar',path.name)
  if match:return GROUPS[artifact],artifact,match.group(1),'known-artifact-filename'
 return ('','','','UNMAPPED')

def pins(root):
 runtime={};files=[]
 for path in sorted(root.rglob('*.gradle')):
  if any(x in path.parts for x in ['build','.gradle']):continue
  files.append({'path':path.relative_to(root).as_posix(),'sha256':sha(path)})
  for group,artifact,version in re.findall(r"(?:implementation|runtimeOnly|api)\s+['\"]([^:'\"]+):([^:'\"]+):([^:'\"]+)['\"]",path.read_text()):runtime[(group,artifact,version)]=True
 for path in sorted(root.rglob('gradle.lockfile')):
  if 'build' in path.parts:continue
  files.append({'path':path.relative_to(root).as_posix(),'sha256':sha(path)})
  for line in path.read_text().splitlines():
   if '=' not in line or line.startswith('#'):continue
   gav,configs=line.split('=',1)
   if 'runtimeClasspath' in configs.split(',') and len(gav.split(':'))==3:
    group,artifact,version=gav.split(':')
    if not group.startswith(('org.junit','org.apiguardian','org.opentest4j')) and 'monocle' not in artifact:runtime[(group,artifact,version)]=True
 return runtime,files

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):raise urllib.error.HTTPError(req.full_url,code,'OSV redirect rejected',headers,fp)

def fetch(path,payload=None):
 url='https://api.osv.dev'+path
 if not path.startswith(('/v1/query','/v1/vulns/')) or any(c in path for c in ['\r','\n']):raise ValueError('OSV path')
 data=None if payload is None else json.dumps(payload,separators=(',',':')).encode()
 request=urllib.request.Request(url,data=data,headers={'Content-Type':'application/json','Accept':'application/json','User-Agent':'AEGIS-dependency-audit/5.0.0'},method='GET' if data is None else 'POST')
 with urllib.request.build_opener(NoRedirect).open(request,timeout=20) as response:
  if response.status!=200 or urllib.parse.urlsplit(response.url).netloc!='api.osv.dev':raise OSError('OSV origin/status mismatch')
  raw=response.read(MAX_RESPONSE+1)
  if len(raw)>MAX_RESPONSE:raise OSError('OSV response exceeds bound')
 return raw

def severity(record):
 found=set()
 global_value=record.get('database_specific',{}).get('severity')
 if isinstance(global_value,str):found.add(global_value.upper())
 for affected in record.get('affected',[]):
  value=affected.get('database_specific',{}).get('severity')
  if isinstance(value,str):found.add(value.upper())
 for level in ['CRITICAL','HIGH','MODERATE','MEDIUM','LOW']:
  if level in found:return level
 return 'UNKNOWN'

def audit(root,folders,out,offline=False,reuse_snapshot=None):
 out.mkdir(parents=True,exist_ok=True);rawdir=out/'osv-raw';rawdir.mkdir(exist_ok=True)
 runtime,pin_files=pins(root);inventory=[];packages={};unmapped=[];excluded=[]
 reused={}
 if reuse_snapshot is not None:
  previous=json.loads(reuse_snapshot.read_text())
  for record in previous.get("queries",[]):
   if record.get("status") in ["PASS_QUERY","FINDINGS"]:reused[record["coordinate"]]=(record,previous.get("timestampUtc"),previous.get("advisories",[]))
 for folder in folders:
  for path in sorted(folder.glob('*.jar')):
   coordinate=coordinates(path)
   if coordinate is None:excluded.append(path.name);continue
   group,artifact,version,origin=coordinate
   entry={'filename':path.name,'sha256':sha(path),'bytes':path.stat().st_size,'coordinateSource':origin}
   if group:
    key=(group,artifact,version);entry['coordinate']=':'.join(key);packages.setdefault(key,{'files':[],'declaredRuntimePin':key in runtime})['files'].append(entry)
   else:unmapped.append(entry)
   inventory.append(entry)
 # A declared runtime pin absent from supplied directories is explicit, not silently skipped.
 missing=[{'coordinate':':'.join(k),'status':'NOT_RUN','reason':'PINNED_RUNTIME_JAR_NOT_SUPPLIED'} for k in runtime if k not in packages and k[0]!='org.securemail']
 results=[];issues={}
 for index,(coordinate,metadata) in enumerate(sorted(packages.items())):
  group,artifact,version=coordinate;query={'package':{'ecosystem':'Maven','name':group+':'+artifact},'version':version}
  result={'queriedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'coordinate':':'.join(coordinate),'purl':f'pkg:maven/{group}/{artifact}@{version}','query':query,**metadata,'status':'NOT_RUN','vulnerabilities':[]}
  if offline:result['reason']='OFFLINE_INVENTORY_ONLY';results.append(result);continue
  prior=reused.get(result['coordinate'])
  if prior is not None:
   record,when,advisories=prior
   same={ (f['filename'],f['sha256']) for f in record.get('files',[]) }=={ (f['filename'],f['sha256']) for f in result['files'] }
   if same:
    copied=[]
    try:
     for evidence in record.get('evidence',[]):
      source=reuse_snapshot.parent/evidence['path'];raw=source.read_bytes()
      if hashlib.sha256(raw).hexdigest()!=evidence['sha256']:raise ValueError('Cached OSV evidence changed')
      name='reused-'+evidence['sha256']+'.json';(rawdir/name).write_bytes(raw);copied.append({**evidence,'path':'osv-raw/'+name})
     if not copied:raise ValueError('Cached OSV evidence missing')
     result.update(status=record['status'],vulnerabilities=record.get('vulnerabilities',[]),evidence=copied,queriedAtUtc=record.get('queriedAtUtc',when),reusedSnapshotSha256=sha(reuse_snapshot))
     for advisory in advisories:
      if advisory.get('id') in result['vulnerabilities']:issues[advisory['id']]=advisory
     results.append(result);continue
    except (OSError,ValueError):pass
  try:
   all_vulns=[];page='';seen=set()
   for page_number in range(20):
    request=dict(query)
    if page:request['page_token']=page
    raw=fetch('/v1/query',request);name=f'{index:03d}-{page_number:02d}.json';(rawdir/name).write_bytes(raw)
    value=json.loads(raw)
    if not isinstance(value,dict) or not isinstance(value.get('vulns',[]),list):raise ValueError('Invalid OSV shape')
    result.setdefault('evidence',[]).append({'path':'osv-raw/'+name,'sha256':hashlib.sha256(raw).hexdigest(),'request':request})
    all_vulns.extend(value.get('vulns',[]));page=value.get('next_page_token','')
    if not page:break
    if page in seen or not isinstance(page,str):raise ValueError('OSV pagination rejected')
    seen.add(page)
   else:raise ValueError('OSV page limit')
   for vulnerability in all_vulns:
    ident=vulnerability.get('id')
    if not isinstance(ident,str):raise ValueError('Missing OSV identifier')
    issues.setdefault(ident,{'id':ident,'severity':severity(vulnerability),'summary':vulnerability.get('summary',''),'aliases':vulnerability.get('aliases',[]),'references':vulnerability.get('references',[]),'withdrawn':vulnerability.get('withdrawn'),'affectedCoordinates':[]})
    issues[ident]['affectedCoordinates'].append(result['coordinate']);result['vulnerabilities'].append(ident)
   result['status']='PASS_QUERY' if not all_vulns else 'FINDINGS'
  except Exception as error:
   result['status']='NOT_RUN';result['reason']=type(error).__name__;result['message']='Не удалось завершить точный запрос OSV; отсутствие уязвимостей не подтверждено'
  results.append(result)
 blocked=sorted(i for i,v in issues.items() if v['severity'] in ['HIGH','CRITICAL'] and not v.get('withdrawn'))
 native=[]
 for path in sorted((root/'packaging').rglob('*provenance*.json')):
  if 'runtime' in path.name:native.append({'path':path.relative_to(root).as_posix(),'sha256':sha(path),'status':'NOT_RUN','scope':'Native/JRE/Tor upstream advisory review is separate from Maven OSV queries'})
 not_run=sum(r['status']=='NOT_RUN' for r in results)+len(missing)+len(unmapped)
 report={'schema':1,'version':'5.0.0','timestampUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'queryService':'https://api.osv.dev/v1/query','documentation':'https://google.github.io/osv.dev/post-v1-query/','scope':'Exact product Maven versions from actual supplied JAR bytes and runtime Gradle pins; no test-only JUnit/Monocle or application own JARs','status':'BLOCKED_HIGH_CRITICAL' if blocked else 'PARTIAL' if not_run else 'QUERIES_COMPLETE','productionReady':False,'packageCount':len(results),'notRunCount':not_run,'blockingAdvisories':blocked,'pinInputs':pin_files,'runtimeJars':inventory,'excluded':sorted(set(excluded)),'unmapped':unmapped,'missingRuntimeJars':missing,'queries':results,'advisories':list(issues.values()),'separateNativeReview':native,'limitations':['No result proves absence of unknown vulnerabilities.','Native codecs, Tor Browser, Tor, bundled Java and operating-system components require their own advisory/provenance review.','Reachability/exploitability is not inferred from an OSV version match; high/critical matches block acceptance pending remediation or documented evidence.']}
 (out/'DEPENDENCY-AUDIT-5.0.0.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 return report

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]);p.add_argument('--jars',type=pathlib.Path,action='append',required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--offline',action='store_true');p.add_argument('--reuse-snapshot',type=pathlib.Path);a=p.parse_args();r=audit(a.root,a.jars,a.out,a.offline,a.reuse_snapshot);print(json.dumps({k:r[k] for k in ['status','packageCount','notRunCount','blockingAdvisories']},ensure_ascii=False));return 2 if r['blockingAdvisories'] or r['notRunCount'] else 0
if __name__=='__main__':raise SystemExit(main())
