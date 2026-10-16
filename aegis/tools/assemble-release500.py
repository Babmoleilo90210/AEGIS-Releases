#!/usr/bin/env python3
"""Two-phase frozen 5.0 candidate assembly. Never sign, publish or modify readiness.
Prepare sources/docs/evidence, then build native/operator packages separately, then finalize.
"""
from __future__ import annotations
import argparse,datetime,hashlib,importlib.util,json,os,pathlib,re,stat,subprocess,sys,tarfile,tempfile,uuid,zipfile
VERSION='5.0.0'
ROOT=pathlib.Path(__file__).resolve().parents[1]
BINARY_FILES=('AEGIS-Setup-5.0.0-x64.exe','AEGIS-5.0.0-Windows-x64.zip','AEGIS-5.0.0-CachyOS-x86_64.AppImage')
SOURCE_FILES=('AEGIS-5.0.0-source.zip','AEGIS-5.0.0-client-source.zip')
EXTRA_PACKAGES=('AEGIS-5.0.0-native-acceptance.zip','AEGIS-5.0.0-evidence.zip','AEGIS-5.0.0-community-server.zip','AEGIS-5.0.0-news-worker.zip')
REQUIRED_DOCS=('CHANGELOG-5.0.0.md','README.md','README-WINDOWS.md','README-CACHYOS.md','BUILD-5.0.0.md','BUILD-PROVENANCE-5.0.0.json','SOURCE-PROVENANCE-5.0.0.json','IMPLEMENTATION-REPORT-5.0.0-RU.md','ORGANIZATIONS-5.0.0.md','ACCESS-CONTROL-5.0.0.md','VERIFICATION-SYSTEM-5.0.0.md','NEWS-5.0.0.md','AI-NEWS-AGENT-5.0.0.md','AI-SECURITY-5.0.0.md','LIBRARY-5.0.0.md','LIBRARY-THREAT-MODEL-5.0.0.md','SECURITY-AUDIT-5.0.0-RU.md','VZOR-5.0.0.md','GLAS-5.0.0.md','INTERFACE-5.0.0.md','MIGRATION-2.5.0-TO-5.0.0.md','TEST-REPORT-5.0.0.md','NATIVE-ACCEPTANCE-5.0.0.md','RELEASE-GATES-5.0.0.json','FINAL-VERIFICATION-5.0.0.json','OWNER-OFFLINE-SIGNING-5.0.0.md')
DEFERRED={'BUILD-PROVENANCE-5.0.0.json','SOURCE-PROVENANCE-5.0.0.json','IMPLEMENTATION-REPORT-5.0.0-RU.md','TEST-REPORT-5.0.0.md','RELEASE-GATES-5.0.0.json','FINAL-VERIFICATION-5.0.0.json'}
PROVENANCE_DOCS=('BUILD-PROVENANCE-5.0.0.json','SOURCE-PROVENANCE-5.0.0.json','RELEASE-GATES-5.0.0.json','FINAL-VERIFICATION-5.0.0.json')
FORBIDDEN_SUFFIX={'.html','.htm','.har','.pcap','.pcapng','.env','.key','.pem','.pkcs8','.p12','.pfx','.vault','.enc','.db','.sqlite','.exe','.dll','.so','.jar','.zip'}
EVIDENCE_SUFFIX={'.json','.md','.txt','.log','.xml','.png','.jpg','.jpeg','.java','.py','.sh','.cmd','.asc'}
EXTRA_PUBLIC={'AEGIS-5.0.0-final-test-evidence.zip','START-HERE-5.0.0-RU.md','STRUCTURAL-VERIFICATION-5.0.0.json','JAVA-RUNTIME-5.0.0.json','BUNDLED-RUNTIME-LOCAL-CHECK-5.0.0.json','SERVER-BUILD-PROVENANCE-5.0.0.json','AEGIS-5.0.0-community-server-PROVENANCE.json','AEGIS-5.0.0-news-worker-PROVENANCE.json','COMMUNITY-SERVER-5.0.0.md','SERVER-DEPLOYMENT-PROPOSAL-5.0.0-RU.md','VZOR-THREAT-MODEL-5.0.0.md','GLAS-THREAT-MODEL-5.0.0.md','GLAS-CRYPTOGRAPHY-5.0.0.md'}
OWNER_ZIP='AEGIS-5.0.0-owner-acceptance-package.zip'
SAFE_NAME=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,179}')

def sha(path):
 with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def git(project,*args):return subprocess.check_output(['git','-C',str(project),*args],timeout=90)
def regular(path,nonempty=True):
 if path.is_symlink()or not path.is_file()or(nonempty and path.stat().st_size==0):raise ValueError('Missing/empty/unsafe file: '+str(path))
 return path

def safe_relative(name):
 p=pathlib.PurePosixPath(name)
 if not p.parts or p.is_absolute()or'..'in p.parts or'\\'in name or':'in name or any(ord(c)<32 or ord(c)==127 for c in name):raise ValueError('Unsafe archive member')
 return p.as_posix()

def evidence_name_allowed(name):
 p=pathlib.PurePosixPath(name);return p.suffix.lower()in EVIDENCE_SUFFIX or p.name=='SHA256SUMS'

def public_text(name,data):
 lower=name.lower();suffix=pathlib.PurePosixPath(lower).suffix
 if suffix in FORBIDDEN_SUFFIX or pathlib.PurePosixPath(lower).name in{'env.log','env.txt','environment.log','printenv.txt'}:raise ValueError('Private/raw file is not public evidence: '+name)
 if suffix in {'.png','.jpg','.jpeg'}:return
 try:text=data.decode('utf-8')
 except UnicodeError:raise ValueError('Evidence text must be audited UTF-8: '+name)from None
 if suffix=='.asc' and (len(data)>16384 or not text.strip().startswith('-----BEGIN PGP SIGNATURE-----') or not text.strip().endswith('-----END PGP SIGNATURE-----') or 'PRIVATE KEY' in text):raise ValueError('Only bounded public detached PGP signatures are allowed: '+name)
 patterns=(r'(?m)^-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----',r'(?m)^-----BEGIN PGP PRIVATE KEY BLOCK-----',r'(?mi)^(?:authorization:\s*(?:bearer|basic)|cookie:|set-cookie:|aegis-signature:)',r'(?m)^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \S+ HTTP/1\.[01]\s*$',r'(?m)^HTTP/1\.[01] [0-9]{3}',r'(?m)^(?:HOME|PATH|GITHUB_TOKEN|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|PASSWORD|API_KEY)=')
 if any(re.search(p,text)for p in patterns):raise ValueError('Raw HTTP/key/environment content excluded: '+name)

class Frozen:
 def __init__(self,project,expected):
  self.project=pathlib.Path(project).resolve()
  if not re.fullmatch('[a-f0-9]{40}',expected):raise ValueError('Full frozen expected commit required')
  self.repo=pathlib.Path(git(self.project,'rev-parse','--show-toplevel').decode().strip());self.prefix=self.project.relative_to(self.repo).as_posix();self.prefix=''if self.prefix=='.'else self.prefix+'/'
  self.commit=git(self.project,'rev-parse','HEAD').decode().strip()
  if self.commit!=expected:raise ValueError('HEAD differs from expected frozen commit')
  self.assert_clean();self.tree=git(self.project,'rev-parse','HEAD^{tree}').decode().strip();self.epoch=int(git(self.project,'show','-s','--format=%ct','HEAD').decode());self.date=datetime.datetime.fromtimestamp(self.epoch,datetime.timezone.utc);self.zip_date=tuple(self.date.timetuple()[:6])
  if not 1980<=self.zip_date[0]<=2107:raise ValueError('Commit timestamp outside ZIP range')
  self.entries={}
  for raw in git(self.project,'ls-tree','-r','-z','--full-tree',self.commit).split(b'\0'):
   if not raw:continue
   meta,name=raw.split(b'\t',1);mode,kind,oid=meta.decode().split();path=safe_relative(name.decode('utf-8'))
   if kind!='blob'or mode not in('100644','100755'):raise ValueError('Unsupported committed source mode')
   self.entries[path]=(mode,oid)
  audit=json.loads(self.blob(self.prefix+'docs/test-results/5.0.0/source-audit/RESULTS.json'))
  self.base=audit.get('baseCommit','')
  if audit.get('baseVersion')!='2.5.0'or not re.fullmatch('[a-f0-9]{40}',self.base):raise ValueError('Missing verified 2.5 base source audit')
  if subprocess.run(['git','-C',str(self.project),'merge-base','--is-ancestor',self.base,self.commit],capture_output=True,timeout=30).returncode:raise ValueError('Audited 2.5 base is not an ancestor')
  self.identity={'version':VERSION,'sourceCommit':self.commit,'sourceTree':self.tree,'baseCommit':self.base}
 def assert_clean(self):
  if git(self.project,'status','--porcelain','--untracked-files=all').strip():raise ValueError('Freeze and commit all source/evidence changes first')
 def blob(self,path):
  if path not in self.entries:raise ValueError('Not a frozen tracked source: '+path)
  return git(self.project,'show',self.commit+':'+path)
 def check_file(self,path):
  # A successful compiler/process can legitimately emit zero stdout/stderr.
  # Preserve exact captured logs and their hashes; required documents stay nonempty.
  regular(path,nonempty=path.suffix.lower()!='.log');rel=path.relative_to(self.repo).as_posix();record=self.entries.get(rel)
  if record is None:raise ValueError('Untracked evidence is not allowed: '+rel)
  data=path.read_bytes();digest=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
  if digest!=record[1]:raise ValueError('File differs from frozen commit: '+rel)
  return rel,data

def atomic_bytes(path,data):
 if path.is_symlink():raise ValueError('Output symlink forbidden')
 temp=path.with_name('.'+path.name+'.'+str(uuid.uuid4())+'.part')
 try:
  with temp.open('xb')as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.replace(temp,path)
 finally:temp.unlink(missing_ok=True)
def zip_write(z,name,data,date,mode=0o100644):
 i=zipfile.ZipInfo(safe_relative(name),date);i.compress_type=zipfile.ZIP_DEFLATED;i.external_attr=mode<<16;z.writestr(i,data)
def checked_zip(path):
 with zipfile.ZipFile(regular(path))as z:
  seen=set()
  for i in z.infolist():
   name=safe_relative(i.filename)
   if name.casefold()in seen or stat.S_ISLNK(i.external_attr>>16):raise ValueError('Unsafe/duplicate ZIP member')
   seen.add(name.casefold())
  if z.testzip():raise ValueError('ZIP CRC failure: '+path.name)

def source_archives(frozen,out):
 existing=out/'SOURCE-COMMIT-5.0.0.json'
 if existing.exists()and json.loads(regular(existing).read_text())!=frozen.identity:raise ValueError('Artifact folder belongs to another source commit')
 with tempfile.TemporaryDirectory(prefix='aegis500-source-')as tmp:
  tmp=pathlib.Path(tmp);tar=tmp/'source.tar'
  with tar.open('wb')as f:subprocess.run(['git','-C',str(frozen.repo),'archive','--format=tar',frozen.commit],stdout=f,check=True,timeout=90)
  full=tmp/SOURCE_FILES[0];client=tmp/SOURCE_FILES[1]
  with zipfile.ZipFile(full,'w',zipfile.ZIP_DEFLATED,compresslevel=6)as all_zip,zipfile.ZipFile(client,'w',zipfile.ZIP_DEFLATED,compresslevel=6)as client_zip,tarfile.open(tar,'r:')as files:
   for i in files:
    if i.isdir():continue
    name=safe_relative(i.name)
    if not i.isfile()or name not in frozen.entries:raise ValueError('Unsafe git archive entry')
    data=files.extractfile(i).read();mode,oid=frozen.entries[name]
    if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=oid:raise ValueError('Git archive blob mismatch')
    zip_write(all_zip,name,data,frozen.zip_date,int(mode,8))
    if name.startswith(frozen.prefix):zip_write(client_zip,'aegis/'+name[len(frozen.prefix):],data,frozen.zip_date,int(mode,8))
   metadata=(json.dumps(frozen.identity,ensure_ascii=False,indent=2)+'\n').encode()
   for z in(all_zip,client_zip):zip_write(z,'SOURCE-COMMIT-5.0.0.json',metadata,frozen.zip_date)
  for p,is_client in((full,False),(client,True)):validate_source_archive(frozen,p,is_client);atomic_bytes(out/p.name,p.read_bytes())
 atomic_bytes(existing,(json.dumps(frozen.identity,indent=2)+'\n').encode())

def copy_docs(frozen,out,final=False):
 deferred=[]
 for name in REQUIRED_DOCS:
  target=out/name
  if target.exists():
   regular(target)
   if not target.read_bytes().strip():raise ValueError('Empty required document: '+name)
   continue  # Owner-generated provenance/readiness reports stay authoritative.
  source=frozen.project/name
  if source.is_file():
   _,data=frozen.check_file(source)
   if not data.strip():raise ValueError('Empty required document: '+name)
   atomic_bytes(target,data)
  elif not final and name in DEFERRED:deferred.append(name)
  else:raise ValueError('Required real document missing: '+name)
 return deferred

def evidence_archive(frozen,out,evidence):
 evidence=pathlib.Path(evidence).resolve();allowed=frozen.project/'docs/test-results/5.0.0'
 if not evidence.is_dir()or not evidence.is_relative_to(allowed):raise ValueError('Evidence must be the audited tracked docs/test-results/5.0.0 subtree')
 files={}
 for path in sorted(evidence.rglob('*')):
  if path.is_symlink():raise ValueError('Evidence symlink forbidden')
  if not path.is_file():continue
  if not evidence_name_allowed(path.name):raise ValueError('Non-whitelisted evidence file: '+path.name)
  if path.stat().st_size>64*1024*1024:raise ValueError('Oversized evidence file')
  rel,data=frozen.check_file(path);public_text(rel,data);files[rel]=data
 for path in sorted(frozen.project.glob('*5.0.0*.md')):
  rel,data=frozen.check_file(path);public_text(rel,data);files[rel]=data
 for module in('community-server','news-worker'):
  p=frozen.project/module/'README.md'
  if p.is_file():rel,data=frozen.check_file(p);public_text(rel,data);files[rel]=data
 if not files or sum(map(len,files.values()))>1024*1024*1024:raise ValueError('Empty or oversized evidence scope')
 temp=out/('.evidence-'+str(uuid.uuid4())+'.zip.part')
 try:
  with zipfile.ZipFile(temp,'w',zipfile.ZIP_DEFLATED,compresslevel=6)as z:
   for rel,data in sorted(files.items()):zip_write(z,rel,data,frozen.zip_date)
   proof={**frozen.identity,'scope':'Audited tracked 5.0 evidence and new module documents; raw HTTP/HTML, keys, environment dumps and user stores excluded','filesSha256':{n:hashlib.sha256(b).hexdigest()for n,b in files.items()}}
   zip_write(z,'EVIDENCE-PROVENANCE-5.0.0.json',(json.dumps(proof,ensure_ascii=False,indent=2)+'\n').encode(),frozen.zip_date)
  checked_zip(temp);os.replace(temp,out/'AEGIS-5.0.0-evidence.zip')
 finally:temp.unlink(missing_ok=True)
 return len(files)

def binding(document):
 found=[]
 for key in('sourceCommit','implementationCommit'):
  if document.get(key)is not None:found.append(document[key])
 src=document.get('source')
 if isinstance(src,dict):
  for key in('commit','sourceCommit','implementationCommit'):
   if src.get(key)is not None:found.append(src[key])
 if not found or any(not isinstance(x,str)or not re.fullmatch('[a-f0-9]{40}',x)for x in found)or len(set(found))!=1:raise ValueError('Missing or contradictory exact source commit binding')
 return found[0]
def zip_json(path,basename):
 checked_zip(path)
 with zipfile.ZipFile(path)as z:
  names=[n for n in z.namelist()if pathlib.PurePosixPath(n).name==basename]
  if len(names)!=1:raise ValueError('Missing or ambiguous ZIP provenance: '+basename)
  if z.getinfo(names[0]).file_size>8*1024*1024:raise ValueError('Oversized ZIP provenance')
  return json.loads(z.read(names[0]))
def validate_source_archive(frozen,path,client=False):
 checked_zip(path);expected={}
 for name,(mode,oid) in frozen.entries.items():
  if client and not name.startswith(frozen.prefix):continue
  target='aegis/'+name[len(frozen.prefix):]if client else name;expected[target]=(name,mode,oid)
 with zipfile.ZipFile(path)as z:
  if set(z.namelist())!=set(expected)|{'SOURCE-COMMIT-5.0.0.json'}:raise ValueError('Source ZIP does not contain the exact frozen tree scope')
  if json.loads(z.read('SOURCE-COMMIT-5.0.0.json'))!=frozen.identity:raise ValueError('Wrong frozen source ZIP identity')
  for member,(name,mode,oid) in expected.items():
   data=z.read(member);info=z.getinfo(member)
   if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=oid or stat.S_IMODE(info.external_attr>>16)!=stat.S_IMODE(int(mode,8)):raise ValueError('Source ZIP payload/mode differs from Git: '+member)
   source=frozen.repo/name;regular(source,nonempty=False)
   if hashlib.sha256(data).hexdigest()!=sha(source):raise ValueError('Source ZIP strong hash differs from frozen worktree')
def validate_evidence_archive(frozen,path):
 proof=zip_json(path,'EVIDENCE-PROVENANCE-5.0.0.json')
 if binding(proof)!=frozen.commit or proof.get('sourceTree')!=frozen.tree:raise ValueError('Evidence source mismatch')
 files=proof.get('filesSha256')
 if not isinstance(files,dict)or not files:raise ValueError('Missing evidence inventory')
 with zipfile.ZipFile(path)as z:
  if set(z.namelist())!=set(files)|{'EVIDENCE-PROVENANCE-5.0.0.json'}:raise ValueError('Evidence ZIP contains unlisted files')
  for name,digest in files.items():
   safe_relative(name);relative=name[len(frozen.prefix):]if name.startswith(frozen.prefix)else''
   allowed=relative.startswith('docs/test-results/5.0.0/')or('/'not in relative and relative.endswith('.md')and'5.0.0'in relative)or relative in('community-server/README.md','news-worker/README.md')
   if not allowed or not evidence_name_allowed(name):raise ValueError('Evidence outside audited whitelist')
   data=z.read(name);public_text(name,data)
   if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('Evidence inventory mismatch')
   _,committed=frozen.check_file(frozen.repo/name)
   if data!=committed:raise ValueError('Evidence differs from frozen source')
def validate_final_test_archive(frozen,path):
 checked_zip(path)
 roots={'FINAL-VERIFICATION-5.0.0.json','JUNIT-INVENTORY-5.0.0.json','TESTED-SOURCE-RECEIPT-5.0.0.json','requirements-matrix.json','RELEASE-GATES-5.0.0.json','TEST-REPORT-5.0.0.md'}
 with zipfile.ZipFile(path)as z:
  names=set(z.namelist())
  if not roots|{'SHA256SUMS'}<=names or len(names)>10000 or sum(i.file_size for i in z.infolist())>512*1024*1024:raise ValueError('Incomplete or oversized final test evidence')
  files={}
  for name in names-{'SHA256SUMS'}:
   if name not in roots and not re.fullmatch(r'gradle/(?:common-protocol|client-core|client-ui|relay-server|integration-tests|community-server|news-worker)/TEST-[A-Za-z0-9_.$-]+\.xml',name):raise ValueError('Unexpected final test evidence member')
   if z.getinfo(name).file_size>64*1024*1024:raise ValueError('Oversized final test evidence member')
   data=z.read(name);public_text(name,data);files[name]=data
  inventory={}
  for line in z.read('SHA256SUMS').decode('ascii').splitlines():
   match=re.fullmatch(r'([a-f0-9]{64})  (.+)',line)
   if not match or match[2]in inventory:raise ValueError('Invalid final test evidence checksum inventory')
   inventory[match[2]]=match[1]
  if set(inventory)!=set(files)or any(hashlib.sha256(data).hexdigest()!=inventory[name]for name,data in files.items()):raise ValueError('Final test evidence checksum mismatch')
  docs={name:json.loads(files[name])for name in roots if name.endswith('.json')}
  for name,document in docs.items():
   if document.get('schema')!=1 or document.get('version')!=VERSION or binding(document)!=frozen.commit:raise ValueError('Final test evidence source mismatch: '+name)
  final=docs['FINAL-VERIFICATION-5.0.0.json'];receipt=docs['TESTED-SOURCE-RECEIPT-5.0.0.json'];junit=docs['JUNIT-INVENTORY-5.0.0.json']
  if any(doc.get('sourceTree')!=frozen.tree for doc in(final,receipt,junit))or final.get('productionReady')is not False or final.get('status')!='UNSIGNED_OWNER_ACCEPTANCE_CANDIDATE' or receipt.get('kind')!='SOURCE_BEFORE_FINAL_TESTS':raise ValueError('Invalid final test source receipt/readiness scope')
  receipt_hash=hashlib.sha256(files['TESTED-SOURCE-RECEIPT-5.0.0.json']).hexdigest()
  if any(doc.get('testedSourceReceiptSha256')!=receipt_hash for doc in(final,junit,docs['RELEASE-GATES-5.0.0.json'])):raise ValueError('Final test source receipt digest mismatch')
  source_files=receipt.get('sourceFilesSha256')
  if not isinstance(source_files,dict)or set(source_files)!=set(frozen.entries)or any(source_files[name]!=sha(regular(frozen.repo/name,nonempty=False))for name in frozen.entries):raise ValueError('Final tests used different source file contents')
  source_digest=hashlib.sha256((json.dumps(source_files,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()).hexdigest()
  if receipt.get('sourceFilesDigest')!=source_digest or final.get('testedSourceFilesDigest')!=source_digest or junit.get('testedSourceFilesDigest')!=source_digest:raise ValueError('Final tested source file inventory digest mismatch')
  return final

def validate_bindings(frozen,out):
 for name in(*BINARY_FILES,*SOURCE_FILES,*EXTRA_PACKAGES,*REQUIRED_DOCS):regular(out/name)
 if json.loads(regular(out/'SOURCE-COMMIT-5.0.0.json').read_text())!=frozen.identity:raise ValueError('Flat source identity differs from frozen source')
 for name in PROVENANCE_DOCS:
  if binding(json.loads((out/name).read_text()))!=frozen.commit:raise ValueError('Wrong source binding: '+name)
 build=json.loads((out/'BUILD-PROVENANCE-5.0.0.json').read_text());binary=build.get('binaryArtifactSha256')
 if not isinstance(binary,dict)or any(binary.get(name)!=sha(out/name)for name in BINARY_FILES):raise ValueError('Build provenance must bind all three exact binary hashes')
 for name,is_client in((SOURCE_FILES[0],False),(SOURCE_FILES[1],True)):validate_source_archive(frozen,out/name,is_client)
 windows=zip_json(out/BINARY_FILES[1],'BUILD-INPUTS.json')
 if windows.get('clientVersion')!=VERSION or windows.get('sourceCommit')!=frozen.commit:raise ValueError('Windows binary source mismatch')
 for name in('AEGIS-5.0.0-community-server.zip','AEGIS-5.0.0-news-worker.zip'):
  if binding(zip_json(out/name,'SERVER-BUILD-PROVENANCE-5.0.0.json'))!=frozen.commit:raise ValueError('Server/worker source mismatch')
 native=zip_json(out/'AEGIS-5.0.0-native-acceptance.zip','TESTED-ARTIFACTS.json')
 if binding(native)!=frozen.commit or native.get('sourceZipSha256')!=sha(out/SOURCE_FILES[1])or native.get('windowsClientZipSha256')!=sha(out/BINARY_FILES[1]):raise ValueError('Native kit does not bind current frozen inputs')
 validate_evidence_archive(frozen,out/'AEGIS-5.0.0-evidence.zip')
 proof=out/'AEGIS-5.0.0-final-test-evidence.zip'
 if proof.exists()and validate_final_test_archive(frozen,proof)!=json.loads((out/'FINAL-VERIFICATION-5.0.0.json').read_text()):raise ValueError('Flat final verification differs from bundled final test proof')

def public_flat_files(out):
 required=set((*BINARY_FILES,*SOURCE_FILES,*EXTRA_PACKAGES,*REQUIRED_DOCS,'SOURCE-COMMIT-5.0.0.json','ASSEMBLY-REPORT-5.0.0.json'))
 extra=EXTRA_PUBLIC
 result=[]
 for p in sorted(out.iterdir()):
  if not p.is_file()or p.name.endswith('.UNSIGNED.json')or p.name.startswith('SIGNING-HASHES')or p.name==OWNER_ZIP:continue
  if p.name not in required and p.name not in extra:continue
  regular(p)
  if not SAFE_NAME.fullmatch(p.name):raise ValueError('Unsafe flat filename')
  if p.suffix in('.json','.md','.txt'):public_text(p.name,p.read_bytes())
  result.append(p)
 return result

def generate_manifest(frozen,out):
 previous_bytecode=sys.dont_write_bytecode;sys.dont_write_bytecode=True
 sys.path.insert(0,str(frozen.project/'tools'))
 try:
  spec=importlib.util.spec_from_file_location('aegis500_generator',frozen.project/'tools/generate-release-manifest.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  exact=m.build_manifest(out,VERSION,'stable',published_at=frozen.date.isoformat(timespec='seconds').replace('+00:00','Z'),title='АЕГИС 5.0.0 — Организации, Новости, Библиотека и Безопасность')
  target=out/'stable-5.0.0.UNSIGNED.json'
  if (out/(target.name+'.sig')).exists():raise ValueError('Do not overwrite owner-signed metadata')
  temp=out/(str(uuid.uuid4())+'.UNSIGNED.json')
  try:m.write_unsigned(temp,exact);os.replace(temp,target)
  finally:temp.unlink(missing_ok=True)
  return target
 finally:sys.path.pop(0);sys.dont_write_bytecode=previous_bytecode
def finalize(frozen,out):
 copy_docs(frozen,out,True);validate_bindings(frozen,out)
 report={**frozen.identity,'packageKind':'UNSIGNED_OWNER_ACCEPTANCE_CANDIDATE','nativeAcceptanceExecutedByAssembler':False,'ownerPrivateKeyUsed':False,'productionRelayOrFeedChanged':False,'publicationPerformed':False,'readinessChangedByAssembler':False,'reportedProductionReady':json.loads((out/'FINAL-VERIFICATION-5.0.0.json').read_text()).get('productionReady'),'inputArtifactSha256':{name:sha(out/name)for name in(*BINARY_FILES,*SOURCE_FILES,*EXTRA_PACKAGES)}}
 atomic_bytes(out/'ASSEMBLY-REPORT-5.0.0.json',(json.dumps(report,indent=2)+'\n').encode());files=public_flat_files(out);atomic_bytes(out/'SHA256SUMS',''.join(sha(p)+'  '+p.name+'\n'for p in files).encode('ascii'));manifest=generate_manifest(frozen,out)
 signing={**frozen.identity,'unsignedManifest':{'name':manifest.name,'sha256':sha(manifest)},'checksumsSha256':sha(out/'SHA256SUMS'),'ownerPrivateKeyUsed':False,'instructions':'Sign the exact final manifest offline; no production signature was generated.'};atomic_bytes(out/'SIGNING-HASHES-5.0.0.json',(json.dumps(signing,indent=2)+'\n').encode())
 bundle=files+[out/'SHA256SUMS',manifest,out/'SIGNING-HASHES-5.0.0.json'];temp=out/('.owner-'+str(uuid.uuid4())+'.zip.part')
 try:
  with zipfile.ZipFile(temp,'w',zipfile.ZIP_STORED)as z:
   for p in bundle:
    i=zipfile.ZipInfo(p.name,frozen.zip_date);i.compress_type=zipfile.ZIP_STORED;i.external_attr=0o100644<<16
    with p.open('rb')as src,z.open(i,'w')as dest:
     import shutil;shutil.copyfileobj(src,dest,1024*1024)
  checked_zip(temp);os.replace(temp,out/OWNER_ZIP)
 finally:temp.unlink(missing_ok=True)
 atomic_bytes(out/(OWNER_ZIP+'.sha256'),(sha(out/OWNER_ZIP)+'  '+OWNER_ZIP+'\n').encode('ascii'));frozen.assert_clean();return out/OWNER_ZIP

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True);g.add_argument('--prepare',action='store_true');g.add_argument('--finalize',action='store_true');p.add_argument('--expected-commit',required=True);p.add_argument('--artifacts',type=pathlib.Path,required=True);p.add_argument('--evidence',type=pathlib.Path,required=True);a=p.parse_args(argv)
 frozen=Frozen(ROOT,a.expected_commit);out=a.artifacts.resolve()
 if out.is_relative_to(frozen.repo):raise ValueError('Artifacts must be outside the source checkout')
 out.mkdir(parents=True,exist_ok=True)
 if a.prepare:
  source_archives(frozen,out);deferred=copy_docs(frozen,out);count=evidence_archive(frozen,out,a.evidence);frozen.assert_clean();print(json.dumps({'phase':'prepare','sourceCommit':frozen.commit,'evidenceFiles':count,'deferredOwnerGeneratedDocuments':deferred,'signed':False,'published':False}))
 else:
  bundle=finalize(frozen,out);print(json.dumps({'phase':'finalize','file':bundle.name,'bytes':bundle.stat().st_size,'sha256':sha(bundle),'signed':False,'published':False,'readinessChanged':False}))
 return 0
if __name__=='__main__':raise SystemExit(main())
