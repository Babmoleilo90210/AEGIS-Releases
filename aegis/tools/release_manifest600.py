"""Frozen ecosystem release inventory; no private keys, signatures, publication or runtime updater claims."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import stat
import zipfile
from datetime import datetime, timezone
import release_manifest as legacy

VERSION = '6.0.0'
ROLES = {
 'debian13-server': 'AEGIS-6.0.0-Debian13-Server.tar.gz',
 'windows-installer': 'AEGIS-Setup-6.0.0-x64.exe',
 'windows-portable': 'AEGIS-6.0.0-Windows-x64.zip',
 'cachyos-appimage': 'AEGIS-6.0.0-CachyOS-x86_64.AppImage',
 'source': 'AEGIS-6.0.0-source.zip',
 'client-source': 'AEGIS-6.0.0-client-source.zip',
 **{f'android-{app.lower()}':f'AEGIS-{app}-6.0.0-unsigned.apk' for app in ('Core','Mail','Glas','Strazh')},
}
FINAL_ANDROID = {f'android-{app.lower()}':f'AEGIS-{app}-6.0.0.apk' for app in ('Core','Mail','Glas','Strazh')}
OPTIONAL_ROLES = {f'android-{app.lower()}-test':f'AEGIS-{app}-6.0.0-TEST.apk' for app in ('Core','Mail','Glas','Strazh')}
GROUPS = {'source':None,'client-source':None,'debian13-server':'debian13-server','windows-installer':'windows11-x64','windows-portable':'windows11-x64','cachyos-appimage':'cachyos-kde-x86_64',**{f'android-{app}':'android13-arm64' for app in ('core','mail','glas','strazh')}}
PUBLIC_DENY = {'.pem','.key','.pkcs8','.p12','.pfx','.env','.db','.sqlite','.vault','.enc'}


def document(path, limit=1024*1024):
    value = json.loads(legacy.exact_bytes(path, limit).decode('utf-8'), object_pairs_hook=legacy.unique_object)
    if not isinstance(value, dict): raise ValueError('JSON object required')
    return value


def git(project, *arguments):
    return subprocess.check_output(['git','-C',str(project),*arguments], stderr=subprocess.DEVNULL, timeout=60).decode('utf-8').strip()


class Frozen:
    def __init__(self, project, commit):
        if not re.fullmatch('[a-f0-9]{40}',commit): raise ValueError('Exact source commit required')
        self.project=Path(project).resolve();self.commit=commit
        self.tree=git(self.project,'rev-parse',commit+'^{tree}')
        self.epoch=int(git(self.project,'show','-s','--format=%ct',commit))
        self.assert_clean()
        self.repo=Path(git(self.project,'rev-parse','--show-toplevel'))
        prefix=self.project.relative_to(self.repo).as_posix();self.prefix='' if prefix=='.' else prefix+'/'
        self.entries={}
        data=subprocess.check_output(['git','-C',str(self.repo),'ls-tree','-r','-l','-z',commit],timeout=60)
        for row in data.split(b'\0'):
            if not row:continue
            meta,name=row.split(b'\t',1);mode,kind,oid,size=meta.decode('ascii').split();name=name.decode('utf-8')
            if kind!='blob' or mode not in ('100644','100755') or name.startswith('/') or '..' in Path(name).parts or '\\' in name:raise ValueError('Unsupported frozen source entry')
            self.entries[name]=(mode,oid,int(size))
    def assert_clean(self):
        if git(self.project,'rev-parse','HEAD')!=self.commit or git(self.project,'status','--porcelain','--untracked-files=all'):
            raise ValueError('Source must be frozen at the exact clean HEAD')



def source_identity(frozen):return {'version':VERSION,'sourceCommit':frozen.commit,'sourceTree':frozen.tree}

def source_members(frozen,client):
    return {('aegis/'+name[len(frozen.prefix):] if client else name):entry for name,entry in frozen.entries.items() if not client or name.startswith(frozen.prefix)}

def verify_source_archive(frozen,path,client=False):
    expected=source_members(frozen,client);metadata='SOURCE-COMMIT-6.0.0.json'
    with zipfile.ZipFile(path) as archive:
        infos=archive.infolist();names=[info.filename for info in infos]
        if len(names)!=len(set(names)) or set(names)!=set(expected)|{metadata}:raise ValueError('Source ZIP differs from frozen tree scope')
        if archive.getinfo(metadata).file_size>4096 or json.loads(archive.read(metadata),object_pairs_hook=legacy.unique_object)!=source_identity(frozen):raise ValueError('Wrong source ZIP identity')
        for name,(mode,oid,size) in expected.items():
            info=archive.getinfo(name)
            if info.file_size!=size or stat.S_ISLNK(info.external_attr>>16) or (info.external_attr>>16)&0o777!=int(mode,8)&0o777:raise ValueError('Wrong source ZIP member size/mode')
            digest=hashlib.sha1(b'blob '+str(size).encode('ascii')+b'\0')
            with archive.open(info) as stream:
                for chunk in iter(lambda:stream.read(65536),b''):digest.update(chunk)
            if digest.hexdigest()!=oid:raise ValueError('Source ZIP blob differs from frozen commit')

class GitBlobs:
    """One bounded per-object batch stream avoids a process spawn for every source file."""
    def __init__(self,repo):self.repo=repo
    def __enter__(self):
        self.process=subprocess.Popen(['git','-C',str(self.repo),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        return self
    def read(self,oid,size):
        if size<0 or size>legacy.MAX_ASSET:raise ValueError('Frozen source blob too large')
        self.process.stdin.write((oid+'\n').encode('ascii'));self.process.stdin.flush()
        header=self.process.stdout.readline(256)
        if header!=(oid+' blob '+str(size)+'\n').encode('ascii'):raise ValueError('Unexpected Git object response')
        data=self.process.stdout.read(size)
        if len(data)!=size or self.process.stdout.read(1)!=b'\n' or hashlib.sha1(b'blob '+str(size).encode()+b'\0'+data).hexdigest()!=oid:raise ValueError('Git source blob mismatch')
        return data
    def __exit__(self,kind,error,trace):
        self.process.stdin.close()
        if error is not None:self.process.kill()
        try:self.process.wait(timeout=60)
        except subprocess.TimeoutExpired:self.process.kill();self.process.wait();raise
        finally:self.process.stdout.close()
        if error is None and self.process.returncode:raise ValueError('Git source reader failed')

def prepare_source_archives(project,source_commit,output):
    frozen=Frozen(project,source_commit);output=Path(output)
    if output.is_symlink():raise ValueError('Symbolic output directory')
    output.mkdir(parents=True,exist_ok=True);results={}
    stamp=datetime.fromtimestamp(frozen.epoch,timezone.utc);date=tuple(stamp.timetuple()[:6])
    if not 1980<=date[0]<=2107:raise ValueError('ZIP commit date unsupported')
    with tempfile.TemporaryDirectory(prefix='aegis600-source-') as temporary:
        for client,name in [(False,'AEGIS-6.0.0-source.zip'),(True,'AEGIS-6.0.0-client-source.zip')]:
            target=output/name
            if target.exists() or target.is_symlink():raise ValueError('Source archive output already exists')
            staged=Path(temporary)/name
            with GitBlobs(frozen.repo) as blobs, zipfile.ZipFile(staged,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
                for member,(mode,oid,size) in source_members(frozen,client).items():
                    data=blobs.read(oid,size)
                    info=zipfile.ZipInfo(member,date);info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=int(mode,8)<<16;archive.writestr(info,data)
                info=zipfile.ZipInfo('SOURCE-COMMIT-6.0.0.json',date);info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16;archive.writestr(info,(json.dumps(source_identity(frozen),indent=2)+'\n').encode())
            verify_source_archive(frozen,staged,client);frozen.assert_clean()
            with staged.open('rb') as source,target.open('xb') as sink:
                for chunk in iter(lambda:source.read(65536),b''):sink.write(chunk)
                sink.flush();os.fsync(sink.fileno())
            results[name]=legacy.sha256(target)
    return results


def load_generator():
    spec=importlib.util.spec_from_file_location('aegis600_legacy_generator',Path(__file__).with_name('generate-release-manifest.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def build(project, source_commit, artifacts, spec_file, published_at=None, *, apksigner=None, expected_apk_certificate=None):
    frozen=Frozen(project,source_commit);directory=Path(artifacts)
    if directory.is_symlink() or not directory.is_dir(): raise ValueError('Regular artifact directory required')
    directory=directory.resolve();spec=document(spec_file,65536)
    if set(spec)!={'schemaVersion','version','sourceCommit','artifacts'} or type(spec['schemaVersion']) is not int or spec['schemaVersion']!=1 or spec['version']!=VERSION or spec['sourceCommit']!=source_commit:
        raise ValueError('Wrong ecosystem specification/source binding')
    items=spec['artifacts']
    if not isinstance(items,list) or not len(ROLES)<=len(items)<=len(ROLES)+len(OPTIONAL_ROLES): raise ValueError('Incomplete ecosystem artifact set')
    generator=load_generator();inventory=generator.checksum_inventory(directory)
    for name in inventory:
        if Path(name).suffix.lower() in PUBLIC_DENY or name.lower().startswith(('release-private','password','api-key')):
            raise ValueError('Private data is not a public release artifact')
    if (apksigner is None)!=(expected_apk_certificate is None):raise ValueError('Both public apksigner and expected APK certificate are required')
    final_apks=apksigner is not None
    if final_apks and not re.fullmatch('[a-f0-9]{64}',expected_apk_certificate):raise ValueError('Expected lowercase APK certificate SHA-256 required')
    names={**ROLES,**OPTIONAL_ROLES,**(FINAL_ANDROID if final_apks else {})}
    seen=set();records=[];provenances={}
    for item in items:
        if not isinstance(item,dict) or set(item)!={'role','fileName','provenanceFile'}:raise ValueError('Unknown artifact specification')
        role,name,proof=item['role'],item['fileName'],item['provenanceFile']
        if not isinstance(role,str) or role in seen or names.get(role)!=name:raise ValueError('Wrong duplicate role/name')
        if not isinstance(proof,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,179}\\.json',proof):raise ValueError('Unsafe provenance filename')
        if name not in inventory or proof not in inventory:raise ValueError('Final artifact/provenance missing from checksums')
        path=directory/name;size=path.stat().st_size
        if not 0<size<=legacy.MAX_ASSET:raise ValueError('Artifact size outside supported release limits')
        provenance=document(directory/proof)
        binding=provenance.get('sourceCommit');aliases=[provenance[k] for k in ('implementationCommit',) if k in provenance]
        if binding!=source_commit or any(value!=source_commit for value in aliases) or provenance.get('sourceTree',frozen.tree)!=frozen.tree:
            raise ValueError('Artifact provenance binds another source')
        hashes=provenance.get('binaryArtifactSha256')
        if not isinstance(hashes,dict) or hashes.get(name)!=inventory[name]:raise ValueError('Provenance does not bind exact artifact bytes')
        if role in ('source','client-source'):verify_source_archive(frozen,path,role=='client-source')
        seen.add(role);provenances[proof]={'fileName':proof,'sha256':inventory[proof]}
        record={'role':role,'deliverable':GROUPS.get(role.removesuffix('-test')),'fileName':name,'size':size,'sha256':inventory[name],'url':legacy.release_url(VERSION,name),'sourceCommit':source_commit,'provenanceFile':proof}
        if role.startswith('android-'):
            if final_apks and not role.endswith('-test'):
                from apk_public_verify600 import verify
                receipt=verify(Path(apksigner),path,expected_apk_certificate)
                if receipt.get('apkSha256')!=inventory[name]:raise ValueError('APK changed after checksum inventory')
                record['apkSigning']='owner-certificate-publicly-verified';record['apkVerification']=receipt
            else:record['apkSigning']='test-signature-not-for-production' if role.endswith('-test') else 'unsigned-owner-apk-signing-required' 
        records.append(record)
    if not set(ROLES)<=seen:raise ValueError('A required deliverable is missing')
    stamp=published_at or datetime.fromtimestamp(frozen.epoch,timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
    bootstrap=generator.build_manifest(directory,VERSION,'stable',minimum_supported='1.5.0',published_at=stamp,title='АЕГИС 6.0.0 — модульная экосистема')
    ecosystem={'schemaVersion':1,'application':'AEGIS-ECOSYSTEM','version':VERSION,'tag':'v'+VERSION,'repository':legacy.REPOSITORY,'sourceCommit':source_commit,'sourceTree':frozen.tree,'publishedAt':stamp,'status':'UNSIGNED_OWNER_ACCEPTANCE_CANDIDATE','productionReady':False,'ownerPrivateKeyUsed':False,'productionSignatureGenerated':False,'runtimeEcosystemUpdater':'NOT_IMPLEMENTED_BY_THIS_INVENTORY','artifacts':sorted(records,key=lambda x:x['role']),'provenance':sorted(provenances.values(),key=lambda x:x['fileName']),'checksums':{'fileName':'SHA256SUMS','size':(directory/'SHA256SUMS').stat().st_size,'sha256':legacy.sha256(directory/'SHA256SUMS')},'legacyBootstrapManifest':'AEGIS-6.0.0-stable.UNSIGNED.json','limitations':[(('All four final APK signatures match the explicitly supplied certificate; native acceptance and owner release approval remain separate gates.') if final_apks else 'Owner must sign Android APKs first, then rebuild all hashes/provenance/manifests before Ed25519 release signing.'),'A signed inventory is not evidence of native installation, migration, Tor network, rollback or release acceptance.','Legacy clients consume only the unchanged four-artifact bootstrap manifest; this inventory does not add a runtime updater.']}
    exact=(json.dumps(ecosystem,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    if len(exact)>65536:raise ValueError('Ecosystem inventory too large')
    frozen.assert_clean()
    if generator.checksum_inventory(directory)!=inventory:raise ValueError('Artifact inventory changed during generation')
    return {'AEGIS-6.0.0-stable.UNSIGNED.json':bootstrap,'AEGIS-6.0.0-ecosystem.UNSIGNED.json':exact}


def write_outputs(output, files):
    output=Path(output)
    if output.is_symlink() or output.exists():raise ValueError('Use a new separate output directory')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.aegis600-signing-',dir=output.parent) as temporary:
        staging=Path(temporary)/'candidate';staging.mkdir()
        receipts={}
        for name,data in files.items():
            if not name.endswith('.UNSIGNED.json') or Path(name).name!=name:raise ValueError('Only unsigned manifest outputs are permitted')
            with (staging/name).open('xb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            receipts[name]=hashlib.sha256(data).hexdigest()
        with (staging/'SIGNING-INPUT-SHA256').open('x',encoding='ascii') as stream:
            stream.write(''.join(digest+'  '+name+'\n' for name,digest in sorted(receipts.items())));stream.flush();os.fsync(stream.fileno())
        os.rename(staging,output)
    return receipts


def verify_signed_inventory(manifest, signature, assets):
    """Offline public verification only. This inventory is not a runtime installation authority."""
    data=legacy.exact_bytes(manifest,65536);legacy.verify_signature(data,legacy.exact_bytes(signature,64))
    value=json.loads(data.decode('utf-8'),object_pairs_hook=legacy.unique_object)
    if not isinstance(value,dict) or value.get('application')!='AEGIS-ECOSYSTEM' or value.get('schemaVersion')!=1 or value.get('version')!=VERSION or value.get('tag')!='v'+VERSION or value.get('repository')!=legacy.REPOSITORY or value.get('productionReady') is not False:
        raise ValueError('Wrong ecosystem inventory identity or unsupported readiness claim')
    if not re.fullmatch('[a-f0-9]{40}',value.get('sourceCommit','')) or not re.fullmatch('[a-f0-9]{40}',value.get('sourceTree','')):raise ValueError('Exact frozen source identity required')
    directory=Path(assets)
    if directory.is_symlink() or not directory.is_dir():raise ValueError('Regular final artifact directory required')
    inventory=load_generator().checksum_inventory(directory);checksum=value.get('checksums')
    if not isinstance(checksum,dict) or checksum!={'fileName':'SHA256SUMS','size':(directory/'SHA256SUMS').stat().st_size,'sha256':legacy.sha256(directory/'SHA256SUMS')}:raise ValueError('Checksum inventory binding changed')
    records=value.get('artifacts');seen=set()
    if not isinstance(records,list) or not len(ROLES)<=len(records)<=len(ROLES)+len(OPTIONAL_ROLES):raise ValueError('Wrong ecosystem artifact count')
    for record in records:
        if not isinstance(record,dict):raise ValueError('Artifact object required')
        role=record.get('role');name=record.get('fileName');allowed={**ROLES,**OPTIONAL_ROLES}
        if role in FINAL_ANDROID and name==FINAL_ANDROID[role]:allowed[role]=name
        if role in seen or allowed.get(role)!=name:raise ValueError('Wrong duplicate artifact role/name')
        if record.get('sourceCommit')!=value['sourceCommit'] or record.get('url')!=legacy.release_url(VERSION,name) or inventory.get(name)!=record.get('sha256') or (directory/name).stat().st_size!=record.get('size'):raise ValueError('Final artifact binding changed')
        proof=record.get('provenanceFile')
        if not isinstance(proof,str) or proof not in inventory:raise ValueError('Artifact provenance missing')
        provenance=document(directory/proof)
        if provenance.get('sourceCommit')!=value['sourceCommit'] or provenance.get('sourceTree',value['sourceTree'])!=value['sourceTree'] or provenance.get('binaryArtifactSha256',{}).get(name)!=inventory[name]:raise ValueError('Artifact provenance changed')
        seen.add(role)
    if not set(ROLES)<=seen:raise ValueError('A required deliverable is missing')
    proofs=value.get('provenance')
    if not isinstance(proofs,list):raise ValueError('Provenance inventory required')
    expected={r['provenanceFile'] for r in records}
    if len(proofs)!=len(expected) or {r.get('fileName') for r in proofs if isinstance(r,dict)}!=expected:raise ValueError('Wrong provenance inventory')
    for record in proofs:
        if record!={'fileName':record.get('fileName'),'sha256':inventory.get(record.get('fileName'))}:raise ValueError('Provenance inventory hash changed')
    return value
