from pathlib import Path,PurePosixPath
import zipfile,hashlib,json,subprocess,struct,datetime
root=Path(__file__).resolve().parent
source=root/'OpenJDK21U-jre_x64_windows_hotspot_21.0.12.1_1.zip'
release=json.loads((root/'temurin21-release.json').read_text())
asset=next(a for a in release['assets'] if a['name']==source.name)
def sha(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
expected=asset['digest'].removeprefix('sha256:')
if sha(source)!=expected or (root/(source.name+'.sha256.txt')).read_text().split()[0]!=expected:raise ValueError('Vendor digest mismatch')
parent='jdk-21.0.12.1+1-jre/'
destination=root/'windows'
files={};archive_files={};names=set()
with zipfile.ZipFile(source) as archive:
 if len(archive.infolist())>5000 or sum(i.file_size for i in archive.infolist())>500_000_000:raise ValueError('Archive bounds')
 for item in archive.infolist():
  path=PurePosixPath(item.filename)
  if not item.filename.startswith(parent) or path.is_absolute() or '..' in path.parts or '\\' in item.filename or ':' in item.filename or ((item.external_attr>>16)&0o170000)==0o120000:raise ValueError('Unsafe member')
  if item.filename.casefold() in names:raise ValueError('Casefold duplicate')
  names.add(item.filename.casefold())
  if item.is_dir():continue
  relative=item.filename[len(parent):]
  if not relative:raise ValueError('Empty file')
  data=archive.read(item)
  archive_files[relative]=hashlib.sha256(data).hexdigest()
 if not destination.exists():
  staging=root/'windows-extraction'
  if staging.exists():raise ValueError('Stale staging exists')
  staging.mkdir(mode=0o700)
  archive.extractall(staging)
  (staging/parent.rstrip('/')).rename(destination)
  staging.rmdir()
for path in sorted(destination.rglob('*')):
 if path.is_symlink():raise ValueError('Unexpected tree link')
 if path.is_file():files[path.relative_to(destination).as_posix()]=sha(path)
if files!=archive_files:raise ValueError('Extracted runtime tree differs from signed-hash vendor ZIP')
release_values={}
for line in (destination/'release').read_text().splitlines():
 if '=' in line:
  key,value=line.split('=',1);release_values[key]=value.strip('"')
modules=release_values['MODULES'].split()
for module in ['java.desktop','java.management','java.sql','jdk.charsets','jdk.crypto.ec','jdk.localedata','jdk.unsupported']:
 if module not in modules:raise ValueError('Missing module '+module)
if release_values['JAVA_VERSION']!='21.0.12.1' or release_values['OS_ARCH']!='x86_64':raise ValueError('Wrong Java version/arch')
pe=(destination/'bin/java.exe').read_bytes();offset=struct.unpack_from('<I',pe,0x3c)[0]
if pe[:2]!=b'MZ' or pe[offset:offset+4]!=b'PE\0\0' or struct.unpack_from('<H',pe,offset+4)[0]!=0x8664:raise ValueError('Not AMD64 PE')
jimage=Path('/workspace/scratch/aa629f360927/inputs/jdk-21.0.12.1+1/bin/jimage')
image=subprocess.run([str(jimage),'list',str(destination/'lib/modules')],check=True,text=True,capture_output=True,timeout=45).stdout
(root/'windows-jimage-list.txt').write_text(image)
required_resources=['sun/text/resources/cldr/ext/FormatData_ru.class','sun/util/resources/cldr/ext/LocaleNames_ru.class','sun/util/resources/cldr/ext/CurrencyNames_ru.class','sun/util/resources/cldr/ext/TimeZoneNames_ru.class']
for resource in required_resources:
 if resource not in image:raise ValueError('Russian module resource absent: '+resource)
licenses=[path for path in files if path.startswith('legal/') or path in ['NOTICE','LICENSE']]
if 'legal/java.base/LICENSE' not in files or 'legal/jdk.localedata/LICENSE' not in files:raise ValueError('License files absent')
proof={'schemaVersion':1,'preparedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'PASS_OFFLINE_VENDOR_TREE_AND_RU_RESOURCES','vendor':'Eclipse Adoptium','releaseTag':release['tag_name'],'releaseUrl':release['html_url'],'releaseApiUrl':'https://api.github.com/repos/adoptium/temurin21-binaries/releases/tags/jdk-21.0.12.1%2B1','releaseApiSnapshotSha256':sha(root/'temurin21-release.json'),'assetUrl':asset['browser_download_url'],'assetId':asset['id'],'archiveSize':source.stat().st_size,'archiveSha256':expected,'checksumUrl':asset['browser_download_url']+'.sha256.txt','vendorAssetDigestVerified':True,'vendorSha256TextVerified':True,'zipCrcAndEveryExtractedFileVerified':True,'runtimeRoot':str(destination),'release':release_values,'releaseModules':modules,'runtimeFileCount':len(files),'runtimeFilesSha256':files,'archiveRuntimeFilesSha256':archive_files,'runtimeSymlinks':{},'licenseFiles':licenses,'ruResourcesPresent':required_resources,'jimageListingSha256':sha(root/'windows-jimage-list.txt'),'javaExePeMachine':'AMD64_0x8664','windowsNativeExecution':'NOT_RUN','actualWindowsRussianFormatting':'NOT_RUN','targetPlatformAcceptance':'NOT_RUN','productionReady':False}
(root/'windows-runtime-provenance.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({key:proof[key] for key in ['status','runtimeRoot','archiveSha256','runtimeFileCount','javaExePeMachine','windowsNativeExecution','actualWindowsRussianFormatting','productionReady']},indent=2))
