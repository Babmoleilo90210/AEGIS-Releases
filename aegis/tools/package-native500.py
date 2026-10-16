#!/usr/bin/env python3
"""Prepare the 5.0 owner kit from frozen source/client ZIPs; never run native tests.
No downloads, production profile/Relay/feed changes, signing, microphone or browser launch.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,pathlib,shutil,subprocess,tempfile,uuid,zipfile
VERSION='5.0.0'
APPLICATION_JARS=('client-core-5.0.0.jar','client-ui-5.0.0.jar','common-protocol-0.2.0.jar')
OBSOLETE_UI={'SafeWeb200Smoke.java','Interface200Smoke.java','SettingsResponsive200Smoke.java','Interface250RefinementSmoke.java'}
REQUIRED_UI=('Interface500Smoke.java','ArchiveMenu500Smoke.java','Community500FlowSmoke.java','VzorGlas250Smoke.java')
PINNED={
 'sqlite-jdbc-3.53.4.0.jar':'bcb1f51e36f940867e83342f9efbf5968ac44a6bef4d397bb4af7b17b45cd2fb',
 'slf4j-api-2.0.17.jar':'7b751d952061954d5abfed7181c1f645d336091b679891591d63329c622eb832',
 'slf4j-nop-2.0.17.jar':'3716f83649ec66161a2edefd4f49df34d1dd1c51cdcf941996c6987260f0a829',
 'junit-platform-console-standalone-1.13.4.jar':'3fdfc37e29744a9a67dd5365e81467e26fbde0b7aa204e6f8bbe79eeaa7ae892'}
PLATFORMS=('Windows11x64','CachyOSKDEWayland','CachyOSKDEX11')
CHECKS=('STARTUP','LOGIN','TOR','MAIL','CONTACTS','PROFILES_AVATARS','PERSONAL_ARCHIVE','VZOR','GLAS','CALL_PERMISSIONS','ORGANIZATIONS','ROLES_ACCESS','NEWS','CITY_FEED','EVENTS','LIBRARY_GRAPH','EDITORS','AI_LINKS','ADMINISTRATION','SIGNED_UPDATER')
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def helper():
 spec=importlib.util.spec_from_file_location('native250_helpers',pathlib.Path(__file__).with_name('package-native250.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def source_identity(directory):
 p=directory/f'SOURCE-COMMIT-{VERSION}.json';m=json.loads(p.read_text('utf-8'))
 import re
 if m.get('version')!=VERSION or any(not re.fullmatch('[a-f0-9]{40}',str(m.get(k,'')))for k in ('sourceCommit','sourceTree','baseCommit')):raise ValueError('Frozen source identity is missing or invalid')
 return m

def check_client(app):
 for name in APPLICATION_JARS:
  if not(app/'app'/name).is_file():raise ValueError('Missing 5.0 application JAR: '+name)
 for p in(app/'app').glob('*.jar'):
  if p.name.startswith(('client-core-','client-ui-','common-protocol-'))and p.name not in APPLICATION_JARS:raise ValueError('Mixed application JARs')
  if p.name.startswith(('relay-server','community-server','news-worker','aegis-native-tests','aegis-community-tests','aegis-ui-tests','junit-')):raise ValueError('Server/test classes leaked into production client')

def statuses(metadata):
 def item(key):return {'id':key,'status':'NOT_RUN','checkedAtUtc':None,'evidence':[],'notes':''}
 return {'schemaVersion':1,'version':VERSION,'sourceCommit':metadata['sourceCommit'],'sourceTree':metadata['sourceTree'],'productionReady':False,'confirmedByOwner':False,'testedArtifacts':{},'platforms':[{ 'id':p,'osEdition':'','osBuild':'','desktop':'','session':('wayland'if p.endswith('Wayland')else'x11'if p.endswith('X11')else'windows'),'hardwareLabel':'','checks':[item(c)for c in CHECKS]}for p in PLATFORMS],'twoPhysicalDevices':{'deviceLabels':[],'independentNetworkLabels':[],'checks':[item(f'CROSS-{i:02d}')for i in range(1,16)]},'migration':[item(f'MIGRATION-{i:02d}')for i in range(1,21)],'updater':[item(f'UPDATER-{i:02d}')for i in range(1,26)]}

def results_schema():
 status={'type':'string','enum':['PASS','FAIL','BLOCKED','NOT_RUN']}
 item={'type':'object','additionalProperties':False,'required':['id','status','checkedAtUtc','evidence','notes'],'properties':{'id':{'type':'string','maxLength':80},'status':status,'checkedAtUtc':{'type':['string','null'],'maxLength':40},'evidence':{'type':'array','maxItems':30,'items':{'type':'object','additionalProperties':False,'required':['path','sha256'],'properties':{'path':{'type':'string','pattern':r'^(?!/)(?!.*(?:\.\.|\\|:)).+$','maxLength':240},'sha256':{'type':'string','pattern':'^[a-f0-9]{64}$'}}}},'notes':{'type':'string','maxLength':2000}},'allOf':[{'if':{'properties':{'status':{'const':'PASS'}}},'then':{'properties':{'checkedAtUtc':{'type':'string','minLength':20},'evidence':{'minItems':1}}}}]}
 checks={'type':'array','items':item,'minItems':1,'maxItems':100}
 platform={'type':'object','additionalProperties':False,'required':['id','osEdition','osBuild','desktop','session','hardwareLabel','checks'],'properties':{'id':{'enum':list(PLATFORMS)},**{k:{'type':'string','maxLength':160}for k in('osEdition','osBuild','desktop','hardwareLabel')},'session':{'enum':['windows','wayland','x11']},'checks':checks}}
 return {'$schema':'https://json-schema.org/draft/2020-12/schema','title':'AEGIS 5.0 owner evidence, no automatic readiness promotion','type':'object','additionalProperties':False,'required':['schemaVersion','version','sourceCommit','sourceTree','productionReady','confirmedByOwner','testedArtifacts','platforms','twoPhysicalDevices','migration','updater'],'properties':{'schemaVersion':{'const':1},'version':{'const':VERSION},'sourceCommit':{'type':'string','pattern':'^[a-f0-9]{40}$'},'sourceTree':{'type':'string','pattern':'^[a-f0-9]{40}$'},'productionReady':{'const':False},'confirmedByOwner':{'type':'boolean'},'testedArtifacts':{'type':'object','additionalProperties':{'type':'string','pattern':'^[a-f0-9]{64}$'}},'platforms':{'type':'array','minItems':3,'maxItems':3,'items':platform,'allOf':[{'contains':{'properties':{'id':{'const':p}},'required':['id']},'minContains':1,'maxContains':1}for p in PLATFORMS]},'twoPhysicalDevices':{'type':'object','additionalProperties':False,'required':['deviceLabels','independentNetworkLabels','checks'],'properties':{'deviceLabels':{'type':'array','maxItems':10,'items':{'type':'string','maxLength':100}},'independentNetworkLabels':{'type':'array','maxItems':10,'items':{'type':'string','maxLength':100}},'checks':checks}},'migration':checks,'updater':checks}}

def compile_java(javac,sources,cp,classes,args):
 classes.mkdir(parents=True,exist_ok=True)
 if not sources or any(not p.is_file()for p in sources):raise ValueError('Missing acceptance source')
 args.write_text('\n'.join('"'+str(p).replace('\\','\\\\').replace('"','\\"')+'"'for p in sources)+'\n',encoding='utf-8')
 subprocess.run([str(javac),'--release','21','-encoding','UTF-8','-parameters','-cp',cp,'-d',str(classes),'@'+str(args)],check=True,timeout=180)
def jar_classes(jar,classes,target,resources=None):
 command=[str(jar),'--create','--date=2026-01-01T00:00:00Z','--file',str(target),'-C',str(classes),'.']
 if resources and resources.is_dir():command+=['-C',str(resources),'.']
 subprocess.run(command,check=True,timeout=60)
def copy_wrappers(source,kit):
 folder=source/'packaging/native-kit500'
 required=('README.md','AppearanceNativeLauncher500.java','Common-CachyOS.sh','Run-Windows.cmd','Run-CachyOS.sh','Run-Appearance-Windows.cmd','Run-Appearance-CachyOS.sh','Run-Voice-Windows.cmd','Run-Voice-CachyOS.sh','Run-Community-Windows.cmd','Run-Community-CachyOS.sh','Run-Community-UI-Windows.cmd','Run-Community-UI-CachyOS.sh','tor-runtime-provenance-5.0.0.json','snowflake-bridges.txt')
 for name in required:
  p=folder/name
  if not p.is_file():raise ValueError('Missing current wrapper: '+name)
  if p.suffix=='.cmd':(kit/name).write_bytes(('\r\n'.join(p.read_text('utf-8').splitlines())+'\r\n').encode('utf-8'))
  else:shutil.copy2(p,kit/name)
  if p.suffix=='.sh':(kit/name).chmod(0o755)
def package(a):
 h=helper();artifacts=a.artifacts.resolve();jdk=a.jdk.resolve();deps=a.test_deps.resolve();suffix='.exe'if(jdk/'bin/javac.exe').is_file()else'';javac=jdk/f'bin/javac{suffix}';jar=jdk/f'bin/jar{suffix}'
 version=subprocess.run([str(javac),'-version'],capture_output=True,text=True,check=True,timeout=15).stdout
 if not version.startswith('javac 21.'):raise ValueError('A trusted Java 21 JDK is required')
 for name,digest in PINNED.items():
  if not(deps/name).is_file()or(deps/name).is_symlink()or sha(deps/name)!=digest:raise ValueError('Unverified test dependency: '+name)
 source_zip=artifacts/f'AEGIS-{VERSION}-client-source.zip';client_zip=artifacts/f'AEGIS-{VERSION}-Windows-x64.zip'
 with tempfile.TemporaryDirectory(prefix='aegis500-native-kit-')as tmp:
  tmp=pathlib.Path(tmp);h.extract(source_zip,tmp/'source');h.extract(client_zip,tmp/'client');identity=source_identity(tmp/'source');source=tmp/'source/aegis';app=tmp/'client/AEGIS';check_client(app)
  # The packager and safety helper must be the exact frozen sources being packaged.
  for name in('package-native500.py','package-native250.py'):
   if sha(source/'tools'/name)!=sha(pathlib.Path(__file__).with_name(name)):raise ValueError('Packager differs from frozen source')
  kit=tmp/'native-acceptance';kit.mkdir();copy_wrappers(source,kit);cp=str(app/'app/*');classes=tmp/'ui-native-classes'
  # Current UI integration fixtures import the real community services. Build
  # their separate staging runtime before compiling those fixtures; client app/
  # stays unchanged and contains no server or test dependencies.
  staging=kit/'staging';staging.mkdir()
  for name in PINNED:shutil.copy2(deps/name,staging/name)
  service_classes=tmp/'service-classes';compile_java(javac,sorted((source/'community-server/src/main/java').rglob('*.java')),cp,service_classes,tmp/'community.sources');jar_classes(jar,service_classes,staging/'community-server.jar',source/'community-server/src/main/resources')
  worker_classes=tmp/'worker-classes';compile_java(javac,sorted((source/'news-worker/src/main/java').rglob('*.java')),cp+os.pathsep+str(service_classes),worker_classes,tmp/'worker.sources');jar_classes(jar,worker_classes,staging/'news-worker.jar',source/'news-worker/src/main/resources')
  cp+=os.pathsep+str(staging/'*')
  ui=source/'client-ui/src/smoke/java';sources=[p for p in sorted(ui.rglob('*.java'))if p.name not in OBSOLETE_UI]
  for name in REQUIRED_UI:
   if not any(p.name==name for p in sources):raise ValueError('Missing current 5.0 fixture: '+name)
  native=source/'client-core/src/test/java/org/securemail/client/security';sources +=[native/n for n in('NativeAcceptanceMain.java','NativeCredentialStoreSmoke.java','VoiceNativeAcceptanceMain.java')];sources.append(kit/'AppearanceNativeLauncher500.java');compile_java(javac,sources,cp,classes,tmp/'ui.sources')
  native_classes=tmp/'native-classes';ui_classes=tmp/'ui-classes';native_classes.mkdir();ui_classes.mkdir()
  for f in classes.rglob('*.class'):
   rel=f.relative_to(classes);target=(native_classes if'security'in rel.parts else ui_classes)/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(f,target)
  jar_classes(jar,native_classes,kit/'aegis-native-tests.jar');jar_classes(jar,ui_classes,kit/'aegis-ui-tests.jar')
  with zipfile.ZipFile(kit/'aegis-ui-tests.jar')as archive:
   if any(any(pathlib.Path(x).stem.split('$')[0]==pathlib.Path(o).stem for o in OBSOLETE_UI)for x in archive.namelist()):raise ValueError('Obsolete UI assertions leaked')
  tests=sorted((source/'community-server/src/test/java').rglob('*.java'))+sorted((source/'news-worker/src/test/java').rglob('*.java'))+sorted((source/'client-core/src/test/java/org/securemail/client/community').glob('*.java'))+[source/'integration-tests/src/test/java/org/securemail/integration/CommunityIntegration500Test.java']
  test_classes=tmp/'community-test-classes';test_cp=cp+os.pathsep+str(staging/'*');compile_java(javac,tests,test_cp,test_classes,tmp/'community-tests.sources');jar_classes(jar,test_classes,kit/'aegis-community-tests.jar')
  h.copy_frozen_fixtures(source,kit)
  for name in('NATIVE-ACCEPTANCE-5.0.0.md','VZOR-5.0.0.md','GLAS-5.0.0.md','LIBRARY-THREAT-MODEL-5.0.0.md','VERIFICATION-SYSTEM-5.0.0.md'):shutil.copy2(source/name,kit/name)
  shutil.copy2(source/'packaging/native-kit/voice-runtime-provenance.json',kit/'voice-runtime-provenance.json')
  metadata={'version':VERSION,**identity,'productionReady':False,'nativeAcceptanceExecuted':False,'applicationJarSha256':{n:sha(app/'app'/n)for n in APPLICATION_JARS},'sourceZipSha256':sha(source_zip),'windowsClientZipSha256':sha(client_zip),'testDependencySha256':dict(PINNED),'testJdkVersion':version.strip(),'testJarSha256':{p.name:sha(p)for p in sorted(kit.glob('*.jar'))},'stagingJarSha256':{p.name:sha(p)for p in sorted(staging.glob('*.jar'))},'productionClientClasspathModified':False,'microphoneOpenedByPackaging':False,'signatureFixtures':'EPHEMERAL_TEST_KEYS_ONLY; NOT OWNER SIGNING OR UPDATER E2E','currentUiFixtures':list(REQUIRED_UI),'excludedObsoleteUi':sorted(OBSOLETE_UI),'trustedTorInputsSha256':{n:sha(kit/n)for n in('tor-runtime-provenance-5.0.0.json','snowflake-bridges.txt')},'targetPlatforms':{p:'NOT_RUN'for p in PLATFORMS}}
  (kit/'TESTED-ARTIFACTS.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');owner=statuses(identity);owner['testedArtifacts']={name:sha(artifacts/name)for name in(f'AEGIS-Setup-{VERSION}-x64.exe',f'AEGIS-{VERSION}-Windows-x64.zip',f'AEGIS-{VERSION}-CachyOS-x86_64.AppImage',f'AEGIS-{VERSION}-source.zip',f'AEGIS-{VERSION}-client-source.zip')if(artifacts/name).is_file()};(kit/'OWNER-RESULTS-5.0.0.json').write_text(json.dumps(owner,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');(kit/'OWNER-RESULTS-5.0.0.schema.json').write_text(json.dumps(results_schema(),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
  (kit/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.relative_to(kit).as_posix()+'\n'for p in sorted(kit.rglob('*'))if p.is_file()and p.name!='SHA256SUMS'),encoding='ascii')
  archive=artifacts/f'AEGIS-{VERSION}-native-acceptance.zip';partial=artifacts/f'.native500-{uuid.uuid4()}.zip.part'
  try:
   with zipfile.ZipFile(partial,'w',zipfile.ZIP_DEFLATED,compresslevel=6)as z:
    for p in sorted(kit.rglob('*')):
     if p.is_file():
      info=zipfile.ZipInfo('native-acceptance/'+p.relative_to(kit).as_posix(),(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=(0o100755 if p.suffix=='.sh'else 0o100644)<<16;z.writestr(info,p.read_bytes())
   with zipfile.ZipFile(partial)as z:
    if z.testzip():raise ValueError('Native ZIP CRC failed')
   destination=artifacts/'native-acceptance500'
   previous=None
   if destination.exists():
    previous=artifacts/f'native-acceptance500-previous-{uuid.uuid4()}';destination.rename(previous)
   try:shutil.copytree(kit,destination);partial.replace(archive)
   except Exception:
    if destination.exists():shutil.rmtree(destination)
    if previous is not None:previous.rename(destination)
    raise
  finally:partial.unlink(missing_ok=True)
 print(json.dumps({'file':archive.name,'sha256':sha(archive),'bytes':archive.stat().st_size,'nativeAcceptanceExecuted':False}))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--jdk',type=pathlib.Path,required=True);p.add_argument('--artifacts',type=pathlib.Path,required=True);p.add_argument('--test-deps',type=pathlib.Path,required=True);package(p.parse_args())
if __name__=='__main__':main()
