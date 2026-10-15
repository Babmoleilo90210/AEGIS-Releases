from pathlib import Path
import hashlib,json,datetime,struct
root=Path(__file__).resolve().parent
linux=json.loads((root/'linux-runtime-proof.json').read_text())
common=json.loads((root/'linux-runtime-common-proof.json').read_text())['runtimes']['linux']
win=json.loads((root/'windows-runtime-provenance.json').read_text())
def sha(p):
 with p.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
for label,directory,files in [('linux',root/'linux',common['files']),('win',root/'windows',win['runtimeFilesSha256'])]:
 for relative,digest in files.items():
  path=directory/relative
  if not path.resolve(strict=True).is_relative_to(directory.resolve()):raise ValueError('Escaping runtime path '+relative)
  if sha(path)!=digest:raise ValueError('Changed runtime file '+label+'/'+relative)
 actual={path.relative_to(directory).as_posix() for path in directory.rglob('*') if path.is_file()}
 if actual!=set(files):raise ValueError('Unexpected runtime files '+label)
 if any(path.suffix in ('.class','.java') or path.name.endswith('proof.json') for path in directory.rglob('*')):raise ValueError('Test/proof data in runtime')
for name in ['bin/java','lib/server/libjvm.so']:
 data=(root/'linux'/name).read_bytes()[:64]
 if data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',data,18)[0]!=62:raise ValueError('Not x86_64 ELF64 '+name)
linux_value={
 'files':common['files'],'sourceArchiveSha256':linux['sourceJdk']['archiveSha256'],'sourceArchiveUrl':linux['sourceJdk']['officialArchiveUrl'],'sourceChecksumUrl':linux['sourceJdk']['officialSha256Url'],'sourceChecksumFileSha256':linux['sourceJdk']['officialSha256FileSha256'],'vendorSha256Verified':True,'javaVersion':linux['runtimeRelease']['JAVA_VERSION'],'modules':linux['runtimeRelease']['MODULES'].split(),'runtimeFilesSha256':linux['runtimeFilesSha256'],'runtimeSymlinks':common['runtimeSymlinks'],'format':'ELF64_x86_64','formatVerifiedFiles':['bin/java','lib/server/libjvm.so'],'jlinkCommand':linux['jlink']['commandShell'],'includeLocales':['en','ru'],'sourceJmodsSha256':linux['sourceJdk']['jmodsSha256'],'licenses':linux['legal'],'localeProbe':{'status':'PASS_CURRENT_LINUX_HOST','results':linux['probe']['results'],'previousRuntimeResults':linux['baseRuntime']['probe'],'sourceSha256':linux['probe']['sourceSha256'],'compiledClassSha256':linux['probe']['compiledClassSha256']},'targetPlatformAcceptance':{'CachyOSKDEWayland':'NOT_RUN','CachyOSKDEX11':'NOT_RUN'}
}
win_value={
 'files':win['runtimeFilesSha256'],'sourceArchiveSha256':win['archiveSha256'],'sourceArchiveUrl':win['assetUrl'],'sourceChecksumUrl':win['checksumUrl'],'sourceArchiveSize':win['archiveSize'],'sourceReleaseTag':win['releaseTag'],'sourceReleaseApiUrl':win['releaseApiUrl'],'sourceReleaseApiSnapshotSha256':win['releaseApiSnapshotSha256'],'vendorSha256Verified':True,'vendorApiAssetDigestVerified':True,'vendorZipEveryExtractedFileSha256Verified':True,'javaVersion':win['release']['JAVA_VERSION'],'modules':win['releaseModules'],'runtimeSymlinks':{},'format':'PE_AMD64_0x8664','formatVerifiedFiles':list(win['peX64Verified']),'licenses':win['licenseFiles'],'ruResourcesPresent':win['ruResourcesPresent'],'jimageListingSha256':win['jimageListingSha256'],'windowsNativeExecution':'NOT_RUN','actualWindowsRussianFormatting':'NOT_RUN','targetPlatformAcceptance':{'Windows11x64':'NOT_RUN'}
}
proof={'version':'2.5.0','schemaVersion':1,'preparedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'purpose':'Locale-complete Java runtime inputs for AEGIS 2.5.0 packaging; test source/classes/proofs stay outside runtime','runtimes':{'linux':linux_value,'win':win_value},'productionReady':False,'runtimeInputsPrepared':True,'nativeAcceptanceExecuted':False}
path=root/'java-runtime-provenance-2.5.0.json';path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
print(path);print(sha(path));print('linuxfiles',len(linux_value['files']),'winfiles',len(win_value['files']))
