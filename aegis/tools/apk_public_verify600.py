"""Public verification only: invokes an official, separately trusted apksigner; never loads keys."""
from __future__ import annotations
import hashlib,os,pathlib,re,subprocess,threading

MAX_OUTPUT=64*1024
TIMEOUT_SECONDS=60

def _digest(path:pathlib.Path)->str:
    with path.open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def _stat(path:pathlib.Path)->tuple:
    s=path.stat();return s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns

def verify(apksigner:pathlib.Path,apk:pathlib.Path,expected_certificate_sha256:str)->dict:
    """Require one exact signer and a verified v2/v3 scheme on the unchanged APK.

    The caller independently provisions the official SDK executable and certificate pin.
    Java/sdk environment is inherited; shell, private keys and signing commands are never used.
    """
    if not isinstance(expected_certificate_sha256,str)or not re.fullmatch('[0-9a-f]{64}',expected_certificate_sha256):raise ValueError('Expected Android certificate must be lowercase SHA-256')
    tool=pathlib.Path(apksigner).resolve(strict=True);package=pathlib.Path(apk).resolve(strict=True)
    if not tool.is_file():raise ValueError('apksigner is not a regular file')
    if tool.suffix.lower()in {'.bat','.cmd','.ps1'}:raise ValueError('Use official lib/apksigner.jar on Windows; shell wrappers are not accepted')
    if tool.suffix.lower()=='.jar':
        java_home=os.environ.get('JAVA_HOME','')
        java=(pathlib.Path(java_home)/'bin'/('java.exe'if os.name=='nt'else'java')).resolve(strict=True)if java_home else None
        if java is None or not java.is_file():raise ValueError('JAVA_HOME is required for official apksigner.jar')
        prefix=[str(java),'-jar',str(tool)]
    else:
        if not os.access(tool,os.X_OK):raise ValueError('apksigner is not executable')
        prefix=[str(tool)]
    if not package.is_file()or package.stat().st_size<1 or package.stat().st_size>1024*1024*1024:raise ValueError('APK size/type is invalid')
    before=_stat(package);package_sha=_digest(package);output=bytearray();overflow=threading.Event();read_failed=threading.Event()
    command=prefix+['verify','--verbose','--print-certs','--min-sdk-version','33','-Werr',str(package)]
    process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,close_fds=True)
    def read_bounded():
        try:
            while True:
                data=process.stdout.read(8192)
                if not data:return
                if len(output)+len(data)>MAX_OUTPUT:
                    overflow.set()
                    try:process.kill()
                    except ProcessLookupError:pass
                    return
                output.extend(data)
        except (OSError,ValueError):read_failed.set()
    reader=threading.Thread(target=read_bounded,name='aegis-public-apk-verifier-output',daemon=True);reader.start()
    try:
        status=process.wait(timeout=TIMEOUT_SECONDS);reader.join(timeout=5)
        if reader.is_alive()or read_failed.is_set():raise ValueError('apksigner output did not finish')
        if overflow.is_set():raise ValueError('apksigner output exceeds bound')
        if status!=0:raise ValueError('apksigner rejected the APK')
    except subprocess.TimeoutExpired as failure:raise ValueError('apksigner verification timed out')from failure
    finally:
        if process.poll()is None:process.kill()
        process.wait(timeout=5)
        if process.stdout:process.stdout.close()
        reader.join(timeout=5)
    if _stat(package)!=before or _digest(package)!=package_sha:raise ValueError('APK changed during verification')
    try:text=bytes(output).decode('utf-8',errors='strict')
    except UnicodeDecodeError as failure:raise ValueError('Invalid apksigner output encoding')from failure
    if 'Verifies'not in text.splitlines()or'DOES NOT VERIFY'in text:raise ValueError('APK verification success missing')
    counts=re.findall(r'^Number of signers: ([0-9]+)$',text,re.M)
    certificates=re.findall(r'^Signer #([0-9]+) certificate SHA-256 digest: ([0-9a-f]{64})$',text,re.M)
    signer_numbers=set(re.findall(r'^Signer #([0-9]+) ',text,re.M))
    if counts!=['1']or len(certificates)!=1 or certificates[0]!=("1",expected_certificate_sha256)or signer_numbers!={'1'}:raise ValueError('APK certificate or signer count mismatch')
    patterns={'v2':r'^Verified using v2 scheme \(APK Signature Scheme v2\): (true|false)$','v3':r'^Verified using v3 scheme \(APK Signature Scheme v3\): (true|false)$','v3.1':r'^Verified using v3\.1 scheme \(APK Signature Scheme v3\.1\): (true|false)$'}
    schemes={}
    for name,pattern in patterns.items():
        values=re.findall(pattern,text,re.M)
        if name=='v3.1'and not values:schemes[name]=False;continue
        if len(values)!=1:raise ValueError('Ambiguous APK scheme verification output')
        schemes[name]=values[0]=='true'
    if not any(schemes.values()):raise ValueError('APK v2/v3 signature is required')
    return {'certificateSha256':certificates[0][1],'schemes':schemes,'stdoutSha256':hashlib.sha256(output).hexdigest(),'apkSha256':package_sha,'bytes':before[2],'signerCount':1}
