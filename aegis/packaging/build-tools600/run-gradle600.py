#!/usr/bin/env python3
"""Run pinned Gradle/JDK with OS TLS roots and private proxy settings; never log proxy credentials."""
import os,subprocess,sys,urllib.parse,re
from pathlib import Path
project=Path(sys.argv[sys.argv.index('--project-dir')+1]).resolve() if '--project-dir' in sys.argv else Path.cwd().resolve();root=Path(os.environ.get('AEGIS_BUILD_WORKSPACE',str(project.parent.parent))).resolve();toolchain=Path(os.environ.get('AEGIS_TOOLCHAIN_ROOT',str(root/'inputs600/toolchain'))).resolve();jdk=toolchain/'jdk-21.0.12.1+1';gradle=toolchain/'gradle-9.8.0/bin/gradle'
if len(sys.argv)<3:raise SystemExit('Usage: run-gradle600.py LOG [Gradle arguments...]')
log=Path(sys.argv[1]).resolve();log.parent.mkdir(parents=True,exist_ok=True);cache=Path(os.environ.get('AEGIS_GRADLE_USER_HOME',str(root/'gradle600-cache'))).resolve();
if '--project-dir' in sys.argv and (cache==project or cache.is_relative_to(project)):raise SystemExit('Private Gradle cache must be outside the source project')
cache.mkdir(parents=True,exist_ok=True);cache.chmod(0o700);props=[];secrets=[]
def prop(key,value):
 value=str(value).replace('\\','\\\\').replace('\n','\\n').replace('\r','\\r').replace('=','\\=').replace(':','\\:');props.append(key+'='+value)
proxy=os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
if proxy:
 u=urllib.parse.urlparse(proxy);secrets.append(proxy)
 if not u.hostname or u.scheme not in ('http','https'):raise SystemExit('Unsupported proxy configuration')
 for proto in ('http','https'):
  prop('systemProp.'+proto+'.proxyHost',u.hostname);prop('systemProp.'+proto+'.proxyPort',u.port or (443 if u.scheme=='https' else 80))
  if u.username:username=urllib.parse.unquote(u.username);secrets.append(username);prop('systemProp.'+proto+'.proxyUser',username)
  if u.password:password=urllib.parse.unquote(u.password);secrets.append(password);prop('systemProp.'+proto+'.proxyPassword',password)
 prop('systemProp.http.nonProxyHosts','localhost|127.*|[::1]')
prop('systemProp.javax.net.ssl.trustStore','/etc/ssl/certs/java/cacerts');prop('systemProp.javax.net.ssl.trustStorePassword','changeit');prop('org.gradle.java.installations.auto-download','false');prop('org.gradle.java.installations.paths',jdk)
private=cache/'gradle.properties';fd=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,'O_NOFOLLOW',0),0o600)
with os.fdopen(fd,'w') as f:f.write('\n'.join(props)+'\n')
private.chmod(0o600);env=os.environ.copy();env['JAVA_HOME']=str(jdk);env['PATH']=str(jdk/'bin')+os.pathsep+env.get('PATH','');env['GRADLE_USER_HOME']=str(cache);args=['bash',str(gradle),'--no-daemon',*sys.argv[2:]]
def safe(text):
 for value in sorted(set(secrets),key=len,reverse=True):
  if value:text=text.replace(value,'[REDACTED]')
 return re.sub(r'(?i)(https?://)[^/@\s]+:[^/@\s]+@',r'\1[REDACTED]@',text)
with log.open('w') as f:
 child=subprocess.Popen(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
 for line in child.stdout:line=safe(line);f.write(line);f.flush();sys.stdout.write(line);sys.stdout.flush()
 code=child.wait()
raise SystemExit(code)
