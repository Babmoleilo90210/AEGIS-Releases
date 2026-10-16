from pathlib import Path
import subprocess,os
root=Path('/workspace/scratch/aa629f360927/aegis/aegis');outer=root.parents[1];build=outer/'glas500-build'
jdk=outer/'inputs500/jdk-21.0.12.1+1';deps=list((outer/'inputs250/squashfs-root/app').glob('*.jar'))+list((outer/'inputs500/deps').glob('*.jar'));cp=os.pathsep.join(map(str,deps));classes=build/'classes';classes.mkdir(exist_ok=True)
sources=list((root/'client-core/src/main/java/org/securemail/client/voice').glob('*.java'))+[root/'client-core/src/main/java/org/securemail/client/appearance/Appearance.java']
p=subprocess.run([str(jdk/'bin/javac'),'--release','21','-encoding','UTF-8','-cp',cp,'-d',str(classes)]+list(map(str,sources)),capture_output=True,text=True);(build/'compile.log').write_text(p.stdout+p.stderr);print('compile',p.returncode,p.stderr[-4000:]);
if p.returncode:raise SystemExit(p.returncode)
tests=list((root/'client-core/src/test/java/org/securemail/client/voice').glob('*.java'))+list((root/'client-core/src/test/java/org/securemail/client/storage').glob('NavigationMigration*Test.java'));testclasses=build/'tests';testclasses.mkdir(exist_ok=True)
p=subprocess.run([str(jdk/'bin/javac'),'--release','21','-encoding','UTF-8','-cp',str(classes)+os.pathsep+cp,'-d',str(testclasses)]+list(map(str,tests)),capture_output=True,text=True);(build/'test-compile.log').write_text(p.stdout+p.stderr);print('testcompile',p.returncode,p.stderr[-4000:]);
if p.returncode:raise SystemExit(p.returncode)
command=[str(jdk/'bin/java'),'-Xmx768m','-Daegis.native.root='+str(outer/'inputs250/squashfs-root'),'-jar',str(outer/'inputs500/deps/junit-platform-console-standalone-1.13.4.jar'),'execute','--class-path',str(testclasses)+os.pathsep+str(classes)+os.pathsep+cp,'--select-package','org.securemail.client.voice','--select-package','org.securemail.client.storage','--fail-if-no-tests','--reports-dir',str(build/'junit'),'--details=summary']
with (build/'junit.log').open('w') as log:p=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=240)
print('junit',p.returncode);print((build/'junit.log').read_text()[-7000:]);raise SystemExit(p.returncode)
