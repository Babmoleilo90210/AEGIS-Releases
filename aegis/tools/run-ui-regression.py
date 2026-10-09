#!/usr/bin/env python3
"""Bounded Monocle regression; explicitly not Windows/KDE native acceptance."""
import argparse, pathlib, os, subprocess
p=argparse.ArgumentParser();p.add_argument('--jdk',type=pathlib.Path,required=True);p.add_argument('--deps',action='append',type=pathlib.Path,required=True);p.add_argument('--native-root',type=pathlib.Path,required=True);p.add_argument('--test',default='ClientUiRegressionSmoke');a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];out=root/'build/local-java21';classes=out/'ui-tests';classes.mkdir(exist_ok=True)
deps=[f.resolve() for d in a.deps for f in d.glob('*.jar') if not f.name.startswith(('client-core-','client-ui-','common-protocol-','relay-server-'))]
cp=os.pathsep.join(map(str,deps+list(out.glob('*.jar'))+[classes]))
sources=sorted((root/'client-ui/src/smoke/java').rglob('*.java'));lst=out/'ui-tests.sources';lst.write_text('\n'.join('"'+str(v)+'"' for v in sources)+'\n')
subprocess.run([str(a.jdk.resolve()/'bin/javac'),'--release','21','-encoding','UTF-8','-cp',cp,'-d',str(classes),'@'+str(lst)],check=True,timeout=120)
subprocess.run([str(a.jdk.resolve()/'bin/java'),'-Xmx768m','-Daegis.native.root='+str(a.native_root.resolve()),'-Dprism.order=sw','-Dglass.platform=Monocle','-Dmonocle.platform=Headless','-Dheadless.geometry=1600x1200-32','-cp',cp,'org.securemail.ui.'+a.test],check=True,cwd=root,timeout=180)
