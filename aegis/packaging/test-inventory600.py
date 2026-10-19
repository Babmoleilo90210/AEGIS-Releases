#!/usr/bin/env python3
"""Read-only source inventory. Presence is not evidence that any test has passed."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def inventory():
 settings=(ROOT/'settings.gradle').read_text();modules=[]
 for line in settings.splitlines():
  if line.strip().startswith('include '):modules.extend(re.findall(r"['\"]([a-z0-9-]+)['\"]",line))
 sources=[];smokes=[]
 for module in modules:
  for p in sorted((ROOT/module/'src/test').rglob('*.java')):
   text=p.read_text();sources.append({'file':str(p.relative_to(ROOT)),'sha256':sha(p),'containsTestAnnotation':bool(re.search(r'@(?:Test|ParameterizedTest|RepeatedTest|TestFactory|TestTemplate)\b',text))})
  for p in sorted((ROOT/module/'src/smoke').rglob('*.java')):
   if 'public static void main(' in p.read_text():smokes.append({'file':str(p.relative_to(ROOT)),'sha256':sha(p)})
 tools=[]
 for p in sorted(ROOT.rglob('test*.py')):
  if not any(part in {'build','.gradle','.native-test'} for part in p.relative_to(ROOT).parts):tools.append({'file':str(p.relative_to(ROOT)),'sha256':sha(p)})
 commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip();dirty=bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=ROOT,text=True).strip())
 return {'schema':1,'sourceCommit':commit,'workingTreeDirty':dirty,'modules':modules,'javaTestSources':sources,'guiSmokeMains':smokes,'pythonTestTools':tools,'scope':'Static source inventory only. Execution status is NOT_RUN here; consult actual JUnit XML, GUI receipts and Python logs.'}
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path);a=p.parse_args();text=json.dumps(inventory(),indent=2,ensure_ascii=False)+'\n'
 if a.out:a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(text)
 else:print(text,end='')
if __name__=='__main__':main()
