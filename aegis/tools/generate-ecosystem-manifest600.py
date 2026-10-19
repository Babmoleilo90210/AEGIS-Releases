#!/usr/bin/env python3
"""Prepare frozen source-bound unsigned AEGIS6 release metadata only; never sign or publish."""
import argparse,json,sys
from pathlib import Path
import release_manifest600 as release

def main(arguments=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--project',required=True,type=Path);p.add_argument('--source-commit',required=True);p.add_argument('--artifacts',required=True,type=Path);p.add_argument('--spec',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--published-at');p.add_argument('--apksigner',type=Path);p.add_argument('--expected-apk-certificate');a=p.parse_args(arguments)
 try:receipts=release.write_outputs(a.output,release.build(a.project,a.source_commit,a.artifacts,a.spec,a.published_at,apksigner=a.apksigner,expected_apk_certificate=a.expected_apk_certificate))
 except (ValueError,OSError,UnicodeError) as error:print('Unsigned ecosystem metadata rejected: '+str(error),file=sys.stderr);return 1
 print(json.dumps({'status':'UNSIGNED_PREPARED','productionReady':False,'sourceCommit':a.source_commit,'manifestSha256':receipts,'ownerKeyUsed':False,'published':False}));return 0
if __name__=='__main__':raise SystemExit(main())
