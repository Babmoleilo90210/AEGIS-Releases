#!/usr/bin/env python3
"""Export and verify actual frozen Git source blobs; never overwrite or invent source provenance."""
import argparse,json,sys
from pathlib import Path
import release_manifest600 as release
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--project',required=True,type=Path);p.add_argument('--source-commit',required=True);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
try:print(json.dumps({'sourceCommit':a.source_commit,'sourceArchiveSha256':release.prepare_source_archives(a.project,a.source_commit,a.output)}))
except Exception as error:print('Source export rejected: '+str(error),file=sys.stderr);sys.exit(1)
