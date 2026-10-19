#!/usr/bin/env python3
"""Offline public verification of exact owner-signed inventory and file hashes; never install or publish."""
import argparse,json,sys
from pathlib import Path
import release_manifest600 as release
p=argparse.ArgumentParser(description=__doc__);p.add_argument('manifest',type=Path);p.add_argument('signature',type=Path);p.add_argument('--assets',required=True,type=Path);a=p.parse_args()
try:
 value=release.verify_signed_inventory(a.manifest,a.signature,a.assets)
 print(json.dumps({'status':'OWNER_SIGNATURE_AND_HASHES_VALID','sourceCommit':value['sourceCommit'],'artifacts':len(value['artifacts']),'productionReady':False,'installed':False,'published':False}))
except Exception as error:
 print('Ecosystem verification rejected: '+str(error),file=sys.stderr);sys.exit(1)
