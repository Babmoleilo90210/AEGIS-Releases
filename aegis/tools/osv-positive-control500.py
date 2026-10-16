#!/usr/bin/env python3
"""Live OSV positive control, never a bundled dependency or a product finding."""
import argparse,datetime,hashlib,importlib.util,json,pathlib

spec=importlib.util.spec_from_file_location('aegis_osv',pathlib.Path(__file__).with_name('audit-dependencies500.py'))
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
QUERY={'package':{'ecosystem':'Maven','name':'org.apache.logging.log4j:log4j-core'},'version':'2.14.1'}

def evaluate(document):
 if not isinstance(document,dict) or not isinstance(document.get('vulns'),list):return False
 return any(v.get('id')=='CVE-2021-44228' or 'CVE-2021-44228' in v.get('aliases',[]) for v in document['vulns'])

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
 report={'schema':1,'version':'5.0.0','timestampUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'CONTROL ONLY: known-vulnerable log4j-core 2.14.1 is not an AEGIS dependency and is never downloaded or executed','query':QUERY,'endpoint':'https://api.osv.dev/v1/query','expectedAlias':'CVE-2021-44228','status':'NOT_RUN','productionReady':False}
 try:
  raw=audit.fetch('/v1/query',QUERY);(a.out/'CONTROL-OSV-RESPONSE.json').write_bytes(raw);document=json.loads(raw);report.update(status='PASS_CONTROL' if evaluate(document) else 'FAIL_CONTROL',responseSha256=hashlib.sha256(raw).hexdigest(),responseBytes=len(raw),advisoryIds=[v.get('id') for v in document.get('vulns',[])],expectedAdvisoryObserved=evaluate(document),pagination=document.get('next_page_token',''))
 except Exception as e:report.update(reason=type(e).__name__,message='Не удалось завершить положительный контроль; отсутствие ответа не считается успехом')
 (a.out/'CONTROL-RESULTS.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps({k:report.get(k) for k in ['status','expectedAdvisoryObserved','responseBytes','reason']},ensure_ascii=False));return 0 if report['status']=='PASS_CONTROL' else 2
if __name__=='__main__':raise SystemExit(main())
