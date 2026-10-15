#!/usr/bin/env python3
"""Run identical standalone offline workloads; requires explicitly prepared runtime snapshots."""
import argparse, datetime, hashlib, json, os, pathlib, statistics, subprocess

p=argparse.ArgumentParser()
p.add_argument('--runtime',type=pathlib.Path,required=True)
p.add_argument('--inputs',type=pathlib.Path,required=True)
p.add_argument('--java',type=pathlib.Path,required=True)
p.add_argument('--output',type=pathlib.Path,required=True)
a=p.parse_args();runtime=a.runtime.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
source=pathlib.Path(__file__).resolve().with_name('CoreBaselineBenchmark.java')
meta=json.loads(a.inputs.read_text());assert hashlib.sha256(source.read_bytes()).hexdigest()==meta['benchmarkSourceSha256']
for version,records in meta['applicationJars'].items():
    for name,record in records.items():assert hashlib.sha256((runtime/version/name).read_bytes()).hexdigest()==record['sha256'],version+'/'+name
for record in meta['identicalDependencyJars']:assert hashlib.sha256((runtime/'dependencies'/record['name']).read_bytes()).hexdigest()==record['sha256'],record['name']
meta['runStartedUTC']=datetime.datetime.now(datetime.timezone.utc).isoformat();meta['runtimeSnapshot']=str(runtime);meta['runnerSha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest();(out/'INPUTS.json').write_text(json.dumps(meta,indent=2)+'\n')
for name in ['classes','runs','logs','fixtures']:(out/name).mkdir(exist_ok=True)
compile_cp=os.pathsep.join([str(runtime/'2.0.0'/'*'),str(runtime/'dependencies'/'*')])
with (out/'compile.log').open('w') as log:
    subprocess.run([str(a.java.with_name('javac')),'-cp',compile_cp,'-d',str(out/'classes'),str(source)],stdout=log,stderr=subprocess.STDOUT,check=True)
rows=[]
for step in meta['sequentialOrder']:
    version,repetition=step.split('/');name=version+'-run-'+repetition;cp=os.pathsep.join([str(out/'classes'),str(runtime/version/'*'),str(runtime/'dependencies'/'*')]);output=out/'runs'/(name+'.json')
    command=[str(a.java),*meta['javaOptions'],'-cp',cp,'org.securemail.client.archive.CoreBaselineBenchmark',version,repetition,str(out/'fixtures'),str(output)]
    with (out/'logs'/(name+'.log')).open('w') as log:
        log.write('startedUTC='+datetime.datetime.now(datetime.timezone.utc).isoformat()+'\ncommand='+repr(command)+'\n');log.flush()
        result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=180);log.write('exitCode='+str(result.returncode)+'\n')
    if result.returncode:raise SystemExit('Benchmark failed: '+name)
    row=json.loads(output.read_text());assert row['fixtureChecks']=='PASS'
    assert row['loadedApplicationSources']['LocalStore'].endswith('/'+version+'/client-core.jar')
    assert row['loadedApplicationSources']['Protocol'].endswith('/'+version+'/common-protocol.jar')
    rows.append(row);print(name+' PASS idleCpu='+row['boundedIdle']['cpuStatus'],flush=True)

def stats(values):return {'minimum':min(values),'median':statistics.median(values),'maximum':max(values),'samples':values}

summary={'status':'PASS_OFFLINE_SYNTHETIC_MEASUREMENTS','productionReady':False,'repetitionsPerVersion':3,'freshJvmPerRepetition':True,'measurements':{},'memory':{},'boundedIdle':{},'notRun':['native application startup','network authentication/login','Tor connection','actual browser startup/network','microphone/audio device use','physical host stress/soak','Windows11 native performance','CachyOS KDE Wayland/X11 native performance'],'interpretation':'Descriptive three-run values only; no claim of statistical significance or whole-application optimization. Container/host activity is not fully controlled.'}
for metric in rows[0]['timingNanos']:
    groups={version:stats([r['timingNanos'][metric] for r in rows if r['versionLabel']==version]) for version in ['2.0.0','2.5.0']}
    groups['medianRatio250to200']=groups['2.5.0']['median']/groups['2.0.0']['median'];groups['medianChangePercent']=(groups['medianRatio250to200']-1)*100;summary['measurements'][metric]=groups
summary['measurements']['repeatedSearchMedianPerJvmNanos']={version:stats([statistics.median(r['archiveRepeatedFullTextSearchNanos']) for r in rows if r['versionLabel']==version]) for version in ['2.0.0','2.5.0']}
for version in ['2.0.0','2.5.0']:
    group=[r for r in rows if r['versionLabel']==version]
    summary['memory'][version]={'heapAfterGcBytes':stats([r['memoryAfterExplicitGcAnd500msSettle']['heapUsedBytes'] for r in group]),'linuxRssAfterIdleBytes':stats([r['memoryAfterIdle']['linuxRssBytes'] for r in group]),'linuxPeakRssBytes':stats([r['memoryAfterIdle']['linuxPeakRssBytes'] for r in group])}
    summary['boundedIdle'][version]=[r['boundedIdle'] for r in group]
summary['finishedUTC']=datetime.datetime.now(datetime.timezone.utc).isoformat();(out/'SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
print('All six independent JVM workloads passed; native/network/browser/audio NOT_RUN',flush=True)
