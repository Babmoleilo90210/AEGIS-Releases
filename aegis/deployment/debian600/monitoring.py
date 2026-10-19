#!/usr/bin/env python3
"""Bounded staging health collector: local status only, no token/log/account/audio/database reads."""
import argparse,json,os,pathlib,re,subprocess,tempfile,time

STATE=pathlib.Path('/var/lib/aegis600/monitoring')
SERVICES=('mail-relay','identity','attachments','glas-signaling','community','library','news-worker','management','management-broker','tor')
PROPERTIES=('ActiveState','SubState','MemoryCurrent','TasksCurrent','CPUUsageNSec')

def parse_properties(raw):
    if len(raw)>8192:raise ValueError('Размер статуса')
    result={}
    for line in raw.splitlines():
        key,separator,value=line.partition('=')
        if not separator or key not in PROPERTIES or key in result:continue
        if key in {'ActiveState','SubState'}:
            if not re.fullmatch('[a-z-]{1,40}',value):continue
        elif not re.fullmatch('[0-9]{1,20}|\\[not set\\]',value):continue
        result[key]=value
    return result

def collect():
    systemd=pathlib.Path('/proc/1/comm').read_text().strip()=='systemd';units={}
    for service in SERVICES:
        if not systemd:units[service]={'state':'NOT_RUN','reason':'systemd-not-pid1'};continue
        try:
            command=['/usr/bin/systemctl','show','--no-pager','--property='+','.join(PROPERTIES),'--','aegis600-staging-'+service+'.service']
            process=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,env={'PATH':'/usr/bin:/usr/sbin','LANG':'C.UTF-8'},check=False)
            units[service]={'state':'OBSERVED','properties':parse_properties(process.stdout.decode('utf-8',errors='strict'))} if process.returncode==0 else {'state':'UNAVAILABLE'}
        except (OSError,ValueError,subprocess.TimeoutExpired):units[service]={'state':'UNAVAILABLE'}
    return {'schema':1,'minute':int(time.time())//60,'scope':'staging-service-properties-only','systemdIsPid1':systemd,'units':units,'nativeAcceptance':'NOT_RUN','productionReady':False}

def publish(result):
    if not STATE.is_dir() or STATE.resolve()!=STATE.absolute() or STATE.stat().st_mode&0o077:raise ValueError('Приватный каталог мониторинга')
    fd,name=tempfile.mkstemp(prefix='.health-',dir=STATE)
    try:
        with os.fdopen(fd,'w') as output:json.dump(result,output,ensure_ascii=False);output.write('\n');output.flush();os.fsync(output.fileno())
        os.replace(name,STATE/'health.json')
    finally:
        if pathlib.Path(name).exists():os.unlink(name)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--once',action='store_true');args=parser.parse_args()
    if args.once:print(json.dumps(collect(),ensure_ascii=False,indent=2));return
    while True:
        started=time.monotonic();publish(collect());time.sleep(max(1,60-(time.monotonic()-started)))
if __name__=='__main__':main()
