#!/usr/bin/env python3
"""Fixed-scope encrypted restic backup and isolated restore. Dry run unless --apply."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, shutil, signal, stat, subprocess, tempfile, time, uuid

STATE = pathlib.Path("/var/lib/aegis600")
CONFIG = pathlib.Path("/etc/aegis600/backup.json")
# Stop callers before their authorities; restart in reverse dependency order.
SERVICES = ("management", "management-broker", "news-worker", "library", "community", "glas-signaling", "attachments", "mail-relay", "identity", "tor")

def digest(path):
    h=hashlib.sha256()
    with pathlib.Path(path).open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()

def secure_file(path: pathlib.Path):
    if not path.is_file() or path.is_symlink() or path.resolve()!=path.absolute() or path.stat().st_mode&0o077 or path.stat().st_uid!=os.geteuid():raise ValueError("Нужен собственный отдельный файл с правами0600 без symlink")
    return path

def load_config(path=CONFIG):
    secure_file(path);obj=json.loads(path.read_text())
    if set(obj)!={"repositoryFile","passwordFile","offsiteConfirmed"} or obj["offsiteConfirmed"] is not True:raise ValueError("Внешний зашифрованный репозиторий должен быть явно подготовлен оператором")
    repository=secure_file(pathlib.Path(obj["repositoryFile"]));password=secure_file(pathlib.Path(obj["passwordFile"]))
    value=repository.read_text().strip()
    if not value or len(value)>2048 or any(ord(c)<32 for c in value):raise ValueError("Адрес внешнего репозитория")
    # Local repositories can be useful in a fixture but are never accepted as offsite production backup.
    if not (value.startswith("sftp:") or value.startswith("s3:https://") or value.startswith("rest:https://") or value.startswith("azure:")):raise ValueError("Требуется внешний поддерживаемый репозиторий, не каталог того жеVPS")
    return repository,password

def check_restore_budget(root, max_bytes=32*1024**3, max_objects=100_000, minimum_free=256*1024**2):
    """Bound a partial restore before it is parsed or selected as usable state."""
    count=0;total=0;pending=[pathlib.Path(root)]
    while pending:
        directory=pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                count+=1
                if count>max_objects:raise ValueError("Лимит объектов восстановления")
                metadata=entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):pending.append(pathlib.Path(entry.path))
                elif stat.S_ISREG(metadata.st_mode):total+=metadata.st_size
                else:raise ValueError("Недопустимый объект восстановления")
                if total>max_bytes:raise ValueError("Лимит размера восстановления")
    if shutil.disk_usage(root).free<minimum_free:raise ValueError("Недостаточно свободного места для восстановления")
    return total,count

def command(argv, *, timeout=3600, environment=None, restore_root=None, budget_bytes=32*1024**3, budget_objects=100_000):
    env={"PATH":"/usr/sbin:/usr/bin","LANG":"C.UTF-8"};env.update(environment or {})
    # No password/token in argv or exported environment: only paths to root-only credential files.
    p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,start_new_session=True)
    deadline=time.monotonic()+timeout
    try:
        while p.poll() is None:
            if time.monotonic()>=deadline:raise TimeoutError("Истёк срок системной операции")
            if restore_root is not None:check_restore_budget(restore_root,max_bytes=budget_bytes,max_objects=budget_objects)
            try:p.wait(timeout=0.5)
            except subprocess.TimeoutExpired:pass
        if p.returncode:raise RuntimeError("Системная операция завершилась ошибкой; подробности не публикуются")
        if restore_root is not None:check_restore_budget(restore_root,max_bytes=budget_bytes,max_objects=budget_objects)
    finally:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait(timeout=3)

def copy_opaque(source, target, maximum):
    """Never decode attacker bytes; reject symlink/FIFO/growth and cap all reads to initial file size."""
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as inp:
        metadata=os.fstat(inp.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size>maximum:raise ValueError('Размер или тип источника')
        remaining=metadata.st_size
        with pathlib.Path(target).open('xb') as output:
            while remaining:
                data=inp.read(min(1024*1024,remaining))
                if not data:raise ValueError('Источник изменился во время копирования')
                output.write(data);remaining-=len(data)
            if inp.read(1) or os.fstat(inp.fileno()).st_size!=metadata.st_size:raise ValueError('Источник изменился во время копирования')
    return metadata.st_size

def opaque_snapshot_tree(source: pathlib.Path, target: pathlib.Path, max_bytes=32*1024**3):
    """Root only copies opaque regular bytes after writers stopped. It never imports SQLite."""
    source=source.absolute();target=target.absolute()
    if source.resolve()!=source or target.exists() or target.parent.resolve()!=target.parent:raise ValueError("Отдельный snapshot-каталог обязателен")
    target.mkdir(mode=0o700);total=0;files=0;visited=[0]
    def walk(directory,depth=0):
        if depth>64:raise ValueError("Глубина snapshot превышена")
        entries=[]
        with os.scandir(directory) as listing:
            for entry in listing:
                if directory==source and entry.name in {"backup-staging","restored","monitoring"}:continue
                visited[0]+=1
                if visited[0]>100_000:raise ValueError("Лимит объектов snapshot")
                entries.append(entry)
        for entry in sorted(entries,key=lambda e:e.name):
            path=pathlib.Path(entry.path)
            if entry.is_symlink():raise ValueError("Symlink в state запрещён")
            yield path
            if entry.is_dir(follow_symlinks=False):yield from walk(path,depth+1)
    for path in walk(source):
        relative=path.relative_to(source)
        if path.is_symlink() or not (path.is_file() or path.is_dir()):raise ValueError("Необычный объект в server state")
        out=target/relative
        if path.is_dir():out.mkdir(mode=0o700,parents=True,exist_ok=True);continue
        if "release-private" in path.name.lower():raise ValueError("Release private key не должен находиться на сервере; файл не читается")
        declared=path.stat().st_size;files+=1;total+=declared
        if total>max_bytes or files>100_000:raise ValueError("Лимит snapshot исчерпан")
        out.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if shutil.disk_usage(target).free<declared+256*1024**2:raise ValueError('Недостаточно места для snapshot')
        copy_opaque(path,out,declared)
        out.chmod(0o600)
    return {"sourceBytes":total,"filesCopied":files}

def validator_command(job: pathlib.Path):
    if job.resolve()!=job.absolute() or any(c in str(job) for c in ' :\\\n\r'):raise ValueError('Неизменный путь validator')
    properties=[
        'Type=exec','DynamicUser=yes','NoNewPrivileges=yes','PrivateNetwork=yes','PrivateDevices=yes',
        'RootDirectory='+str(job),'WorkingDirectory=/','MountAPIVFS=yes','ProtectSystem=strict','ProtectHome=yes',
        'ProtectKernelTunables=yes','ProtectKernelModules=yes','ProtectControlGroups=yes','ProtectProc=invisible',
        'RestrictNamespaces=yes','CapabilityBoundingSet=','AmbientCapabilities=','RestrictSUIDSGID=yes',
        'SystemCallFilter=~@network-io @privileged @mount @debug','SystemCallErrorNumber=EPERM','IPAddressDeny=any',
        'MemoryMax=192M','TasksMax=4','CPUQuota=100%','LimitCPU=15','LimitFSIZE=1073741824','LimitNOFILE=32',
        'LimitCORE=0','RuntimeMaxSec=20','TimeoutStartSec=25','UMask=0077','KillMode=control-group',
        'AppArmorProfile=aegis600-staging-sqlite-validator',
        'BindReadOnlyPaths=/usr /lib -/lib64 -/etc/ld.so.cache /opt/aegis600/bin/sqlite_validator.py:/validator.py '+str(job/'input')+':/input',
        'BindPaths='+str(job/'output')+':/output']
    args=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect','--unit=aegis600-staging-sqlite-validator-'+uuid.uuid4().hex]
    for value in properties:args.append('--property='+value)
    args+=['/usr/bin/python3','-I','-B','/validator.py']
    return args

def run_systemd_validator(job: pathlib.Path):
    if os.geteuid()!=0 or pathlib.Path('/proc/1/comm').read_text().strip()!='systemd':raise RuntimeError('Изолированный SQLite validator требует настоящую systemd staging-среду')
    if not any(job.is_relative_to(STATE/name) for name in ('backup-staging','restored')):raise ValueError('Только фиксированная private staging-среда validator')
    command(validator_command(job),timeout=30,restore_root=job,budget_bytes=1536*1024**2,budget_objects=32)

def validate_snapshot_databases(target: pathlib.Path, validator=None, consolidate=True):
    validator=validator or run_systemd_validator
    if target.resolve()!=target.absolute() or target.stat().st_mode&0o077 or target.parent.stat().st_mode&0o077:raise ValueError('Приватный родитель validator обязателен')
    databases=sorted(p for p in target.rglob('*') if p.is_file() and p.suffix in {'.sqlite','.db'})
    if len(databases)>64:raise ValueError('Лимит числа БД в snapshot')
    for database in databases:
        if database.is_symlink() or database.resolve()!=database.absolute():raise ValueError('Путь БД')
        with tempfile.TemporaryDirectory(prefix='sqlite-validator-',dir=target.parent) as temporary:
            job=pathlib.Path(temporary);job.chmod(0o755);(job/'input').mkdir(mode=0o700);(job/'output').mkdir(mode=0o777);(job/'output').chmod(0o777)
            (job/'AEGIS-SQLITE-VALIDATOR').write_text('AEGIS-PER-DATABASE-VALIDATOR/v1\n');(job/'AEGIS-SQLITE-VALIDATOR').chmod(0o444)
            total=0
            for suffix in ('','-wal','-journal'):
                src=pathlib.Path(str(database)+suffix)
                if not src.exists():continue
                if src.is_symlink() or not src.is_file():raise ValueError('Необычный файл БД')
                total+=src.stat().st_size
                if total>512*1024**2:raise ValueError('Одна БД превышает лимит sandbox512MiB')
                dest=job/'input'/('database.sqlite'+suffix)
                copy_opaque(src,dest,512*1024**2)
                dest.chmod(0o444)
            (job/'input').chmod(0o555)
            if shutil.disk_usage(job).free<total*2+256*1024**2:raise ValueError('Недостаточно места для sandbox validator')
            validator(job)
            result=job/'output/validated.sqlite'
            if not result.is_file() or result.is_symlink() or result.resolve()!=result.absolute() or result.stat().st_size>512*1024**2:raise ValueError('Нет безопасного результата validator')
            if consolidate:
                staged=database.with_name(database.name+'.validated-'+uuid.uuid4().hex)
                copy_opaque(result,staged,512*1024**2)
                staged.chmod(0o600);os.replace(staged,database)
                for suffix in ('-wal','-shm','-journal'):pathlib.Path(str(database)+suffix).unlink(missing_ok=True)
    return len(databases)

def finalize_snapshot(target: pathlib.Path, source_bytes, validator=None):
    validated=validate_snapshot_databases(target,validator);inventory=[];total=0
    for path in sorted(target.rglob('*')):
        if path.is_symlink() or not(path.is_file() or path.is_dir()):raise ValueError('Объект snapshot')
        if path.is_file():
            total+=path.stat().st_size
            if total>32*1024**3 or len(inventory)>=100_000:raise ValueError('Лимит проверенного snapshot')
            inventory.append({'path':path.relative_to(target).as_posix(),'bytes':path.stat().st_size,'sha256':digest(path)})
    manifest={'schema':1,'scope':'quiesced-opaque-copy-and-unprivileged-per-database-validation','files':inventory,'sourceBytes':source_bytes,'sqliteDatabasesValidated':validated,'ownerReleasePrivateKeyExpected':False}
    p=target/'SNAPSHOT.json';p.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n');p.chmod(0o600);return manifest

def snapshot_tree(source: pathlib.Path, target: pathlib.Path, max_bytes=32*1024**3, validator=None):
    copied=opaque_snapshot_tree(source,target,max_bytes);return finalize_snapshot(target,copied['sourceBytes'],validator)

def verify_tree(root: pathlib.Path):
    root=root.absolute();metadata=root/"SNAPSHOT.json"
    if root.resolve()!=root or not metadata.is_file() or metadata.is_symlink() or metadata.stat().st_size>32*1024**2:raise ValueError("Формат snapshot")
    manifest=json.loads(metadata.read_text());seen=set()
    if manifest.get("schema")!=1 or not isinstance(manifest.get("files"),list) or len(manifest["files"])>100_000:raise ValueError("Формат snapshot")
    for item in manifest["files"]:
        if not isinstance(item,dict) or set(item)!={"path","bytes","sha256"} or type(item["bytes"]) is not int or not 0<=item["bytes"]<=32*1024**3 or not isinstance(item["sha256"],str) or not re.fullmatch('[a-f0-9]{64}',item["sha256"]):raise ValueError("Формат snapshot")
        name=item["path"]
        if not isinstance(name,str) or len(name)>4096:raise ValueError("Небезопасный путь snapshot")
        p=pathlib.PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts or p.as_posix()!=name or name in seen:raise ValueError("Небезопасный путь snapshot")
        seen.add(name);f=root/name
        if not f.is_file() or f.is_symlink() or f.resolve()!=f.absolute() or f.stat().st_size!=item["bytes"] or digest(f)!=item["sha256"]:raise ValueError("Snapshot не прошёл проверку целостности")
    return len(seen)

def backup():
    repository,password=load_config();root=STATE/"backup-staging";root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if root.resolve()!=root or root.stat().st_mode&0o077:raise ValueError("Приватный snapshot-каталог")
    target=root/str(uuid.uuid4());active=[]
    try:
        try:
            for service in SERVICES:
                unit="aegis600-staging-"+service+".service"
                if subprocess.run(["/usr/bin/systemctl","is-active","--quiet","--",unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10).returncode==0:active.append(unit)
            for unit in active:command(["/usr/bin/systemctl","stop","--",unit],timeout=60)
            copied=opaque_snapshot_tree(STATE,target)
        finally:
            failures=[]
            for unit in reversed(active):
                try:command(["/usr/bin/systemctl","start","--",unit],timeout=60)
                except Exception as failure:failures.append(failure)
            if failures:raise RuntimeError("Не все ранее работавшие staging-службы восстановлены; требуется диагностика") from failures[0]
        finalize_snapshot(target,copied["sourceBytes"]);verify_tree(target)
        command(["/usr/bin/restic","--no-cache","--repository-file",str(repository),"--password-file",str(password),"backup","--tag","aegis600-staging","--",str(target)])
        command(["/usr/bin/restic","--no-cache","--repository-file",str(repository),"--password-file",str(password),"check","--read-data"])
        print(json.dumps({"backup":"PASS_COMMAND","integrity":"PASS_RESTIC_READ_DATA","offsiteRestoreDrill":"NOT_RUN","productionReady":False}))
    finally:
        if target.exists():shutil.rmtree(target)

def restore(snapshot: str):
    if not re.fullmatch(r"[a-f0-9]{64}",snapshot):raise ValueError("Только полный immutable restic snapshot ID")
    repository,password=load_config();root=STATE/"restored";root.mkdir(mode=0o700,parents=True,exist_ok=True);target=root/(snapshot+"-"+str(uuid.uuid4()));target.mkdir(mode=0o700)
    command(["/usr/bin/restic","--no-cache","--repository-file",str(repository),"--password-file",str(password),"restore",snapshot,"--target",str(target),"--verify"],restore_root=target)
    manifests=list(target.rglob("SNAPSHOT.json"))
    if len(manifests)!=1:raise ValueError("Ожидался один проверяемый server snapshot")
    verified=verify_tree(manifests[0].parent)
    validate_snapshot_databases(manifests[0].parent,consolidate=False)
    # Deliberately never replace a running DB or auto-start an old/new schema.
    print(json.dumps({"restore":"PASS_ISOLATED_RESTORE","verifiedFiles":verified,"liveStateSwitched":False,"nativeRestartDrill":"NOT_RUN","productionReady":False}))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("operation",choices=["backup","restore"]);p.add_argument("--snapshot");p.add_argument("--apply",action="store_true");a=p.parse_args()
    if not a.apply:print(json.dumps({"mode":"DRY_RUN","operation":a.operation,"fixedStateDirectory":str(STATE),"liveRelayChanged":False}));return
    if os.geteuid()!=0:raise SystemExit("Нужна явно установленная защищённая системная backup job")
    if a.operation=="backup":backup()
    else:restore(a.snapshot or "")
if __name__=="__main__":main()
