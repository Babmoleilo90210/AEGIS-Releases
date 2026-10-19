#!/usr/bin/env python3
"""One DB only, inside systemd DynamicUser/RootDirectory/no-network sandbox. Never run as root."""
import contextlib,ctypes,json,os,pathlib,shutil,socket,sqlite3,stat,sys

MAX_DATABASE=512*1024**2
MARKER='AEGIS-PER-DATABASE-VALIDATOR/v1\n'

def require_sandbox():
    if os.geteuid()==0 or pathlib.Path('/AEGIS-SQLITE-VALIDATOR').read_text()!=MARKER:raise RuntimeError('Требуется отдельная непривилегированная sandbox')
    if ctypes.CDLL(None,use_errno=True).prctl(39,0,0,0,0)!=1:raise RuntimeError('NoNewPrivileges обязателен')
    # The production transient unit denies all socket syscalls, not merely outbound addresses.
    for family in (socket.AF_INET,socket.AF_INET6,socket.AF_UNIX):
        try:s=socket.socket(family,socket.SOCK_STREAM)
        except OSError:continue
        else:s.close();raise RuntimeError('Сетевые syscalls должны быть запрещены')
    if pathlib.Path('/etc/aegis600').exists() or pathlib.Path('/var/lib/aegis600').exists():raise RuntimeError('Корень sandbox должен содержать только runtime и одну БД')

def validate():
    require_sandbox();result=consolidate(pathlib.Path('/input'),pathlib.Path('/output'))
    print(json.dumps({'validated':True,'scope':'unprivileged-single-database-sandbox',**result}))

def consolidate(source, output):
    """Parser routine, called by validate only after OS sandbox checks; trusted synthetic unit fixtures call it directly."""
    expected={'database.sqlite','database.sqlite-wal','database.sqlite-journal'};total=0
    for p in source.iterdir():
        metadata=p.lstat()
        if p.name not in expected or not stat.S_ISREG(metadata.st_mode) or metadata.st_size>MAX_DATABASE:raise ValueError('Неверный вход sandbox')
        total+=metadata.st_size
        if total>MAX_DATABASE:raise ValueError('Лимит БД')
        with p.open('rb') as src,(output/p.name).open('xb') as dst:shutil.copyfileobj(src,dst,1024*1024)
        (output/p.name).chmod(0o600)
    database=output/'database.sqlite';result=output/'validated.sqlite'
    if not database.is_file() or database.stat().st_size>MAX_DATABASE:raise ValueError('Отсутствует БД')
    with contextlib.closing(sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=2)) as src,contextlib.closing(sqlite3.connect(result,timeout=2)) as dst:
        for connection in (src,dst):
            connection.enable_load_extension(False);connection.execute('PRAGMA trusted_schema=OFF');connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,16*1024**2);connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,1024*1024)
            if hasattr(connection,'setconfig') and hasattr(sqlite3,'SQLITE_DBCONFIG_DEFENSIVE'):connection.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE,True)
        src.backup(dst,pages=256,sleep=0.01);dst.execute('PRAGMA wal_checkpoint(TRUNCATE)');dst.execute('PRAGMA journal_mode=DELETE')
        if dst.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Целостность БД')
    if result.stat().st_size>MAX_DATABASE:raise ValueError('Лимит результата')
    result.chmod(0o600)
    return {'sqliteVersion':sqlite3.sqlite_version}

if __name__=='__main__':
    try:
        if len(sys.argv)!=1:raise ValueError('Фиксированный формат запуска')
        validate()
    except Exception:
        print('Проверка изолированной БД не завершена; результат не принимается',file=sys.stderr);sys.exit(1)
