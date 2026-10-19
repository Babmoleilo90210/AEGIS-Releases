#!/usr/bin/env python3
"""Reviewable Debian staging installation. Explicit --apply; never replaces /opt/aegis/relay."""
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess

PREFIXES=("opt/aegis600/","etc/aegis600/","etc/systemd/system/aegis600-staging-","etc/apparmor.d/aegis600-staging-","usr/lib/sysusers.d/aegis600.conf","usr/lib/tmpfiles.d/aegis600.conf")

def plan(bundle):
    bundle=bundle.absolute()
    if bundle.resolve()!=bundle:raise ValueError("Путь комплекта без symlink обязателен")
    provenance=bundle/"BUILD-PROVENANCE-6.0.0.json"
    if not provenance.is_file() or provenance.is_symlink() or provenance.stat().st_size>2*1024**2:raise ValueError("Формат provenance")
    proof=json.loads(provenance.read_text());files=[]
    if not re.fullmatch(r"[a-f0-9]{40}",proof["sourceCommit"]) or type(proof["workingTreeDirty"]) is not bool or not isinstance(proof["files"],dict) or len(proof["files"])>2000:raise ValueError("Формат provenance")
    for name,item in proof["files"].items():
        path=pathlib.PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or path.as_posix()!=name or "\\" in name:raise ValueError("Небезопасный путь комплекта")
        if not name.startswith(PREFIXES):continue
        f=bundle/name
        if not f.is_file() or f.is_symlink() or f.resolve()!=f.absolute() or item["mode"] not in {"0o644","0o755"} or type(item["size"]) is not int or not 0<=item["size"]<=128*1024**2 or f.stat().st_size!=item["size"]:raise ValueError("Комплект изменён")
        digest=hashlib.sha256()
        with f.open("rb") as source:
            for part in iter(lambda:source.read(1024*1024),b""):digest.update(part)
        if digest.hexdigest()!=item["sha256"]:raise ValueError("Комплект изменён")
        target=pathlib.Path("/")/name
        if target.exists() or target.is_symlink():raise ValueError("Установка поверх имеющихся AEGIS6 путей запрещена; требуется отдельная проверяемая миграция")
        files.append({"source":str(f),"destination":str(target),"mode":item["mode"]})
    return {"mode":"DRY_RUN","sourceCommit":proof["sourceCommit"],"workingTreeDirty":proof["workingTreeDirty"],"files":files,"productionRelayChanged":False,"productionFeedChanged":False,"servicesAutoStarted":False,"requiresOwnerProductionAuthorization":True}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("bundle",type=pathlib.Path);p.add_argument("--apply",action="store_true");p.add_argument("--staging-confirmation",choices=["NEW-ISOLATED-STAGING"]);a=p.parse_args();result=plan(a.bundle)
    if not a.apply:print(json.dumps(result,ensure_ascii=False,indent=2));return
    if os.geteuid()!=0 or a.staging_confirmation!="NEW-ISOLATED-STAGING":raise SystemExit("Для применения нужны root и явное подтверждение отдельной новой staging-среды")
    release=pathlib.Path("/etc/os-release").read_text()
    if 'ID=debian' not in release or 'VERSION_ID="13"' not in release:raise SystemExit("Поддерживается только Debian13; текущая ОС не изменена")
    if result["workingTreeDirty"]:raise SystemExit("Development-комплект не разворачивается этим скриптом")
    for item in result["files"]:
        target=pathlib.Path(item["destination"])
        for ancestor in target.parents:
            if ancestor.is_symlink() or ancestor.exists() and not ancestor.is_dir():raise SystemExit("Символический системный путь запрещён")
        target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        if target.parent.resolve()!=target.parent:raise SystemExit("Символический системный путь запрещён")
        with pathlib.Path(item["source"]).open("rb") as src,target.open("xb") as dst:shutil.copyfileobj(src,dst,1024*1024)
        target.chmod(int(item["mode"],8))
    for command in [["/usr/bin/systemd-sysusers","/usr/lib/sysusers.d/aegis600.conf"],["/usr/bin/systemd-tmpfiles","--create","/usr/lib/tmpfiles.d/aegis600.conf"],["/usr/bin/systemctl","daemon-reload"]]:subprocess.run(command,check=True)
    for profile in pathlib.Path("/etc/apparmor.d").glob("aegis600-staging-*"):subprocess.run(["/usr/sbin/apparmor_parser","-r",str(profile)],check=True)
    print(json.dumps({"stagingFilesInstalled":True,"servicesStarted":False,"productionRelayChanged":False,"requiresServiceBootstrapAndNativeAcceptance":True,"productionReady":False}))
if __name__=="__main__":main()
