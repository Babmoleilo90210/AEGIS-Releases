#!/usr/bin/env python3
"""Read-only Debian target acceptance prerequisite report; never marks another OS native PASS."""
import json, pathlib, platform, shutil, subprocess

def collect():
    release={}
    for line in pathlib.Path("/etc/os-release").read_text().splitlines():
        if "=" in line:k,v=line.split("=",1);release[k]=v.strip('"')
    systemd=pathlib.Path("/proc/1/comm").read_text().strip()=="systemd"
    apparmor=pathlib.Path("/sys/module/apparmor/parameters/enabled")
    enabled=apparmor.exists() and apparmor.read_text().strip()=="Y"
    tools={t:shutil.which(t) for t in ["java","tor","apparmor_parser","aa-status","restic","systemctl","systemd-analyze","sqlite3"]}
    native=release.get("ID")=="debian" and release.get("VERSION_ID")=="13" and systemd
    return {"os":release.get("PRETTY_NAME"),"kernel":platform.release(),"systemdIsPid1":systemd,"apparmorKernelEnabled":enabled,"tools":tools,"debian13NativeEnvironment":"PASS_PREREQUISITE" if native else "BLOCKED","nativeServiceAcceptance":"NOT_RUN","torOnionConnectivity":"NOT_RUN","appArmorProfilesEnforced":"NOT_RUN","offsiteRestore":"NOT_RUN","productionReady":False}
if __name__=="__main__":print(json.dumps(collect(),ensure_ascii=False,indent=2))
