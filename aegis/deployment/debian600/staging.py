#!/usr/bin/env python3
"""Build/read-only plan/materialize a NEW Debian staging tree. Never touches live Relay/feed."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shutil, stat, subprocess, tarfile, tempfile, gzip

PROJECT = pathlib.Path(__file__).resolve().parents[2]
COMPONENTS = {
    "identity": {"main": "org.securemail.identity.IdentityMain", "jars": ["identity-server", "common-protocol"], "args": "serve --home /var/lib/aegis600/identity/state --port 38250", "heap": 192},
    "attachments": {"main": "org.securemail.attachments.AttachmentMain", "jars": ["attachment-service", "common-protocol"], "args": "serve /var/lib/aegis600/attachments/state 38251 --identity http://127.0.0.1:38250/identity/v1 /etc/aegis600/identity-public.txt", "heap": 96},
    "glas-signaling": {"main": "org.securemail.glas.signaling.GlasSignalingMain600", "jars": ["glas-signaling", "attachment-service", "common-protocol"], "args": "serve /var/lib/aegis600/glas-signaling/state 38255 --identity http://127.0.0.1:38250/identity/v1 /etc/aegis600/identity-public.txt", "heap": 96},
    "community": {"main": "org.securemail.community.gateway600.CommunityMain600", "jars": ["community-server", "common-protocol"], "args": "--serve /var/lib/aegis600/community/state", "heap": 384},
    "library": {"main": "org.securemail.community.library600.LibraryServerMain600", "jars": ["community-server", "common-protocol"], "args": "--serve /var/lib/aegis600/library/state", "heap": 192, "user": "community"},
    "news-worker": {"main": "org.securemail.worker.NewsWorkerMain", "jars": ["news-worker", "community-server", "common-protocol"], "args": "", "heap": 192},
    "management": {"main": "org.securemail.management.ManagementMain", "jars": ["management-agent", "attachment-service", "common-protocol"], "args": "serve /var/lib/aegis600/management/state 38254", "heap": 96},
    "mail-relay": {"main": "org.securemail.relay.RelayMain600", "jars": ["relay-server", "common-protocol"], "args": "serve --home /var/lib/aegis600/mail-relay/state", "heap": 256, "password4j": True},
}
BASE_DEPENDENCIES = ("gson-2.14.0.jar", "error_prone_annotations-2.48.0.jar", "sqlite-jdbc-3.53.4.0.jar", "slf4j-api-2.0.17.jar", "slf4j-nop-2.0.17.jar")
DEPENDENCIES = BASE_DEPENDENCIES + ("password4j-1.8.4.jar",)

def sha(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""): h.update(b)
    return h.hexdigest()

def safe_root(root: pathlib.Path) -> pathlib.Path:
    root = root.absolute()
    if root == pathlib.Path("/") or root.exists() and (root.is_symlink() or root.resolve() != root): raise ValueError("Нужен отдельный новый staging-каталог, не корень ОС")
    parent = root.parent
    if not parent.is_dir() or parent.resolve() != parent: raise ValueError("Родитель staging должен существовать без symlink")
    return root

def write(root: pathlib.Path, name: str, text: str, executable=False):
    path = root / name
    if path.exists() or path.is_symlink(): raise ValueError("Перезапись staging запрещена: " + name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8"); path.chmod(0o755 if executable else 0o644)

def launcher(component: str, spec: dict) -> str:
    return "#!/bin/sh\nset -eu\nunset JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS CLASSPATH LD_PRELOAD LD_LIBRARY_PATH\n" + f'exec /usr/bin/java -Xms16m -Xmx{spec["heap"]}m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "/opt/aegis600/{component}/lib/*" {spec["main"]} "$@"\n'

def unit(component: str, spec: dict) -> str:
    user = spec.get("user", component)
    command = f'/opt/aegis600/{component}/bin/{component} {spec["args"]}'
    if component == "news-worker": command = "/opt/aegis600/bin/start-news-worker"
    extra = "ReadWritePaths=/var/lib/aegis600/community/state\n" if component == "library" else ""
    network = "" if component == "news-worker" else "IPAddressDeny=any\nIPAddressAllow=localhost\n"
    runtime = "management-agent" if component == "management" else component
    after = "network.target" if component == "identity" else "network.target aegis600-staging-identity.service"
    return f'''[Unit]
Description=AEGIS 6 staging {component} (production Relay is unchanged)
After={after}
ConditionPathExists=/var/lib/aegis600/{component}/state
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=simple
User=aegis600-{user}
Group=aegis600-{user}
WorkingDirectory=/var/lib/aegis600/{component}
ExecStart={command.rstrip()}
Restart=on-failure
RestartSec=10
TimeoutStopSec=20
UMask=0077
StateDirectory=aegis600/{component}
StateDirectoryMode=0700
RuntimeDirectory=aegis600-{runtime}
RuntimeDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectProc=invisible
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
LimitCORE=0
LimitNOFILE=512
TasksMax=64
MemoryMax={spec['heap'] + 192}M
CPUQuota=150%
LogRateLimitIntervalSec=30s
LogRateLimitBurst=20
AppArmorProfile=aegis600-staging-{component}
{network}{extra}
[Install]
WantedBy=multi-user.target
'''

def apparmor(component: str, spec: dict) -> str:
    extra = "/var/lib/aegis600/community/state/community.sqlite{,-journal,-wal,-shm} rwk,\n" if component == "library" else ""
    if component == "management": extra += "/run/aegis600-management/broker.sock rw,\n"
    configuration = "/etc/aegis600/news-worker.json r," if component == "news-worker" else "/etc/aegis600/identity-public.txt r,"
    if component == "mail-relay": configuration += "\n  /etc/aegis600/mail-relay.properties r,"
    # Only the news collector resolves permitted public sources. Other origin services use literal loopback.
    dns = "network inet dgram,\n  network inet6 dgram," if component == "news-worker" else ""
    starter = "/opt/aegis600/bin/start-news-worker{,.py} rix,\n  /usr/bin/python3{,.13} rix,\n  /usr/lib/python3.13/** r,\n  /usr/lib/python3/dist-packages/** r," if component == "news-worker" else ""
    return f'''# Debian 13 staging profile. Enforce/load and JDK paths require real native acceptance.
#include <tunables/global>
profile aegis600-staging-{component} flags=(attach_disconnected) {{
  #include <abstractions/base>
  /bin/{{sh,dash}} rix,
  /usr/bin/{{sh,dash}} rix,
  /usr/bin/java rix,
  /usr/lib/jvm/java-21-openjdk-*/bin/java rix,
  /usr/lib/jvm/java-21-openjdk-*/** mr,
  /etc/java-21-openjdk/** r,
  /etc/ssl/certs/** r,
  {configuration}
  /opt/aegis600/{component}/bin/{component} rix,
  /opt/aegis600/{component}/lib/*.jar r,
  /var/lib/aegis600/{component}/ rw,
  /var/lib/aegis600/{component}/** rwk,
  /run/aegis600-{"management-agent" if component == "management" else component}/** rw,
  /tmp/** rwk,
  /tmp/sqlite-*-libsqlitejdbc.so mr,
  /proc/self/** r,
  /proc/thread-self/** r,
  /proc/sys/kernel/random/boot_id r,
  network inet stream,
  network inet6 stream,
  network unix stream,
  {dns}
  {extra}
  {starter}
  deny /home/** rwklx,
  deny /root/** rwklx,
  deny /opt/aegis/relay/** rwklx,
  deny /var/lib/aegis-relay/** rwklx,
}}
'''

def dependency_files(dirs: list[pathlib.Path]) -> dict[str, pathlib.Path]:
    result = {}
    for name in DEPENDENCIES:
        matches = [d / name for d in dirs if (d / name).is_file()]
        if not matches or any(sha(p) != sha(matches[0]) for p in matches): raise ValueError("Нет однозначной закреплённой зависимости: " + name)
        result[name] = matches[0]
    return result

def materialize(root: pathlib.Path, jar_dir: pathlib.Path, deps: list[pathlib.Path], source_commit: str, development=False) -> dict:
    root = safe_root(root)
    if root.exists(): raise ValueError("Staging-каталог уже существует")
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PROJECT, capture_output=True, text=True, check=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=PROJECT, capture_output=True, text=True, check=True).stdout)
    if git != source_commit or dirty and not development: raise ValueError("Нужен точный зафиксированный source commit")
    dependencies = dependency_files(deps)
    required = {j for spec in COMPONENTS.values() for j in spec["jars"]}
    jar_entries={}
    for name in required:
        p = jar_dir / (name + ".jar")
        if not p.is_file() or p.is_symlink(): raise ValueError("Отсутствует production JAR: " + name)
        import zipfile
        with zipfile.ZipFile(p) as z:
            if z.testzip() is not None or any("/client/" in n or "/ui/" in n for n in z.namelist()): raise ValueError("Клиентский/повреждённый JAR в сервере: " + name)
            jar_entries[name]=set(z.namelist())
    for component,spec in COMPONENTS.items():
        entry=spec["main"].replace(".","/")+".class"
        if not any(entry in jar_entries[name] for name in spec["jars"]):raise ValueError("В JAR нет действительного entry point: "+component)
    root.mkdir(mode=0o755)
    for component, spec in COMPONENTS.items():
        write(root, f"opt/aegis600/{component}/bin/{component}", launcher(component, spec), True)
        for jar in spec["jars"]:
            target = root / f"opt/aegis600/{component}/lib/{jar}.jar"; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(jar_dir / (jar + ".jar"), target); target.chmod(0o644)
        for name, source in dependencies.items():
            if name == "password4j-1.8.4.jar" and not spec.get("password4j"):continue
            target=root / f"opt/aegis600/{component}/lib/{name}";shutil.copyfile(source,target);target.chmod(0o644)
        write(root, f"etc/systemd/system/aegis600-staging-{component}.service", unit(component, spec))
        write(root, f"etc/apparmor.d/aegis600-staging-{component}", apparmor(component, spec))
    users = sorted({spec.get("user", component) for component, spec in COMPONENTS.items()} | {"tor", "monitoring"})
    write(root, "usr/lib/sysusers.d/aegis600.conf", "".join(f'u aegis600-{u} - "AEGIS 6 staging {u}" /var/lib/aegis600/{u} /usr/sbin/nologin\n' for u in users))
    write(root, "usr/lib/tmpfiles.d/aegis600.conf", "d /var/lib/aegis600 0755 root root -\n" + "".join(f'd /var/lib/aegis600/{c} 0700 aegis600-{s.get("user",c)} aegis600-{s.get("user",c)} -\n' for c,s in COMPONENTS.items()) + "d /var/lib/aegis600/management-broker 0700 root root -\nd /var/lib/aegis600/backup-staging 0700 root root -\nd /var/lib/aegis600/restored 0700 root root -\n")
    scripts = pathlib.Path(__file__).parent
    for name in ["backup_restore.py", "sqlite_validator.py", "preflight.py", "deploy.py", "start-news-worker.py", "monitoring.py"]:
        write(root, "opt/aegis600/bin/" + name, (scripts / name).read_text(), True)
    write(root, "opt/aegis600/bin/start-news-worker", "#!/bin/sh\nset -eu\nexec /usr/bin/python3 /opt/aegis600/bin/start-news-worker.py\n", True)
    write(root, "opt/aegis600/bin/aegis-admin", '#!/bin/sh\nset -eu\nexec /opt/aegis600/identity/bin/identity "$@"\n', True)
    broker = launcher("management", COMPONENTS["management"]).replace('"$@"', 'broker-serve')
    write(root, "opt/aegis600/bin/aegis-management-broker", broker, True)
    write(root, "etc/aegis600/management-broker.properties", "identityEndpoint=http://127.0.0.1:38250/identity/v1\nidentityPublicKey=/etc/aegis600/identity-public.txt\nstateDirectory=/var/lib/aegis600/management-broker\n")
    write(root, "etc/aegis600/news-worker.json.example", json.dumps({"server": "http://REPLACE_WITH_COMMUNITY_V3_ONION/api/v1", "serverKeyBase64": "REPLACE_WITH_PINNED_PUBLIC_KEY", "torSocksPort":39250, "workerKeyFile":"/var/lib/aegis600/news-worker/state/worker.pk8"}, indent=2)+"\n")
    write(root, "etc/aegis600/backup.json.example", json.dumps({"repositoryFile":"/etc/aegis600/backup-repository.txt", "passwordFile":"/etc/aegis600/backup-password", "offsiteConfirmed":False}, indent=2)+"\n")
    write(root,"etc/aegis600/mail-relay.properties.example","databasePath=/var/lib/aegis600/mail-relay/state/relay.sqlite\nlistenAddress=127.0.0.1\nlistenPort=38256\nmaxMessageAge=604800000\nmaxFileSize=104857600\nmaxPendingStoragePerUser=536870912\nmaxPendingPackets=256\nmaxUsers=32\nregistrationMode=closed\n")
    write(root, "etc/aegis600/torrc.staging", "DataDirectory /var/lib/aegis600/tor\nSocksPort 127.0.0.1:39250 IsolateSOCKSAuth\nControlPort 0\nSafeLogging 1\nAvoidDiskWrites 1\n" + "".join(f"HiddenServiceDir /var/lib/aegis600/tor/{name}\nHiddenServicePort 80 127.0.0.1:{port}\n" for name,port in [("identity",38250),("attachments",38251),("community",38252),("library",38253),("management",38254),("glas-signaling",38255),("mail-relay",38256)]))
    write(root, "etc/aegis600/wg-aegis.conf.example", "# OPTIONAL. Operator creates keys locally; no private key is included.\n[Interface]\nAddress = 10.66.60.1/24\nListenPort = 51826\nPrivateKey = REPLACE_LOCAL_PRIVATE_KEY\n\n[Peer]\nPublicKey = REPLACE_ADMIN_PUBLIC_KEY\nAllowedIPs = 10.66.60.2/32\n# A separate host firewall permits only explicit administration ports. No forwarding/NAT.\n")
    write(root, "etc/systemd/system/aegis600-staging-management-broker.service", '''[Unit]
Description=AEGIS 6 fixed root broker (signed action allowlist only)
After=aegis600-staging-identity.service
[Service]
Type=simple
User=root
Group=aegis600-management
ExecStart=/opt/aegis600/bin/aegis-management-broker
RuntimeDirectory=aegis600-management
RuntimeDirectoryMode=0710
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectProc=invisible
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET
IPAddressDeny=any
IPAddressAllow=localhost
ReadWritePaths=/var/lib/aegis600/management-broker
AppArmorProfile=aegis600-staging-management-broker
MemoryMax=256M
TasksMax=64
LimitCORE=0
TimeoutStopSec=20
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
''')
    write(root,"etc/systemd/system/aegis600-staging-monitoring.service", '''[Unit]
Description=AEGIS 6 bounded local health collector (no user data)
After=network.target
[Service]
Type=simple
User=aegis600-monitoring
Group=aegis600-monitoring
ExecStart=/usr/bin/python3 /opt/aegis600/bin/monitoring.py
StateDirectory=aegis600/monitoring
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
AppArmorProfile=aegis600-staging-monitoring
MemoryMax=64M
TasksMax=8
LimitCORE=0
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
''')
    write(root,"etc/apparmor.d/aegis600-staging-monitoring", '''#include <tunables/global>
profile aegis600-staging-monitoring flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/dbus-strict>
  /usr/bin/python3{,.13} rix,
  /usr/lib/python3.13/** r,
  /usr/lib/python3/dist-packages/** r,
  /usr/bin/systemctl rix,
  /opt/aegis600/bin/monitoring.py r,
  /var/lib/aegis600/monitoring/ rw,
  /var/lib/aegis600/monitoring/** rwk,
  /proc/1/comm r,
  /run/dbus/system_bus_socket rw,
  /run/systemd/private rw,
  network unix stream,
  dbus (send, receive) bus=system peer=(name=org.freedesktop.systemd1),
  deny /home/** rwklx,
  deny /root/** rwklx,
  deny /var/lib/aegis-relay/** rwklx,
}
''')
    write(root, "etc/apparmor.d/aegis600-staging-management-broker", '''#include <tunables/global>
profile aegis600-staging-management-broker flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/dbus-strict>
  /bin/{sh,dash} rix,
  /usr/bin/{sh,dash} rix,
  /usr/bin/java rix,
  /usr/lib/jvm/java-21-openjdk-*/bin/java rix,
  /usr/bin/systemctl rix,
  /usr/lib/jvm/java-21-openjdk-*/** mr,
  /etc/java-21-openjdk/** r,
  /etc/aegis600/management-broker.properties r,
  /etc/aegis600/identity-public.txt r,
  /opt/aegis600/bin/aegis-management-broker rix,
  /opt/aegis600/management/lib/*.jar r,
  /var/lib/aegis600/management-broker/** rwk,
  /run/aegis600-management/ rw,
  /run/aegis600-management/broker.sock rw,
  /run/dbus/system_bus_socket rw,
  /run/systemd/private rw,
  /proc/self/** r,
  /tmp/** rwk,
  /tmp/sqlite-*-libsqlitejdbc.so mr,
  network inet stream,
  network unix stream,
  dbus (send, receive) bus=system peer=(name=org.freedesktop.systemd1),
  deny /home/** rwklx,
  deny /root/** rwklx,
  deny /var/lib/aegis-relay/** rwklx,
}
''')
    write(root,"etc/systemd/system/aegis600-staging-tor.service", '''[Unit]
Description=AEGIS 6 staging Tor (separate state; existing Tor untouched)
After=network.target
[Service]
User=aegis600-tor
Group=aegis600-tor
ExecStart=/usr/bin/tor -f /etc/aegis600/torrc.staging
AppArmorProfile=aegis600-staging-tor
StateDirectory=aegis600/tor
StateDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=
MemoryMax=384M
TasksMax=64
LimitCORE=0
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
''')
    write(root,"etc/apparmor.d/aegis600-staging-tor",'''#include <tunables/global>
profile aegis600-staging-tor flags=(attach_disconnected) {
  #include <abstractions/base>
  /usr/bin/tor rix,
  /etc/aegis600/torrc.staging r,
  /etc/ssl/certs/** r,
  /var/lib/aegis600/tor/ rw,
  /var/lib/aegis600/tor/** rwk,
  /tmp/** rwk,
  /proc/self/** r,
  /proc/sys/kernel/random/** r,
  network inet stream,
  network inet6 stream,
  network unix stream,
  deny /home/** rwklx,
  deny /root/** rwklx,
  deny /var/lib/aegis-relay/** rwklx,
}
''')
    for action in ("backup", "restore@"):
        command = "backup" if action == "backup" else "restore --snapshot %i"
        write(root, f"etc/systemd/system/aegis600-staging-{action}.service", f'''[Unit]
Description=AEGIS 6 staging encrypted {action}
[Service]
Type=oneshot
User=root
UMask=0077
ExecStart=/usr/bin/python3 /opt/aegis600/bin/backup_restore.py {command} --apply
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/aegis600
AppArmorProfile=aegis600-staging-backup
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER
LimitCORE=0
MemoryMax=512M
TasksMax=64
TimeoutStartSec=3600
''')
    write(root,"etc/apparmor.d/aegis600-staging-backup",'''#include <tunables/global>
profile aegis600-staging-backup flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/dbus-strict>
  capability dac_read_search,
  capability chown,
  capability fowner,
  /usr/bin/python3{,.13} rix,
  /usr/lib/python3.13/** r,
  /usr/lib/python3/dist-packages/** r,
  /usr/bin/systemctl rix,
  /usr/bin/systemd-run rix,
  /usr/bin/restic rix,
  /opt/aegis600/bin/backup_restore.py r,
  /etc/aegis600/backup.json r,
  /etc/aegis600/backup-repository.txt r,
  /etc/aegis600/backup-password r,
  /etc/ssl/certs/** r,
  /var/lib/aegis600/ r,
  /var/lib/aegis600/{identity,attachments,glas-signaling,community,library,news-worker,management,management-broker,mail-relay,tor}/** rk,
  /var/lib/aegis600/{backup-staging,restored}/ rw,
  /var/lib/aegis600/{backup-staging,restored}/** rwk,
  /run/dbus/system_bus_socket rw,
  /run/systemd/private rw,
  /proc/self/** r,
  /tmp/** rwk,
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network unix stream,
  dbus (send, receive) bus=system peer=(name=org.freedesktop.systemd1),
  deny /home/** rwklx,
  deny /root/** rwklx,
  deny /var/lib/aegis-relay/** rwklx,
}
''')
    write(root,"etc/apparmor.d/aegis600-staging-sqlite-validator",'''#include <tunables/global>
profile aegis600-staging-sqlite-validator flags=(attach_disconnected) {
  #include <abstractions/base>
  /usr/bin/python3{,.13} rix,
  /usr/lib/** mr,
  /lib/** mr,
  /lib64/** mr,
  /validator.py r,
  /opt/aegis600/bin/sqlite_validator.py r,
  /AEGIS-SQLITE-VALIDATOR r,
  /etc/ld.so.cache r,
  /input/ r,
  /input/** r,
  /output/ rw,
  /output/** rwk,
  /proc/self/** r,
  /var/lib/aegis600/{backup-staging,restored}/**/sqlite-validator-*/input/** r,
  /var/lib/aegis600/{backup-staging,restored}/**/sqlite-validator-*/output/** rwk,
  /var/lib/aegis600/backup-staging/sqlite-validator-*/input/** r,
  /var/lib/aegis600/backup-staging/sqlite-validator-*/output/** rwk,
  /var/lib/aegis600/backup-staging/sqlite-validator-*/AEGIS-SQLITE-VALIDATOR r,
  /var/lib/aegis600/restored/**/sqlite-validator-*/AEGIS-SQLITE-VALIDATOR r,
  deny network,
  deny /home/** rwklx,
  deny /root/** rwklx,
  deny /etc/aegis600/** rwklx,
}
''')
    write(root, "README-DEBIAN13-6.0.0.md", (scripts / "README.md").read_text())
    for notice in sorted((scripts/"licenses").glob("*")):
        if not notice.is_file() or notice.is_symlink():raise ValueError("Недопустимый license notice")
        write(root,"opt/aegis600/licenses/"+notice.name,notice.read_text())
    inventory = {p.relative_to(root).as_posix(): {"size":p.stat().st_size,"sha256":sha(p),"mode":oct(stat.S_IMODE(p.stat().st_mode))} for p in sorted(root.rglob("*")) if p.is_file()}
    proof = {"version":"6.0.0","sourceCommit":git,"workingTreeDirty":dirty,"productionReady":False,"scope":"Actual packaged server JARs and staging configuration. No production deployment or native Debian acceptance.","legacyRelayReplaced":False,"isolatedMailRelay600Implemented":True,"isolatedMailRelay600NativeAcceptance":"NOT_RUN","nativeDebianAcceptance":"NOT_RUN","librarySharesCommunityTrustBoundary":True,"librarySyncDaemonImplemented":False,"glasSignalingSeparateServerImplemented":True,"glasSignalingNativeTorAcceptance":"NOT_RUN","monitoringNativeAcceptance":"NOT_RUN","backupRootParsesSqlite":False,"backupValidator":"unprivileged-per-database-systemd-sandbox","backupValidatorNativeAcceptance":"NOT_RUN","files":inventory}
    write(root,"BUILD-PROVENANCE-6.0.0.json",json.dumps(proof,ensure_ascii=False,indent=2)+"\n")
    return proof

def archive(root: pathlib.Path, target: pathlib.Path):
    if target.exists(): raise ValueError("Артефакт уже существует")
    with target.open("xb") as raw, gzip.GzipFile(filename="",mode="wb",fileobj=raw,mtime=0,compresslevel=6) as gz, tarfile.open(fileobj=gz,mode="w") as tar:
        for p in sorted(root.rglob("*")):
            info=tar.gettarinfo(str(p),arcname="AEGIS-6.0.0-Debian13-Server/"+p.relative_to(root).as_posix());info.uid=info.gid=0;info.uname=info.gname="root";info.mtime=0
            if info.issym() or info.islnk() or not (info.isfile() or info.isdir()): raise ValueError("Небезопасный объект пакета")
            if info.isfile():
                with p.open("rb") as f:tar.addfile(info,f)
            else:tar.addfile(info)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--jar-dir",type=pathlib.Path,required=True);p.add_argument("--deps",type=pathlib.Path,action="append",required=True);p.add_argument("--root",type=pathlib.Path,required=True);p.add_argument("--source-commit",required=True);p.add_argument("--archive",type=pathlib.Path);p.add_argument("--allow-development",action="store_true");a=p.parse_args()
    result=materialize(a.root,a.jar_dir,a.deps,a.source_commit,a.allow_development)
    if a.archive:archive(a.root,a.archive)
    print(json.dumps({"files":len(result["files"]),"sourceCommit":result["sourceCommit"],"productionReady":False,"archive":str(a.archive) if a.archive else None,"archiveSha256":sha(a.archive) if a.archive else None},indent=2))
if __name__=="__main__":main()
