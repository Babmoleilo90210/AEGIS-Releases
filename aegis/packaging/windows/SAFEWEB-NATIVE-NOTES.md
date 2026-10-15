# Windows Safe Web: implemented boundaries and acceptance limits

`WindowsSafeWebSandbox` is the application backend. It requires an already enabled
Microsoft Windows Sandbox with its current `wsb` CLI on Windows 11 **24H2+** x64
Pro, Enterprise or Education.
Windows Home is explicitly unsupported by that component. AEGIS does not enable
optional features, modify firewall rules, grant loopback exemptions, install a
third-party driver or silently launch a less isolated browser.

Only the dedicated verified session bundle is mapped into the guest as
`C:\SafeWeb`. AEGIS storage, archive, keys, credentials, signing metadata and
unrelated host folders are not mapped. Clipboard, printers, audio input, camera
input and vGPU sharing are disabled. Protected Client is enabled. Networking is
enabled because stock Tor Browser must start its own Tor. This is **not** a
kernel Tor-only firewall against a compromised browser broker or unrelated guest
OS network services.

The fixed packaged guest script reads the validated URL from a Base64 **data
file**. URLs are not interpolated into PowerShell source or a shell command. The
script starts the official browser and its existing stock profile using native
`CreateProcess`, before execution assigning it to a private kill-on-close Job
Object. Descendants, including the bundle's Tor, stay in that guest job. There
are no browser sandbox, proxy, fingerprinting, extension or WebRTC preference
overrides. Only the download-directory preferences are set.

The controller and guest exchange a nonce-bound, bounded heartbeat. A Java crash
expires the guest lease, kills the guest job and shuts down that disposable guest.
Normal close writes a stop request and uses Microsoft's `wsb stop --id` with the
random ID supplied by AEGIS to its own `wsb start`. The host's `wsb list --raw`
must prove that exact VM stopped before the controller releases the session lock
or permits temporary-folder removal. Guest `CLOSED` records are untrusted hints,
and launcher termination is not treated as proof that a VM stopped. Failed stop
verification retains the lock and files. A pre-existing Windows Sandbox is
rejected; it is never adopted or terminated. The control plane is resolved from
the OS-known LocalAppData App Execution Alias, with no PATH search; its reparse
data must bind the Microsoft Sandbox package and the protected Program Files
executable. Unknown alias formats fail closed.
Windows Sandbox is a system singleton, so this backend cannot run alongside a
user's separate instance. `WindowsSandbox.exe` legacy launcher fallback is not
used. Actual CLI-ID creation, alias format, stop verification and shutdown timing
need native Windows 11 acceptance. Neither process creation nor a guest status record
proves Tor connectivity or successful native acceptance.

Writable mapped folders are a real permission grant. A compromised guest can
alter its bundle/profile/downloads. Trusted executable hashes are held outside
the mapped bundle and checked before reuse. Pre-existing reparse points are
rejected. Download imports must copy via validated file/directory handles, and no
guest file is automatically executed on the host. A Windows sandbox/redirected
filesystem vulnerability is outside the application-level isolation guarantee.
Windows Sandbox accesses mapped files as SYSTEM; only the browser session bundle
and its Safe Web parent directories receive current-user + SYSTEM ACLs. No
Everyone/Users/AppContainer grant is added, and AEGIS data remains untouched.

## Experimental AppContainer helper

`safeweb.c` is a separate experiment, **not** the normal backend. Its strict CLI
is `AEGIS-SafeWeb.exe --bundle PATH --url URL` or `--self-test`. The bundle must be
one simple child of `%LOCALAPPDATA%\AEGIS-SafeWeb\bundles`; a normal Firefox or
user-selected folder is not accepted. It ACLs only this bundle for the current
user, SYSTEM and a unique AppContainer SID, sets low mandatory integrity, rejects
reparse points/hardlinked files, clears the browser environment, whitelists only
NUL standard handles, verifies the suspended child's exact AppContainer SID,
and then assigns its own Job Object before resuming.

Every experimental browser launch first runs a native probe that checks its
AppContainer token, own sentinel read/write, denied outside sentinel read/write,
clipboard job policy and TCP loopback between two processes in the same
AppContainer. Failures stop launch; no permissions or sandbox protections are
weakened. Its only network capability is `internetClient`, required by its own
Tor. This capability does not constitute a Tor-only egress rule.

Official Firefox/Tor Browser multiprocess sandboxing may be incompatible with an
external AppContainer. No `MOZ_DISABLE_*`, single-process custom browser or
disable-updater workaround is used. The probe cannot prove Firefox compatibility.
The helper therefore remains experimental even if `--self-test` succeeds.

The helper's controller stdin must be a pipe. EOF, `CLOSE\n` or malformed input
closes only its owned job. Browser descendants never inherit the pipe or AEGIS
handles. It emits bounded JSON records containing constant status identifiers,
numeric errors and the created PID, without URLs, paths or browser logs.

Build (cross compilation is not native acceptance):

```sh
x86_64-w64-mingw32-gcc -std=c11 -Os -Wall -Wextra -Werror -municode -static \
  -o AEGIS-SafeWeb.exe packaging/windows/safeweb.c \
  -luserenv -ladvapi32 -lshell32 -lole32 -lbcrypt -luuid -lws2_32
```

`test_safeweb_policy.py` compiles and executes the exact pure URL/Windows CRT
argument-quoting functions on Linux. `Test-SafeWeb.ps1` runs the actual Windows
probe and URL rejection checks when explicitly invoked on Windows. No Windows
probe, Tor Browser launch, VM launch, Tor/onion/HTTPS traffic test or Windows 11
native acceptance was executed in the Linux build environment: **NOT_RUN**.

## Primary technical references inspected

- [Windows Sandbox editions, singleton and virtualization model](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)
- [Windows Sandbox configuration and mapped-folder/security controls](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
- [Windows Sandbox prerequisites and explicit optional-feature installation](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install)
- [Official Windows Sandbox CLI: ID-scoped start, list, connect and stop](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli)
- [Microsoft's CLI alias resolution and observed raw list schema](https://github.com/microsoft/winappCli/blob/main/src/winapp-CLI/WinApp.Cli/ExecutionTargets/WindowsSandbox/WindowsSandboxCli.cs)
- [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- [CreateAppContainerProfile, Windows 8 minimum API](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile)
- [Job Object UI restrictions](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions)
- [Mozilla native child sandbox broker implementation](https://searchfox.org/firefox-main/source/security/sandbox/win/src/sandboxbroker/sandboxBroker.cpp)

The independent [SandboxYourFox experiment](https://github.com/WildByDesign/SandboxYourFox)
is an incompatibility warning, not an official supported Tor integration. Its
custom single-process/no-update workaround is deliberately not adopted.
