#!/usr/bin/env python3
"""Run native libsecret against an owned, isolated D-Bus/keyring test process.

Test dependencies are installed or extracted separately by the test operator.
This script downloads nothing, changes no OS settings, and never uses the
desktop's existing keyring. It is not Windows/CachyOS desktop acceptance.
Compile NativeCredentialStoreSmoke.java into --classes before invoking it.
"""
import argparse
from pathlib import Path
import os
import secrets
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--appdir', type=Path, required=True)
parser.add_argument('--classes', type=Path, required=True)
parser.add_argument('--keyring-daemon', type=Path, required=True)
parser.add_argument('--library-dir', type=Path)
parser.add_argument('--inside-isolated-bus', action='store_true', help=argparse.SUPPRESS)
args = parser.parse_args()

if not args.inside_isolated_bus:
    command = ['dbus-run-session', '--', sys.executable, str(Path(__file__).resolve()),
               *sys.argv[1:], '--inside-isolated-bus']
    raise SystemExit(subprocess.call(command))

appdir, classes, daemon = args.appdir.resolve(), args.classes.resolve(), args.keyring_daemon.resolve()
if not (appdir / 'runtime/bin/java').is_file() or not daemon.is_file() or not classes.is_dir():
    parser.error('AppDir, native daemon and compiled probe classes must exist')
command = [str(appdir / 'runtime/bin/java'), '-Daegis.secret.test.isolated=true',
           '-cp', str(classes) + os.pathsep + str(appdir / 'app/*'),
           'org.securemail.client.security.NativeCredentialStoreSmoke']

with tempfile.TemporaryDirectory(prefix='aegis-native-secret-service-') as temporary:
    root = Path(temporary)
    environment = os.environ.copy()
    for name, relative in [('XDG_DATA_HOME', 'data'), ('XDG_CONFIG_HOME', 'config'),
                           ('XDG_RUNTIME_DIR', 'runtime')]:
        directory = root / relative
        directory.mkdir(mode=0o700)
        environment[name] = str(directory)
    # Environment is scoped to these owned child processes; existing HOME is untouched.
    environment['GSETTINGS_BACKEND'] = 'memory'
    if args.library_dir:
        directory = str(args.library_dir.resolve())
        environment['LD_LIBRARY_PATH'] = directory + (os.pathsep + environment['LD_LIBRARY_PATH'] if environment.get('LD_LIBRARY_PATH') else '')
    control = root / 'control'; control.mkdir(mode=0o700)
    keyring_password = secrets.token_urlsafe(48).encode('ascii')
    with (root / 'keyring.log').open('wb') as log:
        process = subprocess.Popen([str(daemon), '--foreground', '--components=secrets',
                                    '--control-directory', str(control), '--unlock'],
                                   env=environment, stdin=subprocess.PIPE, stdout=log, stderr=log)
        try:
            process.stdin.write(keyring_password)
            process.stdin.close()
            keyring_password = None
            # Check the real D-Bus name rather than assuming a fixed sleep is readiness.
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise RuntimeError('Owned test keyring exited before D-Bus became ready')
                state = subprocess.run(['dbus-send', '--session', '--print-reply',
                    '--dest=org.freedesktop.DBus', '/org/freedesktop/DBus',
                    'org.freedesktop.DBus.NameHasOwner', 'string:org.freedesktop.secrets'],
                    env=environment, capture_output=True, timeout=5, check=True)
                if b'boolean true' in state.stdout:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError('Owned test keyring D-Bus readiness timed out')
                time.sleep(0.1)
            subprocess.run([*command, str(root / 'profile')], env=environment, timeout=90, check=True)
            unavailable = environment.copy()
            unavailable['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=' + str(root / 'nonexistent-bus')
            subprocess.run([*command, str(root / 'unavailable-profile'), 'unavailable'],
                           env=unavailable, timeout=35, check=True)
            print('PASS actual packaged Java/core JAR + native libsecret/gnome-keyring; isolated test data removed')
        finally:
            keyring_password = None
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
