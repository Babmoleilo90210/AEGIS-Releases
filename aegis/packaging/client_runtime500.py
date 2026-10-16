"""5.0 client packaging uses the same reviewed crypto/native input pins."""
from pathlib import Path
import zipfile
from client_runtime import (SAFE_WEB_ARTIFACTS as BASE_ARTIFACTS, SAFE_WEB_RUNTIME as BASE_RUNTIME, sha256,
                            verify_voice_native, verify_safe_web_runtime as _verify)

# Independent 5.0 inventory: historical 2.5 fixtures/defaults keep their original
# pins. This additional transitive input is already locked and hash-verified by
# Gradle; reusing the old published binary's 1.3.5 would diverge from the source.
SAFE_WEB_RUNTIME = {
    **BASE_RUNTIME,
    'commons-logging-1.4.0.jar': 'd175dbd751dd782a63bde28c7a039520e971f25e84b79c19b8435edc3603e0dc',
}
SAFE_WEB_ARTIFACTS = set(BASE_ARTIFACTS) | {'commons-logging'}

CORE_JAR = 'client-core-5.0.0.jar'
REQUIRED_CLASSES = [
    'org/securemail/client/safeweb/' + name + '.class'
    for name in ['SandboxPreparation', 'SandboxDiagnostics', 'WindowsFeatureInstaller']
]


def verify_safe_web_runtime(app, *, verify_core=True):
    app = Path(app)
    result = _verify(app, verify_core=verify_core, core_jar_name=CORE_JAR)
    for file in app.glob('*.jar'):
        if any(file.name.startswith(artifact + '-') for artifact in SAFE_WEB_ARTIFACTS) and file.name not in SAFE_WEB_RUNTIME:
            raise ValueError('Conflicting 5.0 runtime dependency version in client: ' + file.name)
    for name in SAFE_WEB_RUNTIME.keys() - BASE_RUNTIME.keys():
        file = app / name
        if file.is_symlink() or not file.is_file() or sha256(file) != SAFE_WEB_RUNTIME[name]:
            raise ValueError('Missing or changed pinned 5.0 runtime dependency: ' + name)
        with zipfile.ZipFile(file) as archive:
            if archive.testzip() is not None:
                raise ValueError('5.0 runtime JAR CRC failure: ' + name)
        result[name] = SAFE_WEB_RUNTIME[name]
    if verify_core:
        with zipfile.ZipFile(app / CORE_JAR) as archive:
            if not set(REQUIRED_CLASSES) <= set(archive.namelist()):
                raise ValueError('5.0 system preparation implementation missing from client core')
    return result
