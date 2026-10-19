package org.securemail.identity;
import java.nio.file.attribute.*;
import java.util.Set;
final class PosixFilePermissions600 {
    private PosixFilePermissions600() { }
    static Set<PosixFilePermission> directory(){return PosixFilePermissions.fromString("rwx------");}
    static Set<PosixFilePermission> file(){return PosixFilePermissions.fromString("rw-------");}
}
