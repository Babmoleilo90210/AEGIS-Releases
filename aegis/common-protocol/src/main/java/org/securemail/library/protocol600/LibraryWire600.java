package org.securemail.library.protocol600;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Fixed-domain service operation and signed response framing. No JSON reserialization or private root keys. */
public final class LibraryWire600 {
    public static final int MAX_BODY=8*1024*1024,MAX_ARGS=4*1024*1024;
    private static final Set<String> READ=new HashSet<String>(Arrays.asList("read","read.authorize","file","export","list","graph","revisions","catalog","project","cache.authorize","proposal.list","proposal.get","access.list","capabilities","permissions","link.list"));
    private static final Set<String> WRITE=new HashSet<String>(Arrays.asList("discovery.grant","discovery.revoke","access.request","access.decide","proposal.create","proposal.decide","create","update","submit","moderate","publish","retract","delete","revert","link.propose","link.decide","file.upload"));
    private LibraryWire600() { }
    public static String identityAction(String action) {
        if(action==null||!action.startsWith("library600."))throw new IllegalArgumentException("Library action");
        String operation=action.substring(11);
        if(READ.contains(operation))return "library.read";
        if(WRITE.contains(operation))return "library.write";
        throw new IllegalArgumentException("Library action");
    }
    public static byte[] operation(String libraryAudience,String action,byte[] exactArgsJson) {
        IdentityProtocol.idValue(libraryAudience);identityAction(action);
        if(exactArgsJson==null||exactArgsJson.length<2||exactArgsJson.length>MAX_ARGS)throw new IllegalArgumentException("Library operation size");
        try {ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF("AEGIS-LIBRARY-OPERATION/v1");out.writeUTF(libraryAudience);out.writeUTF(action);out.writeInt(exactArgsJson.length);out.write(exactArgsJson);out.close();return bytes.toByteArray();
        }catch(IOException impossible){throw new IllegalStateException(impossible);}
    }
    public static byte[] response(String libraryAudience,String outerNonce,byte[] request,byte[] response) {
        IdentityProtocol.idValue(libraryAudience);IdentityProtocol.nonceValue(outerNonce);
        if(request==null||response==null||request.length>MAX_BODY||response.length>MAX_BODY)throw new IllegalArgumentException("Library response size");
        try {ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF("AEGIS-LIBRARY-HTTP-RESPONSE/v1");out.writeUTF(libraryAudience);out.writeUTF(outerNonce);
            out.writeInt(request.length);out.write(IdentityProtocol.digest(request));out.writeInt(response.length);out.write(IdentityProtocol.digest(response));out.close();return bytes.toByteArray();
        }catch(IOException impossible){throw new IllegalStateException(impossible);}
    }
}
