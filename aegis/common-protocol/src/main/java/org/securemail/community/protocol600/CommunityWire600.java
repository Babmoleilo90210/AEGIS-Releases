package org.securemail.community.protocol600;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import java.io.*;
import java.util.*;
/** Dedicated ecosystem Community operation/response domains; no root identity key required. */
public final class CommunityWire600 {
    public static final int MAX_BODY=8*1024*1024,MAX_ARGS=6*1024*1024;
    private CommunityWire600() { }
    /** Role requests carry ACCOUNT_READ; target scope, delegated rights, fresh step-up and global two-party permits are enforced by AdminService. */
    public static String identityAction(String action) {if(action==null||!action.matches("[a-z][a-z0-9_.]{0,95}"))throw new IllegalArgumentException("Community action");return action.startsWith("admin.")&&!action.startsWith("admin.roles.")||action.startsWith("agent.")&&!action.equals("agent.cities.list")||action.equals("community600.critical.get")||action.equals("org.applications.decide")?"admin.execute":"account.read";}
    public static byte[] operation(String audience,String action,byte[] args) {IdentityProtocol.idValue(audience);identityAction(action);if(args.length<2||args.length>MAX_ARGS)throw new IllegalArgumentException("Community operation limit");return encode(out->{out.writeUTF("AEGIS-COMMUNITY-ECOSYSTEM-OPERATION/v1");out.writeUTF(audience);out.writeUTF(action);out.writeInt(args.length);out.write(args);});}
    public static byte[] response(String audience,String nonce,byte[] request,byte[] response) {IdentityProtocol.idValue(audience);IdentityProtocol.nonceValue(nonce);if(request.length>MAX_BODY||response.length>MAX_BODY)throw new IllegalArgumentException("Community response limit");return encode(out->{out.writeUTF("AEGIS-COMMUNITY-ECOSYSTEM-RESPONSE/v1");out.writeUTF(audience);out.writeUTF(nonce);out.writeInt(request.length);out.write(IdentityProtocol.digest(request));out.writeInt(response.length);out.write(IdentityProtocol.digest(response));});}
    public static String criticalOperation(String kind) {if(kind==null||!kind.matches("[A-Z][A-Z0-9_]{0,39}"))throw new IllegalArgumentException("Critical kind");return "community."+kind.toLowerCase(Locale.ROOT);}
    private interface Writer {void write(DataOutputStream out)throws IOException;}
    private static byte[] encode(Writer writer){try{ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(bytes)){writer.write(out);}return bytes.toByteArray();}catch(IOException impossible){throw new IllegalStateException(impossible);}}
}
