package org.securemail.ecosystem.protocol;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/** Fixed, public administration purposes. Existing capabilities and mutation domains are unchanged. */
public final class IdentityAdministrationProtocol600 {
    private IdentityAdministrationProtocol600() {}
    public enum Operation {
        ASSIGN("administrator.assign", "administratorAssign", "assigned"),
        REVOKE("administrator.revoke", "administratorRevoke", "revoked"),
        APPROVE_RECOVERY("account.sensitive_recovery.approve", "sensitiveRecoveryApprove", "approved");
        public final String wire, rpc, result;
        Operation(String wire,String rpc,String result){this.wire=wire;this.rpc=rpc;this.result=result;}
    }
    public static byte[] payload(Operation operation,String account,String roleName) {
        if(operation==null)throw new IllegalArgumentException("Administration purpose");
        IdentityProtocol.idValue(account);
        if(operation==Operation.ASSIGN)return IdentityProtocol.administratorAssignment(account,roleName);
        if(roleName==null||!roleName.isEmpty())throw new IllegalArgumentException("Unexpected role name");
        return operation==Operation.REVOKE?IdentityProtocol.administratorRevocation(account):IdentityProtocol.accountRecoveryApproval(account);
    }
    /** Unlike approval, inspection authorizes no mutation and signs no caller supplied payload. */
    public static byte[] criticalInspection(String audience,String requestId,long time,String nonce) {
        IdentityProtocol.idValue(audience);IdentityProtocol.nonceValue(requestId);IdentityProtocol.nonceValue(nonce);
        if(time<1)throw new IllegalArgumentException("Inspection time");
        try{ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF("AEGIS-IDENTITY-CRITICAL-INSPECTION/v1");out.writeUTF(audience);out.writeUTF(requestId);out.writeLong(time);out.writeUTF(nonce);out.flush();return bytes.toByteArray();
        }catch(IOException impossible){throw new IllegalStateException(impossible);}
    }
}
