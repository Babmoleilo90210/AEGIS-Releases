package org.securemail.client.ecosystem;

import java.util.*;

/** A narrow Identity capability plus its unique application proof key; never a legacy account root private key. */
public record ComponentLease(ComponentId component,String accountId,long generation,byte[] capability,byte[] proofPrivatePkcs8,byte[] proofPublicX509,byte[] auxiliaryPublic) implements AutoCloseable {
  public ComponentLease {
    Objects.requireNonNull(component);Objects.requireNonNull(accountId);Objects.requireNonNull(capability);Objects.requireNonNull(proofPrivatePkcs8);Objects.requireNonNull(proofPublicX509);Objects.requireNonNull(auxiliaryPublic);
    if(accountId.isBlank()||accountId.length()>256||accountId.codePoints().anyMatch(Character::isISOControl)||generation<1||capability.length<1||capability.length>32768
        ||auxiliaryPublic.length>65536
        ||!(proofPrivatePkcs8.length==0&&proofPublicX509.length==0 || proofPrivatePkcs8.length>=48&&proofPrivatePkcs8.length<=256&&proofPublicX509.length==44))throw new IllegalArgumentException("Некорректный допуск приложения");
    capability=capability.clone();proofPrivatePkcs8=proofPrivatePkcs8.clone();proofPublicX509=proofPublicX509.clone();auxiliaryPublic=auxiliaryPublic.clone();
  }
  public ComponentLease(ComponentId component,String accountId,long generation,byte[] capability,byte[] privateKey,byte[] publicKey){this(component,accountId,generation,capability,privateKey,publicKey,new byte[0]);}
  /** Only local protocol fixtures and the explicitly separate pairing purpose use an empty proof key. Production Mail rejects it. */
  public ComponentLease(ComponentId component,String accountId,long generation,byte[] capability){this(component,accountId,generation,capability,new byte[0],new byte[0]);}
  @Override public byte[] auxiliaryPublic(){return auxiliaryPublic.clone();}
  @Override public byte[] capability(){return capability.clone();}
  @Override public byte[] proofPrivatePkcs8(){return proofPrivatePkcs8.clone();}
  @Override public byte[] proofPublicX509(){return proofPublicX509.clone();}
  @Override public String toString(){return "ComponentLease[component="+component+", generation="+generation+"]";}
  @Override public void close(){Arrays.fill(capability,(byte)0);Arrays.fill(proofPrivatePkcs8,(byte)0);Arrays.fill(proofPublicX509,(byte)0);Arrays.fill(auxiliaryPublic,(byte)0);}
}
