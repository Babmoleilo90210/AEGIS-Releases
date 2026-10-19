"""Generate Android provider/API adaptation of existing reviewed v2 VoiceTls, preserving wire bytes."""
def adapt(original:str)->str:
    text=original.replace('VoiceTls','AndroidVoiceTls').replace('HexFormat.of()','org.aegis.android.AndroidHex.INSTANCE')
    start=text.index('    public static Pending create(Identity identity,')
    end=text.index('    /** Mail signs only',start)
    text=text[:start]+text[end:]  # Android has no legacy-root signing factory.
    def once(old,new):
        nonlocal text
        if text.count(old)!=1:raise ValueError('Desktop VoiceTls adapter point changed: '+old[:70])
        text=text.replace(old,new)
    once('    private AndroidVoiceTls() { }','''    private static final java.security.Provider ANDROID_CRYPTO=new org.bouncycastle.jce.provider.BouncyCastleProvider();
    private static final java.security.Provider ANDROID_JSSE=new org.bouncycastle.jsse.provider.BouncyCastleJsseProvider(false,ANDROID_CRYPTO);
    private AndroidVoiceTls() { }
    private static boolean verifyIdentity(byte[] encoded,byte[] body,byte[] signature){
        try{java.security.PublicKey key=java.security.KeyFactory.getInstance("Ed25519",ANDROID_CRYPTO).generatePublic(new java.security.spec.X509EncodedKeySpec(encoded));java.security.Signature verifier=java.security.Signature.getInstance("Ed25519",ANDROID_CRYPTO);verifier.initVerify(key);verifier.update(body);return verifier.verify(signature);}catch(java.security.GeneralSecurityException|RuntimeException invalid){return false;}
    }
    public static String applicationProtocol(SSLSocket socket){return ((org.bouncycastle.jsse.BCSSLSocket)socket).getApplicationProtocol();}''')
    text=text.replace('Identity.verify(','verifyIdentity(').replace('KeyPairGenerator.getInstance("Ed25519")','KeyPairGenerator.getInstance("Ed25519",ANDROID_CRYPTO)').replace('Signature.getInstance("Ed25519")','Signature.getInstance("Ed25519",ANDROID_CRYPTO)').replace('CertificateFactory.getInstance("X.509")','CertificateFactory.getInstance("X.509",ANDROID_CRYPTO)').replace('certificate.verify(certificate.getPublicKey());','certificate.verify(certificate.getPublicKey(),ANDROID_CRYPTO);')
    once('SSLContext.getInstance("TLSv1.3", "SunJSSE")','SSLContext.getInstance("TLSv1.3", ANDROID_JSSE)')
    once('if((offer.delegation()==null)!=(remote.delegation()==null))throw new GeneralSecurityException("Voice protocol downgrade denied");','if(offer.delegation()==null||remote.delegation()==null)throw new GeneralSecurityException("Voice protocol downgrade denied");')
    once('SSLParameters parameters = tls.getSSLParameters();','org.bouncycastle.jsse.BCSSLParameters parameters = ((org.bouncycastle.jsse.BCSSLSocket)tls).getParameters();')
    once('tls.setSSLParameters(parameters);','((org.bouncycastle.jsse.BCSSLSocket)tls).setParameters(parameters);')
    text=text.replace('tls.getApplicationProtocol()','applicationProtocol(tls)')
    start=text.index('    /** Standard SunJSSE TLS 1.3 post-handshake KeyUpdate;')
    end=text.index('    /** Certificate-pair comparison code',start)
    text=text[:start]+'''    /** BCJSSE handles standard inbound/automatic TLS1.3 KeyUpdate. No public manual trigger exists. */
    public static void requestKeyUpdate(SSLSocket socket)throws IOException {
        throw new SSLException("BCJSSE has no supported public manual KeyUpdate trigger; no downgrade is permitted");
    }

'''+text[end:]
    return text

if __name__=='__main__':
    import argparse,pathlib
    p=argparse.ArgumentParser();p.add_argument('source',type=pathlib.Path);p.add_argument('output',type=pathlib.Path);a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(adapt(a.source.read_text()),encoding='utf-8')
