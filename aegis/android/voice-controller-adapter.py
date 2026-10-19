"""Preserve existing call state machine/media framing; adapt provider, storage and onion publisher APIs."""
from pathlib import Path
NAMES={'VoiceCallService':'AndroidVoiceCallService','VoiceLocalStore600':'AndroidVoiceLocalStore600','VoiceHistory':'AndroidVoiceHistory','VoiceCallPolicy':'AndroidVoiceCallPolicy','VoiceOrganizationAuthorizer':'AndroidVoiceOrganizationAuthorizer','VoiceTls':'AndroidVoiceTls'}
def common(text):
    for old,new in NAMES.items():text=text.replace(old,new)
    return text.replace('HexFormat.of()','org.aegis.android.AndroidHex.INSTANCE')
def replace_once(text,old,new):
    if text.count(old)!=1:raise ValueError('Call adaptation point changed: '+old[:80])
    return text.replace(old,new)
def generate(root:Path,out:Path):
    voice=root/'client-core/src/main/java/org/securemail/client/voice';outputs=[]
    for name in NAMES:
        if name=='VoiceTls':continue
        text=common((voice/(name+'.java')).read_text())
        text=text.replace('import org.securemail.client.net.NetworkService;','').replace('import org.securemail.client.storage.*;','').replace('import org.securemail.client.storage.LocalStore;','').replace('import org.securemail.client.storage.LocalFeatures;','')
        if name=='VoiceLocalStore600':text=text[:text.index('  static AndroidVoiceLocalStore600 legacy(')]+'}\n'
        if name=='VoiceHistory':
            start=text.index('  AndroidVoiceHistory(LocalStore local)');end=text.index('  AndroidVoiceHistory(AndroidVoiceLocalStore600 local)',start);text=text[:start]+text[end:]
        if name=='VoiceCallService':
            start=text.index('  public AndroidVoiceCallService(LocalStore local,');end=text.index('  AndroidVoiceCallService(AndroidVoiceLocalStore600 local,Connector connector,MediaFactory mediaFactory)',start)
            text=text[:start]+'''  public AndroidVoiceCallService(AndroidVoiceLocalStore600 local,Connector connector)throws IOException,GeneralSecurityException {
    this(local,connector,AndroidVoiceCallService::openMedia);
  }
'''+text[end:]
            text=text.replace('@FunctionalInterface interface Connector','@FunctionalInterface public interface Connector')
            # The provider has no public manual KeyUpdate API. Existing bounded reconnect
            # establishes a new authenticated TLS1.3 session; it never sends plaintext.
            text=replace_once(text,'AndroidVoiceTls.requestKeyUpdate(link.tls);link.lastKeyUpdate=now;link.bytesSinceKeyUpdate=0;','lost(call,link);return; /* Fresh authenticated TLS; microphone remains off until explicitly reenabled. */')
        target=out/'org/securemail/client/voice'/(NAMES[name]+'.java');target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text);outputs.append(target)
    original=root/'client-core/src/main/java/org/securemail/client/voice600/GlasSignalingClient600.java';text=original.read_text().replace('GlasSignalingClient600','AndroidGlasSignalingClient600').replace('import org.securemail.client.AppPaths;','').replace('import org.securemail.client.ecosystemauth.CorePublicConfig600;','')
    start=text.index('    public static Config load()');end=text.index('  public record Resolved',start);text=text[:start]+'  }\n'+text[end:]
    text=text.replace('CorePublicConfig600 identity','byte[] identity').replace('identity.identityPublicKey()','identity').replace('PrivateKey appKey','Signer appKey').replace('IdentityProtocol.sign(appKey,','appKey.sign(')
    text=text.replace('  public record Resolved','  @FunctionalInterface public interface Signer {byte[] sign(byte[] canonical)throws IOException;}\n  public record Resolved')
    text=replace_once(text,'private final Semaphore slots=', 'private final java.util.function.BooleanSupplier authorized;\n  private final Semaphore slots=')
    text=replace_once(text,'TorTransport tor){this(config,identity,wire,appKey,tor::connectPeer);}','TorTransport tor,java.util.function.BooleanSupplier authorized)throws IOException{this(config,identity,wire,appKey,tor::connectPeer,authorized);}')
    text=replace_once(text,'Signer appKey,Connector connector){','Signer appKey,Connector connector,java.util.function.BooleanSupplier authorized)throws IOException{\n    this.authorized=Objects.requireNonNull(authorized);if(!authorized.getAsBoolean())throw new IOException("Глас заблокирован");')
    text=text.replace('if(closed||!slots.tryAcquire())','if(closed||!authorized.getAsBoolean()||!slots.tryAcquire())').replace('if(closed)throw new IOException("Глас закрыт")','if(closed||!authorized.getAsBoolean())throw new IOException("Глас закрыт")')
    text=text.replace('  public String audience()', '  public IdentityProtocol.Capability capability(){return cap;}\n  public String audience()')
    target=out/'org/securemail/client/voice600/AndroidGlasSignalingClient600.java';target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text);outputs.append(target)
    original=root/'client-core/src/main/java/org/securemail/client/voice600/GlasOnionTransport600.java';text=common(original.read_text()).replace('GlasOnionTransport600','AndroidGlasOnionTransport600').replace('GlasSignalingClient600','AndroidGlasSignalingClient600').replace('GlasState600','AndroidGlasState').replace('PrivateKey appKey','AndroidGlasSignalingClient600.Signer appKey').replace('IdentityProtocol.sign(appKey,','appKey.sign(')
    text=text.replace('private volatile TorControl control;','private volatile Publisher publisher;')
    start=text.index('  /** Runs on a worker; SAFECOOKIE');end=text.index('  private void register()',start)
    text=text[:start]+'''  /** Publisher is a narrow owned Core onion handle, never a cookie/control socket. */
  public interface Publisher extends AutoCloseable {String publish(int localPort)throws IOException;void close()throws IOException;}
  public void start(AndroidVoiceCallService service,Publisher publisher)throws IOException,GeneralSecurityException{
    if(closed||calls!=null)throw new IOException("Глас уже запущен или закрыт");calls=Objects.requireNonNull(service);this.publisher=Objects.requireNonNull(publisher);
    Thread accept=new Thread(this::accept,"glas-onion-accept");accept.setDaemon(true);accept.start();
    try{onion=publisher.publish(listener.getLocalPort());if(!GlasProtocol600.validOnion(onion))throw new IOException("Не подтверждён адрес onion");register();ready=true;service.networkAvailable(true);status.accept(true);}catch(IOException|RuntimeException failure){throw failure;}
    timer.scheduleWithFixedDelay(this::refresh,1,2,TimeUnit.SECONDS);
  }
'''+text[end:]
    text=replace_once(text,'if(in.readUnsignedByte()!=101||!Binary.text(in,64).isEmpty())throw new IOException("Тип соединения Гласа");timeout.cancel(false);calls.handleIncoming(socket);','int operation=in.readUnsignedByte();if(!Binary.text(in,64).isEmpty())throw new IOException("Тип соединения Гласа");if(operation==org.aegis.android.VoiceEndpointProof.OPERATION){String nonce=Binary.text(in,64);byte[] proof=appKey.sign(org.aegis.android.VoiceEndpointProof.canonical(signaling.capability(),listener.getLocalPort(),nonce));DataOutputStream out=new DataOutputStream(socket.getOutputStream());Binary.header(out);Binary.bytes(out,proof);out.flush();}else{if(operation!=101||!ready)throw new IOException("Глас ещё не подключён");timeout.cancel(false);calls.handleIncoming(socket);}')
    text=replace_once(text,'TorControl own=control;control=null;if(own!=null)try{own.close();}catch(IOException ignored){}','Publisher own=publisher;publisher=null;if(own!=null)try{own.close();}catch(IOException ignored){}')
    start=text.index('  @Override public void close(){');end=text.index('  private void closeListener()',start)
    text=text[:start]+'''  /** Local sockets/threads stop immediately even when remote publisher cleanup is queued. */
  public Publisher closeLocal(){Publisher own;synchronized(this){if(closed)return null;closed=true;own=publisher;publisher=null;}ready=false;AndroidVoiceCallService service=calls;if(service!=null){service.networkAvailable(false);service.close();}timer.shutdownNow();inbound.shutdownNow();closeListener();for(Socket socket:sockets)close(socket);sockets.clear();peers.clear();signaling.close();return own;}
  @Override public void close(){Publisher own=closeLocal();if(own!=null)try{own.close();}catch(IOException ignored){}}
'''+text[end:]
    target=out/'org/securemail/client/voice600/AndroidGlasOnionTransport600.java';target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text);outputs.append(target)
    return outputs
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();generate(a.root,a.out)
