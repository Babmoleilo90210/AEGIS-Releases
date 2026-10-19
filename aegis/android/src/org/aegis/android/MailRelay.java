package org.aegis.android;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.*;
import java.util.function.BooleanSupplier;
import org.securemail.client.crypto.Identity;
import org.securemail.client.crypto.Secrets;
import org.securemail.client.net.TorTransport;
import org.securemail.protocol.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.MailSessionProtocol600;

/** Android lifecycle adapter for the unchanged protocol-1 relay; only ciphertext can be stored. */
final class MailRelay implements AutoCloseable {
    static final int MAX_PACKET=192*1024;
    private final TorTransport tor;private final String onion;private final int port;private final BooleanSupplier authorized;private volatile String token="";private volatile Socket active;private volatile boolean closed;
    MailRelay(String onion,int port,int socks,BooleanSupplier authorized){this.onion=Limits.onion(onion);if(port<1||port>65535)throw new IllegalArgumentException("Порт Relay");this.port=port;tor=new TorTransport("127.0.0.1",socks);this.authorized=authorized;}
    interface Reader<T>{T read(DataInputStream input)throws IOException;}
    private void guard()throws IOException{if(closed||!authorized.getAsBoolean())throw new IOException("Допуск Почты отозван; сеть остановлена");}
    private <T>T exchange(Operation op,String session,Binary.Writer writer,Reader<T> reader)throws IOException {
        guard();try(Socket socket=tor.connectPeer(onion,port,s->{guard();active=s;});DataInputStream in=new DataInputStream(new BufferedInputStream(socket.getInputStream()));DataOutputStream out=new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))){guard();socket.setSoTimeout(20_000);Binary.header(out);out.writeByte(op.code);Binary.text(out,session);writer.write(out);guard();out.flush();Binary.header(in);int status=in.readInt();if(status!=0)throw new IOException("Relay отклонил запрос · код "+status);T result=reader.read(in);guard();return result;}finally{active=null;}
    }
    interface LoginSigner {byte[] sign(byte[] canonical)throws Exception;}
    void login(Identity identity,String nickname,char[] password,IdentityProtocol.Capability capability,byte[] relayServiceKey,LoginSigner signer)throws Exception {String nick=Limits.nickname(nickname);if(password.length<12||password.length>1024)throw new IllegalArgumentException("Пароль аккаунта: 12–1024 символа");byte[] pass=Secrets.utf8(password);token="";try{if(capability.appId!=IdentityProtocol.App.MAIL||!capability.accountId.equals(identity.userId())||!capability.capabilities.contains(IdentityProtocol.Scope.MAIL_READ))throw new SecurityException("Допуск другого приложения или аккаунта");IdentityProtocol.publicKey(relayServiceKey);String wire=IdentityProtocol.encodeCapability(capability),nonce=IdentityProtocol.nonce();long now=System.currentTimeMillis();byte[] body=MailSessionProtocol600.login(IdentityProtocol.id(relayServiceKey),identity.userId(),nick,pass),proof=signer.sign(IdentityProtocol.requestDigest(capability,"mail.read",IdentityProtocol.digest(body),now,nonce));String result=exchange(Operation.LOGIN6,"",out->{Binary.text(out,nick);Binary.bytes(out,pass);Binary.text(out,wire);out.writeLong(now);Binary.text(out,nonce);Binary.bytes(out,proof);},in->{String value=Binary.text(in,64);if(!value.matches("[a-f0-9]{64}"))throw new IOException("Неверная сессия Relay");UserInfo me=UserInfo.read(in);if(!nick.equals(me.nickname())||!identity.userId().equals(me.userId())||!MessageDigest.isEqual(identity.publicKey(),me.publicKey()))throw new IOException("Relay связан с другой identity");return value;});guard();token=result;}finally{Arrays.fill(pass,(byte)0);Arrays.fill(password,'\0');}}
    void register(Identity identity,String nickname,char[] password,IdentityProtocol.Capability capability,byte[] relayServiceKey,LoginSigner signer)throws Exception {
        String nick=Limits.nickname(nickname);if(password.length<12||password.length>1024)throw new IllegalArgumentException("Пароль аккаунта: 12–1024 символа");byte[] pass=Secrets.utf8(password);try{if(capability.appId!=IdentityProtocol.App.MAIL||!capability.accountId.equals(identity.userId())||!capability.capabilities.containsAll(EnumSet.of(IdentityProtocol.Scope.MAIL_READ,IdentityProtocol.Scope.MAIL_SEND)))throw new SecurityException("Недостаточный допуск регистрации Почты");IdentityProtocol.publicKey(relayServiceKey);String wire=IdentityProtocol.encodeCapability(capability),nonce=IdentityProtocol.nonce();long now=System.currentTimeMillis();byte[] pub=identity.publicKey(),body=MailSessionProtocol600.registration(IdentityProtocol.id(relayServiceKey),identity.userId(),nick,pass,pub),proof=signer.sign(IdentityProtocol.requestDigest(capability,"mail.send",IdentityProtocol.digest(body),now,nonce));UserInfo me=exchange(Operation.REGISTER6,"",out->{Binary.text(out,nick);Binary.bytes(out,pass);Binary.bytes(out,pub);Binary.text(out,wire);out.writeLong(now);Binary.text(out,nonce);Binary.bytes(out,proof);},UserInfo::read);if(!nick.equals(me.nickname())||!identity.userId().equals(me.userId())||!MessageDigest.isEqual(pub,me.publicKey()))throw new IOException("Ответ регистрации другой identity");}finally{Arrays.fill(pass,(byte)0);}
    }
    private String session()throws IOException{guard();String value=token;if(value.isEmpty())throw new IOException("Войдите в Relay с паролем аккаунта");return value;}
    UserInfo find(String nickname)throws IOException {String nick=Limits.nickname(nickname);UserInfo peer=exchange(Operation.FIND,session(),out->Binary.text(out,nick),UserInfo::read);if(!nick.equals(peer.nickname())||!peer.userId().equals(Identity.id(peer.publicKey())))throw new IOException("Некорректная identity контакта");return peer;}
    void send(EncryptedPacket packet,Identity identity,UserInfo pinned)throws IOException {if(!packet.senderId().equals(identity.userId())||!packet.recipientId().equals(pinned.userId())||!Identity.verifyPacket(packet))throw new IOException("Разрешены только подписанные E2EE-пакеты");UserInfo fresh=find(pinned.nickname());if(!fresh.userId().equals(pinned.userId())||!MessageDigest.isEqual(fresh.publicKey(),pinned.publicKey()))throw new IOException("Identity контакта изменилась; отправка запрещена");exchange(Operation.STORE,session(),out->PacketCodec.write(out,packet),in->null);}
    EncryptedPacket fetch()throws IOException{return exchange(Operation.FETCH,session(),out->{},in->in.readBoolean()?PacketCodec.read(in,MAX_PACKET):null);}
    void acknowledge(Receipt receipt)throws IOException{exchange(Operation.ACK,session(),receipt::write,in->null);}
    boolean loggedIn(){return !token.isEmpty()&&!closed;}
    @Override public void close(){closed=true;token="";Socket socket=active;if(socket!=null)try{socket.close();}catch(IOException ignored){}}
}
