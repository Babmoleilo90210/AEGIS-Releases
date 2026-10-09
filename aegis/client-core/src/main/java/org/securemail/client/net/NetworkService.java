package org.securemail.client.net;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import org.securemail.client.crypto.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.storage.LocalStore;
import org.securemail.protocol.*;

/** Only message-send API accepts EncryptedPacket; never accepts a plaintext String. */
public final class NetworkService {
  public enum Delivery {
    P2P_CONFIRMED,
    RELAY_QUEUED
  }

  @FunctionalInterface
  private interface Reader<T> {
    T read(DataInputStream in) throws IOException;
  }

  private final TorTransport tor;
  private final String relayOnion;
  private final int relayPort, maxCiphertext;
  private final LocalStore local;
  private volatile String token = "";
  private volatile boolean registrationAccepted;
  private volatile int capabilities=-1;
  public boolean registrationAccepted(){return registrationAccepted;}

  public NetworkService(TorTransport tor, String relay, int port, LocalStore local, int max) {
    this.tor = tor;
    relayOnion = Limits.onion(relay);
    relayPort = port;
    this.local = local;
    maxCiphertext = max;
  }

  public void authenticate(String nickname, char[] password, boolean register)
      throws IOException, GeneralSecurityException {
    String nick = Limits.nickname(nickname);
    byte[] pass = Secrets.utf8(password);
    if (password.length < 12 || password.length > 1024) {
      Arrays.fill(pass, (byte) 0);
      throw new IllegalArgumentException("Пароль аккаунта: 12–1024 символа");
    }
    try {
      if (register) {
        exchange(
            relayOnion,
            relayPort,
            Operation.REGISTER,
            "",
            o -> {
              Binary.text(o, nick);
              Binary.bytes(o, pass);
              Binary.bytes(o, local.identity().publicKey());
            },
            UserInfo::read);
        registrationAccepted=true;
      }
      exchange(
          relayOnion,
          relayPort,
          Operation.LOGIN,
          "",
          o -> {
            Binary.text(o, nick);
            Binary.bytes(o, pass);
          },
          in -> {
            String session = Binary.text(in, 64);
            UserInfo me = UserInfo.read(in);
            if (!me.userId().equals(local.identity().userId())
                || !me.nickname().equals(nick)
                || !MessageDigest.isEqual(me.publicKey(), local.identity().publicKey()))
              throw new IOException(
                  "Аккаунт связан с другим локальным ключом. Восстановите исходное хранилище.");
            token = session;
            return null;
          });
      local.bindNickname(nick);
      capabilities=-1;
    } finally {
      Arrays.fill(pass, (byte) 0);
    }
  }

  public boolean loggedIn() {
    return !token.isEmpty();
  }
  public String sessionToken(){return token;}
  public void resume(String session)throws IOException {
    if(!session.matches("[a-f0-9]{64}"))throw new IOException("Invalid relay session");token=session;
    try{UserInfo me=find(local.nickname());if(!me.userId().equals(local.identity().userId())||!MessageDigest.isEqual(me.publicKey(),local.identity().publicKey()))throw new IOException("Identity mismatch");}catch(IOException|RuntimeException failure){token="";throw failure;}
  }

  public UserInfo find(String nick) throws IOException {
    String normalized = Limits.nickname(nick);
    UserInfo u = request(Operation.FIND, o -> Binary.text(o, normalized), UserInfo::read);
    if (!u.nickname().equals(normalized) || !u.userId().equals(Identity.id(u.publicKey())))
      throw new IOException("Bad directory response");
    return u;
  }

  public void publish(Route route) throws IOException {
    request(Operation.PUBLISH, route::write, i -> null);
  }

  /** An authenticated recipient may explicitly discard its own pending packet. */
  public void deletePending(String id) throws IOException {
    Limits.messageId(id);
    request(Operation.DELETE, o -> Binary.text(o, id), i -> null);
  }

  public record DeliveryResult(Delivery delivery, long confirmedAt) {}

  public Delivery deliver(EncryptedPacket p) throws IOException { return deliverDetailed(p).delivery(); }

  public DeliveryResult deliverDetailed(EncryptedPacket p) throws IOException {
    if (!p.senderId().equals(local.identity().userId()) || !Identity.verifyPacket(p))
      throw new IOException("Only locally signed encrypted packets can be sent");
    UserInfo contact =
        local.contacts().stream()
            .filter(u -> u.userId().equals(p.recipientId()))
            .findFirst()
            .orElseThrow(() -> new IOException("Добавьте и проверьте контакт"));
    UserInfo remote = find(contact.nickname());
    if (!remote.userId().equals(contact.userId())
        || !MessageDigest.isEqual(remote.publicKey(), contact.publicKey()))
      throw new IOException("Ключ контакта изменился. Отправка остановлена.");
    Route r = remote.route();
    long now = local.now();
    if (r != null
        && r.userId().equals(contact.userId())
        && r.expiresAt() > now
        && r.expiresAt() <= now + 300_000
        && Identity.verify(contact.publicKey(), r.signingBytes(), r.signature()))
      try {
        Receipt ack =
            exchange(
                r.onionAddress(),
                r.port(),
                Operation.DELIVER,
                "",
                o -> PacketCodec.write(o, p),
                Receipt::read);
        if (!ack.messageId().equals(p.messageId())
            || !MessageDigest.isEqual(ack.packetDigest(), Identity.digest(p))
            || ack.deliveredAt() < p.createdAt() - 300_000
            || ack.deliveredAt() > local.now() + 300_000
            || !Identity.verify(contact.publicKey(), ack.signingBytes(), ack.signature()))
          throw new IOException("Invalid peer ACK");
        return new DeliveryResult(Delivery.P2P_CONFIRMED, ack.deliveredAt());
      } catch (IOException ignored) {
        /* Same packet and ID used for fallback; lost ACK cannot reset recipient TTL. */
      }
    request(Operation.STORE, o -> PacketCodec.write(o, p), i -> null);
    return new DeliveryResult(Delivery.RELAY_QUEUED, 0);
  }

  public int fetchAndAcknowledge() throws IOException, GeneralSecurityException {
    int count = 0;
    for (int i = 0; i < 8; i++) {
      EncryptedPacket p =
          request(
              Operation.FETCH,
              o -> {},
              in -> in.readBoolean() ? PacketCodec.read(in, maxCiphertext) : null);
      if (p == null) break;
      Receipt ack = local.accept(p);
      request(Operation.ACK, ack::write, in -> null);
      count++;
    }
    return count;
  }

  public void logout() {
    if (token.isEmpty()) return;
    try {
      request(Operation.LOGOUT, o -> {}, i -> null);
    } catch (IOException ignored) {
    } finally {
      token = "";
    }
  }

  public void forgetSession() {
    token = "";
    capabilities=-1;
  }
  public int capabilities()throws IOException{
    if(capabilities<0){try{int value=request(Operation.CAPABILITIES,o->{},DataInputStream::readInt);if((value&~3)!=0||value<0)throw new IOException("Invalid capabilities");capabilities=value;}
      catch(RequestRejected oldRelay){if(oldRelay.code()!=1)throw oldRelay;capabilities=0;}}
    return capabilities;
  }
  public PublicProfile profile(String nickname)throws IOException{
    if((capabilities()&1)==0)return null;UserInfo owner=find(nickname);
    var value=request(Operation.PROFILE_GET,o->Binary.text(o,owner.nickname()),in->in.readBoolean()?PublicProfile.read(in):null);
    if(value!=null&&(!value.userId().equals(owner.userId())||!value.nickname().equals(owner.nickname())||!MessageDigest.isEqual(value.publicKey(),owner.publicKey())||!Identity.verify(owner.publicKey(),value.signingBytes(),value.signature())))throw new IOException("Invalid signed profile");return value;
  }
  public void publishProfile(PublicProfile profile)throws IOException{
    if((capabilities()&1)==0)throw new IOException("Этот сервер не поддерживает публичные профили");
    request(Operation.PROFILE_PUT,profile::write,in->null);
  }
  public record Relationship(ContactAssertion ours,ContactAssertion theirs){}
  public Relationship relationship(UserInfo peer)throws IOException{
    if((capabilities()&2)==0)return new Relationship(null,null);
    return request(Operation.CONTACT_GET,o->Binary.text(o,peer.userId()),in->new Relationship(in.readBoolean()?ContactAssertion.read(in):null,in.readBoolean()?ContactAssertion.read(in):null));
  }
  public void publishConsent(ContactAssertion assertion)throws IOException{
    if((capabilities()&2)==0)throw new IOException("Этот сервер не поддерживает дружбу");
    request(Operation.CONTACT_PUT,assertion::write,in->null);
  }

  private <T> T request(Operation op, Binary.Writer w, Reader<T> r) throws IOException {
    if (token.isEmpty()) throw new IOException("Сначала войдите в аккаунт");
    return exchange(relayOnion, relayPort, op, token, w, r);
  }

  private <T> T exchange(
      String onion, int port, Operation op, String session, Binary.Writer writer, Reader<T> reader)
      throws IOException {
    try (Socket socket = tor.connect(onion, port);
        var in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        var out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))) {
      Binary.header(out);
      out.writeByte(op.code);
      Binary.text(out, session);
      writer.write(out);
      out.flush();
      Binary.header(in);
      int status=in.readInt();
      if (status != 0)throw new RequestRejected(status);
      return reader.read(in);
    }
  }
}
