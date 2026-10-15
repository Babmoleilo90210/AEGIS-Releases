package org.securemail.client.net;
import java.io.*;
import org.securemail.client.ClientConfig;
import org.securemail.protocol.*;
/** An unauthenticated FIND gets a bounded protocol-1 rejection, without creating an account. */
public final class RelayProbe {
  private RelayProbe(){}
  public static void check(ClientConfig c)throws IOException{
    try(var socket=new TorTransport(c.torSocksAddress(),c.torSocksPort()).connect(c.relayOnionAddress(),c.relayPort());var in=new DataInputStream(socket.getInputStream());var out=new DataOutputStream(socket.getOutputStream())){
      Binary.header(out);out.writeByte(Operation.FIND.code);Binary.text(out,"");Binary.text(out,"aegis_probe");out.flush();Binary.header(in);int status=in.readInt();if(status==0)throw new IOException("Неверный ответ сервера");
    }
  }
}
