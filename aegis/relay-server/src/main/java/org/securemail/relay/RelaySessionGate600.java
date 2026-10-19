package org.securemail.relay;

import java.io.*;
import org.securemail.protocol.UserInfo;

/** Optional, explicitly configured staging gate. The unchanged legacy constructor does not enable it. */
public interface RelaySessionGate600 extends AutoCloseable {
  record Binding(String capability){public Binding{if(capability==null||capability.length()>4096)throw new IllegalArgumentException("Допуск Почты");}@Override public String toString(){return "MailBinding[redacted]";}}
  Binding authenticate(UserInfo user,String nickname,byte[] passwordUtf8,DataInputStream proof)throws IOException;
  default Binding register(UserInfo user,String nickname,byte[] passwordUtf8,DataInputStream proof)throws IOException {throw new IOException("Регистрация Identity6 не поддерживается");}
  default void checkFresh(UserInfo user,Binding binding)throws IOException {check(user,binding);}
  default void authorizeOperation(UserInfo user,Binding binding,org.securemail.protocol.Operation operation)throws IOException {check(user,binding);}
  void check(UserInfo user,Binding binding)throws IOException;
  @Override void close();
}
