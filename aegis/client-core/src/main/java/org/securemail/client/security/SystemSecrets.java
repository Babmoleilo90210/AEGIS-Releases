package org.securemail.client.security;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import com.sun.jna.*;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.platform.win32.Crypt32Util;
import org.securemail.client.AppPaths;
import org.securemail.client.storage.AtomicFiles;

/** OS-protected random device secret only. No password is sent to OS storage. */
public interface SystemSecrets {
  void store(byte[] secret)throws IOException;
  byte[] load()throws IOException;
  void clear()throws IOException;
  static SystemSecrets current(Path profile)throws IOException {
    try{return AppPaths.windows()?new Dpapi(profile):new SecretService(profile);}catch(LinkageError e){throw new IOException("Защищённое хранилище системы недоступно",e);}
  }
  final class Dpapi implements SystemSecrets {
    private final Path file;
    public Dpapi(Path profile)throws IOException{Path dir=profile.resolve("session");AtomicFiles.directory(dir);file=dir.resolve("device.dpapi");}
    public void store(byte[] value)throws IOException {if(value.length!=32)throw new IOException("Invalid device secret");try{AtomicFiles.write(file,Crypt32Util.cryptProtectData(value));}catch(RuntimeException e){throw new IOException("DPAPI CurrentUser недоступен",e);}}
    public byte[] load()throws IOException {if(!Files.exists(file))return null;try{byte[] value=Crypt32Util.cryptUnprotectData(AtomicFiles.read(file,8192));if(value.length!=32){Arrays.fill(value,(byte)0);throw new IOException("Invalid DPAPI secret");}return value;}catch(RuntimeException e){throw new IOException("Не удалось открыть сохранённую сессию Windows",e);}}
    public void clear()throws IOException{Files.deleteIfExists(file);AtomicFiles.syncDirectory(file.getParent());}
  }
  final class SecretService implements SystemSecrets {
    private interface Secret extends Library {
      int secret_password_storev_sync(Pointer schema,Pointer attrs,String collection,String label,Pointer password,Pointer cancel,PointerByReference error);
      Pointer secret_password_lookupv_sync(Pointer schema,Pointer attrs,Pointer cancel,PointerByReference error);
      int secret_password_clearv_sync(Pointer schema,Pointer attrs,Pointer cancel,PointerByReference error);
      void secret_password_free(Pointer password);
    }
    private interface Glib extends Library {Pointer g_hash_table_new(Pointer hash,Pointer equal);int g_hash_table_insert(Pointer table,Pointer key,Pointer value);void g_hash_table_unref(Pointer table);void g_error_free(Pointer error);}
    private interface Gio extends Library {Pointer g_cancellable_new();void g_cancellable_cancel(Pointer cancel);}
    private interface GObject extends Library {void g_object_unref(Pointer object);}
    private final Secret secret=Native.load("secret-1",Secret.class);private final Glib glib=Native.load("glib-2.0",Glib.class);private final Gio gio=Native.load("gio-2.0",Gio.class);private final GObject objects=Native.load("gobject-2.0",GObject.class);
    private final String id;private final NativeLibrary glibFunctions=NativeLibrary.getInstance("glib-2.0");
    private static final ScheduledExecutorService timeout=Executors.newSingleThreadScheduledExecutor(r->{var t=new Thread(r,"aegis-secret-service-timeout");t.setDaemon(true);return t;});
    public SecretService(Path profile)throws IOException {try{id=HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(profile.toAbsolutePath().normalize().toString().getBytes(java.nio.charset.StandardCharsets.UTF_8)));}catch(java.security.GeneralSecurityException e){throw new IOException(e);}}
    private static Memory string(String text){byte[] b=text.getBytes(java.nio.charset.StandardCharsets.UTF_8);Memory m=new Memory(b.length+1);m.write(0,b,0,b.length);m.setByte(b.length,(byte)0);Arrays.fill(b,(byte)0);return m;}
    private <T>T call(Action<T> action)throws IOException {
      List<Memory> values=new ArrayList<>();Pointer attrs=glib.g_hash_table_new(glibFunctions.getFunction("g_str_hash"),glibFunctions.getFunction("g_str_equal")),cancel=gio.g_cancellable_new();Object guard=new Object();boolean[] active={true};
      ScheduledFuture<?> timer=timeout.schedule(()->{synchronized(guard){if(active[0])gio.g_cancellable_cancel(cancel);}},20,TimeUnit.SECONDS);
      PointerByReference error=new PointerByReference();
      try {
        for(String[] pair:new String[][]{{"application","AEGIS"},{"profile",id}}){Memory k=string(pair[0]),v=string(pair[1]);values.add(k);values.add(v);glib.g_hash_table_insert(attrs,k,v);}
        T result=action.run(attrs,cancel,error);if(error.getValue()!=null)throw new IOException("KWallet / Secret Service недоступен или заблокирован");return result;
      }catch(RuntimeException e){throw new IOException("Не удалось использовать защищённое хранилище системы",e);}
      finally{synchronized(guard){active[0]=false;timer.cancel(false);objects.g_object_unref(cancel);}if(error.getValue()!=null)glib.g_error_free(error.getValue());glib.g_hash_table_unref(attrs);values.forEach(Memory::close);}
    }
    public void store(byte[] value)throws IOException {
      if(value.length!=32)throw new IOException("Invalid device secret");Memory m=string(Base64.getEncoder().encodeToString(value));
      try{boolean accepted=call((attrs,cancel,error)->secret.secret_password_storev_sync(null,attrs,null,"AEGIS device session",m,cancel,error)!=0);if(!accepted)throw new IOException("Система не сохранила сессию");}finally{m.clear();m.close();}
    }
    public byte[] load()throws IOException {
      return call((attrs,cancel,error)->{Pointer p=secret.secret_password_lookupv_sync(null,attrs,cancel,error);if(p==null)return null;try{byte[] value=Base64.getDecoder().decode(p.getString(0));if(value.length!=32){Arrays.fill(value,(byte)0);throw new IOException("Invalid system secret");}return value;}finally{secret.secret_password_free(p);}});
    }
    public void clear()throws IOException{call((attrs,cancel,error)->{secret.secret_password_clearv_sync(null,attrs,cancel,error);return null;});}
    @FunctionalInterface private interface Action<T>{T run(Pointer attrs,Pointer cancel,PointerByReference error)throws IOException;}
  }
}
