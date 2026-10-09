package org.securemail.client.update;

import java.io.*;
import java.net.URI;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.*;
import org.securemail.client.AppPaths;
import org.securemail.client.storage.AtomicFiles;

/** One serial state machine. A valid signature gates all policies, letters and downloads. */
public final class UpdateService implements AutoCloseable {
  public enum State{CHECKING,AVAILABLE,DOWNLOADING,VERIFYING,READY_TO_INSTALL,INSTALLING,RESTARTING,UP_TO_DATE,FAILED}
  public record Snapshot(State state,long downloaded,long total,SignedManifest manifest,boolean announcement,String message){}
  @FunctionalInterface public interface Progress{void accept(long downloaded,long total);}
  public interface Downloads{byte[] bytes(URI uri,int max)throws IOException;void file(SignedManifest.Asset asset,Path target,BooleanSupplier cancelled,Progress progress)throws IOException;default boolean resumable(){return false;}}
  @FunctionalInterface interface Verifier{SignedManifest verify(byte[] json,byte[] signature,String channel,String current,String highest)throws GeneralSecurityException,IOException;}
  private final Verifier verifier;
  private final Downloads downloads;private final UpdateStateStore store;private final boolean windows;private final ExecutorService executor=Executors.newSingleThreadExecutor(r->{var t=new Thread(r,"aegis-updates");t.setDaemon(true);return t;});
  private final AtomicBoolean cancelled=new AtomicBoolean();private volatile Snapshot snapshot=new Snapshot(State.UP_TO_DATE,0,0,null,false,"Обновления ещё не проверялись");private volatile Consumer<Snapshot> listener=s->{};private volatile boolean working;
  private byte[] exact,signature;private Path artifact;private volatile String channel="stable";
  private final ScheduledExecutorService periodic=Executors.newSingleThreadScheduledExecutor(r->{var t=new Thread(r,"aegis-update-clock");t.setDaemon(true);return t;});
  private volatile BooleanSupplier automaticCheck=()->false,automaticDownload=()->false;
  public UpdateService(Path profile,int port)throws IOException{this(new TorHttpsClient(port),new UpdateStateStore(profile),AppPaths.windows());}
  UpdateService(Downloads downloads,UpdateStateStore store,boolean windows){this(downloads,store,windows,SignedManifest::verify);}
  // Same-package test seam only. Production has no key, verifier or endpoint configuration.
  UpdateService(Downloads downloads,UpdateStateStore store,boolean windows,Verifier verifier){this.downloads=downloads;this.store=store;this.windows=windows;this.verifier=verifier;periodic.scheduleWithFixedDelay(()->{if(automaticCheck.getAsBoolean())check(automaticDownload.getAsBoolean());},24,24,TimeUnit.HOURS);}
  public void automatic(BooleanSupplier enabled,BooleanSupplier download){automaticCheck=Objects.requireNonNull(enabled);automaticDownload=Objects.requireNonNull(download);}
  public Snapshot snapshot(){return snapshot;}public void listener(Consumer<Snapshot> value){listener=Objects.requireNonNull(value);}
  public void channel(String value){if(!Set.of("stable","beta").contains(value))throw new IllegalArgumentException("Invalid update channel");if(working)throw new IllegalStateException("Update in progress");channel=value;artifact=null;exact=null;signature=null;emit(State.UP_TO_DATE,0,0,null,false,"Обновления ещё не проверялись");}
  public synchronized void check(boolean autoDownload){if(working)return;working=true;cancelled.set(false);String selected=channel;executor.execute(()->{try{
    emit(State.CHECKING,0,0,snapshot.manifest(),false,"Проверка обновлений…");URI base=URI.create("https://raw.githubusercontent.com/"+SignedManifest.REPOSITORY+"/main/updates/"+selected+".json");
    byte[] json=downloads.bytes(base,SignedManifest.MAX_BYTES),sig=downloads.bytes(URI.create(base.toString()+".sig"),64);
    SignedManifest manifest=verifier.verify(json,sig,selected,SignedManifest.CURRENT,store.highest(selected));boolean announcement=store.remember(manifest,json,sig);exact=json;signature=sig;
    if(manifest.newerThan(SignedManifest.CURRENT)){emit(State.AVAILABLE,0,manifest.clientAsset(windows).size(),manifest,announcement,"Доступно обновление АЕГИС "+manifest.version());if(autoDownload)downloadNow(manifest);}
    else emit(State.UP_TO_DATE,0,0,manifest,false,"У вас последняя версия АЕГИС "+SignedManifest.CURRENT);
  }catch(Exception failure){emit(State.FAILED,0,0,null,false,failure instanceof GeneralSecurityException?"Цифровая подпись обновления отклонена":"Не удалось проверить обновления через Tor");}finally{working=false;}});}
  public synchronized void download(){if(working||snapshot.manifest()==null)return;working=true;cancelled.set(false);SignedManifest manifest=snapshot.manifest();executor.execute(()->{try{downloadNow(manifest);}catch(Exception failure){emit(State.FAILED,0,0,manifest,false,cancelled.get()?"Скачивание отменено":"Не удалось скачать и проверить обновление");}finally{working=false;}});}
  private void downloadNow(SignedManifest manifest)throws Exception {
    SignedManifest.Asset asset=manifest.clientAsset(windows);Path file=store.root().resolve("download-"+asset.sha256()+".part");
    if(!downloads.resumable())Files.deleteIfExists(file);
    try{
      emit(State.DOWNLOADING,Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)?Files.size(file):0,asset.size(),manifest,false,"Скачивание обновления");downloads.file(asset,file,cancelled::get,(n,total)->emit(State.DOWNLOADING,n,asset.size(),manifest,false,"Скачивание обновления"));
      if(cancelled.get())throw new InterruptedIOException("Update cancelled");emit(State.VERIFYING,asset.size(),asset.size(),manifest,false,"Проверка цифровой подписи и SHA-256…");verifier.verify(exact,signature,channel,SignedManifest.CURRENT,store.highest(channel));
      verifyFile(file,asset);PackageSanity.check(file,asset,manifest.version());artifact=file;emit(State.READY_TO_INSTALL,asset.size(),asset.size(),manifest,false,"Обновление готово к установке");
    }catch(Exception failure){if(!downloads.resumable()||failure instanceof GeneralSecurityException||!(failure instanceof IOException)||snapshot.state()==State.VERIFYING)Files.deleteIfExists(file);throw failure;}
  }
  public static void verifyFile(Path file,SignedManifest.Asset asset)throws IOException,GeneralSecurityException {
    if(Files.isSymbolicLink(file)||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)||Files.size(file)!=asset.size())throw new IOException("Update size mismatch");
    MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[65536];try(var in=Files.newInputStream(file)){int n;while((n=in.read(buffer))!=-1)digest.update(buffer,0,n);}byte[] hash=digest.digest();
    if(!MessageDigest.isEqual(hash,HexFormat.of().parseHex(asset.sha256())))throw new GeneralSecurityException("Update hash mismatch");
  }
  public Path prepareInstall(Path currentProgram,long clientPid,long launcherPid)throws Exception {
    if(working||snapshot.state()!=State.READY_TO_INSTALL||artifact==null)throw new IOException("Update is not ready");
    SignedManifest manifest=verifier.verify(exact,signature,channel,SignedManifest.CURRENT,store.highest(channel));verifyFile(artifact,manifest.clientAsset(windows));PackageSanity.check(artifact,manifest.clientAsset(windows),manifest.version());
    emit(State.INSTALLING,snapshot.downloaded(),snapshot.total(),manifest,false,"Подготовка установки…");
    try{return UpdateInstaller.prepare(store.root(),currentProgram,artifact,exact,signature,manifest,clientPid,launcherPid,windows);}catch(Exception failure){installFailed();throw failure;}
  }
  public void restarting(){emit(State.RESTARTING,0,0,snapshot.manifest(),false,"Перезапуск…");}
  public void installFailed(){emit(State.FAILED,0,0,snapshot.manifest(),false,"Обновление не установлено. Текущая версия сохранена.");}
  public void cancel(){cancelled.set(true);}
  public void announcementShown()throws IOException{if(snapshot.manifest()!=null)store.announcementShown(snapshot.manifest());}
  public void announcementShown(SignedManifest manifest)throws IOException{store.announcementShown(manifest);}
  public List<SignedManifest> history()throws IOException{return store.history(channel);}
  private void emit(State state,long n,long total,SignedManifest manifest,boolean announce,String message){snapshot=new Snapshot(state,n,total,manifest,announce,message);listener.accept(snapshot);}
  public void close(){cancelled.set(true);executor.shutdownNow();periodic.shutdownNow();}
}
