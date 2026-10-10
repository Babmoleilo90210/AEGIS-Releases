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
  public record Snapshot(State state,long downloaded,long total,SignedManifest manifest,boolean announcement,String message,UpdateDiagnostic diagnostic){
    public Snapshot(State state,long downloaded,long total,SignedManifest manifest,boolean announcement,String message){this(state,downloaded,total,manifest,announcement,message,null);}
  }
  @FunctionalInterface public interface Progress{void accept(long downloaded,long total);}
  public interface Downloads{byte[] bytes(URI uri,int max)throws IOException;void file(SignedManifest.Asset asset,Path target,BooleanSupplier cancelled,Progress progress)throws IOException;default boolean resumable(){return false;}}
  @FunctionalInterface interface Verifier{SignedManifest verify(byte[] json,byte[] signature,String channel,String current,String highest)throws GeneralSecurityException,IOException;}
  private final Verifier verifier;private final UpdateEvents events;
  private final Downloads downloads;private final UpdateStateStore store;private final boolean windows;private final ExecutorService executor=Executors.newSingleThreadExecutor(r->{var t=new Thread(r,"aegis-updates");t.setDaemon(true);return t;});
  private final AtomicBoolean cancelled=new AtomicBoolean();private volatile Snapshot snapshot=new Snapshot(State.UP_TO_DATE,0,0,null,false,"Обновления ещё не проверялись");private volatile Consumer<Snapshot> listener=s->{};private volatile boolean working;
  private byte[] exact,signature;private Path artifact;private volatile String channel="stable";
  private final ScheduledExecutorService periodic=Executors.newSingleThreadScheduledExecutor(r->{var t=new Thread(r,"aegis-update-clock");t.setDaemon(true);return t;});
  private volatile BooleanSupplier automaticCheck=()->false,automaticDownload=()->false;
  public UpdateService(Path profile,int port)throws IOException{this(new TorHttpsClient(port),new UpdateStateStore(profile),AppPaths.windows());}
  UpdateService(Downloads downloads,UpdateStateStore store,boolean windows){this(downloads,store,windows,SignedManifest::verifyForCheck);}
  // Same-package test seam only. Production has no key, verifier or endpoint configuration.
  UpdateService(Downloads downloads,UpdateStateStore store,boolean windows,Verifier verifier){this.downloads=downloads;this.store=store;this.windows=windows;this.verifier=verifier;try{events=new UpdateEvents(store.root(),verifier);}catch(IOException e){throw new java.io.UncheckedIOException(e);}periodic.schedule(()->{try{events.migrateLegacy();events.reconcile();}catch(IOException ignored){}},0,TimeUnit.SECONDS);periodic.scheduleWithFixedDelay(()->{try{events.reconcile();}catch(IOException ignored){}},1,3,TimeUnit.SECONDS);periodic.scheduleWithFixedDelay(()->{if(automaticCheck.getAsBoolean())check(automaticDownload.getAsBoolean());},24,24,TimeUnit.HOURS);}
  public void automatic(BooleanSupplier enabled,BooleanSupplier download){automaticCheck=Objects.requireNonNull(enabled);automaticDownload=Objects.requireNonNull(download);}
  public Snapshot snapshot(){return snapshot;}public void listener(Consumer<Snapshot> value){listener=Objects.requireNonNull(value);}
  public void channel(String value){if(!Set.of("stable","beta").contains(value))throw new IllegalArgumentException("Invalid update channel");if(working)throw new IllegalStateException("Update in progress");channel=value;artifact=null;exact=null;signature=null;emit(State.UP_TO_DATE,0,0,null,false,"Обновления ещё не проверялись");}
  public synchronized void check(boolean autoDownload){if(working)return;working=true;cancelled.set(false);String selected=channel;executor.execute(()->{UpdateDiagnostic.Phase phase=UpdateDiagnostic.Phase.FETCH;try{
    artifact=null;exact=null;signature=null;
    emit(State.CHECKING,0,0,snapshot.manifest(),false,"Проверка обновлений…");URI base=URI.create("https://raw.githubusercontent.com/"+SignedManifest.REPOSITORY+"/main/updates/"+selected+".json");
    byte[] json=downloads.bytes(base,SignedManifest.MAX_BYTES),sig=downloads.bytes(URI.create(base.toString()+".sig"),64);
    phase=UpdateDiagnostic.Phase.VERIFY;SignedManifest manifest=verifier.verify(json,sig,selected,SignedManifest.CURRENT,"0.0.0");
    if(!manifest.newerThan(SignedManifest.CURRENT)){
      snapshot=new Snapshot(State.UP_TO_DATE,0,0,null,false,"Новых обновлений нет. Установлена АЕГИС "+SignedManifest.CURRENT,new UpdateDiagnostic(UpdateDiagnostic.Category.POLICY,manifest.version().equals(SignedManifest.CURRENT)?"FEED_CURRENT":"FEED_BEHIND_CLIENT",""));listener.accept(snapshot);return;
    }
    phase=UpdateDiagnostic.Phase.POLICY;manifest.requireInstallable(SignedManifest.CURRENT,store.highest(selected));
    phase=UpdateDiagnostic.Phase.STORE;boolean announcement=store.remember(manifest,json,sig);exact=json;signature=sig;events.record(manifest,UpdateEvents.Kind.AVAILABLE,selected,"");
    if(manifest.newerThan(SignedManifest.CURRENT)){emit(State.AVAILABLE,0,manifest.clientAsset(windows).size(),manifest,announcement,"Доступно обновление АЕГИС "+manifest.version());if(autoDownload){phase=UpdateDiagnostic.Phase.DOWNLOAD;downloadNow(manifest);}}
    else emit(State.UP_TO_DATE,0,0,manifest,false,"У вас последняя версия АЕГИС "+SignedManifest.CURRENT);
  }catch(Exception failure){failed(failure,phase,null);}finally{working=false;}});}
  public synchronized void download(){if(working||snapshot.manifest()==null||snapshot.state()!=State.AVAILABLE&&snapshot.state()!=State.FAILED)return;working=true;cancelled.set(false);SignedManifest manifest=snapshot.manifest();executor.execute(()->{try{downloadNow(manifest);}catch(Exception failure){failed(failure,UpdateDiagnostic.Phase.DOWNLOAD,manifest);}finally{working=false;}});}
  private void downloadNow(SignedManifest manifest)throws Exception {
    manifest.requireInstallable(SignedManifest.CURRENT,store.highest(channel));
    SignedManifest.Asset asset=manifest.clientAsset(windows);Path file=store.root().resolve("download-"+asset.sha256()+".part");
    if(!downloads.resumable())Files.deleteIfExists(file);
    try{
      emit(State.DOWNLOADING,Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)?Files.size(file):0,asset.size(),manifest,false,"Скачивание обновления");downloads.file(asset,file,cancelled::get,(n,total)->emit(State.DOWNLOADING,n,asset.size(),manifest,false,"Скачивание обновления"));
      if(cancelled.get())throw new InterruptedIOException("Update cancelled");events.record(manifest,UpdateEvents.Kind.DOWNLOADED,channel,"");emit(State.VERIFYING,asset.size(),asset.size(),manifest,false,"Проверка цифровой подписи и SHA-256…");verifier.verify(exact,signature,channel,SignedManifest.CURRENT,store.highest(channel));
      verifyFile(file,asset);PackageSanity.check(file,asset,manifest.version());artifact=file;events.record(manifest,UpdateEvents.Kind.VERIFIED,channel,"");emit(State.READY_TO_INSTALL,asset.size(),asset.size(),manifest,false,"Обновление готово к установке");
    }catch(Exception failure){boolean verifying=snapshot.state()==State.VERIFYING;if(!downloads.resumable()||failure instanceof GeneralSecurityException||!(failure instanceof IOException)||verifying)Files.deleteIfExists(file);if(verifying){failed(failure,UpdateDiagnostic.Phase.PACKAGE,manifest);return;}throw failure;}
  }
  public static void verifyFile(Path file,SignedManifest.Asset asset)throws IOException,GeneralSecurityException {
    if(Files.isSymbolicLink(file)||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)||Files.size(file)!=asset.size())throw new IOException("Update size mismatch");
    MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[65536];try(var in=Files.newInputStream(file)){int n;while((n=in.read(buffer))!=-1)digest.update(buffer,0,n);}byte[] hash=digest.digest();
    if(!MessageDigest.isEqual(hash,HexFormat.of().parseHex(asset.sha256())))throw new GeneralSecurityException("Update hash mismatch");
  }
  public Path prepareInstall(Path currentProgram,long clientPid,long launcherPid)throws Exception {
    if(working||snapshot.state()!=State.READY_TO_INSTALL||artifact==null)throw new IOException("Update is not ready");
    SignedManifest manifest=verifier.verify(exact,signature,channel,SignedManifest.CURRENT,store.highest(channel));manifest.requireInstallable(SignedManifest.CURRENT,store.highest(channel));verifyFile(artifact,manifest.clientAsset(windows));PackageSanity.check(artifact,manifest.clientAsset(windows),manifest.version());
    emit(State.INSTALLING,snapshot.downloaded(),snapshot.total(),manifest,false,"Подготовка установки…");
    try{return UpdateInstaller.prepare(store.root(),currentProgram,artifact,exact,signature,manifest,clientPid,launcherPid,windows);}catch(Exception failure){installFailed();throw failure;}
  }
  public void restarting(){emit(State.RESTARTING,0,0,snapshot.manifest(),false,"Перезапуск…");}
  public void installFailed(){try{events.record(snapshot.manifest(),UpdateEvents.Kind.FAILED,channel,"INSTALL_FAILED");}catch(IOException ignored){}emit(State.FAILED,0,0,snapshot.manifest(),false,"Обновление не установлено. Текущая версия сохранена.");}
  public void cancel(){cancelled.set(true);}
  public void announcementShown()throws IOException{if(snapshot.manifest()!=null)store.announcementShown(snapshot.manifest());}
  public void announcementShown(SignedManifest manifest)throws IOException{store.announcementShown(manifest);}
  public List<SignedManifest> history()throws IOException{return store.history(channel);}
  public List<UpdateEvents.Event> events()throws IOException{return events.history();}
  private void failed(Throwable failure,UpdateDiagnostic.Phase phase,SignedManifest manifest){
    UpdateDiagnostic d=cancelled.get()?new UpdateDiagnostic(UpdateDiagnostic.Category.CANCELLED,"CANCELLED",""):UpdateDiagnostic.failure(failure,phase);
    snapshot=new Snapshot(State.FAILED,0,0,manifest,false,d.userMessage(),d);listener.accept(snapshot);
    try{events.record(manifest,UpdateEvents.Kind.FAILED,channel,d.code());}catch(IOException ignored){}
    // Public technical events only. No stack trace, exception text, URLs, cookies or payload.
    try{Path log=store.root().resolve("diagnostic.log");byte[] old=Files.exists(log,LinkOption.NOFOLLOW_LINKS)?AtomicFiles.read(log,65536):new byte[0];byte[] line=(d.category()+" "+d.code()+" "+d.exceptionType()+"\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII);byte[] next=old.length+line.length>65536?line:Arrays.copyOf(old,old.length+line.length);if(next!=line)System.arraycopy(line,0,next,old.length,line.length);AtomicFiles.write(log,next);}catch(IOException ignored){/* Diagnostics cannot bypass verification or block normal mail. */}
  }
  private void emit(State state,long n,long total,SignedManifest manifest,boolean announce,String message){snapshot=new Snapshot(state,n,total,manifest,announce,message);listener.accept(snapshot);}
  public void close(){cancelled.set(true);executor.shutdownNow();periodic.shutdownNow();}
}
