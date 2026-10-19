package org.securemail.ui;

import com.google.gson.*;
import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import javafx.application.Platform;
import javafx.geometry.Bounds;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import org.securemail.client.*;
import org.securemail.client.appearance.Appearance;
import org.securemail.client.ecosystem.*;
import org.securemail.client.ecosystemauth.*;
import org.securemail.client.net.*;
import org.securemail.community.access.AccessControl;
import org.securemail.community.agent.AgentService;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.CommunityStore;
import org.securemail.community.gateway600.*;
import org.securemail.community.org.OrgAdminService;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.identity.*;
import org.securemail.ui.ecosystem.DesktopLockBinding;

/** Actual CoreApp600 JavaFX/Monocle UI. Tor, OS-lock and local SOCKS routing are explicit test fixtures.
 * Signed Identity/Community HTTP and SQL are real. This is not native desktop/Tor/process-isolation acceptance. */
public final class CoreSmoke600 {
  private static final String IDENTITY="a".repeat(56)+".onion",COMMUNITY="b".repeat(56)+".onion";
  private static final char[] PASSWORD="Тестовый пароль только ключа устройства 600!".toCharArray();
  private static final List<Map<String,Object>> screenshots=new ArrayList<>();
  private static final List<String> checks=new ArrayList<>();
  private static int fixedWidth,fixedHeight;
  private CoreSmoke600(){}
  private static <T>T fx(Callable<T> task)throws Exception {var answer=new CompletableFuture<T>();Platform.runLater(()->{try{answer.complete(task.call());}catch(Throwable failed){answer.completeExceptionally(failed);}});return answer.get(30,TimeUnit.SECONDS);}
  private static Object field(Object target,String name)throws Exception {Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);}
  private static void field(Object target,String name,Object value)throws Exception {Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);f.set(target,value);}
  private static Object call(CoreApp600 app,String name,Class<?>[] types,Object...arguments)throws Exception {Method method=CoreApp600.class.getDeclaredMethod(name,types);method.setAccessible(true);try{return method.invoke(app,arguments);}catch(InvocationTargetException e){Throwable cause=e.getCause();if(cause instanceof Exception failure)throw failure;if(cause instanceof Error failure)throw failure;throw e;}}
  private static Object call(CoreApp600 app,String name)throws Exception{return call(app,name,new Class<?>[0]);}
  private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
  private static void waitFor(BooleanSupplier ready,String description)throws Exception {long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(20);while(!ready.getAsBoolean()){if(System.nanoTime()>=until)throw new AssertionError("Timed out: "+description);Thread.sleep(10);}}
  private static void flush(CoreApp600 app)throws Exception {ThreadPoolExecutor worker=(ThreadPoolExecutor)field(app,"worker");worker.submit(()->{}).get(20,TimeUnit.SECONDS);fx(()->null);fx(()->null);}
  private static List<Node> nodes(Node root){List<Node> all=new ArrayList<>();all.add(root);if(root instanceof Parent parent)for(Node child:parent.getChildrenUnmodifiable())all.addAll(nodes(child));return all;}
  private static boolean text(Stage stage,String value){Parent root=stage.getScene().getRoot();root.applyCss();root.layout();return nodes(root).stream().anyMatch(n->n instanceof Labeled label&&label.getText().equals(value));}
  private static Appearance.Settings scale(Appearance.Settings s,int scale){return new Appearance.Settings(s.theme(),s.mode(),s.lightTheme(),s.darkTheme(),s.lightAt(),s.darkAt(),scale,s.density(),s.typography(),s.components(),s.layout(),s.backdrop());}
  private static void matrix(CoreApp600 app,Stage stage,Path output,String page)throws Exception {
    ThemeManager themes=(ThemeManager)field(app,"themes");
    List<int[]> sizes=fixedWidth>0?List.of(new int[]{fixedWidth,fixedHeight}):List.of(new int[]{800,600},new int[]{1024,768},new int[]{1920,1080});
    for(String theme:List.of("minimal-dark","minimal-light"))for(int scale:List.of(100,125,150,200))for(int[] size:sizes){
      fx(()->{themes.preview(scale(themes.settings().manual(theme),scale));stage.setWidth(size[0]);stage.setHeight(size[1]);return null;});Thread.sleep(120);fx(()->null);
      fx(()->{capture(stage,output,page,theme,scale,size[0],size[1]);return null;});
    }
  }
  private static void capture(Stage stage,Path output,String page,String theme,int scale,int width,int height)throws Exception {
    Parent root=stage.getScene().getRoot();root.applyCss();root.layout();List<String> overlaps=new ArrayList<>();int buttons=0;
    for(Node node:nodes(root)){
      if(node instanceof Button button&&button.isVisible()&&button.isManaged()){buttons++;check(button.getWidth()>0&&button.getHeight()>0,"Zero-size button: "+button.getText());}
      if(node instanceof HBox||node instanceof VBox||node instanceof FlowPane){List<Node> children=((Parent)node).getChildrenUnmodifiable().stream().filter(n->n instanceof Control&&n.isManaged()&&n.isVisible()).toList();
        for(int i=0;i<children.size();i++)for(int j=i+1;j<children.size();j++){Bounds a=children.get(i).getBoundsInParent(),b=children.get(j).getBoundsInParent();double x=Math.min(a.getMaxX(),b.getMaxX())-Math.max(a.getMinX(),b.getMinX()),y=Math.min(a.getMaxY(),b.getMaxY())-Math.max(a.getMinY(),b.getMinY());if(x>1&&y>1)overlaps.add(children.get(i).getClass().getSimpleName()+"/"+children.get(j).getClass().getSimpleName()+" "+Math.round(x)+"x"+Math.round(y));}
      }
    }
    String filename=page+"-"+theme+"-"+scale+"-"+width+"x"+height+".png";var image=stage.getScene().snapshot(null);var pixels=image.getPixelReader();var png=new java.awt.image.BufferedImage((int)image.getWidth(),(int)image.getHeight(),java.awt.image.BufferedImage.TYPE_INT_ARGB);for(int y=0;y<png.getHeight();y++)for(int x=0;x<png.getWidth();x++)png.setRGB(x,y,pixels.getArgb(x,y));javax.imageio.ImageIO.write(png,"png",output.resolve(filename).toFile());
    screenshots.add(Map.of("file",filename,"page",page,"theme",theme,"scalePercent",scale,"requestedWidth",width,"requestedHeight",height,"sceneWidth",png.getWidth(),"sceneHeight",png.getHeight(),"buttons",buttons,"overlaps",overlaps));check(overlaps.isEmpty(),"Sibling controls overlap in "+filename+": "+overlaps);
  }
  private static void noMailVault(Path profile)throws Exception {try(var files=Files.walk(profile)){check(files.noneMatch(p->Set.of("state.vault","vault-kdf","mail","sent").contains(p.getFileName().toString())),"Core created Mail storage/root identity");}}
  private static ComponentInstallation installation()throws Exception {
    var classpath=new LinkedHashMap<Path,String>();for(Class<?> type:List.of(CoreApp600.class,CoreAccountSession600.class,IdentityProtocol.class)){Path jar=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());check(Files.isRegularFile(jar)&&jar.toString().endsWith(".jar"),"Smoke requires actual current JARs for inventory: "+jar);classpath.put(jar,ComponentInstallation.sha256(jar));}
    Path java=Path.of(System.getProperty("java.home"),"bin","java");return new ComponentInstallation(java,ComponentInstallation.sha256(java),classpath);
  }
  private static void substituteOsObservation(CoreApp600 app,Stage stage)throws Exception {
    // Only the smoke harness replaces the unavailable native backend, in the same FX turn as authenticated().
    AutoCloseable old=(AutoCloseable)field(app,"osLock");if(old!=null)old.close();AutoCloseable binding=(AutoCloseable)field(app,"lockBinding");if(binding!=null)binding.close();
    IdleLockGuard guard=new IdleLockGuard(reason->{try{call(app,"lock");}catch(Exception failed){throw new IllegalStateException(failed);}});field(app,"idle",guard);field(app,"lockBinding",new DesktopLockBinding(stage.getScene(),guard));field(app,"osLock",(AutoCloseable)()->{});
  }
  private static List<Object> ownerPages(CoreApp600 app,Stage stage,Path out)throws Exception {
    return fx(()->{call(app,"ownerAdministration");Object owner=field(app,"ownerAdministration"),setup=field(app,"authoritySetup");check(owner!=null&&setup!=null,"Actual authority pages absent");
      for(TextInputControl input:inputControls(owner))input.setText("PUBLIC OWNER CHALLENGE FIXTURE");
      for(TextInputControl input:inputControls(setup))input.setText("PUBLIC BOOTSTRAP CHALLENGE FIXTURE");
      stage.getScene().getRoot().applyCss();stage.getScene().getRoot().layout();
      check(stage.getScene().getRoot().lookup("#core600-authority-setup")!=null,"Actual authority setup was not attached to Core");
      capture(stage,out,"authority-public-challenges","minimal-light",200,(int)Math.round(stage.getWidth()),(int)Math.round(stage.getHeight()));return List.of(owner,setup);
    });
  }
  private static List<TextInputControl> inputControls(Object page)throws Exception {List<TextInputControl> inputs=new ArrayList<>();for(Field declared:page.getClass().getDeclaredFields())if(TextInputControl.class.isAssignableFrom(declared.getType())){declared.setAccessible(true);inputs.add((TextInputControl)declared.get(page));}check(!inputs.isEmpty(),"Authority view has no text input fixtures");return inputs;}
  private static void ownerPagesCleared(List<Object> pages)throws Exception {
    fx(()->{for(Object page:pages){check(Boolean.TRUE.equals(field(page,"closed")),"Authority page remained open after Core lock");for(TextInputControl input:inputControls(page))check(input.getText().isEmpty(),"Core lock retained a public authority challenge");}return null;});checks.add("Actual Core authority/bootstrap pages render and clear all public challenge inputs after lock (no Mail signing claimed)");
  }
  private static boolean kernelLockAvailable(Path file){try(var channel=java.nio.channels.FileChannel.open(file,StandardOpenOption.WRITE);var acquired=channel.tryLock()){return acquired!=null;}catch(IOException|java.nio.channels.OverlappingFileLockException busy){return false;}}
  private static PasswordField recoveryPage(CoreApp600 app,Stage stage,Path out)throws Exception {
    return fx(()->{call(app,"deviceRecovery");check(text(stage,"Восстановление устройства"),"Actual device recovery page absent");
      var controls=nodes(stage.getScene().getRoot());Button recover=(Button)controls.stream().filter(n->n instanceof Button button&&button.getText().equals("Проверить набор и восстановить через Почту")).findFirst().orElseThrow();
      CheckBox consent=(CheckBox)controls.stream().filter(n->n instanceof CheckBox).findFirst().orElseThrow();check(recover.isDisabled(),"Recovery did not require explicit revocation consent");consent.setSelected(true);check(!recover.isDisabled(),"Explicit recovery consent was ignored");
      PasswordField password=(PasswordField)controls.stream().filter(n->n instanceof PasswordField).findFirst().orElseThrow();password.setText("PUBLIC SYNTHETIC RECOVERY PASSWORD");
      capture(stage,out,"device-recovery","minimal-light",200,(int)Math.round(stage.getWidth()),(int)Math.round(stage.getHeight()));return password;
    });
  }
  private static void stalledConsentCannotSurviveLock(CoreApp600 app,Stage stage,Path out,CoreAccountSession600 session)throws Exception {
    String fixture=System.getProperty("aegis.core600.consentFixtureJar");check(fixture!=null,"Pass the separate JDK-only consent fixture JAR");Path jar=Path.of(fixture);ComponentInstallation normal=installation();var cp=new LinkedHashMap<Path,String>();cp.put(jar,ComponentInstallation.sha256(jar));normal.classpath().forEach((path,hash)->{if(!path.getFileName().toString().startsWith("client-ui-"))cp.put(path,hash);});
    var install=new ComponentInstallation(normal.javaExecutable(),normal.javaSha256(),cp);var consent=new MailPairingBroker600(install,(CorePublicConfig600)field(app,"config"));Path receipt=AppPaths.root().resolve("core600/smoke-consent");
    // A second real child must supply its own heartbeat/shutdown evidence, never reuse the first receipt.
    if(Files.exists(receipt))try(var old=Files.walk(receipt)){for(Path path:old.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}
    var pending=consent.beginRegistration(pair().getPublic().getEncoded());
    try{
      waitFor(()->Files.exists(receipt.resolve("heartbeat")),"actual owned consent child READY and heartbeat");Process child=(Process)field(consent,"active");check(child!=null&&child.isAlive(),"Consent child is not actually alive");check(child.pid()!=ProcessHandle.current().pid(),"Consent child shares Core JVM");check(!kernelLockAvailable(receipt.resolve("started.lock")),"Actual child did not retain kernel lock");var exited=child.onExit();AtomicBoolean restored=new AtomicBoolean();
      fx(()->{field(app,"pairing",consent);call(app,"work",new Class<?>[]{Callable.class,Consumer.class},(Callable<Object>)()->pending.get(20,TimeUnit.SECONDS),(Consumer<Object>)value->{restored.set(true);((BorderPane)uncheckedField(app,"root")).setCenter(new Label("STALE CONSENT PAGE"));});return null;});
      long millis=fx(()->{long before=System.nanoTime();call(app,"lock");return TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-before);});check(millis<750,"Core lock blocked FX for owned child shutdown: "+millis+" ms");
      check(fx(()->field(app,"pairing")==null),"Core did not detach pairing immediately");check(session==null||session.locked(),"Core session did not lock");
      check(exited.get(8,TimeUnit.SECONDS)==child&&!child.isAlive(),"Actual owned consent child did not exit");check(Files.exists(receipt.resolve("shutdown")),"Actual child did not receive authenticated SHUTDOWN");check(kernelLockAvailable(receipt.resolve("started.lock")),"Owned child retained kernel lock after shutdown");
      try{pending.get(2,TimeUnit.SECONDS);throw new AssertionError("Cancelled consent produced a usable result");}catch(ExecutionException expected){check(expected.getCause() instanceof IOException,"Consent failure was not a safe I/O cancellation");}
      waitFor(()->((Map<?,?>)uncheckedField(app,"closingConsents")).isEmpty(),"tracked consent cleanup receipt");flush(app);fx(()->{check(!restored.get()&&!text(stage,"STALE CONSENT PAGE"),"Stale consent restored private UI");check(((BorderPane)field(app,"root")).getLeft()==null,"Locked Core retained navigation");capture(stage,out,session==null?"locked-prelogin-consent":"locked-owned-consent","minimal-light",200,(int)Math.round(stage.getWidth()),(int)Math.round(stage.getHeight()));return null;});
      checks.add("Real separate-JVM public consent fixture: anonymous pipe + MAC READY/HEARTBEAT/PONG, Core.lock returned in "+millis+" ms, authenticated SHUTDOWN, actual Process.onExit/kernel lock release, cancelled Future and no late UI restoration");
    }finally{consent.close();}
  }
  private static void queuedResponseCannotRestorePage(CoreApp600 app,Stage stage,Path out)throws Exception {
    flush(app);AtomicBoolean applied=new AtomicBoolean();CoreAccountSession600 session=(CoreAccountSession600)field(app,"session");ThreadPoolExecutor worker=(ThreadPoolExecutor)field(app,"worker");AtomicBoolean fetched=new AtomicBoolean();
    fx(()->{
      Callable<JsonObject> response=()->{JsonObject value=session.profile();fetched.set(true);return value;};Consumer<JsonObject> stale=value->{applied.set(true);((BorderPane)uncheckedField(app,"root")).setCenter(new Label("STALE PRIVATE ACCOUNT PAGE"));};
      call(app,"work",new Class<?>[]{Callable.class,Consumer.class},response,stale);
      // Deliberately hold this test FX turn until the actual signed response is queued, then lock first.
      long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);while(!fetched.get()||worker.getActiveCount()!=0||!worker.getQueue().isEmpty()){if(System.nanoTime()>=until)throw new AssertionError("Signed profile response did not queue");Thread.sleep(5);}
      call(app,"lock");check(session.locked(),"Core session was not locked");return null;
    });fx(()->null);fx(()->{check(!applied.get(),"A queued private response bypassed Core uiEpoch lock");check(!text(stage,"STALE PRIVATE ACCOUNT PAGE"),"Private page returned after lock");check(((BorderPane)field(app,"root")).getLeft()==null,"Locked Core retained private navigation");capture(stage,out,"locked-stale-response","minimal-light",200,(int)Math.round(stage.getWidth()),(int)Math.round(stage.getHeight()));return null;});checks.add("Actual signed Identity profile response queued before lock cannot restore private page afterward");
  }
  private static Object uncheckedField(Object target,String name){try{return field(target,name);}catch(Exception failed){throw new IllegalStateException(failed);}}

  public static void main(String[] arguments)throws Exception {
    Path out=Path.of(arguments.length==0?"build/core600-smoke":arguments[0]).toAbsolutePath();if(arguments.length==3){fixedWidth=Integer.parseInt(arguments[1]);fixedHeight=Integer.parseInt(arguments[2]);check(fixedWidth>=800&&fixedWidth<=1920&&fixedHeight>=600&&fixedHeight<=1080,"Unsupported smoke geometry");}else check(arguments.length<=1,"Pass output only, or output width height");Files.createDirectories(out);Path test=Files.createTempDirectory("aegis-core600-smoke-"),profile=test.resolve("core-profile");System.setProperty("aegis.profile",profile.toString());
    var started=new CompletableFuture<Void>();Platform.startup(()->{Platform.setImplicitExit(false);started.complete(null);});started.get(10,TimeUnit.SECONDS);CoreApp600 app=fx(CoreApp600::new);Stage stage=fx(()->{Stage window=new Stage();if(fixedWidth>0){window.setWidth(fixedWidth);window.setHeight(fixedHeight);}app.start(window);return window;});
    String result="FAIL";Fixture fixture=null;
    try{
      flush(app);fx(()->{check(text(stage,"Доверенный сервер"),"Actual unconfigured Core did not show operator configuration");return null;});matrix(app,stage,out,"configuration");
      fx(()->{call(app,"showLogin");return null;});matrix(app,stage,out,"login");noMailVault(profile);checks.add("Actual CoreApp600.start unconfigured configuration/login, without Mail vault");
      fixture=new Fixture(test.resolve("servers"));fixture.prepareDeviceVault((DeviceCredentialStore600)field(app,"credentials"));Fixture service=fixture;
      TorConnection tor=new TorConnection(()->new TorConnection.Attempt(){private boolean ready;public void start(EmbeddedTor.Mode mode,Duration timeout,IntConsumer progress){ready=true;progress.accept(100);}public boolean ready(){return ready;}public void close(){ready=false;}});tor.start(Duration.ofSeconds(1),Duration.ofSeconds(1),(m,n)->{});
      fx(()->{field(app,"config",new CorePublicConfig600(IDENTITY,80,service.service.getPublic().getEncoded(),service.socks.port()));field(app,"tor",tor);field(app,"transport",service.transport);field(app,"identity",service.client);field(app,"installation",installation());return null;});
      PasswordField recoveryPassword=recoveryPage(app,stage,out);stalledConsentCannotSurviveLock(app,stage,out,null);
      fx(()->{check(recoveryPassword.getText().isEmpty(),"Lock retained a detached recovery password field");check(!text(stage,"Восстановление устройства"),"Lock retained recovery page");return null;});checks.add("Pre-login Core lock cancels an actual owned consent child and clears detached recovery password controls");
      check(Boolean.TRUE.equals(call(app,"openExisting",new Class<?>[]{char[].class,long.class},PASSWORD.clone(),((AtomicLong)field(app,"uiEpoch")).get())),"Actual Core device-vault login failed");
      fx(()->{call(app,"authenticated");substituteOsObservation(app,stage);return null;});flush(app);noMailVault(profile);
      fx(()->{check(text(stage,"Приложения АЕГИС"),"Actual Core launcher was not installed");check(text(stage,"Испытатель Core 600"),"Signed remote profile nickname did not reach Core");check(!((CoreAccountSession600)field(app,"session")).locked(),"Explicit OS fixture did not hold the UI session");return null;});matrix(app,stage,out,"applications");
      fx(()->{call(app,"settings");return null;});matrix(app,stage,out,"settings");checks.add("Actual encrypted device vault unlock, signed Identity HTTP login/profile through bounded local SOCKS fixture");
      service.writeCommunityConfig(profile);fx(()->{call(app,"showCommunity",new Class<?>[]{boolean.class},false);return null;});service.awaitCommunity(app);fx(()->{check(stage.getScene().getRoot().lookup("#organizations-page")!=null,"Actual organization page absent");capture(stage,out,"organizations-http","minimal-light",200,(int)Math.round(stage.getWidth()),(int)Math.round(stage.getHeight()));return null;});
      fx(()->{call(app,"showCommunity",new Class<?>[]{boolean.class},true);return null;});service.awaitCommunity(app);fx(()->{check(stage.getScene().getRoot().lookup("#news-page")!=null,"Actual news page absent");capture(stage,out,"news-http","minimal-light",200,(int)Math.round(stage.getWidth()),(int)Math.round(stage.getHeight()));return null;});checks.add("Actual Community Gateway/Identity authorization/SQLite read responses rendered through local SOCKS fixture");
      List<Object> pages=ownerPages(app,stage,out);CoreAccountSession600 active=(CoreAccountSession600)field(app,"session");
      stalledConsentCannotSurviveLock(app,stage,out,active);ownerPagesCleared(pages);
      // The signed-response race also runs after an actual consent cancellation, while still locked.
      // Re-open the same device session solely through the ordinary authenticated login path.
      check(Boolean.TRUE.equals(call(app,"openExisting",new Class<?>[]{char[].class,long.class},PASSWORD.clone(),((AtomicLong)field(app,"uiEpoch")).get())),"Reauthentication after consent cancellation failed");
      fx(()->{call(app,"authenticated");substituteOsObservation(app,stage);return null;});flush(app);
      queuedResponseCannotRestorePage(app,stage,out);noMailVault(profile);result="PASS";
    }finally{
      Map<String,Object> report=new LinkedHashMap<>();report.put("result",result);report.put("scope","Actual JavaFX Monocle Core window + signed local Identity/Community HTTP/SQLite + SOCKS fixture; Tor readiness and OS lock observation are explicit harness-only fixtures. Native Windows/CachyOS, public Tor, audio and separate-process memory isolation NOT_RUN.");report.put("checks",checks);report.put("screenshots",screenshots);report.put("runtimeHashes",runtimeHashes());if(fixture!=null)report.put("socksOnionDestinations",List.copyOf(fixture.socks.destinations));Files.writeString(out.resolve("RESULT.json"),new GsonBuilder().setPrettyPrinting().create().toJson(report)+"\n");
      try{fx(()->{app.stop();return null;});}catch(Exception ignored){}if(fixture!=null)fixture.close();Platform.exit();Arrays.fill(PASSWORD,'\0');
    }
    System.out.println("PASS: actual Core window matrix, signed HTTP device login, no Mail vault, queued private response rejected after lock. Native/Tor NOT_RUN.");
  }
  private static Map<String,String> runtimeHashes()throws Exception {Map<String,String> result=new TreeMap<>();for(Class<?> type:List.of(CoreApp600.class,CoreSmoke600.class,CoreAccountSession600.class)){try(InputStream in=type.getResourceAsStream(type.getSimpleName()+".class")){result.put(type.getName(),HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Objects.requireNonNull(in).readAllBytes())));}}return result;}

  private static final class Fixture implements AutoCloseable {
    final KeyPair root=pair(),device=pair(),recovery=pair(),service=pair(),communityKey=pair();final IdentityStore identity;final IdentityHttpServer identityHttp;final Socks socks;final TorTransport transport;final IdentityClient600 client;
    final CommunityStore community;final AccessControl access;final AgentService agent;final CommunityIdentityBridge600 bridge;final CommunityHttpGateway600 gateway;
    Fixture(Path home)throws Exception {
      Files.createDirectories(home);Files.setPosixFilePermissions(home,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));identity=new IdentityStore(home.resolve("identity.db"),service,new byte[32],Clock.systemUTC());identityHttp=new IdentityHttpServer(new InetSocketAddress("127.0.0.1",0),identity,service);identityHttp.start();
      String name="Испытатель Core 600",nonce=IdentityProtocol.nonce();long now=System.currentTimeMillis();byte[] body=IdentityProtocol.registration(identity.audience(),key(root),key(device),key(recovery),name,now,nonce);identity.register(key(root),key(device),key(recovery),name,now,nonce,IdentityProtocol.sign(root.getPrivate(),body),IdentityProtocol.sign(device.getPrivate(),body));
      community=new CommunityStore(home.resolve("community.db"));access=new AccessControl(community,new byte[32]);community.bindServiceIdentity(IdentityProtocol.id(key(communityKey)));ContentService content=new ContentService(community,access);community.setNotificationSink(content::notifyAccount);agent=new AgentService(community,access,content::ingestAi);bridge=new CommunityIdentityBridge600(identityHttp.port(),key(service),key(communityKey),access,community);gateway=new CommunityHttpGateway600(new InetSocketAddress("127.0.0.1",0),community,access,content,new OrgAdminService(community,access,community.clock()),agent,communityKey,bridge);gateway.start();
      socks=new Socks(Map.of(IDENTITY,identityHttp.port(),COMMUNITY,gateway.port()));transport=new TorTransport("127.0.0.1",socks.port());client=new IdentityClient600(IDENTITY,80,key(service),transport);
    }
    void prepareDeviceVault(DeviceCredentialStore600 store)throws Exception {try(var credentials=new DeviceCredentials600(key(root),device,key(recovery))){store.create(credentials,PASSWORD);}}
    void writeCommunityConfig(Path profile)throws Exception {Properties p=new Properties();p.setProperty("onion",COMMUNITY);p.setProperty("port","80");p.setProperty("publicKey",IdentityProtocol.b64(key(communityKey)));try(OutputStream out=Files.newOutputStream(profile.resolve("core600/community.properties"))){p.store(out,"Synthetic smoke public service configuration");}}
    void awaitCommunity(CoreApp600 app)throws Exception {Object api=field(app,"community");ThreadPoolExecutor work=(ThreadPoolExecutor)field(api,"work");for(int n=0;n<3;n++){work.submit(()->{}).get(20,TimeUnit.SECONDS);fx(()->null);}}
    public void close()throws Exception {client.close();socks.close();gateway.close();bridge.close();agent.close();access.close();community.close();identityHttp.close();identity.close();}
  }
  private static KeyPair pair()throws Exception{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}private static byte[] key(KeyPair pair){return pair.getPublic().getEncoded();}
  private static final class Socks implements AutoCloseable {
    private final ServerSocket server=new ServerSocket(0,8,InetAddress.getByName("127.0.0.1"));private final ThreadPoolExecutor workers=new ThreadPoolExecutor(8,8,0,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<>(32),r->{Thread t=new Thread(r,"core-smoke-socks-fixture");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());private final Set<Socket> owned=ConcurrentHashMap.newKeySet();private final Map<String,Integer> routes;final List<String> destinations=new CopyOnWriteArrayList<>();private volatile boolean closed;
    Socks(Map<String,Integer> routes)throws IOException {this.routes=Map.copyOf(routes);Thread accept=new Thread(()->{while(!closed)try{Socket socket=server.accept();owned.add(socket);workers.execute(()->handle(socket));}catch(IOException|RejectedExecutionException stopped){if(!closed)throw new IllegalStateException(stopped);}},"core-smoke-socks-accept");accept.setDaemon(true);accept.start();}
    int port(){return server.getLocalPort();}
    private void handle(Socket socket){try(socket){socket.setSoTimeout(10_000);DataInputStream in=new DataInputStream(socket.getInputStream());OutputStream out=socket.getOutputStream();check(in.readUnsignedByte()==5&&in.readUnsignedByte()==1&&in.readUnsignedByte()==0,"Unexpected SOCKS greeting");out.write(new byte[]{5,0});out.flush();check(in.readUnsignedByte()==5&&in.readUnsignedByte()==1&&in.readUnsignedByte()==0&&in.readUnsignedByte()==3,"SOCKS fixture requires domain request");int length=in.readUnsignedByte();String host=new String(in.readNBytes(length),StandardCharsets.US_ASCII);int port=in.readUnsignedShort();Integer route=routes.get(host);check(route!=null&&port==80,"Unexpected non-onion/local route");destinations.add(host);try(Socket remote=new Socket(InetAddress.getByName("127.0.0.1"),route)){owned.add(remote);out.write(new byte[]{5,0,0,1,127,0,0,1,0,0});out.flush();Future<?> upload=workers.submit(()->copy(socket,remote));copy(remote,socket);try{upload.get(10,TimeUnit.SECONDS);}catch(Exception ignored){}owned.remove(remote);}}catch(IOException expected){/* Fixture shutdown or peer close. */}finally{owned.remove(socket);}}
    private static void copy(Socket from,Socket to){try{from.getInputStream().transferTo(to.getOutputStream());to.shutdownOutput();}catch(IOException expected){/* The other direction may close first. */}}
    public void close(){closed=true;try{server.close();}catch(IOException ignored){}for(Socket socket:owned)try{socket.close();}catch(IOException ignored){}workers.shutdownNow();}
  }
}
