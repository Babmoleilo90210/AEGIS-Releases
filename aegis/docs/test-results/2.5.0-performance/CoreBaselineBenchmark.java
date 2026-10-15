package org.securemail.client.archive;

import com.google.gson.GsonBuilder;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import org.securemail.client.storage.LocalStore;

/** Standalone, synthetic offline core workload. No UI, network, browser or audio activation. */
public final class CoreBaselineBenchmark {
    private static final long BINARY_BYTES=32L*1024*1024;
    private static final int DOCUMENTS=32,TEXT_BYTES=8192;
    private static long cpuNanos(){
        try{Class<?> type=Class.forName("com.sun.management.OperatingSystemMXBean");Object os=ManagementFactory.getOperatingSystemMXBean();if(type.isInstance(os)){long n=((Number)type.getMethod("getProcessCpuTime").invoke(os)).longValue();if(n>=0)return n;}}
        catch(ReflectiveOperationException|LinkageError|SecurityException unsupported){}
        return ProcessHandle.current().info().totalCpuDuration().map(Duration::toNanos).orElse(-1L);
    }
    private static Map<String,Object> memory(){
        var heap=ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
        var result=new LinkedHashMap<String,Object>();result.put("heapUsedBytes",heap.getUsed());result.put("heapCommittedBytes",heap.getCommitted());result.put("heapMaximumBytes",heap.getMax());
        try{for(String line:Files.readAllLines(Path.of("/proc/self/status"),StandardCharsets.US_ASCII)){
            if(line.startsWith("VmRSS:")||line.startsWith("VmHWM:")){String[] parts=line.trim().split("\\s+");result.put(line.startsWith("VmRSS:")?"linuxRssBytes":"linuxPeakRssBytes",Long.parseLong(parts[1])*1024);}
        }}catch(IOException|RuntimeException unsupported){result.put("linuxRssStatus","UNAVAILABLE");}
        return result;
    }
    private static void check(boolean condition,String why){if(!condition)throw new AssertionError(why);}
    private static InputStream binary(){return new InputStream(){long remaining=BINARY_BYTES;public int read(){if(remaining--<=0)return -1;return 0x41;}public int read(byte[] buffer,int offset,int length){if(length==0)return 0;int n=(int)Math.min(remaining,length);if(n<=0)return -1;Arrays.fill(buffer,offset,offset+n,(byte)0x41);remaining-=n;return n;}};}
    private static byte[] text(int n){byte[] bytes=new byte[TEXT_BYTES];Arrays.fill(bytes,(byte)'A');byte[] prefix=("Синтетический документ "+n+"; benchmark-needle-"+n+". Кириллица и Latin.\n").getBytes(StandardCharsets.UTF_8);System.arraycopy(prefix,0,bytes,0,prefix.length);return bytes;}
    private static String binaryDigest()throws Exception{MessageDigest digest=MessageDigest.getInstance("SHA-256");try(var in=binary()){byte[] buffer=new byte[65536];int n;while((n=in.read(buffer))!=-1)digest.update(buffer,0,n);}return HexFormat.of().formatHex(digest.digest());}
    public static void main(String[] args)throws Exception{
        if(args.length!=4)throw new IllegalArgumentException("Usage: version repetition fixture-parent output-json");
        String version=args[0];int repetition=Integer.parseInt(args[1]);Path parent=Path.of(args[2]);Files.createDirectories(parent);Path root=Files.createTempDirectory(parent,"synthetic-core-");
        var output=new LinkedHashMap<String,Object>();var timing=new LinkedHashMap<String,Long>();
        output.put("versionLabel",version);output.put("repetition",repetition);output.put("startedUTC",Instant.now().toString());
        output.put("cpuCounterPreference","public OperatingSystemMXBean.getProcessCpuTime via reflection; optional ProcessHandle fallback; missing or regressing counter is UNAVAILABLE");
        output.put("loadedApplicationSources",Map.of("LocalStore",LocalStore.class.getProtectionDomain().getCodeSource().getLocation().toString(),"EncryptedArchive",EncryptedArchive.class.getProtectionDomain().getCodeSource().getLocation().toString(),"Protocol",org.securemail.protocol.Algorithm.class.getProtectionDomain().getCodeSource().getLocation().toString()));
        output.put("environment",Map.of("osName",System.getProperty("os.name"),"osVersion",System.getProperty("os.version"),"osArch",System.getProperty("os.arch"),"javaVersion",System.getProperty("java.version"),"javaVendor",System.getProperty("java.vendor"),"vmName",System.getProperty("java.vm.name"),"logicalProcessors",Runtime.getRuntime().availableProcessors(),"vmArguments",ManagementFactory.getRuntimeMXBean().getInputArguments()));
        output.put("fixture",Map.of("binaryBytes",BINARY_BYTES,"binaryPattern","constant 0x41 stream, no plaintext file staging","binarySha256",binaryDigest(),"textDocuments",DOCUMENTS,"textBytesEach",TEXT_BYTES,"searchQuery","benchmark-needle-31","searchExpectedMatches",1,"vault","one synthetic bound identity, no mail/contacts/avatar","clock","2026-10-15T00:00:00Z","randomCryptoMaterial","normal SecureRandom; intentionally not seeded"));
        char[] vaultPassword="synthetic offline core benchmark password".toCharArray(),archivePassword="synthetic independent archive benchmark password".toCharArray();
        Clock clock=Clock.fixed(Instant.parse("2026-10-15T00:00:00Z"),ZoneOffset.UTC);LocalStore reopened=null;EncryptedArchive archive=null;
        long workCpuBefore=cpuNanos(),workStart=System.nanoTime();
        try{
            long started=System.nanoTime();String identity;
            try(var local=new LocalStore(root.resolve("vault"),vaultPassword,clock,4*1024*1024,128L*1024*1024)){
                local.bindNickname("perfuser");identity=local.identity().userId();
            }
            timing.put("localVaultCreateBindCloseNanos",System.nanoTime()-started);
            started=System.nanoTime();reopened=new LocalStore(root.resolve("vault"),vaultPassword,clock,4*1024*1024,128L*1024*1024);timing.put("localVaultOpenOfflineNanos",System.nanoTime()-started);
            check(identity.equals(reopened.identity().userId())&&reopened.nickname().equals("perfuser"),"Offline identity/nickname changed");
            started=System.nanoTime();var created=EncryptedArchive.create(root.resolve("archive"),root.resolve("guards"),archivePassword,false,clock);archive=created.archive();Arrays.fill(created.recoveryKey(),'\0');timing.put("archiveCreateNanos",System.nanoTime()-started);
            started=System.nanoTime();ArchiveEntry binary;
            try(var input=binary()){binary=archive.importStream("generated.bin","file",BINARY_BYTES,input,"",List.of(),false,false,EncryptedArchive.QUIET,()->false);}
            timing.put("archiveBinaryImport32MiBNanos",System.nanoTime()-started);check(binary.size()==BINARY_BYTES&&binary.digest().equals(((Map<?,?>)output.get("fixture")).get("binarySha256")),"Binary digest/size mismatch");
            started=System.nanoTime();for(int n=0;n<DOCUMENTS;n++){byte[] data=text(n);try{archive.importBytes(String.format(Locale.ROOT,"document-%02d.txt",n),"text",data,"",false,EncryptedArchive.QUIET,()->false);}finally{Arrays.fill(data,(byte)0);}}
            timing.put("archiveTextImport32x8KiBNanos",System.nanoTime()-started);check(archive.entries().size()==DOCUMENTS+1,"Imported entry count mismatch");
            archive.close();archive=null;started=System.nanoTime();archive=EncryptedArchive.open(root.resolve("archive"),root.resolve("guards"),archivePassword,false,clock);timing.put("archiveOpenPopulatedNanos",System.nanoTime()-started);check(archive.entries().size()==DOCUMENTS+1,"Reopened archive lost entries");
            var query=new EncryptedArchive.Filter("benchmark-needle-31","","",0,Long.MAX_VALUE,false,false,true);
            started=System.nanoTime();var found=archive.search(query,EncryptedArchive.QUIET,()->false);timing.put("archiveFullTextFirstSearchNanos",System.nanoTime()-started);check(found.size()==1&&found.getFirst().name().equals("document-31.txt"),"First full-text query failed");
            List<Long> repeats=new ArrayList<>();for(int n=0;n<5;n++){started=System.nanoTime();found=archive.search(query,EncryptedArchive.QUIET,()->false);repeats.add(System.nanoTime()-started);check(found.size()==1&&found.getFirst().name().equals("document-31.txt"),"Repeated full-text query failed");}
            output.put("archiveRepeatedFullTextSearchNanos",repeats);output.put("timingNanos",timing);output.put("workWallNanos",System.nanoTime()-workStart);long workCpuAfter=cpuNanos();output.put("workCpuCounterBeforeNanos",workCpuBefore);output.put("workCpuCounterAfterNanos",workCpuAfter);if(workCpuBefore>=0&&workCpuAfter>=workCpuBefore)output.put("workProcessCpuNanos",workCpuAfter-workCpuBefore);else output.put("workProcessCpuStatus","UNAVAILABLE");
            output.put("memoryAfterWorkBeforeExplicitGc",memory());
            // GC preparation is outside operation timings and idle CPU window.
            System.gc();Thread.sleep(500);output.put("memoryAfterExplicitGcAnd500msSettle",memory());
            long idleCpuBefore=cpuNanos(),idleStarted=System.nanoTime();Thread.sleep(2000);long idleElapsed=System.nanoTime()-idleStarted,idleCpuAfter=cpuNanos();var idle=new LinkedHashMap<String,Object>();idle.put("wallNanos",idleElapsed);idle.put("cpuCounterBeforeNanos",idleCpuBefore);idle.put("cpuCounterAfterNanos",idleCpuAfter);idle.put("vaultAndArchiveRemainOpen",true);idle.put("applicationUiNetworkAudioThreadsStarted",false);
            if(idleCpuBefore>=0&&idleCpuAfter>=idleCpuBefore){idle.put("cpuStatus","MEASURED");idle.put("processCpuNanosDelta",idleCpuAfter-idleCpuBefore);idle.put("oneCoreCpuPercent",(idleCpuAfter-idleCpuBefore)*100.0/idleElapsed);idle.put("normalizedCpuPercent",(idleCpuAfter-idleCpuBefore)*100.0/idleElapsed/Runtime.getRuntime().availableProcessors());}else idle.put("cpuStatus","UNAVAILABLE");
            output.put("boundedIdle",idle);output.put("memoryAfterIdle",memory());output.put("fixtureChecks","PASS");output.put("nativeAcceptance","NOT_RUN");output.put("networkAuthentication","NOT_RUN");output.put("TorBrowserAudioStartup","NOT_RUN");output.put("finishedUTC",Instant.now().toString());
            Files.writeString(Path.of(args[3]),new GsonBuilder().setPrettyPrinting().create().toJson(output)+"\n");
            System.out.println("CoreBaselineBenchmark "+version+" repetition="+repetition+" PASS (synthetic offline core only)");
        }finally{
            if(archive!=null)archive.close();if(reopened!=null)reopened.close();Arrays.fill(vaultPassword,'\0');Arrays.fill(archivePassword,'\0');
            try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}
        }
    }
}
