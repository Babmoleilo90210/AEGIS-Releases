package org.securemail.client.safeweb;

import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Read-only, finite installation discovery. Never starts a browser or reads its
 * profile, cookies, passwords, bookmarks or Tor state. A detected bundle is NOT
 * authenticated: only an official detached-signature-verified package can become
 * an AEGIS template. Existing browser profiles are never copied or adopted.
 */
public final class TorBrowserDiscovery {
    private TorBrowserDiscovery() { }
    public record Candidate(Path bundle,String versionLabel,String architecture,boolean compatible,String status) { }
    public static List<Candidate> discover() { return discover(Path.of(System.getProperty("user.home")),System.getenv(),System.getProperty("os.name","")); }
    static List<Candidate> discover(Path home,Map<String,String> environment,String os) {
        LinkedHashSet<Path> locations=new LinkedHashSet<>();
        if(os.startsWith("Windows")) {
            for(String parent:List.of("Desktop","Downloads"))for(String name:List.of("Tor Browser","TorBrowser"))locations.add(home.resolve(parent).resolve(name));
            for(String variable:List.of("LOCALAPPDATA","ProgramFiles","ProgramFiles(x86)")) {
                String directory=environment.get(variable);if(directory!=null&&!directory.isBlank())locations.add(Path.of(directory).resolve("Tor Browser"));
            }
        } else if(os.equals("Linux")) {
            locations.add(home.resolve("tor-browser"));locations.add(home.resolve("Downloads/tor-browser"));locations.add(Path.of("/opt/tor-browser"));
            String data=environment.get("XDG_DATA_HOME");Path dataRoot=data==null||data.isBlank()?home.resolve(".local/share"):Path.of(data);
            locations.add(dataRoot.resolve("tor-browser"));locations.add(dataRoot.resolve("torbrowser/tbb/x86_64/tor-browser"));
        }
        Map<Path,Candidate> result=new LinkedHashMap<>();
        for(Path directory:locations)try {inspectDirectory(directory).ifPresent(candidate->result.putIfAbsent(candidate.bundle(),candidate));}catch(IOException|InvalidPathException ignored){/* unreadable installations do not block clean download */}
        return List.copyOf(result.values());
    }
    /** Supports the ordinary bundle root or a manually selected Browser directory. */
    public static Optional<Candidate> inspectDirectory(Path selected)throws IOException {
        Path source=selected.toAbsolutePath().normalize();if(!Files.isDirectory(source,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(source))return Optional.empty();
        Path bundle=source.getFileName()!=null&&source.getFileName().toString().equals("Browser")?source.getParent():source;
        if(bundle==null)return Optional.empty();
        TorBrowserDownloadService.rejectParentLinks(bundle);Path real=bundle.toRealPath();
        Path browser=real.resolve("Browser"),ini=browser.resolve("application.ini");
        if(!insideRegular(real,ini)||Files.size(ini)>32768)return Optional.empty();
        Map<String,String> app=new HashMap<>();String section="";
        byte[] iniBytes;try(InputStream input=Files.newInputStream(ini)){iniBytes=input.readNBytes(32769);}
        if(iniBytes.length>32768)return Optional.empty();
        try(BufferedReader reader=new BufferedReader(new InputStreamReader(new ByteArrayInputStream(iniBytes),StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)))) {
            String line;int characters=0;
            while((line=reader.readLine())!=null) {
                if((characters+=line.length())>32768||line.length()>4096)return Optional.empty();
                line=line.strip();if(line.startsWith("[")&&line.endsWith("]")){section=line.substring(1,line.length()-1);continue;}
                if(!section.equals("App")||line.startsWith(";")||line.startsWith("#"))continue;
                int equals=line.indexOf('=');if(equals>0)app.put(line.substring(0,equals).strip(),line.substring(equals+1).strip());
            }
        }
        String name=app.getOrDefault("Name","").replace(" ","").toLowerCase(Locale.ROOT);
        String remote=app.getOrDefault("RemotingName","").replace(" ","").toLowerCase(Locale.ROOT);
        if(!name.equals("torbrowser")&&!remote.equals("torbrowser"))return Optional.empty();
        boolean windows=insideRegular(real,browser.resolve("firefox.exe"));
        Path executable=browser.resolve(windows?"firefox.exe":"firefox"),tor=browser.resolve(windows?"TorBrowser/Tor/tor.exe":"TorBrowser/Tor/tor");
        if(!insideRegular(real,executable)||!insideRegular(real,tor)||!windows&&!insideRegular(real,browser.resolve("start-tor-browser")))return Optional.empty();
        String browserArch=architecture(executable),torArch=architecture(tor);
        boolean nativePlatform=windows?System.getProperty("os.name","").startsWith("Windows"):System.getProperty("os.name","").equals("Linux");
        boolean compatible=nativePlatform&&browserArch.equals("x86_64")&&torArch.equals("x86_64");
        String architecture=browserArch.equals(torArch)?browserArch:browserArch+" / Tor: "+torArch;
        String version=app.getOrDefault("TorBrowserVersion","");
        if(!version.matches("[0-9]+(?:\\.[0-9]+){1,3}")) {
            version=app.getOrDefault("Version","");version=version.matches("[0-9A-Za-z.]{1,40}")?"Версия движка "+version:"Версия не определена";
        } else version="Заявленная версия Tor Browser "+version;
        if(insideRegular(real,browser.resolve("tbb_version.json")))try{var declared=TorBrowserPackageMetadata.bundle(real);version="Заявленная версия Tor Browser "+declared.version();}catch(IOException invalid){version="Повреждены сведения о версии Tor Browser";}
        return Optional.of(new Candidate(real,version,architecture,compatible,compatible?"Найдена установка; подлинность ещё не проверена, профиль не используется":"Найдена несовместимая/неопределённая архитектура; профиль не используется"));
    }
    private static boolean insideRegular(Path bundle,Path file)throws IOException {
        if(!Files.isRegularFile(file))return false;
        return file.toRealPath().startsWith(bundle);
    }
    /** Only bounded executable headers are read; the program is never executed. */
    static String architecture(Path file)throws IOException {
        try(FileChannel input=FileChannel.open(file,StandardOpenOption.READ)) {
            ByteBuffer header=ByteBuffer.allocate(64);if(input.read(header)<64)return "unknown";byte[] bytes=header.array();
            if(bytes[0]==0x7f&&bytes[1]=='E'&&bytes[2]=='L'&&bytes[3]=='F') {
                if(bytes[4]!=2||bytes[5]!=1)return "unsupported";
                int machine=(bytes[18]&255)|((bytes[19]&255)<<8);return machine==62?"x86_64":machine==183?"aarch64":"unsupported";
            }
            if(bytes[0]=='M'&&bytes[1]=='Z') {
                long offset=Integer.toUnsignedLong(ByteBuffer.wrap(bytes,60,4).order(ByteOrder.LITTLE_ENDIAN).getInt());
                if(offset<64||offset>1_048_576||offset+6>input.size())return "unknown";
                ByteBuffer pe=ByteBuffer.allocate(6);if(input.read(pe,offset)!=6)return "unknown";byte[] data=pe.array();
                if(data[0]!='P'||data[1]!='E'||data[2]!=0||data[3]!=0)return "unknown";
                int machine=(data[4]&255)|((data[5]&255)<<8);return machine==0x8664?"x86_64":machine==0xAA64?"aarch64":"unsupported";
            }
            return "unknown";
        }
    }
}
