package org.securemail.client.safeweb;

import com.google.gson.*;
import com.sun.jna.*;
import com.sun.jna.platform.win32.*;
import com.sun.jna.ptr.IntByReference;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/** Narrow Microsoft WSB control plane. It never accepts a guest command/ID. */
final class WindowsSandboxCli {
  private final Path executable,windows,local,control;
  private static final int MAX_OUTPUT=65536;
  WindowsSandboxCli(Path windows,Path local,Path control)throws IOException {
    this.windows=windows;this.local=local;this.control=control;
    executable=requireInstalledAlias(local);
    Result version=run(List.of("--version"),Duration.ofSeconds(20));
    if(version.exit()!=0||version.output().isBlank())throw new IOException("Компонент Windows Sandbox ещё не готов; завершите его установку из меню Пуск");
  }
  /** Read-only validation for download preflight: no process, VM or temporary directory. */
  static Path requireInstalledAlias(Path local)throws IOException {
    Path executable=local.resolve("Microsoft/WindowsApps/wsb.exe").toAbsolutePath().normalize();
    int attributes=Kernel32.INSTANCE.GetFileAttributes(executable.toString());
    if(attributes==WinBase.INVALID_FILE_ATTRIBUTES||(attributes&WinNT.FILE_ATTRIBUTE_REPARSE_POINT)==0)
      throw new IOException("Нужен актуальный Microsoft Windows Sandbox с CLI wsb.exe (Windows 11 24H2+); откройте компонент через меню Пуск для завершения установки");
    // No PATH search, user-selected executable, or ordinary planted wsb.exe.
    // Bind the Windows App Execution Alias to the Microsoft Sandbox package and
    // its executable in the protected Program Files/WindowsApps directory.
    WinNT.HANDLE handle=Kernel32.INSTANCE.CreateFile(executable.toString(),WinNT.FILE_READ_ATTRIBUTES,
      WinNT.FILE_SHARE_READ|WinNT.FILE_SHARE_WRITE|WinNT.FILE_SHARE_DELETE,null,WinNT.OPEN_EXISTING,
      WinNT.FILE_FLAG_OPEN_REPARSE_POINT|WinNT.FILE_FLAG_BACKUP_SEMANTICS,null);
    if(WinBase.INVALID_HANDLE_VALUE.equals(handle))throw new IOException("Не удалось проверить системный псевдоним Windows Sandbox");
    try(Memory data=new Memory(16384)) {
      IntByReference received=new IntByReference();
      if(!Kernel32.INSTANCE.DeviceIoControl(handle,0x000900a8,null,0,data,(int)data.size(),received,null))
        throw new IOException("Не удалось проверить пакет Windows Sandbox");
      byte[] raw=data.getByteArray(0,received.getValue());
      Path programFiles=Path.of(Shell32Util.getKnownFolderPath(KnownFolders.FOLDERID_ProgramFiles)).toRealPath();
      validateAlias(raw,programFiles.toString());
      String payload=new String(raw,12,raw.length-12,StandardCharsets.UTF_16LE);
      Path target=Path.of(payload.split("\\u0000",-1)[2]);
      if(!Files.isRegularFile(target,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(target))
        throw new IOException("Официальный CLI Windows Sandbox не установлен полностью");
    } finally {Kernel32.INSTANCE.CloseHandle(handle);}
    return executable;
  }
  static void validateAlias(byte[] raw,String programFiles)throws IOException {
    if(raw.length<16||raw.length>16384||(raw.length&1)!=0)throw new IOException("Некорректный системный псевдоним");
    ByteBuffer bytes=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
    if(bytes.getInt(0)!=0x8000001b||Short.toUnsignedInt(bytes.getShort(4))+8!=raw.length||
      bytes.getInt(8)!=3)throw new IOException("Неподдерживаемый формат системного псевдонима Windows Sandbox");
    String payload=new String(raw,12,raw.length-12,StandardCharsets.UTF_16LE);
    String[] parts=payload.split("\u0000",-1);
    if(parts.length<4||!parts[parts.length-1].isEmpty())throw new IOException("Неполный системный псевдоним");
    String family=parts[0],application=parts[1],target=parts[2];
    String prefix=programFiles+"\\WindowsApps\\";
    if(!target.toLowerCase(Locale.ROOT).startsWith(prefix.toLowerCase(Locale.ROOT)))
      throw new IOException("Пакет Windows Sandbox находится вне защищённого каталога");
    String remainder=target.substring(prefix.length());int separator=remainder.indexOf('\\');
    if(separator<=0)throw new IOException("Неполный путь пакета Windows Sandbox");
    String packageName=remainder.substring(0,separator);
    if(!family.equals("MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy")||
      !packageName.matches("MicrosoftWindows\\.WindowsSandbox_[0-9.]+_(?:x64|arm64|neutral)__cw5n1h2txyewy")||
      !application.startsWith("MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy!")||
      !target.toLowerCase(Locale.ROOT).endsWith("\\wsb.exe")||target.contains(".."))
      throw new IOException("Псевдоним не принадлежит официальному пакету Microsoft Windows Sandbox");
  }
  record Result(int exit,String output){}
  ProcessBuilder builder(List<String> arguments) {
    List<String> command=new ArrayList<>();command.add(executable.toString());command.addAll(arguments);
    ProcessBuilder builder=new ProcessBuilder(command);builder.environment().clear();
    builder.environment().put("SystemRoot",windows.toString());builder.environment().put("windir",windows.toString());
    builder.environment().put("PATH",windows.resolve("System32").toString());
    builder.environment().put("TEMP",control.toString());builder.environment().put("TMP",control.toString());
    builder.environment().put("LOCALAPPDATA",local.toString());builder.environment().put("USERPROFILE",System.getProperty("user.home"));
    return builder;
  }
  Result run(List<String> arguments,Duration timeout)throws IOException {
    ProcessBuilder builder=builder(arguments);builder.redirectError(ProcessBuilder.Redirect.DISCARD);
    Process process=builder.start();process.getOutputStream().close();
    FutureTask<byte[]> read=new FutureTask<>(()->{try(InputStream input=process.getInputStream()){
      byte[] output=input.readNBytes(MAX_OUTPUT+1);if(output.length>MAX_OUTPUT)throw new IOException("Слишком большой ответ Windows Sandbox");return output;}});
    Thread.startVirtualThread(read);
    try {
      if(!process.waitFor(timeout.toMillis(),TimeUnit.MILLISECONDS)){process.destroyForcibly();throw new IOException("Windows Sandbox не ответил вовремя");}
      return new Result(process.exitValue(),new String(read.get(3,TimeUnit.SECONDS),StandardCharsets.UTF_8));
    }catch(InterruptedException error){Thread.currentThread().interrupt();process.destroyForcibly();throw new IOException("Управление Windows Sandbox прервано",error);}
     catch(ExecutionException|TimeoutException error){process.destroyForcibly();throw new IOException("Некорректный ответ Windows Sandbox",error);}
  }
  Map<String,Boolean> list()throws IOException {
    Result result=run(List.of("list","--raw"),Duration.ofSeconds(20));
    if(result.exit()!=0)throw new IOException("Не удалось проверить состояние Windows Sandbox");
    return parseList(result.output());
  }
  static Map<String,Boolean> parseList(String value)throws IOException {
    try {
      if(value.length()>MAX_OUTPUT)throw new IOException("Слишком большой ответ Windows Sandbox");
      JsonObject root=JsonParser.parseString(value).getAsJsonObject();JsonArray environments=root.getAsJsonArray("WindowsSandboxEnvironments");
      if(environments==null||environments.size()>16)throw new IOException("Неполный список Windows Sandbox");
      Map<String,Boolean> result=new HashMap<>();
      for(JsonElement item:environments){JsonObject environment=item.getAsJsonObject();
        String id=environment.get("Id").getAsString().toLowerCase(Locale.ROOT);
        if(!id.matches("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")||result.containsKey(id))
          throw new IOException("Некорректный идентификатор Windows Sandbox");
        // An omitted/unknown state is conservatively treated as live.
        boolean active=!environment.has("Status")||!environment.get("Status").getAsString().equalsIgnoreCase("Stopped");
        result.put(id,active);
      }
      return Map.copyOf(result);
    }catch(RuntimeException error){throw new IOException("Неподдерживаемый ответ Windows Sandbox",error);}
  }
  void stop(String ownedId)throws IOException {
    if(!ownedId.matches("[a-f0-9-]{36}"))throw new IOException("Некорректная собственная сессия Windows Sandbox");
    Result result=run(List.of("stop","--id",ownedId,"--raw"),Duration.ofSeconds(30));
    if(result.exit()!=0&&Boolean.TRUE.equals(list().get(ownedId)))throw new IOException("Microsoft Windows Sandbox не завершил собственную сессию");
    long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(20);
    do{if(!Boolean.TRUE.equals(list().get(ownedId)))return;try{Thread.sleep(250);}catch(InterruptedException error){Thread.currentThread().interrupt();throw new IOException("Остановка прервана",error);}}while(System.nanoTime()<end);
    throw new IOException("Завершение собственной виртуальной машины Взор не подтверждено");
  }
}
