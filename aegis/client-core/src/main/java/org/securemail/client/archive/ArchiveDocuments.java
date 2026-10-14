package org.securemail.client.archive;

import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.awt.image.BufferedImage;
import java.util.*;
import java.util.concurrent.*;
import javax.imageio.*;
import javax.imageio.stream.MemoryCacheImageInputStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.apache.fontbox.FontBoxFont;
import org.apache.commons.logging.LogFactory;
import org.securemail.protocol.Binary;

/** Local bounded document decoding; no WebView, URL loading, scripts, or plaintext temp files. */
public final class ArchiveDocuments {
  public static final int MAX_PREVIEW=20*1024*1024,MAX_TEXT=2*1024*1024;
  public record PdfPage(byte[] png,String text,int pages){@Override public String toString(){return "PdfPage[redacted]";}}
  private ArchiveDocuments(){}
  static String type(Path source)throws IOException {
    byte[] head;try(var in=Files.newInputStream(source)){head=in.readNBytes(1024);}String name=source.getFileName().toString().toLowerCase(Locale.ROOT);
    if(pdf(head))return "pdf";if(image(head))return "image";
    if(name.endsWith(".txt")||name.endsWith(".md")||name.endsWith(".csv")||name.endsWith(".log"))return "text";return "file";
  }
  public static boolean pdf(byte[] b){return b.length>=5&&b[0]=='%'&&b[1]=='P'&&b[2]=='D'&&b[3]=='F'&&b[4]=='-';}
  public static boolean image(byte[] b){return b.length>=12&&(b[0]==(byte)0x89&&b[1]=='P'&&b[2]=='N'&&b[3]=='G'||b[0]==(byte)0xff&&b[1]==(byte)0xd8&&b[2]==(byte)0xff||b[0]=='R'&&b[1]=='I'&&b[2]=='F'&&b[3]=='F'&&b[8]=='W'&&b[9]=='E'&&b[10]=='B'&&b[11]=='P');}
  public static String text(byte[] b)throws IOException {if(b.length>MAX_TEXT)throw new IOException("Предпросмотр текста: не более 2 МБ");try{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(b)).toString();}catch(CharacterCodingException invalid){throw new IOException("Файл не является UTF-8 текстом",invalid);}}
  public static byte[] imagePreview(byte[] encoded)throws IOException {
    if(encoded.length>MAX_PREVIEW||!image(encoded))throw new IOException("Неподдерживаемое изображение");
    try(var input=new MemoryCacheImageInputStream(new ByteArrayInputStream(encoded))){var readers=ImageIO.getImageReaders(input);if(!readers.hasNext())throw new IOException("Изображение повреждено");var reader=readers.next();
      try{reader.setInput(input,true,true);int width=reader.getWidth(0),height=reader.getHeight(0);if(width<=0||height<=0||width>32000||height>32000||(long)width*height>64_000_000)throw new IOException("Изображение превышает безопасные размеры");int sample=Math.max(1,(int)Math.ceil(Math.sqrt((double)width*height/4_000_000)));var params=reader.getDefaultReadParam();params.setSourceSubsampling(sample,sample,0,0);BufferedImage image=reader.read(0,params);try(var output=new ByteArrayOutputStream()){ImageIO.write(image,"PNG",output);if(output.size()>16*1024*1024)throw new IOException("Предпросмотр слишком большой");return output.toByteArray();}finally{image.flush();}}finally{reader.dispose();}
    }
  }
  public static String pdfText(byte[] bytes)throws IOException {return pdf(bytes,-1).text();}
  public static PdfPage pdf(byte[] bytes,int page)throws IOException {
    if(bytes.length>MAX_PREVIEW||!pdf(bytes)||page< -1||page>511)throw new IOException("PDF не подходит для безопасного просмотра");
    Set<String> paths=new LinkedHashSet<>();for(Class<?> c:List.of(PdfWorkerMain.class,Binary.class,PDDocument.class,RandomAccessReadBuffer.class,FontBoxFont.class,LogFactory.class))try{paths.add(Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());}catch(Exception invalid){throw new IOException("PDF-библиотека недоступна",invalid);}
    String executable=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toString();
    Process child=new ProcessBuilder(executable,"-Xmx192m","-Djava.awt.headless=true","-XX:+DisableAttachMechanism","-XX:-HeapDumpOnOutOfMemoryError","-Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.NoOpLog","-cp",String.join(File.pathSeparator,paths),PdfWorkerMain.class.getName()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    var watchdog=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-pdf-deadline");t.setDaemon(true);return t;});var stop=watchdog.schedule(child::destroyForcibly,12,TimeUnit.SECONDS);
    try{
      try(var out=new DataOutputStream(child.getOutputStream())){out.writeInt(page);out.writeInt(bytes.length);out.write(bytes);}
      try(var in=new DataInputStream(child.getInputStream())){if(in.readInt()!=0x41455044)throw new IOException("PDF не удалось открыть");int count=in.readInt();if(count<1||count>512)throw new IOException("PDF превышает лимит страниц");byte[] png=Binary.bytes(in,16*1024*1024);String text=Binary.text(in,MAX_TEXT);if(in.read()!=-1||!child.waitFor(2,TimeUnit.SECONDS)||child.exitValue()!=0)throw new IOException("PDF не удалось открыть");return new PdfPage(png,text,count);}
    }catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new InterruptedIOException("Просмотр отменён");}catch(EOFException malformed){throw new IOException("PDF повреждён или превысил лимит обработки",malformed);}
    finally{stop.cancel(false);child.destroyForcibly();watchdog.shutdownNow();}
  }
}
