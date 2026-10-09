package org.securemail.client.crypto;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.channels.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.BooleanSupplier;
import net.lingala.zip4j.io.outputstream.ZipOutputStream;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.*;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.protocol.*;

/** Memory-only content. Versions 1 and 3 remain readable; v4 carries multiple files. */
public final class PlainMessage implements AutoCloseable {
  public static final int MAX_ATTACHMENTS=64;
  private final byte[] text,letter;
  private final String subject;
  private final List<Attachment> attachments;
  private final int version;
  private final MailContext context;
  private record Attachment(String name,byte[] data) {}
  public record FileInfo(String name,int size) {}
  public static final class FileBundle implements AutoCloseable{
    private final List<Attachment> files;
    private FileBundle(List<Attachment> source){files=source.stream().map(f->new Attachment(f.name(),f.data().clone())).toList();}
    public List<FileInfo> info(){return files.stream().map(f->new FileInfo(f.name(),f.data().length)).toList();}
    public int size(){return files.stream().mapToInt(f->f.data().length).sum();}
    public FileBundle copy(){return new FileBundle(files);}
    public void close(){files.forEach(f->Arrays.fill(f.data(),(byte)0));}
  }
  public FileBundle copyFiles(){return new FileBundle(attachments);}
  public static final class FileLimitException extends IOException {
    private static final long serialVersionUID=1L;
    public final int limit;
    public FileLimitException(int limit){super("Файл слишком большой для текущего лимита: "+limit+" байт");this.limit=limit;}
  }
  public PlainMessage(byte[] text,String filename,byte[] file){this(text,"",new byte[0],filename.isEmpty()?List.of():List.of(new Attachment(filename,file)),1);if(filename.isEmpty()&&file.length!=0)throw new IllegalArgumentException("Недопустимое вложение");}
  private PlainMessage(byte[] text,String subject,byte[] letter,List<Attachment> files,int version){
    this(text,subject,letter,files,version,null);
  }
  private PlainMessage(byte[] text,String subject,byte[] letter,List<Attachment> files,int version,MailContext context){
    if(text.length>Limits.TEXT_BYTES||letter.length>LetterEnvelope.MAX_BYTES||subject.getBytes(StandardCharsets.UTF_8).length>1024||files.size()>MAX_ATTACHMENTS)throw new IllegalArgumentException("Превышен размер письма");
    long total=0;Set<String> names=new HashSet<>();for(var f:files){validateFilename(f.name());total+=f.data().length;if(!names.add(f.name().toLowerCase(Locale.ROOT)))throw new IllegalArgumentException("Имена вложений повторяются");}
    if(total>Limits.HARD_FILE_BYTES)throw new IllegalArgumentException("Превышен размер вложений");
    if(text.length>0&&letter.length>0)throw new IllegalArgumentException("Ambiguous mail protection");
    this.text=text;this.subject=subject;this.letter=letter;this.attachments=List.copyOf(files);this.version=version;this.context=context;
  }
  /** Use only after authenticating the recipient's optional signed profile (1.1 capability). */
  public static PlainMessage rich(String subject,String text,byte[] envelope,List<Path> files,int max,MailContext context)throws IOException{
    return new PlainMessage(text.getBytes(StandardCharsets.UTF_8),subject,envelope.clone(),readFiles(files,max),5,context);
  }
  public MailContext context(){return context;}
  public static PlainMessage compose(String subject,String body,byte[] envelope,List<Path> paths,FileBundle forwarded,int max,MailContext context,boolean rich)throws IOException{
    byte[] text=(envelope.length>0?"":rich||subject.isBlank()?body:subject+"\n\n"+body).getBytes(StandardCharsets.UTF_8);
    List<Attachment> files=new ArrayList<>();boolean success=false;
    try{
      if(text.length>Limits.TEXT_BYTES||subject.getBytes(StandardCharsets.UTF_8).length>1024||envelope.length>LetterEnvelope.MAX_BYTES)throw new IOException("Письмо превышает допустимый размер");
      files.addAll(readFiles(paths,max));if(forwarded!=null)for(var f:forwarded.files)files.add(new Attachment(f.name(),f.data().clone()));
      if(files.stream().mapToLong(f->f.data().length).sum()>max)throw new FileLimitException(max);
      if(!rich&&envelope.length==0&&files.size()>1)throw new IOException("Для нескольких вложений этому контакту включите дополнительную защиту");
      var result=new PlainMessage(text,rich||envelope.length>0?subject:"",envelope.clone(),files,rich?5:envelope.length>0?4:1,rich?context:null);success=true;return result;
    }finally{if(!success){Arrays.fill(text,(byte)0);files.forEach(f->Arrays.fill(f.data(),(byte)0));}}
  }
  public static PlainMessage text(String text){return new PlainMessage(text.getBytes(StandardCharsets.UTF_8),"",new byte[0]);}
  public static PlainMessage withFile(String text,Path file,int max)throws IOException {return new PlainMessage(text.getBytes(StandardCharsets.UTF_8),"",new byte[0],readFiles(List.of(file),max),1);}
  /** Kept for existing callers and old-format fixtures. */
  public static PlainMessage letter(String subject,byte[] envelope,Path file,int max)throws IOException {
    if(envelope.length==0)throw new IllegalArgumentException("Пустое письмо");
    return new PlainMessage(new byte[0],subject,envelope.clone(),file==null?List.of():readFiles(List.of(file),max),3);
  }
  public static PlainMessage letterWithAttachments(String subject,byte[] envelope,List<Path> files,int max)throws IOException {
    if(envelope.length==0)throw new IllegalArgumentException("Пустое письмо");
    return new PlainMessage(new byte[0],subject,envelope.clone(),readFiles(files,max),4);
  }
  private static List<Attachment> readFiles(List<Path> files,int max)throws IOException {
    if(files.size()>MAX_ATTACHMENTS)throw new IOException("Не более 64 вложений");
    List<Attachment> result=new ArrayList<>();Set<String> names=new HashSet<>();long total=0;
    try{for(Path path:files){
      if(Files.isSymbolicLink(path)||!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Выберите обычный файл");
      String name=path.getFileName().toString();validateFilename(name);String unique=name;int n=2;
      while(!names.add(unique.toLowerCase(Locale.ROOT))){int dot=name.lastIndexOf('.');String suffix="_"+n++;unique=dot>0?name.substring(0,dot)+suffix+name.substring(dot):name+suffix;validateFilename(unique);}
      long size=Files.size(path);if(size>max-total)throw new FileLimitException(max);
      byte[] bytes;try(var in=Files.newInputStream(path)){bytes=in.readNBytes((int)(max-total)+1);}
      if(bytes.length>max-total){Arrays.fill(bytes,(byte)0);throw new FileLimitException(max);}
      total+=bytes.length;result.add(new Attachment(unique,bytes));
    }return result;}catch(IOException|RuntimeException failure){result.forEach(f->Arrays.fill(f.data(),(byte)0));throw failure;}
  }
  public static void validateFilename(String name){
    if(name.isEmpty()||name.length()>200||name.getBytes(StandardCharsets.UTF_8).length>800||name.equals(".")||name.equals("..")||name.matches("(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\\..*)?$")||name.matches(".*[:<>\"|?*].*")||name.endsWith(".")||name.endsWith(" ")||name.contains("/")||name.contains("\\")||name.chars().anyMatch(c->c<32||c==127))throw new IllegalArgumentException("Недопустимое имя файла");
  }
  public boolean protectedLetter(){return letter.length>0;}
  public String subject(){return subject;}
  public byte[] letterEnvelope(){return letter.clone();}
  public String text(){return new String(text,StandardCharsets.UTF_8);}
  public List<FileInfo> files(){return attachments.stream().map(f->new FileInfo(f.name(),f.data().length)).toList();}
  public String filename(){return attachments.isEmpty()?"":attachments.getFirst().name();}
  public int fileSize(){return attachments.stream().mapToInt(f->f.data().length).sum();}
  public byte[] encode()throws IOException {return Binary.encode(out->{
    out.writeInt(version);if(version==1)Binary.bytes(out,text);else{Binary.text(out,subject);if(version==5)Binary.bytes(out,text);Binary.bytes(out,letter);}
    if(version==5){out.writeBoolean(context!=null);if(context!=null)context.write(out);}
    if(version==4||version==5){out.writeInt(attachments.size());for(var f:attachments){Binary.text(out,f.name());Binary.bytes(out,f.data());}}
    else {Binary.text(out,filename());Binary.bytes(out,attachments.isEmpty()?new byte[0]:attachments.getFirst().data());}
  });}
  public static PlainMessage decode(byte[] encoded,int max)throws IOException {
    byte[] text=new byte[0],letter=new byte[0];List<Attachment> files=new ArrayList<>();boolean success=false;
    try(var in=new DataInputStream(new ByteArrayInputStream(encoded))){
      int v=in.readInt();if(v!=1&&v!=3&&v!=4&&v!=5)throw new IOException("Bad content version");
      String subject=v==1?"":Binary.text(in,1024);if(v==1)text=Binary.bytes(in,Limits.TEXT_BYTES);else {if(v==5)text=Binary.bytes(in,Limits.TEXT_BYTES);letter=Binary.bytes(in,LetterEnvelope.MAX_BYTES);if(v!=5&&letter.length==0)throw new IOException("Empty letter");}
      MailContext context=v==5&&in.readBoolean()?MailContext.read(in):null;
      int count=v==4||v==5?in.readInt():1;if(count<0||count>MAX_ATTACHMENTS)throw new IOException("Bad attachment count");
      int left=max;for(int n=0;n<count;n++){String name=Binary.text(in,800);byte[] data=Binary.bytes(in,left);left-=data.length;
        if(v!=4&&v!=5&&name.isEmpty()&&data.length==0)continue;files.add(new Attachment(name,data));}
      Binary.end(in);PlainMessage result=new PlainMessage(text,subject,letter,files,v,context);success=true;return result;
    }catch(IllegalArgumentException e){throw new IOException("Bad content",e);}finally{if(!success){Arrays.fill(text,(byte)0);Arrays.fill(letter,(byte)0);files.forEach(f->Arrays.fill(f.data(),(byte)0));}}
  }
  /** Explicit legacy single-file export. Never executes or overwrites the destination. */
  public void exportTo(Path target)throws IOException {
    if(attachments.size()!=1)throw new IOException("Используйте скачивание архива вложений");
    exportTo(target,attachments.getFirst().name());
  }
  /** A single explicitly selected attachment; name is never used to construct a destination path. */
  public void exportTo(Path target,String selected)throws IOException{
    var attachment=attachments.stream().filter(f->f.name().equals(selected)).findFirst().orElseThrow(()->new IOException("Вложение недоступно"));
    try(var out=FileChannel.open(target,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.exportAttributes(target.toAbsolutePath().getParent()))){var b=java.nio.ByteBuffer.wrap(attachment.data());while(b.hasRemaining())out.write(b);out.force(true);}
  }
  /** Streams only encrypted ZIP bytes to disk; no plaintext temporary files. */
  public void exportEncryptedZip(Path target,char[] letterPassword,BooleanSupplier permitted)throws IOException {
    if(attachments.isEmpty()||letterPassword.length==0)throw new IOException("Нет вложений или пароля письма");
    boolean created=false,success=false;char[] secret=letterPassword.clone();
    try(var channel=FileChannel.open(target,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.exportAttributes(target.toAbsolutePath().getParent()))){
      created=true;OutputStream output=new FilterOutputStream(Channels.newOutputStream(channel)){@Override public void close()throws IOException{flush();}};
      try(var zip=new ZipOutputStream(output,secret,StandardCharsets.UTF_8)){
        for(var f:attachments){if(!permitted.getAsBoolean())throw new IOException("Письмо закрыто или срок хранения истёк");validateFilename(f.name());
          ZipParameters p=new ZipParameters();p.setEncryptFiles(true);p.setEncryptionMethod(EncryptionMethod.AES);p.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);p.setAesVersion(AesVersion.TWO);p.setFileNameInZip(f.name());p.setCompressionMethod(CompressionMethod.DEFLATE);p.setEntrySize(f.data().length);zip.putNextEntry(p);
          for(int offset=0;offset<f.data().length;offset+=65536){if(!permitted.getAsBoolean())throw new IOException("Письмо закрыто или срок хранения истёк");zip.write(f.data(),offset,Math.min(65536,f.data().length-offset));}zip.closeEntry();
        }
      }channel.force(true);if(!permitted.getAsBoolean())throw new IOException("Письмо закрыто");success=true;
    }finally{Arrays.fill(secret,'\0');if(created&&!success)Files.deleteIfExists(target);}
  }
  @Override public void close(){Arrays.fill(text,(byte)0);Arrays.fill(letter,(byte)0);attachments.forEach(f->Arrays.fill(f.data(),(byte)0));}
  @Override public String toString(){return "PlainMessage[redacted]";}
}
