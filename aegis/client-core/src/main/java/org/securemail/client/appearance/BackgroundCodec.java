package org.securemail.client.appearance;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.imageio.*;
import javax.imageio.stream.MemoryCacheImageInputStream;
import org.securemail.client.storage.AtomicFiles;

/** Explicit local import only. Existing ImageIO/WebP provider; bounded decode, no metadata. */
public final class BackgroundCodec {
  public static final int MAX_INPUT=5*1024*1024,MAX_OUTPUT=12*1024*1024,MAX_SIDE=2048;
  private BackgroundCodec(){}
  public static byte[] load(Path path)throws IOException{
    if(Files.isSymbolicLink(path)||!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Выберите обычный JPG, PNG или WebP");
    byte[] input=AtomicFiles.read(path,MAX_INPUT);try{return normalize(input);}finally{Arrays.fill(input,(byte)0);}
  }
  public static byte[] normalize(byte[] input)throws IOException{return normalize(input,MAX_INPUT);}
  public static byte[] checkStored(byte[] input)throws IOException{return normalize(input,MAX_OUTPUT);}
  private static byte[] normalize(byte[] input,int limit)throws IOException{
    if(input.length<12||input.length>limit)throw new IOException("Изображение превышает допустимый размер");
    try(var stream=new MemoryCacheImageInputStream(new ByteArrayInputStream(input))){
      var readers=ImageIO.getImageReaders(stream);if(!readers.hasNext())throw new IOException("Поддерживаются JPG, PNG и WebP");var reader=readers.next();
      try{
        if(!Set.of("jpeg","jpg","png","webp").contains(reader.getFormatName().toLowerCase(Locale.ROOT)))throw new IOException("Поддерживаются JPG, PNG и WebP");
        reader.setInput(stream,true,true);int w=reader.getWidth(0),h=reader.getHeight(0);
        if(w<1||h<1||w>16384||h>16384||(long)w*h>64_000_000L)throw new IOException("Слишком большое разрешение изображения");
        ImageReadParam p=reader.getDefaultReadParam();int sample=Math.max(1,(Math.max(w,h)+MAX_SIDE-1)/MAX_SIDE);p.setSourceSubsampling(sample,sample,0,0);
        BufferedImage image=reader.read(0,p);if(image==null||image.getWidth()>MAX_SIDE||image.getHeight()>MAX_SIDE)throw new IOException("Не удалось безопасно декодировать изображение");
        try{
          BufferedImage clean=new BufferedImage(image.getWidth(),image.getHeight(),BufferedImage.TYPE_INT_ARGB);Graphics2D g=clean.createGraphics();try{g.drawImage(image,0,0,null);}finally{g.dispose();}
          try{var out=new ByteArrayOutputStream();if(!ImageIO.write(clean,"png",out)||out.size()>MAX_OUTPUT)throw new IOException("Не удалось подготовить фон");return out.toByteArray();}finally{clean.flush();}
        }finally{image.flush();}
      }finally{reader.dispose();}
    }catch(RuntimeException invalid){throw new IOException("Повреждённое изображение",invalid);}
  }
}
