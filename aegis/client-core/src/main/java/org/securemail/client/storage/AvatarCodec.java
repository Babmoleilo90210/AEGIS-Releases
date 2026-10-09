package org.securemail.client.storage;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.imageio.*;
import javax.imageio.stream.MemoryCacheImageInputStream;

/** Local PNG/JPEG/WebP only. Decode is bounded and exported pixels contain no original metadata. */
public final class AvatarCodec {
  public static final int MAX_FILE=2*1024*1024,MAX_DIMENSION=4096,SIZE=256;
  private AvatarCodec(){}
  public static byte[] load(Path path)throws IOException {
    if(Files.isSymbolicLink(path)||!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Выберите обычный файл изображения");byte[] bytes=AtomicFiles.read(path,MAX_FILE);try{return normalize(bytes);}finally{Arrays.fill(bytes,(byte)0);}
  }
  public static byte[] normalize(byte[] bytes)throws IOException {return crop(bytes,.5,.5,1);}
  public static byte[] crop(byte[] bytes,double xFraction,double yFraction,double zoom)throws IOException {
    if(!Double.isFinite(xFraction)||!Double.isFinite(yFraction)||!Double.isFinite(zoom)||xFraction<0||xFraction>1||yFraction<0||yFraction>1||zoom<1||zoom>4)throw new IOException("Invalid crop");
    if(bytes.length<12||bytes.length>MAX_FILE)throw new IOException("Аватар превышает допустимый размер");
    try(var stream=new MemoryCacheImageInputStream(new ByteArrayInputStream(bytes))){Iterator<ImageReader> readers=ImageIO.getImageReaders(stream);if(!readers.hasNext())throw new IOException("Поддерживаются PNG, JPEG и WebP");ImageReader reader=readers.next();
      try{String format=reader.getFormatName().toLowerCase(Locale.ROOT);if(!Set.of("png","jpeg","jpg","webp").contains(format))throw new IOException("Поддерживаются PNG, JPEG и WebP");reader.setInput(stream,true,true);int w=reader.getWidth(0),h=reader.getHeight(0);if(w<1||h<1||w>MAX_DIMENSION||h>MAX_DIMENSION||(long)w*h>16_777_216)throw new IOException("Слишком большое изображение");
        ImageReadParam parameter=reader.getDefaultReadParam();int sample=Math.max(1,Math.min(w,h)/512);parameter.setSourceSubsampling(sample,sample,0,0);BufferedImage image=reader.read(0,parameter);BufferedImage output=new BufferedImage(SIZE,SIZE,BufferedImage.TYPE_INT_ARGB);Graphics2D g=output.createGraphics();try{g.setRenderingHint(RenderingHints.KEY_INTERPOLATION,RenderingHints.VALUE_INTERPOLATION_BICUBIC);int side=Math.max(1,(int)Math.round(Math.min(image.getWidth(),image.getHeight())/zoom)),x=(int)Math.round((image.getWidth()-side)*xFraction),y=(int)Math.round((image.getHeight()-side)*yFraction);g.drawImage(image,0,0,SIZE,SIZE,x,y,x+side,y+side,null);}finally{g.dispose();image.flush();}
        try{ByteArrayOutputStream out=new ByteArrayOutputStream();if(!ImageIO.write(output,"png",out))throw new IOException("PNG encoder unavailable");return out.toByteArray();}finally{output.flush();}
      }finally{reader.dispose();}
    }
  }
  /** Bounded aspect-preserving PNG preview; no original metadata or temporary file. */
  public static byte[] preview(Path path)throws IOException{
    if(Files.isSymbolicLink(path)||!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Выберите обычный файл изображения");
    byte[] bytes=AtomicFiles.read(path,MAX_FILE);
    try(var input=new MemoryCacheImageInputStream(new ByteArrayInputStream(bytes))){
      var readers=ImageIO.getImageReaders(input);if(!readers.hasNext())throw new IOException("Поддерживаются PNG, JPG и WebP");var reader=readers.next();
      try{
        if(!Set.of("png","jpeg","jpg","webp").contains(reader.getFormatName().toLowerCase(Locale.ROOT)))throw new IOException("Поддерживаются PNG, JPG и WebP");
        reader.setInput(input,true,true);int w=reader.getWidth(0),h=reader.getHeight(0);if(w<1||h<1||w>MAX_DIMENSION||h>MAX_DIMENSION)throw new IOException("Слишком большое изображение");
        var p=reader.getDefaultReadParam();int sample=Math.max(1,(Math.max(w,h)+511)/512);p.setSourceSubsampling(sample,sample,0,0);
        BufferedImage image=reader.read(0,p);try{var output=new ByteArrayOutputStream();if(!ImageIO.write(image,"png",output))throw new IOException("PNG unavailable");return output.toByteArray();}finally{image.flush();}
      }finally{reader.dispose();}
    }finally{Arrays.fill(bytes,(byte)0);}
  }
}
