package org.securemail.community.core;
import javax.imageio.*;
import javax.imageio.stream.ImageInputStream;
import java.awt.image.BufferedImage;
import java.io.*;
import java.util.*;
/** Small raster emblems only. Dimensions checked before decode; re-encoding removes metadata. */
public final class ImageSanitizer {
 private ImageSanitizer(){}
 public static byte[] emblem(String base64)throws Exception{
  if(base64.isEmpty())return new byte[0];if(base64.length()>700000)throw CommunityException.invalid();byte[]input;
  try{input=Base64.getDecoder().decode(base64);}catch(IllegalArgumentException e){throw CommunityException.invalid();}
  if(input.length>512*1024)throw CommunityException.invalid();ImageIO.setUseCache(false);
  try(ImageInputStream stream=ImageIO.createImageInputStream(new ByteArrayInputStream(input))){
   Iterator<ImageReader>it=ImageIO.getImageReaders(stream);if(!it.hasNext())throw CommunityException.invalid();ImageReader r=it.next();
   try{String fmt=r.getFormatName().toLowerCase(Locale.ROOT);if(!Set.of("png","jpeg","jpg").contains(fmt))throw CommunityException.invalid();r.setInput(stream,true,true);int w=r.getWidth(0),h=r.getHeight(0);if(w<1||h<1||w>1024||h>1024||(long)w*h>1048576)throw CommunityException.invalid();BufferedImage image=r.read(0);if(image==null)throw CommunityException.invalid();BufferedImage clean=new BufferedImage(w,h,BufferedImage.TYPE_INT_ARGB);var g=clean.createGraphics();try{g.drawImage(image,0,0,null);}finally{g.dispose();image.flush();}ByteArrayOutputStream out=new ByteArrayOutputStream();ImageIO.write(clean,"png",out);clean.flush();if(out.size()>512*1024)throw CommunityException.invalid();return out.toByteArray();}finally{r.dispose();}
  }catch(IOException e){throw CommunityException.invalid();}finally{Arrays.fill(input,(byte)0);}
 }
}
