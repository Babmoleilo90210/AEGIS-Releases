package org.securemail.client.archive;

import java.io.*;
import java.util.Arrays;
import javax.imageio.ImageIO;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.rendering.*;
import org.apache.pdfbox.text.PDFTextStripper;
import org.securemail.protocol.Binary;

/** Isolated renderer: input/output pipes only; actions/JavaScript/URI/embedded files never executed. */
public final class PdfWorkerMain {
  private PdfWorkerMain(){}
  public static void main(String[] args){byte[] data=null;int result=0;try(var in=new DataInputStream(System.in)){
    int page=in.readInt(),size=in.readInt();if(size<5||size>20*1024*1024||page< -1||page>511)throw new IOException("Invalid document");data=in.readNBytes(size);if(data.length!=size||in.read()!=-1)throw new IOException("Invalid input");ImageIO.setUseCache(false);
    try(var doc=Loader.loadPDF(data)){
      int count=doc.getNumberOfPages();if(count<1||count>512||doc.isEncrypted())throw new IOException("Document limit");var text=new StringWriter(){@Override public void write(char[] c,int off,int len){if(getBuffer().length()+len>2*1024*1024)throw new IllegalStateException("Text limit");super.write(c,off,len);}@Override public void write(String s){if(getBuffer().length()+s.length()>2*1024*1024)throw new IllegalStateException("Text limit");super.write(s);}};
      PDFTextStripper stripper=new PDFTextStripper();stripper.setStartPage(1);stripper.setEndPage(count);stripper.writeText(doc,text);
      byte[] png=new byte[0];if(page>=0){if(page>=count)throw new IOException("Page unavailable");var box=doc.getPage(page).getCropBox();float width=box.getWidth(),height=box.getHeight();if(!Float.isFinite(width)||!Float.isFinite(height)||width<=0||height<=0||width>20000||height>20000)throw new IOException("Image limit");float scale=(float)Math.min(1.5,Math.sqrt(4_000_000.0/(width*height)));var image=new PDFRenderer(doc).renderImage(page,scale,ImageType.RGB);try(var output=new ByteArrayOutputStream()){ImageIO.write(image,"PNG",output);if(output.size()>16*1024*1024)throw new IOException("Image limit");png=output.toByteArray();}finally{image.flush();}}
      var out=new DataOutputStream(System.out);out.writeInt(0x41455044);out.writeInt(count);Binary.bytes(out,png);Binary.text(out,text.toString());out.flush();Arrays.fill(png,(byte)0);
    }
  }catch(Throwable invalid){result=2;}finally{if(data!=null)Arrays.fill(data,(byte)0);}if(result!=0)System.exit(result);}
}
