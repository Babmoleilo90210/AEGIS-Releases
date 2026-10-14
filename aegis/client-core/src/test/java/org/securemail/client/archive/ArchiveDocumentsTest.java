package org.securemail.client.archive;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import javax.imageio.ImageIO;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.font.*;

final class ArchiveDocumentsTest {
  @Test void boundedImageAndStrictUtf8()throws Exception {
    var image=new BufferedImage(400,200,BufferedImage.TYPE_INT_RGB);byte[] input;try(var out=new ByteArrayOutputStream()){ImageIO.write(image,"PNG",out);input=out.toByteArray();}finally{image.flush();}
    byte[] result=ArchiveDocuments.imagePreview(input);assertTrue(ArchiveDocuments.image(result));assertEquals("Кириллица English",ArchiveDocuments.text("Кириллица English".getBytes(StandardCharsets.UTF_8)));assertThrows(IOException.class,()->ArchiveDocuments.text(new byte[]{(byte)0xff}));assertThrows(IOException.class,()->ArchiveDocuments.imagePreview("not an image".getBytes(StandardCharsets.UTF_8)));
  }
  @Test void actualIsolatedPdfRenderAndTextExtraction()throws Exception {
    byte[] bytes;
    try(var doc=new PDDocument();var out=new ByteArrayOutputStream()){
      PDPage page=new PDPage();doc.addPage(page);try(var text=new PDPageContentStream(doc,page)){text.beginText();text.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA),14);text.newLineAtOffset(40,700);text.showText("Synthetic private PDF document");text.endText();}doc.save(out);bytes=out.toByteArray();
    }
    ArchiveDocuments.PdfPage page=ArchiveDocuments.pdf(bytes,0);assertEquals(1,page.pages());assertTrue(page.text().contains("Synthetic private PDF document"));assertTrue(ArchiveDocuments.image(page.png()));assertTrue(ArchiveDocuments.pdfText(bytes).contains("Synthetic private PDF document"));
  }
  @Test void damagedPdfFailsWithoutExternalOpening()throws Exception {assertThrows(IOException.class,()->ArchiveDocuments.pdf("%PDF-malformed\nnot a document".getBytes(StandardCharsets.US_ASCII),0));}
}
