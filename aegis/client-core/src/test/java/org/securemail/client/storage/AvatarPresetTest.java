package org.securemail.client.storage;
import static org.junit.jupiter.api.Assertions.*;
import java.awt.image.*;
import java.io.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class AvatarPresetTest {
 @TempDir Path root;
 byte[] image(String format)throws IOException{BufferedImage image=new BufferedImage(400,300,BufferedImage.TYPE_INT_RGB);image.setRGB(3,3,0xff778899);ByteArrayOutputStream out=new ByteArrayOutputStream();ImageIO.write(image,format,out);return out.toByteArray();}
 @Test void pngJpegNormalizeToBoundedPngAndRejectOtherFormats()throws Exception{for(String format:List.of("png","jpeg")){byte[] png=AvatarCodec.normalize(image(format));BufferedImage image=ImageIO.read(new ByteArrayInputStream(png));assertEquals(256,image.getWidth());assertEquals(256,image.getHeight());assertTrue(png.length<65536);}assertThrows(IOException.class,()->AvatarCodec.normalize(image("gif")));assertThrows(IOException.class,()->AvatarCodec.normalize(new byte[AvatarCodec.MAX_FILE+1]));assertThrows(IOException.class,()->AvatarCodec.normalize("https://example.invalid/avatar".getBytes()));}
 @Test void dimensionsAndSymlinksRejectedBeforePixelDecode()throws Exception{BufferedImage large=new BufferedImage(4097,1,BufferedImage.TYPE_INT_RGB);ByteArrayOutputStream out=new ByteArrayOutputStream();ImageIO.write(large,"png",out);assertThrows(IOException.class,()->AvatarCodec.normalize(out.toByteArray()));Path original=root.resolve("avatar.png"),link=root.resolve("link.png");Files.write(original,image("png"));Files.createSymbolicLink(link,original);assertThrows(IOException.class,()->AvatarCodec.load(link));}
 @Test void signedRemoteAvatarStillRejectsOversizeDimensionsBeforeCaching()throws Exception{
   var peer=org.securemail.client.crypto.Identity.create();
   try(var local=new LocalStore(root,"remote avatar passphrase".toCharArray(),Clock.systemUTC(),100000,1000000)){
     local.bindNickname("raven");local.trust(new org.securemail.protocol.UserInfo(peer.userId(),"blackfox",peer.publicKey(),null));
     BufferedImage wide=new BufferedImage(4097,1,BufferedImage.TYPE_INT_RGB);var output=new ByteArrayOutputStream();ImageIO.write(wide,"png",output);wide.flush();
     var signed=peer.profile("blackfox",local.now(),true,"",output.toByteArray());assertThrows(IOException.class,()->local.cacheProfile(signed));assertNull(local.cachedProfile("blackfox"));
     local.cacheProfile(peer.profile("blackfox",local.now()+1,true,"",AvatarCodec.normalize(image("png"))));assertNotNull(local.avatar("blackfox"));
   }
 }
 @Test void webpDecodesLocallyIntoSanitizedPng()throws Exception{assertTrue(ImageIO.getImageReadersByFormatName("webp").hasNext());byte[] webp=Base64.getDecoder().decode("UklGRh4AAABXRUJQVlA4TBEAAAAvE8AEAAfQmYqUqP+BiOh/AAA=");byte[] png=AvatarCodec.normalize(webp);BufferedImage image=ImageIO.read(new ByteArrayInputStream(png));assertEquals(256,image.getWidth());assertEquals(256,image.getHeight());assertEquals(0xff223344,image.getRGB(20,20));}
 @Test void avatarIsEncryptedAndRekeyPreservesIt()throws Exception{Path data=root.resolve("data"),rekey=root.resolve("new");char[] password="account-password-1234".toCharArray(),next="next-password-5678".toCharArray();byte[] png=AvatarCodec.normalize(image("png"));try(LocalStore local=new LocalStore(data,password,Clock.systemUTC(),100000,1000000)){local.bindNickname("raven");local.avatar("raven",png);assertArrayEquals(png,local.avatar("raven"));try(var paths=Files.list(data.resolve("avatars"))){Path file=paths.findFirst().orElseThrow();assertFalse(Arrays.equals(png,Files.readAllBytes(file)));}assertThrows(IOException.class,()->local.avatar("stranger",png));local.rekeyCopy(rekey,next);}try(LocalStore local=new LocalStore(rekey,next,Clock.systemUTC(),100000,1000000)){assertArrayEquals(png,local.avatar("raven"));local.avatar("raven",null);assertNull(local.avatar("raven"));}}
 @Test void customPresetsPersistApplyRenameImportExportAndDelete()throws Exception{UiPresetStore store=new UiPresetStore(root.resolve("profile"));assertEquals(5,store.presets().size());UiPreferences p=new UiPreferences(125,UiPreferences.Density.LARGE,false,UiPreferences.Avatars.MEDIUM,UiPreferences.Preview.BOTTOM,false,false);store.add("Работа",p);store.apply(p);store.rename("Работа","Почтовый");Path file=root.resolve("preset.json");store.exportPreset("Почтовый",file);String json=Files.readString(file);assertFalse(json.contains("password"));assertFalse(json.contains("onion"));UiPresetStore other=new UiPresetStore(root.resolve("other"));other.importPreset(file);assertEquals(p,other.presets().get("Почтовый"));assertEquals(p,new UiPresetStore(root.resolve("profile")).current());store.remove("Почтовый");assertFalse(store.customNames().contains("Почтовый"));assertThrows(IOException.class,()->store.remove("Компактный"));}
 @Test void unsafeExecutableDuplicateAndOversizePresetDataRejected()throws Exception{UiPresetStore store=new UiPresetStore(root);assertThrows(IOException.class,()->store.add("Компактный",store.current()));assertThrows(IOException.class,()->store.add("bad\nname",store.current()));assertThrows(IllegalArgumentException.class,()->new UiPreferences(999,UiPreferences.Density.NORMAL,true,UiPreferences.Avatars.OFF,UiPreferences.Preview.OFF,true,true));Path file=root.resolve("bad.json");Files.writeString(file,"{\"schema\":1,\"schema\":1,\"name\":\"test\",\"layout\":{}}");assertThrows(IOException.class,()->store.importPreset(file));Files.writeString(file,"{\"schema\":1,\"name\":\"test\",\"layout\":{},\"command\":\"run\"}");assertThrows(IOException.class,()->store.importPreset(file));Files.write(file,new byte[32769]);assertThrows(IOException.class,()->store.importPreset(file));}
}
