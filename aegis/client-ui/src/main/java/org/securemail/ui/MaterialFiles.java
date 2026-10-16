package org.securemail.ui;

import com.google.gson.*;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.image.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import java.nio.file.*;
import java.util.*;
import static org.securemail.ui.CommunityUi.*;

/** Explicit bounded file actions. No automatic execution, media URL requests or private-archive import. */
final class MaterialFiles {
  private static final int LIMIT=4*1024*1024;
  static Node node(CommunityUi api,JsonObject material,Label status,Runnable refresh){VBox body=new VBox(8);for(JsonObject file:items(material,"files")){String mime=str(file,"mime");FlowPane actions=actions(label(str(file,"name")),button("Сохранить файл",()->download(api,file,status,bytes->{InWindowFileChooser chooser=new InWindowFileChooser();chooser.setTitle("Сохранение разрешённого вложения");String name=str(file,"name");chooser.setInitialFileName(name.contains("/")||name.contains("\\")?"Материал":name);java.io.File target=chooser.showSaveDialog(main());if(target==null){Arrays.fill(bytes,(byte)0);return;}api.task(()->{try{Files.write(target.toPath(),bytes,StandardOpenOption.CREATE_NEW);return true;}finally{Arrays.fill(bytes,(byte)0);}},status,r->status.setText("Файл сохранён. Автоматический запуск отключён."));})));body.getChildren().add(actions);if(mime.startsWith("image/")||mime.equals("application/pdf"))actions.getChildren().add(button("Предпросмотр",()->download(api,file,status,bytes->api.task(()->{try{return mime.equals("application/pdf")?org.securemail.client.archive.ArchiveDocuments.pdf(bytes,0).png():org.securemail.client.archive.ArchiveDocuments.imagePreview(bytes);}finally{Arrays.fill(bytes,(byte)0);}},status,image->{Image decoded=new Image(new java.io.ByteArrayInputStream(image),600,600,true,true);Arrays.fill(image,(byte)0);if(decoded.isError()){status.setText("Изображение повреждено или не поддерживается.");return;}ImageView view=new ImageView(decoded);view.setPreserveRatio(true);view.setFitWidth(300);body.getChildren().add(view);}))));}
    if(str(material,"state").equals("DRAFT"))body.getChildren().add(button("Добавить вложение",()->{InWindowFileChooser chooser=new InWindowFileChooser();chooser.setTitle("Вложение — до 4 МиБ");java.io.File selected=chooser.showOpenDialog(main());if(selected==null)return;Path path=selected.toPath();api.prepared("content.files.upload",()->{if(Files.isSymbolicLink(path)||!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||Files.size(path)>LIMIT)throw new java.io.IOException("FILE_LIMIT");byte[] bytes=Files.readAllBytes(path);try{String mime=Objects.toString(Files.probeContentType(path),"application/octet-stream");return obj("materialId",str(material,"id"),"name",path.getFileName().toString(),"mime",mime,"base64",Base64.getEncoder().encodeToString(bytes));}finally{Arrays.fill(bytes,(byte)0);}},status,r->refresh.run());}));return fold("Вложения",body);}
  private static void download(CommunityUi api,JsonObject file,Label status,java.util.function.Consumer<byte[]> done){api.prepared("content.files.download",()->obj("id",str(file,"id")),status,r->api.task(()->{String encoded=str(r,"base64");if(encoded.length()>((LIMIT+2L)/3)*4)throw new java.io.IOException("FILE_LIMIT");byte[] bytes=Base64.getDecoder().decode(encoded);if(bytes.length>LIMIT){Arrays.fill(bytes,(byte)0);throw new java.io.IOException("FILE_LIMIT");}String expected=str(r,"sha256");String actual=HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));if(!expected.equals(actual)){Arrays.fill(bytes,(byte)0);throw new java.io.IOException("FILE_HASH");}return bytes;},status,done));}
  private static Stage main(){return javafx.stage.Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).map(w->(Stage)w).findFirst().orElseThrow();}
}
