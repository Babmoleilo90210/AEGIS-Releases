package org.securemail.ui;

import java.nio.file.*;
import java.time.Clock;
import java.lang.management.ManagementFactory;
import com.google.gson.GsonBuilder;
import java.util.*;
import java.util.concurrent.*;
import javafx.application.Platform;
import javafx.geometry.Bounds;
import javafx.scene.*;
import javafx.scene.canvas.Canvas;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.text.Text;
import javafx.stage.*;
import org.securemail.client.appearance.*;
import org.securemail.client.storage.LocalStore;

/** Actual JavaFX controls and encrypted archive fixtures. No native OS or Tor claim. */
public final class Interface250RefinementSmoke {
    private static <T> T fx(Callable<T> action) throws Exception {
        CompletableFuture<T> future = new CompletableFuture<>();
        Platform.runLater(() -> { try { future.complete(action.call()); } catch (Throwable t) { future.completeExceptionally(t); } });
        return future.get(30, TimeUnit.SECONDS);
    }
    private static void check(boolean value, String why) { if (!value) throw new AssertionError(why); }
    private static Object field(Object target, String name) throws Exception {
        var f = target.getClass().getDeclaredField(name); f.setAccessible(true); return f.get(target);
    }
    private static void until(Callable<Boolean> condition) throws Exception {
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (System.nanoTime() < end) { if (fx(condition)) return; Thread.sleep(50); }
        throw new AssertionError("Timed out waiting for actual archive operation");
    }
    private static Button button(Parent root, String label) {
        return root.lookupAll(".button").stream().filter(n -> n instanceof Button b && label.equals(b.getText()))
                .map(n -> (Button)n).findFirst().orElseThrow(() -> new AssertionError("Button missing: " + label));
    }
    private static void layout(Stage stage) { stage.getScene().getRoot().applyCss(); stage.getScene().getRoot().layout(); }
    private static void screenshot(Window window, String name) throws Exception {
        Path output = Path.of("build/ui250-refinement-screenshots"); Files.createDirectories(output);
        var image = window.getScene().snapshot(null); var pixels = image.getPixelReader();
        var bitmap = new java.awt.image.BufferedImage((int)image.getWidth(), (int)image.getHeight(), java.awt.image.BufferedImage.TYPE_INT_ARGB);
        for (int y=0;y<bitmap.getHeight();y++) for (int x=0;x<bitmap.getWidth();x++) bitmap.setRGB(x,y,pixels.getArgb(x,y));
        javax.imageio.ImageIO.write(bitmap,"png",output.resolve(name+".png").toFile());
    }
    private static void popupBounds(String name) throws Exception {
        List<Window> opened = Window.getWindows().stream().filter(w -> w instanceof PopupWindow && w.isShowing()).toList();
        check(!opened.isEmpty(), "Real popup did not open: " + name);
        for (int i=0;i<opened.size();i++) {
            Window popup=opened.get(i); var screen=Screen.getScreensForRectangle(popup.getX(),popup.getY(),popup.getWidth(),popup.getHeight()).getFirst().getVisualBounds();
            check(popup.getWidth()>20&&popup.getHeight()>20,"Empty popup: "+name);
            check(popup.getX()>=screen.getMinX()-.5&&popup.getY()>=screen.getMinY()-.5&&popup.getX()+popup.getWidth()<=screen.getMaxX()+.5&&popup.getY()+popup.getHeight()<=screen.getMaxY()+.5,"Popup outside visual screen: "+name);
            check(popup.getScene().getRoot().lookupAll(".scaled-root").isEmpty(),"Popup skin reparented through ScaledRoot");
            if(name.endsWith("-200"))for(Node n:popup.getScene().getRoot().lookupAll(".label,.list-cell"))if(n instanceof Labeled label&&!label.getText().isBlank())check(label.getFont().getSize()>=27,"Popup text did not follow 200% scale: "+label.getText()+" "+label.getFont().getSize());
            screenshot(popup,name+"-popup-"+i);
        }
    }
    private static void activateVisibleMenu(String label) {
        for(Window window:Window.getWindows())if(window instanceof PopupWindow&&window.isShowing())for(Node node:window.getScene().getRoot().lookupAll(".menu-item")){
            Node text=node.lookup(".label");if(text instanceof Label title&&title.getText().equals(label)){
                // Dispatch through the rendered item's standard action handler;
                // Menu.show alone has no selected item to anchor a submenu to.
                javafx.event.Event.fireEvent(node,new javafx.event.ActionEvent());return;
            }
        }
        throw new AssertionError("Rendered submenu item missing: "+label);
    }
    private static void hidePopups() { new ArrayList<>(Window.getWindows()).stream().filter(w -> w instanceof PopupWindow).forEach(Window::hide); }
    private static long processCpuNanos() {
        try {
            // jdk.management is optional in packaged runtimes. Reflect only on
            // its public interface; never require the module or open internals.
            Class<?> type=Class.forName("com.sun.management.OperatingSystemMXBean");
            Object os=ManagementFactory.getOperatingSystemMXBean();
            if(!type.isInstance(os))return -1;
            return ((Number)type.getMethod("getProcessCpuTime").invoke(os)).longValue();
        } catch(ReflectiveOperationException|LinkageError|SecurityException unavailable) {
            return -1;
        }
    }
    private static void galleryGeometry(AppearanceGallery gallery) {
        for (Node tile : gallery.getChildren()) {
            VBox card=(VBox)tile; Button choose=(Button)card.getChildren().getFirst(); HBox metadata=(HBox)card.getChildren().getLast();
            Bounds a=choose.localToScene(choose.getBoundsInLocal()), b=metadata.localToScene(metadata.getBoundsInLocal());
            check(a.getHeight()>80,"Preset preview compressed into a standard-height action: "+choose.getText());
            check(b.getMinY()>=a.getMaxY()-.5,"Favorite overlaps preset preview/name: "+choose.getText());
            check(choose.isWrapText(),"Preset name cannot wrap");
            check(metadata.getChildren().getLast() instanceof Button,"Favorite is not a separate layout control");
            Node text=choose.lookup(".text"); if(text instanceof Text rendered)check(rendered.getText().equals(choose.getText()),"Preset name ellipsized: "+choose.getText());
        }
    }
    public static void main(String[] args) throws Exception {
        Path profile=Files.createTempDirectory("AEGIS-250-refinement-"); System.setProperty("aegis.profile",profile.toString());
        Platform.startup(() -> Platform.setImplicitExit(false)); ExecutorService worker=Executors.newSingleThreadExecutor();
        LocalStore local=new LocalStore(profile.resolve("fixture-vault"),"synthetic refinement vault password".toCharArray(),Clock.systemUTC(),1_000_000,8_000_000);
        ThemeManager themes=fx(ThemeManager::new);
        BorderPane workspace=fx(BorderPane::new);
        Stage stage=fx(() -> { Stage w=new Stage();w.initStyle(StageStyle.UNDECORATED);BorderPane host=new BorderPane(workspace);host.setTop(new WindowChrome(w));w.setScene(new Scene(host,1280,850));InWindowDialog.bind(w,host);themes.initialize();themes.apply(host);themes.apply(workspace);themes.workspace(workspace);themes.track(w.getScene());w.show();return w; });
        ArchiveView[] archive={null};
        Map<String,Object> performance=new LinkedHashMap<>();List<Map<String,Object>> galleryTimings=new ArrayList<>(),archiveTimings=new ArrayList<>();
        performance.put("environment","Synthetic JavaFX fixtures, 800x600 scene; runtime properties recorded separately");
        performance.put("runtimeProperties",Map.of("osName",System.getProperty("os.name","UNAVAILABLE"),"osVersion",System.getProperty("os.version","UNAVAILABLE"),"javaVersion",System.getProperty("java.version","UNAVAILABLE"),"glassPlatform",System.getProperty("glass.platform","DEFAULT"),"prismOrder",System.getProperty("prism.order","DEFAULT"),"xdgSessionType",Objects.requireNonNullElse(System.getenv("XDG_SESSION_TYPE"),"UNAVAILABLE")));
        performance.put("nativeAcceptance","NOT_RUN");performance.put("baselineComparison","NOT_RUN");performance.put("navigationSectionSwitch","NOT_RUN_THIS_COMPONENT_PROBE");performance.put("TorAndLogin","NOT_RUN");
        try {
            String unsafeDetail="Unsupported schema /private/synthetic-secret.json https://invalid.example/secret";
            Exception parserFailure=new java.io.IOException(unsafeDetail,new IllegalArgumentException(unsafeDetail));
            check(!InterfaceFailureMessages.appearance(parserFailure).contains("synthetic-secret"),"Appearance exposed raw parser/path data");
            check(!InterfaceFailureMessages.archive(parserFailure).contains("invalid.example"),"Archive exposed raw parser/path data");
            check(InterfaceFailureMessages.archive(new java.io.IOException("Symlink в пути архива запрещён")).startsWith("Символические ссылки"),"Symbolic-link error was not localized");
            check(InterfaceFailureMessages.archive(new java.io.IOException("Anchor нельзя хранить внутри контейнера")).startsWith("Локальную отметку целостности"),"Integrity-anchor error was not localized");
            check(InterfaceFailureMessages.appearance(new IllegalArgumentException("Недостаточный контраст текста (нужно 4,5:1)")).startsWith("Недостаточный контраст"),"Useful safe validation detail was lost");
            check(InterfaceFailureMessages.diagnostic(parserFailure).equals(List.of("java.io.IOException","java.lang.IllegalArgumentException")),"Bounded cause type diagnostics were lost or contained raw messages");
            performance.put("localizedFailureAndStoredFontChecks","PASS");
            fx(() -> {
                Appearance.Theme longTheme=themes.store().theme("classic-light").copy("Очень длинное русское название оформления");
                themes.store().addTheme(longTheme,themes.settings());
                return null;
            });
            for(String palette:List.of("minimal-dark","classic-light")) for(int percent:new int[]{100,125,150,200}) {
                fx(() -> {var json=themes.settings().manual(palette).json();json.addProperty("scale",percent);themes.commit(Appearance.Settings.parse(json));stage.setWidth(800);stage.setHeight(600);return null;});
                until(() -> Math.abs(stage.getScene().getWidth()-800)<.5&&Math.abs(stage.getScene().getHeight()-600)<.5);
                fx(() -> {
                    long renderStarted=System.nanoTime();AppearanceView editor=new AppearanceView(stage,themes,worker);editor.show();layout(stage);
                    galleryTimings.add(Map.of("theme",palette,"scalePercent",percent,"constructShowCssLayoutNanos",System.nanoTime()-renderStarted));
                    AppearanceGallery gallery=(AppearanceGallery)field(editor,"gallery");
                    @SuppressWarnings("unchecked") Map<String,Selector<String>> fontSelectors=(Map<String,Selector<String>>)field(editor,"fontFamily");
                    for(Selector<String> font:fontSelectors.values()){
                        String before=font.getValue();font.setValue("System");
                        check(font.getValue().equals("System")&&font.getConverter().toString(font.getValue()).equals("Системный")&&font.getConverter().fromString("Системный").equals("System"),"Localized font changed the stored family identifier");font.setValue(before);
                    }
                    var fail=AppearanceView.class.getDeclaredMethod("failure",Exception.class);fail.setAccessible(true);fail.invoke(editor,parserFailure);
                    Label failureLabel=(Label)field(editor,"message");check(!failureLabel.getText().contains("Unsupported")&&!failureLabel.getText().contains("synthetic-secret"),"Appearance failure UI exposed raw data");
                    check(failureLabel.getUserData().equals(InterfaceFailureMessages.diagnostic(parserFailure)),"Appearance did not retain safe cause types");failureLabel.setText("");
                    check(gallery.getChildren().size()==themes.store().themes().size(),"Preset cards disappeared");
                    galleryGeometry(gallery);screenshot(stage,"gallery-"+palette+"-"+percent);ScrollPane galleryScroll=(ScrollPane)((BorderPane)editor.node()).getCenter();galleryScroll.setVvalue(.4);layout(stage);screenshot(stage,"gallery-cards-"+palette+"-"+percent);galleryScroll.setVvalue(0);
                    Set<Integer> previews=new HashSet<>();int modern=0;
                    for(var preset:PresetLibrary.builtins().values())if(preset.category()!=Appearance.Category.LEGACY) {
                        Button choose=(Button)gallery.lookup("#preset-"+preset.id());check(choose!=null,"Missing preset "+preset.id());
                        Canvas canvas=(Canvas)choose.getGraphic();var image=canvas.snapshot(null,null);int hash=1;
                        for(int y=0;y<(int)image.getHeight();y++)for(int x=0;x<(int)image.getWidth();x++)hash=31*hash+image.getPixelReader().getArgb(x,y);
                        previews.add(hash);modern++;
                    }
                    check(modern==16&&previews.size()==16,"The sixteen preset previews are not distinct");
                    ((Button)gallery.lookup("#preset-favorite-forest-green")).fire();
                    CheckBox favorites=(CheckBox)field(editor,"onlyFavorites");favorites.fire();
                    check(gallery.getChildren().size()==1,"Favorites filter lost saved selection");favorites.fire();
                    TextField search=(TextField)field(editor,"search");search.setText("сепия");check(gallery.getChildren().size()==1,"Preset search failed");search.clear();
                    @SuppressWarnings("unchecked") Selector<String> category=(Selector<String>)field(editor,"category");category.setValue("Минимализм");check(gallery.getChildren().size()==4,"Preset category failed");category.setValue("Все");
                    ((Button)gallery.lookup("#preset-forest-green")).fire();button(stage.getScene().getRoot(),"Применить").fire();check(themes.store().current().theme().equals("forest-green"),"Real gallery Apply failed");
                    themes.store().favorite("forest-green",false);return null;
                });
            }
            fx(() -> {
                var json=themes.settings().manual("minimal-dark").json();json.addProperty("scale",100);themes.commit(Appearance.Settings.parse(json));stage.setWidth(1280);stage.setHeight(850);
                archive[0]=new ArchiveView(stage,themes,local);workspace.setCenter(archive[0].node());layout(stage);
                ((Parent)archive[0].node()).lookupAll(".password-field").forEach(n->((PasswordField)n).setText("synthetic independent archive password"));button((Parent)archive[0].node(),"Создать архив").fire();return null;
            });
            long archiveReadyStarted=System.nanoTime();until(() -> archive[0].unlocked()&&!(boolean)field(archive[0],"busy"));performance.put("archiveCreateRemainingWaitNanos",System.nanoTime()-archiveReadyStarted);
            Path fixture=profile.resolve("synthetic-performance-document.txt");Files.writeString(fixture,"synthetic-search-token-250: кириллица и Latin, encrypted archive fixture");
            long importStarted=System.nanoTime();fx(() -> {var method=ArchiveView.class.getDeclaredMethod("importPaths",List.class);method.setAccessible(true);method.invoke(archive[0],List.of(fixture));return null;});
            until(() -> !(boolean)field(archive[0],"busy")&&((ListView<?>)field(archive[0],"list")).getItems().size()==1);performance.put("archiveImportUiThroughCompletionNanos",System.nanoTime()-importStarted);
            fx(() -> {((TextField)field(archive[0],"search")).setText("absent-250-fixture");return null;});until(() -> ((ListView<?>)field(archive[0],"list")).getItems().isEmpty());
            long searchStarted=System.nanoTime();fx(() -> {((TextField)field(archive[0],"search")).setText("synthetic-search-token-250");return null;});until(() -> ((ListView<?>)field(archive[0],"list")).getItems().size()==1);performance.put("archiveSearchIncluding250msDebounceNanos",System.nanoTime()-searchStarted);
            fx(() -> {
                ArchiveView view=archive[0];Parent root=(Parent)view.node();layout(stage);
                var fail=ArchiveView.class.getDeclaredMethod("showFailure",Exception.class);fail.setAccessible(true);fail.invoke(view,parserFailure);
                Label archiveStatus=(Label)field(view,"status");check(!archiveStatus.getText().contains("Unsupported")&&!archiveStatus.getText().contains("synthetic-secret"),"Archive failure UI exposed raw data");
                check(archiveStatus.getUserData().equals(InterfaceFailureMessages.diagnostic(parserFailure)),"Archive did not retain safe cause types");archiveStatus.setText("Файлы добавлены");
                @SuppressWarnings("unchecked") ComboBox<String> type=(ComboBox<String>)field(view,"type");
                check(type.getItems().equals(List.of("Все типы","letter","text","image","pdf","file","folder")),"Cipher/filter type identifiers changed");
                check(type.getConverter().toString("pdf").equals("PDF-документ")&&type.getConverter().toString("letter").equals("Письмо"),"Archive type labels not Russian");
                MenuButton management=(MenuButton)root.lookup("#archive-management-menu");
                check(management.getItems().stream().map(MenuItem::getText).toList().equals(List.of("Защита","Резервные копии","Обслуживание")),"Management groups missing");
                for(MenuItem group:management.getItems())for(MenuItem action:((Menu)group).getItems()) {
                    action.fire();layout(stage);Node panel=root.lookup("#archive-management-panel");check(panel!=null,"Action has no embedded panel: "+action.getText());
                    check(stage.getScene().getRoot().lookupAll(".in-window-page").isEmpty(),"Archive action replaced the page: "+action.getText());
                    check(panel.getBoundsInLocal().getWidth()<=481,"Management form unbounded");
                    check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Archive action opened another Stage");
                    if(action.getText().equals("Пароль архива")){
                        PasswordField secret=(PasswordField)panel.lookup(".password-field");secret.setText("synthetic temporary panel secret");
                        InWindowDialog<Void> nested=new InWindowDialog<>();nested.initOwner(stage);nested.setTitle("Synthetic nested page");nested.getDialogPane().setContent(new Label("Synthetic fixture"));nested.show();nested.close();
                        check(secret.getText().isEmpty(),"Detached management panel retained password");secret.setText("synthetic replacement secret");button(root,"К архиву").fire();check(secret.getText().isEmpty(),"Revisited management cleanup lost its callback");
                    }
                }
                button(root,"К архиву").fire();return null;
            });
            for(String palette:List.of("minimal-dark","classic-light")) for(int percent:new int[]{100,125,150,200}) {
                fx(() -> {var json=themes.settings().manual(palette).json();json.addProperty("scale",percent);themes.commit(Appearance.Settings.parse(json));stage.setWidth(800);stage.setHeight(600);long renderStarted=System.nanoTime();layout(stage);archiveTimings.add(Map.of("theme",palette,"scalePercent",percent,"cssLayoutNanos",System.nanoTime()-renderStarted));screenshot(stage,"archive-"+palette+"-"+percent);return null;});
                until(() -> Math.abs(stage.getScene().getWidth()-800)<.5&&Math.abs(stage.getScene().getHeight()-600)<.5);
                if(percent==200)fx(() -> {
                    Parent root=(Parent)archive[0].node();MenuButton manage=(MenuButton)root.lookup("#archive-management-menu");int index=0;
                    for(MenuItem group:manage.getItems())for(MenuItem action:((Menu)group).getItems()){
                        action.fire();layout(stage);VBox panel=(VBox)root.lookup("#archive-management-panel");check(panel!=null,"Narrow embedded panel absent");
                        ScrollPane scroller=(ScrollPane)((VBox)field(archive[0],"preview")).getChildren().getFirst();Bounds viewport=scroller.localToScene(scroller.getBoundsInLocal());
                        check(viewport.getHeight()>15&&viewport.getWidth()>50,"Narrow management panel cannot scroll");
                        check(viewport.getMinY()>=0&&viewport.getMaxY()<=stage.getScene().getHeight()+.5,"Narrow panel outside scene");
                        scroller.setVvalue(1);layout(stage);if(index++%4==0)screenshot(stage,"archive-panel-"+palette+"-200-"+index);
                        button(root,"К архиву").fire();
                    }
                    return null;
                });
                fx(() -> {Parent root=(Parent)archive[0].node();ToggleButton filters=(ToggleButton)root.lookup("#archive-filter-toggle");if(!filters.isSelected())filters.fire();layout(stage);((ScrollPane)root.lookup("#archive-toolbar-scroll")).setVvalue(1);((ComboBox<?>)field(archive[0],"type")).show();return null;});Thread.sleep(100);
                fx(() -> {popupBounds("types-"+palette+"-"+percent);((ComboBox<?>)field(archive[0],"type")).hide();hidePopups();Parent root=(Parent)archive[0].node();ToggleButton filters=(ToggleButton)root.lookup("#archive-filter-toggle");if(filters.isSelected())filters.fire();((ScrollPane)root.lookup("#archive-toolbar-scroll")).setVvalue(0);return null;});
                fx(() -> {((MenuButton)((Parent)archive[0].node()).lookup("#archive-more-menu")).show();return null;});Thread.sleep(100);
                fx(() -> {popupBounds("actions-"+palette+"-"+percent);return null;});
                boolean nested=fx(() -> {MenuButton more=(MenuButton)((Parent)archive[0].node()).lookup("#archive-more-menu");Menu manage=(Menu)more.getItems().stream().filter(i->i instanceof Menu&&i.getText().equals("Управление")).findFirst().orElseThrow();if(manage.isVisible()){activateVisibleMenu("Управление");}return manage.isVisible();});
                if(nested){Thread.sleep(100);fx(() -> {check(Window.getWindows().stream().filter(w->w instanceof PopupWindow&&w.isShowing()).count()>=2,"Nested management popup did not open: "+palette+"/"+percent);popupBounds("management-"+palette+"-"+percent);activateVisibleMenu("Резервные копии");return null;});Thread.sleep(100);fx(() -> {check(Window.getWindows().stream().filter(w->w instanceof PopupWindow&&w.isShowing()).count()>=3,"Third-level backup popup did not open");popupBounds("backup-menu-"+palette+"-"+percent);return null;});}
                fx(() -> {((MenuButton)((Parent)archive[0].node()).lookup("#archive-more-menu")).hide();hidePopups();return null;});
            }
            fx(() -> {layout(stage);check(Window.getWindows().stream().filter(w->w instanceof Stage&&w.isShowing()).count()==1,"Unexpected Stage after popup checks");return null;});
            var heap=ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();performance.put("heapBytes",Map.of("used",heap.getUsed(),"committed",heap.getCommitted(),"maximum",heap.getMax()));
            var os=ManagementFactory.getOperatingSystemMXBean();long idleStarted=System.nanoTime();long cpuBefore=processCpuNanos();
            Thread.sleep(1500);long idleElapsed=System.nanoTime()-idleStarted;long cpuAfter=processCpuNanos();
            Map<String,Object> idle=new LinkedHashMap<>();idle.put("wallNanos",idleElapsed);idle.put("logicalProcessors",os.getAvailableProcessors());
            if(cpuBefore>=0&&cpuAfter>=cpuBefore){idle.put("cpuMetricStatus","MEASURED");idle.put("processCpuNanosDelta",cpuAfter-cpuBefore);idle.put("normalizedProcessCpuPercent",(cpuAfter-cpuBefore)*100.0/idleElapsed/os.getAvailableProcessors());}
            else idle.put("cpuMetricStatus","UNAVAILABLE_OPTIONAL_JDK_MANAGEMENT");
            performance.put("boundedIdle",idle);performance.put("gallery",galleryTimings);performance.put("archive",archiveTimings);
            Path performanceOutput=Path.of("build/ui250-refinement-performance.json");Files.writeString(performanceOutput,new GsonBuilder().setPrettyPrinting().create().toJson(performance)+"\n");
            System.out.println("Interface250RefinementSmoke PASS: 16 distinct previews, wrapped names/separate favorites, search/category/favorite/apply, Russian archive types with unchanged IDs, 11 embedded management actions, actual ComboBox/MenuButton popups, 100/125/150/200% light/dark; native Windows11/KDE/Tor NOT_RUN");
        } finally {
            fx(() -> {hidePopups();if(archive[0]!=null)archive[0].close();InWindowDialog.closeAll(stage);themes.close();stage.hide();Platform.exit();return null;});
            worker.shutdownNow();local.close();
        }
    }
}
