package org.securemail.ui;

import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import javafx.animation.*;
import javafx.application.*;
import javafx.geometry.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import javafx.util.Duration;
import org.securemail.client.*;
import org.securemail.client.crypto.*;
import org.securemail.client.net.NetworkService;
import org.securemail.client.storage.LocalStore;
import org.securemail.protocol.*;

/** Thin JavaFX UI. Disk, Argon2 and network work run off the UI thread. */
public final class AegisApp extends Application {
  private Stage stage;
  private BorderPane shell;
  private VBox content;
  private final Label status = new Label("Сеть отключена");
  private final ExecutorService worker =
      Executors.newSingleThreadExecutor(
          r -> {
            Thread t = new Thread(r, "aegis-ui-work");
            t.setDaemon(true);
            return t;
          });
  private Path configFile;
  private ClientConfig config;
  private ClientSession session;
  private Timeline ticks;
  private boolean busy;
  private String page = "";
  private int counter;
  private final Map<Label, Long> countdowns = new HashMap<>();
  private final List<Viewer> viewers = new ArrayList<>();

  private record Viewer(InWindowDialog<Void> stage, TextArea text, PlainMessage message, long expires) {}

  private record Ttl(String label, long seconds) {
    @Override
    public String toString() {
      return label;
    }
  }

  public static Path defaultConfig() {
    return ClientConfig.path("~/.config/aegis/client.properties");
  }

  @Override
  public void start(Stage stage) throws Exception {
    this.stage = stage;
    configFile =
        (getParameters() == null || getParameters().getRaw().isEmpty())
            ? defaultConfig()
            : Path.of(getParameters().getRaw().getFirst());
    config = ClientConfig.load(configFile);
    shell = new BorderPane();
    shell.getStyleClass().add("shell");
    Scene scene = new Scene(shell, 1000, 740);
    scene.getStylesheets().add(css());
    stage.setTitle("АЕГИС — Автономная Единая Гибридная Информационная Система");
    stage.setMinWidth(820);
    stage.setMinHeight(620);
    stage.setScene(scene);
    stage.setOnCloseRequest(e -> closeViewers());
    loginPage();
    stage.show();
    ticks = new Timeline(new KeyFrame(Duration.seconds(1), e -> tick()));
    ticks.setCycleCount(Timeline.INDEFINITE);
    ticks.play();
  }

  private String css() {
    return Objects.requireNonNull(getClass().getResource("/aegis.css")).toExternalForm();
  }

  private void layout(String heading, boolean navigation) {
    countdowns.clear();
    page = heading;
    Label brand = new Label("АЕГИС"), title = new Label(heading);
    brand.getStyleClass().add("brand");
    title.getStyleClass().add("section-title");
    Region space = new Region();
    HBox.setHgrow(space, Priority.ALWAYS);
    var top = new HBox(24, brand, title, space);
    top.setAlignment(Pos.CENTER_LEFT);
    top.getStyleClass().add("topbar");
    if (session != null)
      top.getChildren().add(button("Закрыть хранилище", () -> closeSession(this::loginPage)));
    shell.setTop(top);
    shell.setLeft(null);
    content = new VBox(16);
    content.setPadding(new Insets(28, 32, 28, 32));
    content.setMaxWidth(850);
    var scroll = new ScrollPane(content);
    scroll.setFitToWidth(true);
    shell.setCenter(scroll);
    if (navigation) {
      var nav =
          new VBox(
              8,
              nav("Входящие", this::inboxPage),
              nav("Новое письмо", this::composePage),
              nav("Контакты", this::contactsPage),
              nav("Настройки", this::settingsPage),
              nav("Статус сети", this::networkPage));
      nav.setPrefWidth(175);
      nav.getStyleClass().add("navigation");
      shell.setLeft(nav);
    }
    var footer = new HBox(status);
    footer.getStyleClass().add("footer");
    shell.setBottom(footer);
  }

  private Button nav(String name, Runnable action) {
    var b = button(name, action);
    b.setMaxWidth(Double.MAX_VALUE);
    b.getStyleClass().add("nav-button");
    return b;
  }

  private void loginPage() {
    layout("Вход", false);
    var full = new Label("Автономная Единая Гибридная\nИнформационная Система");
    full.getStyleClass().add("hero-title");
    var nick = new TextField();
    nick.setPromptText("raven");
    var account = new PasswordField();
    account.setPromptText("Пароль аккаунта");
    var vault = new PasswordField();
    vault.setPromptText("Отдельный пароль локального хранилища");
    var form =
        new VBox(
            10,
            field("Nickname", nick),
            field("Пароль аккаунта · не менее 12 символов", account),
            field("Пароль хранилища · не менее 12 символов", vault));
    form.setMaxWidth(480);
    content
        .getChildren()
        .addAll(
            full,
            muted(
                "Закрытая почта для доверенных людей.\n"
                    + "Каждое письмо открывается только после ввода его ключа."),
            form,
            new HBox(
                10,
                primary("Войти", () -> unlock(nick, account, vault, false, false)),
                button("Зарегистрироваться", () -> unlock(nick, account, vault, true, false))),
            button("Открыть локально", () -> unlock(nick, account, vault, false, true)),
            muted(
                "При первом открытии создаётся хранилище. Запомните его пароль:\n"
                    + "восстановления и мастер-ключа нет. Каждый аккаунт использует свою папку."),
            button("Настроить подключение", this::settingsPage));
  }

  private void unlock(
      TextField nick,
      PasswordField account,
      PasswordField vault,
      boolean register,
      boolean offline) {
    char[] a = account.getText().toCharArray(), v = vault.getText().toCharArray();
    String name = nick.getText().strip();
    account.clear();
    vault.clear();
    task(
        () -> {
          ClientSession opened = null;
          try {
            opened = new ClientSession(config, v);
            if (!offline) opened.login(name, a, register);
            return opened;
          } catch (Exception e) {
            if (opened != null) opened.close();
            throw e;
          } finally {
            Arrays.fill(a, '\0');
            Arrays.fill(v, '\0');
          }
        },
        opened -> {
          session = opened;
          inboxPage();
        });
  }

  private void inboxPage() {
    layout("Входящие", true);
    content
        .getChildren()
        .addAll(
            muted("Только зашифрованные письма до окончания их срока."),
            button("Обновить список", this::inboxPage));
    var rows = new VBox(0);
    content.getChildren().add(rows);
    ClientSession current = session;
    task(
        () -> current.local().inbox(),
        items -> {
          if (!page.equals("Входящие") || current != session) return;
          if (items.isEmpty()) rows.getChildren().add(muted("Входящих писем нет."));
          for (var item : items) {
            var sender = new Label("◈  " + item.sender());
            sender.getStyleClass().add("sender");
            var alg = muted(item.algorithm().toString());
            if (item.algorithm() == Algorithm.ENIGMA) alg.getStyleClass().add("warning");
            var when =
                muted(
                    DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")
                        .withZone(ZoneId.systemDefault())
                        .format(Instant.ofEpochMilli(item.receivedAt())));
            var remaining = new Label();
            countdowns.put(remaining, item.expiresAt());
            var details = new VBox(5, sender, alg, when, remaining);
            Region space = new Region();
            HBox.setHgrow(space, Priority.ALWAYS);
            var remove =
                button(
                    "Удалить",
                    () -> {
                      if (confirm(
                          "Удалить письмо?", "Локальная зашифрованная копия будет удалена."))
                        task(
                            () -> {
                              session.local().delete(item.messageId());
                              return true;
                            },
                            ok -> inboxPage());
                    });
            var row =
                new HBox(
                    16,
                    details,
                    space,
                    new VBox(8, button("Расшифровать", () -> decrypt(item)), remove));
            row.setAlignment(Pos.CENTER_LEFT);
            row.getStyleClass().add("mail-row");
            rows.getChildren().add(row);
          }
          tick();
        });
  }

  private void decrypt(LocalStore.InboxItem item) {
    if (item.expiresAt() <= session.local().now()) {
      info("Письмо уже удалено по времени.");
      inboxPage();
      return;
    }
    var key = new PasswordField();
    key.setPromptText("Ключ этого письма");
    var box = new VBox(12, new Label("Введите ключ сообщения"), key);
    if (item.algorithm() == Algorithm.ENIGMA)
      box.getChildren()
          .add(
              warning(
                  Algorithm.ENIGMA_WARNING
                      + "\nНеверный ключ может дать бессмысленный текст без ошибки."));
    InWindowDialog<ButtonType> dialog = new InWindowDialog<>();
    dialog.initOwner(stage);
    dialog.setTitle("Локальное расшифрование");
    style(dialog.getDialogPane());
    dialog.getDialogPane().setContent(box);
    dialog.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);
    if (dialog.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) {
      key.clear();
      return;
    }
    char[] secret = key.getText().toCharArray();
    key.clear();
    ClientSession current = session;
    task(
        () -> {
          try {
            return current
                .crypto()
                .decrypt(current.local().load(item.messageId()), secret, config.maxFileSize());
          } finally {
            Arrays.fill(secret, '\0');
          }
        },
        message -> {
          if (session != current || current.local().now() >= item.expiresAt()) {
            message.close();
            info("Срок письма истёк.");
            return;
          }
          InWindowDialog<Void> view = new InWindowDialog<>();
          view.initOwner(stage);
          view.setTitle("АЕГИС · локальный просмотр");
          var text = new TextArea(message.text());
          text.setEditable(false);
          text.setWrapText(true);
          text.setPrefRowCount(14);
          var root =
              new VBox(
                  14,
                  new Label("От: " + item.sender()),
                  text,
                  muted("Просмотр закроется по TTL. После закрытия текст исчезнет из интерфейса."));
          root.setPadding(new Insets(24));
          if (!message.filename().isEmpty()) {
            root.getChildren()
                .add(
                    new Label(
                        "Вложение: " + message.filename() + " · " + message.fileSize() + " байт"));
            root.getChildren()
                .add(
                    button(
                        "Сохранить расшифрованное вложение…",
                        () -> {
                          if (session == null || session.local().now() >= item.expiresAt()) {
                            view.close();
                            return;
                          }
                          if (!confirm(
                              "Сохранить файл на диск?",
                              "Это открытая копия. TTL не удаляет экспортированные файлы.")) return;
                          var chooser = new InWindowFileChooser();
                          chooser.setInitialFileName(message.filename());
                          var target = chooser.showSaveDialog(stage);
                          if (target != null
                              && view.isShowing()
                              && session == current
                              && current.local().now() < item.expiresAt())
                            try {
                              message.exportTo(target.toPath());
                              info("Файл сохранён без автоматического открытия.");
                            } catch (Exception e) {
                              error(e);
                            }
                        }));
          }
          root.getChildren().add(button("Закрыть", view::close));
          root.getStylesheets().add(css());
          view.getDialogPane().setContent(root);
          var viewer = new Viewer(view, text, message, item.expiresAt());
          viewers.add(viewer);
          view.onClose(
              () -> {
                text.clear();
                message.close();
                viewers.remove(viewer);
              });
          view.show();
        });
  }

  private void composePage() {
    layout("Новое письмо", true);
    var to = new ComboBox<String>();
    to.setEditable(true);
    to.setPromptText("Точный nickname");
    to.getItems().addAll(session.local().contacts().stream().map(UserInfo::nickname).toList());
    to.setMaxWidth(Double.MAX_VALUE);
    var alg = new ComboBox<Algorithm>();
    alg.getItems().addAll(Algorithm.values());
    alg.setValue(Algorithm.AES_256_GCM);
    alg.setMaxWidth(Double.MAX_VALUE);
    var key = new PasswordField();
    key.setPromptText("Уникальный пароль письма · от 12 символов");
    var ttl = new ComboBox<Ttl>();
    ttl.getItems()
        .addAll(
            new Ttl("1 минута", 60),
            new Ttl("5 минут", 300),
            new Ttl("10 минут", 600),
            new Ttl("30 минут", 1800),
            new Ttl("1 час", 3600),
            new Ttl("6 часов", 21600),
            new Ttl("24 часа", 86400),
            new Ttl("Своё значение", -1));
    ttl.setPromptText("Обязательно выберите срок");
    ttl.setMaxWidth(Double.MAX_VALUE);
    var custom = new TextField("" + config.defaultTTL());
    custom.setPromptText("Секунды: 1–604800");
    custom.setVisible(false);
    custom.setManaged(false);
    ttl.valueProperty()
        .addListener(
            (o, a, b) -> {
              custom.setVisible(b != null && b.seconds() < 0);
              custom.setManaged(custom.isVisible());
            });
    var text = new TextArea();
    text.setPromptText("Текст письма");
    text.setWrapText(true);
    text.setPrefRowCount(8);
    var warn = warning(Algorithm.ENIGMA_WARNING);
    var accept = new CheckBox("Понимаю ограничения исторического режима");
    warn.setVisible(false);
    warn.setManaged(false);
    accept.setVisible(false);
    accept.setManaged(false);
    alg.valueProperty()
        .addListener(
            (o, a, b) -> {
              boolean weak = b == Algorithm.ENIGMA;
              warn.setVisible(weak);
              warn.setManaged(weak);
              accept.setVisible(weak);
              accept.setManaged(weak);
              key.setPromptText(
                  weak ? "Три заглавные буквы A–Z" : "Уникальный пароль письма · от 12 символов");
            });
    Path[] attachment = {null};
    var filename = muted("Без вложения");
    var attach =
        button(
            "Прикрепить архив / TXT",
            () -> {
              var c = new InWindowFileChooser();
              c.getExtensionFilters()
                  .add(
                      new FileChooser.ExtensionFilter(
                          "Разрешённые файлы", "*.txt", "*.zip", "*.7z", "*.tar", "*.tar.gz"));
              var f = c.showOpenDialog(stage);
              if (f != null) {
                attachment[0] = f.toPath();
                filename.setText(f.getName());
              }
            });
    var send =
        primary(
            "Зашифровать и отправить",
            () -> {
              try {
                if (!session.online())
                  throw new IllegalArgumentException("Для отправки войдите в аккаунт через Tor");
                String nick = Limits.nickname(to.getEditor().getText().strip());
                UserInfo contact = session.local().contact(nick);
                if (contact == null)
                  throw new IllegalArgumentException(
                      "Сначала добавьте контакт и проверьте отпечаток");
                if (ttl.getValue() == null)
                  throw new IllegalArgumentException("Выберите время удаления после доставки");
                long seconds =
                    ttl.getValue().seconds() < 0
                        ? Long.parseLong(custom.getText())
                        : ttl.getValue().seconds();
                if (seconds < 1 || seconds > Limits.MAX_TTL_SECONDS)
                  throw new IllegalArgumentException("TTL: 1–604800 секунд");
                Algorithm choice = alg.getValue();
                if (choice == Algorithm.ENIGMA && !accept.isSelected())
                  throw new IllegalArgumentException("Подтвердите ограничения Enigma");
                char[] secret = key.getText().toCharArray();
                key.clear();
                String body = text.getText();
                Path file = attachment[0];
                ClientSession current = session;
                task(
                    () -> {
                      try (var message =
                          file == null
                              ? PlainMessage.text(body)
                              : PlainMessage.withFile(body, file, config.maxFileSize())) {
                        var packet =
                            current
                                .crypto()
                                .encrypt(
                                    message,
                                    secret,
                                    choice,
                                    seconds,
                                    config.deliveryTTL(),
                                    current.local().identity(),
                                    current.local().nickname(),
                                    contact.userId());
                        return current.network().deliver(packet);
                      } finally {
                        Arrays.fill(secret, '\0');
                      }
                    },
                    result -> {
                      text.clear();
                      attachment[0] = null;
                      filename.setText("Без вложения");
                      info(
                          result == NetworkService.Delivery.P2P_CONFIRMED
                              ? "Доставлено напрямую. Получатель подтвердил сохранение; TTL"
                                  + " начался."
                              : "Письмо принято relay. TTL начнётся после доставки получателю.");
                    });
              } catch (Exception e) {
                error(e);
              }
            });
    content
        .getChildren()
        .addAll(
            field("Кому", to),
            field("Шифр", alg),
            warn,
            accept,
            field("Ключ сообщения", key),
            field("Удалить после доставки через", ttl),
            custom,
            field("Сообщение", text),
            new HBox(
                10,
                attach,
                button(
                    "Убрать",
                    () -> {
                      attachment[0] = null;
                      filename.setText("Без вложения");
                    })),
            filename,
            muted(
                "Вложение: до "
                    + config.maxFileSize() / 1024 / 1024
                    + " МБ. Без превью и автоматического открытия.\n"
                    + "Недоставленное письмо ожидает на relay не более "
                    + config.deliveryTTL() / 86400_000
                    + " суток."),
            send);
  }

  private void contactsPage() {
    layout("Контакты", true);
    var fingerprint = new TextArea(Identity.fingerprint(session.local().identity().publicKey()));
    fingerprint.setEditable(false);
    fingerprint.setPrefRowCount(2);
    fingerprint.setWrapText(true);
    content
        .getChildren()
        .add(field("Ваш отпечаток · передайте по доверенному каналу", fingerprint));
    var nick = new TextField();
    nick.setPromptText("Точное совпадение nickname");
    content
        .getChildren()
        .add(
            new HBox(
                10,
                nick,
                button(
                    "Найти",
                    () -> {
                      if (!session.online()) {
                        info("Поиск доступен после входа через Tor.");
                        return;
                      }
                      String name = nick.getText().strip();
                      task(
                          () -> session.network().find(name),
                          user -> {
                            if (confirm(
                                "Проверка контакта: " + user.nickname(),
                                "Сверьте весь отпечаток по другому доверенному каналу:\n\n"
                                    + Identity.fingerprint(user.publicKey())
                                    + "\n\nНе подтверждайте только по ответу relay."))
                              task(
                                  () -> {
                                    session.local().trust(user);
                                    return true;
                                  },
                                  ok -> contactsPage());
                          });
                    })));
    for (UserInfo u : session.local().contacts()) {
      var row =
          new HBox(
              16,
              new VBox(6, new Label(u.nickname()), muted(Identity.fingerprint(u.publicKey()))),
              button(
                  "Удалить",
                  () -> {
                    if (confirm("Удалить контакт?", u.nickname()))
                      task(
                          () -> {
                            session.local().removeContact(u.nickname());
                            return true;
                          },
                          ok -> contactsPage());
                  }));
      row.getStyleClass().add("mail-row");
      content.getChildren().add(row);
    }
    content
        .getChildren()
        .add(
            muted(
                "Оба участника добавляют друг друга до обмена письмами.\n"
                    + "Изменение ключа блокирует отправку. Глобального поиска нет."));
  }

  private void settingsPage() {
    layout("Настройки", session != null);
    var relay = new TextField(config.relayOnionAddress());
    relay.setPromptText("Адрес вашего relay: …onion");
    var socks = new TextField("" + config.torSocksPort());
    var control = new TextField("" + config.torControlPort());
    var localPort = new TextField("" + config.localServicePort());
    var cookie = new TextField(config.torCookiePath().toString());
    var storage = new TextField(config.storagePath().toString());
    var ttl = new TextField("" + config.defaultTTL());
    var save =
        primary(
            "Сохранить настройки",
            () -> {
              try {
                config =
                    new ClientConfig(
                        "127.0.0.1",
                        Integer.parseInt(socks.getText()),
                        Integer.parseInt(control.getText()),
                        ClientConfig.path(cookie.getText()),
                        Integer.parseInt(localPort.getText()),
                        Long.parseLong(ttl.getText()),
                        relay.getText().strip(),
                        config.relayPort(),
                        ClientConfig.path(storage.getText()),
                        config.maxFileSize(),
                        config.maxLocalStorage(),
                        config.deliveryTTL());
                config.save(configFile);
                info("Настройки сохранены.");
                loginPage();
              } catch (Exception e) {
                error(e);
              }
            });
    save.setDisable(session != null);
    content
        .getChildren()
        .addAll(
            field("Relay onion · один раз задаётся владельцем сервера", relay),
            field("Tor SOCKS · 127.0.0.1", socks),
            field("Tor Control · 127.0.0.1", control),
            field("Cookie отдельного экземпляра Tor", cookie),
            field("Локальный порт P2P", localPort),
            field("Локальное хранилище", storage),
            field("Начальное значение своего TTL · секунды", ttl),
            save,
            muted(
                "Для изменения настроек закройте хранилище. Firewall настраивается отдельно.\n"
                    + "Программа не скачивает обновления и не отправляет диагностику."));
    if (session == null) content.getChildren().add(button("Ко входу", this::loginPage));
  }

  private void networkPage() {
    layout("Статус сети", true);
    content
        .getChildren()
        .addAll(
            new Label(session.status()),
            muted(
                "Единственный исходящий канал сообщений — SOCKS Tor на 127.0.0.1:"
                    + config.torSocksPort()
                    + ".\nControlPort создаёт onion service без ручного обмена адресами."),
            field("Ваш relay", new Label(config.relayOnionAddress())),
            muted(
                "Если Tor недоступен, сетевой обмен останавливается. Прямого подключения нет.\n"
                    + "P2P использует onion service получателя; иначе письмо ожидает на relay.\n"
                    + "Синхронизация — каждые 15 секунд. Сессия аккаунта — 12 часов."),
            button("Обновить статус", this::networkPage));
  }

  private void tick() {
    if (session == null) return;
    long now = session.local().now();
    status.setText(session.status());
    boolean expired = false;
    for (var e : countdowns.entrySet()) {
      long seconds = Math.max(0, (e.getValue() - now + 999) / 1000);
      e.getKey()
          .setText(
              seconds == 0
                  ? "Срок истёк"
                  : "Удаление через "
                      + String.format(
                          Locale.ROOT,
                          "%02d:%02d:%02d",
                          seconds / 3600,
                          seconds / 60 % 60,
                          seconds % 60));
      if (seconds == 0) expired = true;
    }
    for (Viewer v : List.copyOf(viewers)) if (v.expires() <= now) v.stage().close();
    if (!busy && page.equals("Входящие") && (expired || ++counter >= 15)) {
      counter = 0;
      inboxPage();
    }
  }

  private void closeViewers() {
    for (Viewer v : List.copyOf(viewers)) v.stage().close();
  }

  private void closeSession(Runnable after) {
    closeViewers();
    ClientSession old = session;
    task(
        () -> {
          if (old != null) old.close();
          return true;
        },
        ok -> {
          session = null;
          status.setText("Сеть отключена");
          after.run();
        });
  }

  private <T> void task(Callable<T> job, Consumer<T> success) {
    if (busy) return;
    busy = true;
    shell.setDisable(true);
    status.setText("Выполняется…");
    worker.submit(
        () -> {
          try {
            T result = job.call();
            Platform.runLater(
                () -> {
                  busy = false;
                  shell.setDisable(false);
                  success.accept(result);
                });
          } catch (Exception e) {
            Platform.runLater(
                () -> {
                  busy = false;
                  shell.setDisable(false);
                  error(e);
                });
          }
        });
  }

  private void error(Exception e) {
    String m;
    if (e instanceof java.security.GeneralSecurityException)
      m = "Неверный пароль/ключ или нарушена целостность данных.";
    else if (e instanceof IllegalArgumentException || e instanceof java.io.IOException)
      m = e.getMessage();
    else m = "Операция не завершена. Проверьте настройки, права и свободное место.";
    if (m == null || m.length() > 500) m = "Операция не завершена.";
    var a = new InWindowAlert(Alert.AlertType.ERROR, m, ButtonType.OK);
    a.setHeaderText("АЕГИС");
    a.initOwner(stage);
    style(a.getDialogPane());
    a.showAndWait();
  }

  private void info(String m) {
    var a = new InWindowAlert(Alert.AlertType.INFORMATION, m, ButtonType.OK);
    a.setHeaderText("АЕГИС");
    a.initOwner(stage);
    style(a.getDialogPane());
    a.showAndWait();
  }

  private boolean confirm(String title, String m) {
    var a = new InWindowAlert(Alert.AlertType.CONFIRMATION, m, ButtonType.OK, ButtonType.CANCEL);
    a.setHeaderText(title);
    a.initOwner(stage);
    style(a.getDialogPane());
    return a.showAndWait().orElse(ButtonType.CANCEL) == ButtonType.OK;
  }

  private void style(DialogPane pane) {
    pane.getStylesheets().add(css());
  }

  private static VBox field(String title, Node node) {
    var l = new Label(title);
    l.getStyleClass().add("field-label");
    return new VBox(7, l, node);
  }

  private static Label muted(String text) {
    var l = new Label(text);
    l.setWrapText(true);
    l.getStyleClass().add("muted");
    return l;
  }

  private static Label warning(String text) {
    var l = muted(text);
    l.getStyleClass().add("warning");
    return l;
  }

  private static Button button(String text, Runnable action) {
    var b = new Button(text);
    b.setOnAction(e -> action.run());
    return b;
  }

  private static Button primary(String text, Runnable action) {
    var b = button(text, action);
    b.getStyleClass().add("primary");
    return b;
  }

  @Override
  public void stop() {
    if (stage != null) InWindowDialog.closeAll(stage);
    if (ticks != null) ticks.stop();
    closeViewers();
    worker.shutdownNow();
    if (session != null)
      try {
        session.close();
      } catch (Exception ignored) {
      }
  }
}
