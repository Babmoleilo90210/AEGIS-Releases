package org.securemail.client.safeweb600;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.file.AccessDeniedException;
import org.securemail.client.net.EmbeddedTor;
import org.securemail.client.safeweb.SandboxPrerequisites;

/** Fixed diagnostic codes only: raw native output, URLs and private paths never enter UI errors. */
public final class VzorFailure600 extends IOException {
  private static final long serialVersionUID=1L;
  public enum Code {
    AUTHORIZATION_REQUIRED("Откройте Взор кнопкой в АЕГИС. Передача учётной записи браузеру не требуется."),
    STARTUP_BUSY("Запуск Взора уже выполняется. Дождитесь завершения подготовки."),
    STARTUP_TIMEOUT("Окно Взора не подтвердило запуск вовремя. Его собственный процесс остановлен; попробуйте ещё раз."),
    STARTUP_REJECTED("Взор не подтвердил защищённый локальный запуск. Непроверенный процесс не используется."),
    RUNTIME_MISSING("В комплекте АЕГИС отсутствует Java или модуль Взора. Восстановите полный проверенный пакет приложения."),
    STATE_UNAVAILABLE("Не удалось открыть отдельный каталог Взора. Проверьте права пользователя и свободное место; профиль АЕГИС не используется."),
    ALREADY_RUNNING("Взор уже открыт в отдельном окне. Используйте его существующее окно."),
    TOR_BINARY_MISSING("В полном пакете АЕГИС отсутствует исполняемый Tor для подготовки Взора. Восстановите проверенный пакет; системный или почтовый Tor не используется."),
    TOR_RUNTIME_FAILED("Отдельный Tor подготовки Взора не смог запустить собственную конфигурацию. Проверьте полный пакет приложения, его архитектуру и разрешения ОС; чужой Tor не используется."),
    TOR_UNAVAILABLE("Отдельный Tor подготовки Взора не подключился. Повторите подключение или выберите Snowflake; сеть почты не изменялась."),
    PORT_UNAVAILABLE("Не удалось выделить отдельные локальные порты Взора. Повторите запуск; чужой Tor не используется."),
    UI_UNAVAILABLE("Не удалось открыть окно Взора в текущем графическом сеансе. Запустите АЕГИС внутри обычного сеанса Windows или KDE."),
    CANCELLED("Подготовка Взора отменена. Небезопасный обход изоляции не выполнялся."),
    CLOSE_INCOMPLETE("Завершение собственных процессов Взора не подтверждено. Повторите закрытие окна; почтовый Tor не останавливался."),
    PREPARATION_FAILED("Подготовка Взора не завершена. Проверьте отдельное подключение Tor и компоненты изоляции; предыдущая установка сохранена.");
    private final String russian;
    Code(String russian){this.russian=russian;}
    public String russian(){return russian;}
  }
  private final Code code;
  public VzorFailure600(Code code){super(code.russian());this.code=code;}
  public Code code(){return code;}
  public static String safeMessage(Throwable error){
    for(int i=0;i<8&&error!=null;i++,error=error.getCause()){
      if(error instanceof VzorFailure600 known)return known.code.russian();
      if(error instanceof SandboxPrerequisites.Failure known)return known.code().message();
      if(error instanceof EmbeddedTor.BootstrapFailure)return Code.TOR_UNAVAILABLE.russian();
      if(error instanceof InterruptedIOException||error instanceof InterruptedException)return Code.CANCELLED.russian();
      if(error instanceof AccessDeniedException)return Code.STATE_UNAVAILABLE.russian();
    }
    return Code.PREPARATION_FAILED.russian();
  }
}
