package org.securemail.client.update;

import java.io.*;
import java.security.GeneralSecurityException;
import javax.net.ssl.SSLException;

/** Bounded diagnostics: only enums and exception class names, never exception messages/URLs. */
public record UpdateDiagnostic(Category category, String code, String exceptionType) {
  public enum Category { TRANSPORT, TLS, HTTP, SIGNATURE, SCHEMA, POLICY, STORAGE, CANCELLED, INTERNAL }
  public enum Phase { FETCH, VERIFY, POLICY, STORE, DOWNLOAD, PACKAGE }
  public static final class Failure extends IOException {
    private static final long serialVersionUID=1L;
    public final Category category; public final String code;
    public Failure(Category category,String code){super(code);this.category=category;this.code=code;}
  }
  static UpdateDiagnostic failure(Throwable error,Phase phase) {
    Category category;String code;
    if(error instanceof Failure f){category=f.category;code=f.code;}
    else if(error instanceof SSLException){category=Category.TLS;code="TLS_VALIDATION_OR_HANDSHAKE";}
    else if(error instanceof GeneralSecurityException){category=Category.SIGNATURE;code=phase==Phase.PACKAGE?"PACKAGE_HASH_REJECTED":"ED25519_REJECTED";}
    else if(error instanceof InterruptedIOException && Thread.currentThread().isInterrupted()){category=Category.CANCELLED;code="CANCELLED";}
    else {category=switch(phase){case FETCH,DOWNLOAD->Category.TRANSPORT;case VERIFY->Category.SCHEMA;case POLICY->Category.POLICY;case STORE->Category.STORAGE;case PACKAGE->Category.SCHEMA;};code=switch(phase){case FETCH,DOWNLOAD->"TOR_REQUEST_FAILED";case VERIFY->"SIGNED_MANIFEST_SCHEMA";case POLICY->"UPDATE_POLICY_REJECTED";case STORE->"UPDATE_STATE_IO";case PACKAGE->"PACKAGE_INVALID";};}
    return new UpdateDiagnostic(category,code,error.getClass().getSimpleName());
  }
  public String userMessage(){return switch(category){
    case TRANSPORT->"Не удалось подключиться к обновлениям через Tor";
    case TLS->"Не удалось проверить защищённое соединение с сервером обновлений";
    case HTTP->"Сервер обновлений вернул неподдерживаемый ответ";
    case SIGNATURE->"Цифровая подпись или SHA-256 обновления отклонены";
    case SCHEMA->"Подписанные данные обновления имеют неподдерживаемый формат";
    case POLICY->"Обновление отклонено политикой защиты от отката";
    case STORAGE->"Не удалось сохранить данные обновления на этом устройстве";
    case CANCELLED->"Скачивание отменено";
    case INTERNAL->"Не удалось завершить проверку обновления";};}
  public String technical(){return "Категория: "+category+" · Код: "+code+(exceptionType.isEmpty()?"":" · Тип: "+exceptionType);}
}
