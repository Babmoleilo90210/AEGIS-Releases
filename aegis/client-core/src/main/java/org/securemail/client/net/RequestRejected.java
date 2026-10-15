package org.securemail.client.net;
public final class RequestRejected extends java.io.IOException {
  private final int code;
  public RequestRejected(int code){super(switch(code){case 2->"Регистрация на этом сервере временно закрыта. Обратитесь к владельцу сервера.";case 3->"Этот ник не разрешён сервером.";case 4->"Ник уже занят";case 5->"На сервере достигнут предел аккаунтов";case 6->"Неверный ник или пароль";case 7->"Слишком много попыток. Попробуйте позже.";default->"Сервер отклонил запрос. Проверьте данные и настройки регистрации у владельца сервера.";});this.code=code;}
  public int code(){return code;}
}
