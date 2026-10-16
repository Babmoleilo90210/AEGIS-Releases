package org.securemail.community.core;
/** Safe API rejection. Internal exceptions must never be serialized to the client. */
public final class CommunityException extends Exception {
  private static final long serialVersionUID=1L;
  private final String code;
  public CommunityException(String code,String message){super(message);this.code=code;}
  public String code(){return code;}
  public String safeRussianMessage(){return getMessage();}
  public static CommunityException denied(){return new CommunityException("DENIED","Недостаточно полномочий");}
  public static CommunityException missing(){return new CommunityException("NOT_FOUND","Материал недоступен");}
  public static CommunityException invalid(){return new CommunityException("INVALID","Некорректный запрос");}
  public static CommunityException conflict(){return new CommunityException("CONFLICT","Данные изменены. Обновите страницу");}
}
