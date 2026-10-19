package org.aegis.android;
/** One explicit purpose per non-reused Android permission request; lock cancels late callbacks. */
public final class MicrophonePermissionGate {
  public enum Purpose {NONE,MIC_TEST,CODEC_TEST,CALL}
  private volatile Purpose purpose=Purpose.NONE;private int request=-1,serial=1000;
  public Purpose pending(){return purpose;}
  public int begin(Purpose next){if(next==null||next==Purpose.NONE||purpose!=Purpose.NONE||serial>=65000)throw new IllegalStateException("Запрос микрофона уже выполняется или исчерпан");purpose=next;request=++serial;return request;}
  public Purpose consume(int id,boolean granted){if(id!=request||purpose==Purpose.NONE)return Purpose.NONE;Purpose result=granted?purpose:Purpose.NONE;cancel();return result;}
  public void cancel(){purpose=Purpose.NONE;request=-1;}
}
