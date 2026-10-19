package org.securemail.client.ecosystemauth;

import java.util.*;

/** Bounded in-memory arrival detection. Initial/history pages never trigger presentation. */
public final class CoreNotificationArrivals600 implements AutoCloseable {
  public static final int MAX_SEEN=1024,MAX_PAGE=500;
  public record Notice(String id,boolean read,long createdAt,String title){
    public Notice{if(id==null||!id.matches("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")||createdAt<0||title==null||title.length()>1024)throw new IllegalArgumentException("Некорректное уведомление");}
  }
  public record Presentation(int count,String text,boolean sound,boolean banner){}
  private final LinkedHashSet<String> seen=new LinkedHashSet<>();private long watermark;private boolean initialized,closed;
  public synchronized Optional<Presentation> observe(List<Notice> page,boolean history,CoreNotificationPreferences600.Settings settings){
    Objects.requireNonNull(page);Objects.requireNonNull(settings);if(page.size()>MAX_PAGE)throw new IllegalArgumentException("Слишком много уведомлений");if(closed)return Optional.empty();
    int unread=0;String first="";long newest=watermark;
    for(Notice notice:page){Objects.requireNonNull(notice);boolean known=seen.contains(notice.id());
      if(initialized&&!history&&!known&&!notice.read()&&notice.createdAt()>0&&notice.createdAt()>=watermark){unread++;if(first.isEmpty())first=safeTitle(notice.title());}
      seen.add(notice.id());while(seen.size()>MAX_SEEN)seen.remove(seen.iterator().next());newest=Math.max(newest,notice.createdAt());
    }
    watermark=newest;if(!history)initialized=true;
    if(unread==0||!settings.sound()&&!settings.banner())return Optional.empty();
    String text=settings.hideDetails()?"Новое уведомление АЕГИС.":unread==1&&!first.isBlank()?first:"Новых уведомлений: "+unread;
    return Optional.of(new Presentation(unread,text,settings.sound(),settings.banner()));
  }
  private static String safeTitle(String title){StringBuilder text=new StringBuilder();title.codePoints().filter(c->!Character.isISOControl(c)&&Character.getType(c)!=Character.FORMAT).limit(240).forEach(text::appendCodePoint);return text.toString().strip();}
  public synchronized int retainedIds(){return seen.size();}
  @Override public synchronized void close(){closed=true;seen.clear();watermark=0;initialized=false;}
}
