package org.securemail.client.storage;

import java.util.*;
import org.securemail.client.crypto.*;

/** Local query over encrypted mail, decrypted one packet at a time; no plaintext disk index. */
public final class LocalMailSearch {
  public enum Scope {
    ALL("Все письма"),INBOX("Входящие"),SENT("Отправленные"),UNKNOWN("Неизвестные"),BLOCKED("Заблокированные"),FAVORITES("Избранное"),FRIENDS("Друзья");
    private final String label;Scope(String label){this.label=label;}public String toString(){return label;}
  }
  public record Query(String nickname,String subject,long from,long to,Scope scope){
    public Query{if(nickname.length()>32||subject.length()>500||from<0||to<from||scope==null)throw new IllegalArgumentException("Некорректный поиск");}
  }
  public record Result(LocalStore.MailItem item,String subject,boolean protectedLetter,boolean unknown,boolean signatureValid,String threadId,String peerId,int fileCount,String snippet){
    public Result(LocalStore.MailItem item,String subject,boolean protectedLetter,boolean unknown,boolean signatureValid,String threadId,String peerId,int fileCount){this(item,subject,protectedLetter,unknown,signatureValid,threadId,peerId,fileCount,"");}
  }
  private LocalMailSearch(){}
  public static List<Result> find(LocalStore local,LocalFeatures features,Query query,int maxFile)throws Exception{
    List<Result> result=new ArrayList<>();var automatic=new AutomaticEncryption(java.time.Clock.systemUTC());
    for(boolean outgoing:new boolean[]{false,true}){
      if(query.scope()==Scope.INBOX&&outgoing||query.scope()==Scope.SENT&&!outgoing)continue;
      for(var item:local.mailboxIndex(outgoing)){
        if(item.time()<query.from()||item.time()>query.to()||!item.contact().contains(query.nickname().toLowerCase(Locale.ROOT)))continue;
        var stored=local.loadHistory(item.id(),outgoing);var p=stored.packet();var assessment=local.assessSender(p);
        boolean unknown=!outgoing&&!assessment.keyMatches(),blocked=features.blocked(p);
        if(query.scope()==Scope.BLOCKED?!blocked:blocked)continue;
        if(query.scope()==Scope.UNKNOWN&&!unknown||query.scope()==Scope.FRIENDS&&!features.friend(outgoing?p.recipientId():p.senderId()))continue;
        String subject="Письмо 0.1.0",thread=item.id(),snippet="";boolean protectedLetter=true;int fileCount=0;
        if(AutomaticEncryption.supports(p))try(var plain=automatic.decrypt(p,local.identity(),maxFile)){
          subject=plain.subject();protectedLetter=plain.protectedLetter();fileCount=plain.files().size();if(plain.context()!=null&&!plain.context().forwarded()&&!plain.context().threadId().isEmpty())thread=plain.context().threadId();
          // Only an authenticated ordinary letter may provide a memory-only snippet.
          // Additional letter password/FF1 content is never unlocked by list rendering.
          if(!protectedLetter&&assessment.signatureValid()){String body=plain.text();snippet=body.substring(0,Math.min(240,body.length())).replaceAll("[\\r\\n\\t]+"," ");}
        }catch(java.io.IOException|java.security.GeneralSecurityException invalidContent){subject="Повреждённое письмо";fileCount=0;}
        if(query.scope()==Scope.FAVORITES&&!features.pinned("pinnedMail",item.id())&&(!features.pinned("pinnedThreads",thread)||unknown))continue;
        if(!subject.toLowerCase(Locale.ROOT).contains(query.subject().toLowerCase(Locale.ROOT)))continue;
        result.add(new Result(item,subject,protectedLetter,unknown,assessment.signatureValid(),thread,outgoing?p.recipientId():p.senderId(),fileCount,snippet));
      }
    }
    result.sort(Comparator.comparing((Result r)->!features.pinned("pinnedMail",r.item().id())).thenComparing(r->r.item().time(),Comparator.reverseOrder()));return List.copyOf(result.subList(0,Math.min(200,result.size())));
  }
}
