package org.securemail.client.storage;

import com.google.gson.*;
import java.io.*;
import java.security.*;
import java.util.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.update.JsonData;
import org.securemail.protocol.*;

/** Separate encrypted sidecar; the 1.0 vault format and identity are unchanged. */
public final class LocalFeatures {
  private final LocalStore local;
  private final Set<String> blockedMail=new HashSet<>(),blockedSenders=new HashSet<>(),pinnedContacts=new HashSet<>(),pinnedMail=new HashSet<>(),pinnedThreads=new HashSet<>(),revokedFriends=new HashSet<>(),friends=new HashSet<>();
  private final Map<String,long[]> friendRevisions=new HashMap<>();
  private String about="";private boolean visible,profilePending=true;
  private boolean notifications=true,friendNotifications=true,friendEvents=true,updateNotifications=true;
  public LocalFeatures(LocalStore local)throws IOException,GeneralSecurityException{
    this.local=local;byte[] data=local.readFeatures();if(data==null)return;
    try{
      JsonObject o=JsonData.object(data,2*1024*1024);JsonData.fields(o,"schema","about","visible","profilePending","blockedMail","blockedSenders","pinnedContacts","pinnedMail","pinnedThreads","revokedFriends","friends","friendRevisions","notifications","friendNotifications","friendEvents","updateNotifications");
      if(JsonData.number(o,"schema")!=1)throw new IOException("Unknown feature state");about=JsonData.text(o,"about",500);visible=JsonData.bool(o,"visible");profilePending=JsonData.bool(o,"profilePending");
      for(var entry:sets().entrySet()){
        JsonArray values=o.getAsJsonArray(entry.getKey());if(values.size()>8192)throw new IOException("Feature quota");
        for(var v:values){String id=v.getAsString();validate(entry.getKey(),id);entry.getValue().add(id);}
      }
      JsonObject revisions=o.getAsJsonObject("friendRevisions");if(revisions.size()>128)throw new IOException("Friend quota");
      for(var e:revisions.entrySet()){Limits.userId(e.getKey());JsonArray r=e.getValue().getAsJsonArray();if(r.size()!=2||r.get(0).getAsLong()<0||r.get(1).getAsLong()<0)throw new IOException("Friend revisions");friendRevisions.put(e.getKey(),new long[]{r.get(0).getAsLong(),r.get(1).getAsLong()});}
      notifications=JsonData.bool(o,"notifications");friendNotifications=JsonData.bool(o,"friendNotifications");friendEvents=JsonData.bool(o,"friendEvents");updateNotifications=JsonData.bool(o,"updateNotifications");
    }catch(IllegalArgumentException|IllegalStateException|NullPointerException invalid){throw new IOException("Локальные настройки повреждены",invalid);}finally{Arrays.fill(data,(byte)0);}
  }
  private Map<String,Set<String>> sets(){var m=new LinkedHashMap<String,Set<String>>();m.put("blockedMail",blockedMail);m.put("blockedSenders",blockedSenders);m.put("pinnedContacts",pinnedContacts);m.put("pinnedMail",pinnedMail);m.put("pinnedThreads",pinnedThreads);m.put("revokedFriends",revokedFriends);m.put("friends",friends);return m;}
  private static void validate(String kind,String id){if(kind.equals("blockedMail")||kind.equals("pinnedMail")||kind.equals("pinnedThreads"))Limits.messageId(id);else Limits.userId(id);}
  private void save()throws IOException,GeneralSecurityException{
    JsonObject o=new JsonObject();o.addProperty("schema",1);o.addProperty("about",about);o.addProperty("visible",visible);o.addProperty("profilePending",profilePending);
    for(var e:sets().entrySet()){JsonArray a=new JsonArray();e.getValue().stream().sorted().forEach(a::add);o.add(e.getKey(),a);}
    JsonObject revisions=new JsonObject();for(var e:friendRevisions.entrySet()){JsonArray a=new JsonArray();a.add(e.getValue()[0]);a.add(e.getValue()[1]);revisions.add(e.getKey(),a);}o.add("friendRevisions",revisions);
    o.addProperty("notifications",notifications);o.addProperty("friendNotifications",friendNotifications);o.addProperty("friendEvents",friendEvents);o.addProperty("updateNotifications",updateNotifications);
    byte[] data=JsonData.encode(o);try{local.writeFeatures(data);}finally{Arrays.fill(data,(byte)0);}
  }
  public synchronized String about(){return about;}public synchronized boolean visible(){return visible;}
  public synchronized boolean profilePending(){return profilePending;}
  public synchronized void profile(String text,boolean show)throws IOException,GeneralSecurityException{if(text.length()>500||text.codePoints().anyMatch(c->Character.isISOControl(c)&&c!='\n'))throw new IOException("О себе: до 500 символов");about=text;visible=show;profilePending=true;save();}
  public synchronized void profileChanged()throws IOException,GeneralSecurityException{profilePending=true;save();}
  public synchronized void profilePublished()throws IOException,GeneralSecurityException{profilePending=false;save();}
  public synchronized boolean blocked(EncryptedPacket p){return blockedMail.contains(p.messageId())||blockedSenders.contains(p.senderId());}
  public synchronized boolean blocked(String messageId,String senderId){return blockedMail.contains(messageId)||blockedSenders.contains(senderId);}
  public synchronized boolean blockedSender(String id){return blockedSenders.contains(id);}
  public synchronized void blockMail(String id,boolean value)throws IOException,GeneralSecurityException{Limits.messageId(id);change(blockedMail,id,value);save();}
  public synchronized void blockSender(String id,boolean value)throws IOException,GeneralSecurityException{Limits.userId(id);change(blockedSenders,id,value);save();}
  public synchronized boolean pinned(String kind,String id){return set(kind).contains(id);}
  public synchronized void pin(String kind,String id,boolean value)throws IOException,GeneralSecurityException{Set<String> target=set(kind);validate(kind,id);if(value&&target.size()>=8192)throw new IOException("Pin quota");change(target,id,value);save();}
  private Set<String> set(String kind){return switch(kind){case "pinnedContacts"->pinnedContacts;case "pinnedMail"->pinnedMail;case "pinnedThreads"->pinnedThreads;default->throw new IllegalArgumentException("Unknown pin kind");};}
  private static void change(Set<String> target,String id,boolean value){if(value)target.add(id);else target.remove(id);}
  public synchronized boolean friend(String id){return friends.contains(id)&&!revokedFriends.contains(id);}
  public synchronized boolean consent(String id){return !revokedFriends.contains(id);}
  public synchronized void consent(String id,boolean active)throws IOException,GeneralSecurityException{Limits.userId(id);change(revokedFriends,id,!active);if(!active)friends.remove(id);save();}
  public synchronized boolean friendship(UserInfo peer,ContactAssertion ours,ContactAssertion theirs)throws IOException,GeneralSecurityException{
    UserInfo pinned=local.contact(peer.nickname());if(pinned==null||!pinned.userId().equals(peer.userId()))throw new GeneralSecurityException("Friend identity is not verified");
    long[] previous=friendRevisions.getOrDefault(peer.userId(),new long[2]);
    verifyAssertion(ours,local.identity().userId(),peer.userId(),local.identity().publicKey(),previous[0]);
    verifyAssertion(theirs,peer.userId(),local.identity().userId(),pinned.publicKey(),previous[1]);
    boolean before=friend(peer.userId());boolean active=ours!=null&&theirs!=null&&ours.active()&&theirs.active()&&consent(peer.userId());change(friends,peer.userId(),active);
    long[] revisions={ours==null?previous[0]:ours.revision(),theirs==null?previous[1]:theirs.revision()};
    if(before!=active||!Arrays.equals(previous,revisions)){friendRevisions.put(peer.userId(),revisions);save();}
    return before!=active;
  }
  private static void verifyAssertion(ContactAssertion a,String owner,String target,byte[] key,long floor)throws IOException,GeneralSecurityException{
    if(a!=null&&(!a.ownerId().equals(owner)||!a.targetId().equals(target)||a.revision()<floor||!MessageDigest.isEqual(a.publicKey(),key)||!Identity.verify(key,a.signingBytes(),a.signature())))throw new GeneralSecurityException("Friend consent rejected");
  }
  public synchronized void purgeExpired(Set<String> live)throws IOException,GeneralSecurityException{boolean changed=blockedMail.removeIf(id->!live.contains(id))|pinnedMail.removeIf(id->!live.contains(id));if(changed)save();}
  public synchronized void removeExpired(Set<String> expired)throws IOException,GeneralSecurityException{if(expired.isEmpty())return;boolean changed=blockedMail.removeAll(expired)|pinnedMail.removeAll(expired)|pinnedThreads.removeAll(expired);if(changed)save();}
  public synchronized boolean notifications(){return notifications;}public synchronized boolean friendNotifications(){return friendNotifications;}public synchronized boolean friendEvents(){return friendEvents;}public synchronized boolean updateNotifications(){return updateNotifications;}
  public synchronized void notifications(boolean all,boolean friend,boolean events,boolean updates)throws IOException,GeneralSecurityException{notifications=all;friendNotifications=friend;friendEvents=events;updateNotifications=updates;save();}
}
