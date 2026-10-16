package org.securemail.client.voice;

import java.io.*;
import java.security.GeneralSecurityException;
import java.util.*;
import org.securemail.client.storage.LocalStore;
import org.securemail.protocol.*;

/** Opt-in, encrypted, bounded metadata. Audio and network identifiers are never persisted. */
final class VoiceHistory {
  private final LocalStore local;
  private boolean enabled;
  private boolean incomingEnabled=true,notificationsEnabled=true;
  private VoiceCallPolicy policy=VoiceCallPolicy.defaults();
  private GlasAudioSession.Config config=GlasAudioSession.Config.defaults();
  private final ArrayDeque<VoiceCallService.HistoryEntry> entries=new ArrayDeque<>();
  private VoiceHistory(LocalStore local,boolean empty){this.local=local;}
  static VoiceHistory empty(LocalStore local){return new VoiceHistory(local,true);}
  VoiceHistory(LocalStore local)throws IOException,GeneralSecurityException {
    this.local=local;byte[] bytes=local.readVoiceState();if(bytes==null)return;
    try(var in=new DataInputStream(new ByteArrayInputStream(bytes))){
      int schema=in.readInt();if(schema<1||schema>3)throw new IOException("Call history schema");enabled=in.readBoolean();config=new GlasAudioSession.Config(Binary.text(in,256),Binary.text(in,256),in.readDouble(),in.readDouble(),in.readBoolean(),in.readBoolean());if(schema>=2){incomingEnabled=in.readBoolean();notificationsEnabled=in.readBoolean();}if(schema>=3)policy=new VoiceCallPolicy(readRule(in),readRule(in));int count=in.readInt();if(count<0||count>128)throw new IOException("Call history quota");
      for(int n=0;n<count;n++){
        String id=Binary.text(in,36),peer=Binary.text(in,64);UUID.fromString(id);Limits.userId(peer);boolean outgoing=in.readBoolean();long minute=in.readLong(),duration=in.readLong();String outcome=Binary.text(in,24);
        if(minute<0||minute%60000!=0||duration<0||duration>31L*86400||!Set.of("completed","declined","missed","unavailable","ended").contains(outcome))throw new IOException("Call history fields");
        entries.add(new VoiceCallService.HistoryEntry(id,peer,outgoing,minute,duration,outcome));
      }
      Binary.end(in);
    }catch(IllegalArgumentException invalid){throw new IOException("Call history damaged",invalid);}finally{Arrays.fill(bytes,(byte)0);}
  }
  synchronized VoiceCallPolicy policy(){return policy;}
  synchronized void policy(VoiceCallPolicy value)throws IOException,GeneralSecurityException {var previous=policy;policy=Objects.requireNonNull(value);try{save();}catch(IOException|GeneralSecurityException failure){policy=previous;throw failure;}}
  private static VoiceCallPolicy.Rule readRule(DataInputStream in)throws IOException {
    int mode=in.readUnsignedByte();if(mode>=VoiceCallPolicy.Mode.values().length)throw new IOException("Call policy mode");
    Set<String> selected=readIds(in),denied=readIds(in);return new VoiceCallPolicy.Rule(VoiceCallPolicy.Mode.values()[mode],selected,denied,in.readBoolean());
  }
  private static Set<String> readIds(DataInputStream in)throws IOException {int count=in.readUnsignedShort();if(count>VoiceCallPolicy.MAX_CONTACTS)throw new IOException("Call policy quota");Set<String> ids=new HashSet<>();for(int n=0;n<count;n++)if(!ids.add(Binary.text(in,64)))throw new IOException("Duplicate call policy identity");return ids;}
  private static void writeRule(DataOutputStream out,VoiceCallPolicy.Rule rule)throws IOException {out.writeByte(rule.mode().ordinal());for(Set<String> ids:List.of(rule.selectedContactIds(),rule.deniedContactIds())){out.writeShort(ids.size());for(String id:new TreeSet<>(ids))Binary.text(out,id);}out.writeBoolean(rule.organizationGrantsAllowed());}
  synchronized boolean enabled(){return enabled;}
  synchronized boolean incomingEnabled(){return incomingEnabled;}
  synchronized boolean notificationsEnabled(){return notificationsEnabled;}
  synchronized void incomingEnabled(boolean value)throws IOException,GeneralSecurityException {boolean previous=incomingEnabled;incomingEnabled=value;try{save();}catch(IOException|GeneralSecurityException failure){incomingEnabled=previous;throw failure;}}
  synchronized void notificationsEnabled(boolean value)throws IOException,GeneralSecurityException {boolean previous=notificationsEnabled;notificationsEnabled=value;try{save();}catch(IOException|GeneralSecurityException failure){notificationsEnabled=previous;throw failure;}}
  synchronized GlasAudioSession.Config config(){return config;}
  synchronized void config(GlasAudioSession.Config value)throws IOException,GeneralSecurityException {var previous=config;config=Objects.requireNonNull(value);try{save();}catch(IOException|GeneralSecurityException failure){config=previous;throw failure;}}
  synchronized List<VoiceCallService.HistoryEntry> entries(){return List.copyOf(entries);}
  synchronized void enabled(boolean value)throws IOException,GeneralSecurityException {boolean previous=enabled;enabled=value;try{save();}catch(IOException|GeneralSecurityException failure){enabled=previous;throw failure;}}
  synchronized void clear()throws IOException,GeneralSecurityException {var previous=new ArrayDeque<>(entries);entries.clear();try{save();}catch(IOException|GeneralSecurityException failure){entries.addAll(previous);throw failure;}}
  synchronized void add(VoiceCallService.HistoryEntry entry)throws IOException,GeneralSecurityException {
    if(!enabled)return;var previous=new ArrayDeque<>(entries);entries.addFirst(entry);while(entries.size()>128)entries.removeLast();
    try{save();}catch(IOException|GeneralSecurityException failure){entries.clear();entries.addAll(previous);throw failure;}
  }
  private void save()throws IOException,GeneralSecurityException {
    byte[] bytes=Binary.encode(out->{out.writeInt(3);out.writeBoolean(enabled);Binary.text(out,config.inputDeviceId());Binary.text(out,config.outputDeviceId());out.writeDouble(config.inputGain());out.writeDouble(config.speakerVolume());out.writeBoolean(config.echoCancellation());out.writeBoolean(config.noiseSuppression());out.writeBoolean(incomingEnabled);out.writeBoolean(notificationsEnabled);writeRule(out,policy.incoming());writeRule(out,policy.outgoing());out.writeInt(entries.size());for(var entry:entries){Binary.text(out,entry.callId());Binary.text(out,entry.peerId());out.writeBoolean(entry.outgoing());out.writeLong(entry.startedMinute());out.writeLong(entry.durationSeconds());Binary.text(out,entry.outcome());}});
    try{local.writeVoiceState(bytes);}finally{Arrays.fill(bytes,(byte)0);}
  }
}
