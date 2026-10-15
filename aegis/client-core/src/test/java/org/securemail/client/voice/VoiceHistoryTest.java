package org.securemail.client.voice;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.Identity;
import org.securemail.client.storage.LocalStore;
import org.securemail.protocol.Binary;

class VoiceHistoryTest {
  @TempDir Path root;
  private static final char[] PASSWORD="encrypted-voice-test-password".toCharArray();
  private LocalStore store(Path path)throws Exception{return new LocalStore(path,PASSWORD,Clock.systemUTC(),200000,2_000_000);}
  @Test void optInMetadataAndDeviceSettingsPersistEncryptedAndSurviveRekey()throws Exception{
    Path profile=root.resolve("profile"),rekey=root.resolve("rekey");String peer=Identity.create().userId(),id=UUID.randomUUID().toString();
    try(var local=store(profile)){
      var state=new VoiceHistory(local);assertFalse(state.enabled());state.add(new VoiceCallService.HistoryEntry(id,peer,true,60_000,4,"ended"));assertTrue(state.entries().isEmpty());assertFalse(Files.exists(profile.resolve("voice-v1.vault")));
      state.enabled(true);state.incomingEnabled(false);state.notificationsEnabled(false);state.config(new GlasAudioSession.Config("microphone-id","speaker-id",0.8,0.6,false,true));
      state.add(new VoiceCallService.HistoryEntry(id,peer,true,60_000,4,"ended"));byte[] sealed=Files.readAllBytes(profile.resolve("voice-v1.vault"));assertFalse(new String(sealed,StandardCharsets.ISO_8859_1).contains(peer));assertFalse(new String(sealed,StandardCharsets.ISO_8859_1).contains("microphone-id"));
      local.rekeyCopy(rekey,PASSWORD);
    }
    for(Path path:List.of(profile,rekey))try(var local=store(path)){
      var state=new VoiceHistory(local);assertTrue(state.enabled());assertFalse(state.incomingEnabled());assertFalse(state.notificationsEnabled());assertEquals(id,state.entries().getFirst().callId());assertEquals("microphone-id",state.config().inputDeviceId());state.enabled(false);state.add(new VoiceCallService.HistoryEntry(UUID.randomUUID().toString(),peer,false,120_000,7,"ended"));assertEquals(1,state.entries().size());state.clear();assertTrue(new VoiceHistory(local).entries().isEmpty());
    }
  }
  @Test void versionOneGetsSafeIncomingAndNotificationDefaults()throws Exception{
    try(var local=store(root)){
      byte[] old=Binary.encode(out->{out.writeInt(1);out.writeBoolean(false);Binary.text(out,"");Binary.text(out,"");out.writeDouble(1);out.writeDouble(1);out.writeBoolean(true);out.writeBoolean(true);out.writeInt(0);});local.writeVoiceState(old);
      var state=new VoiceHistory(local);assertTrue(state.incomingEnabled());assertTrue(state.notificationsEnabled());assertFalse(state.enabled());state.notificationsEnabled(false);byte[] upgraded=local.readVoiceState();try(var in=new DataInputStream(new ByteArrayInputStream(upgraded))){assertEquals(2,in.readInt());}finally{Arrays.fill(upgraded,(byte)0);}
    }
  }
  @Test void damagedOrOversizedVoiceStateFailsClosed()throws Exception{
    try(var local=store(root)){
      assertThrows(IOException.class,()->local.writeVoiceState(new byte[128*1024+1]));var state=new VoiceHistory(local);state.enabled(true);Path path=root.resolve("voice-v1.vault");byte[] damaged=Files.readAllBytes(path);damaged[damaged.length-1]^=1;Files.write(path,damaged);assertThrows(java.security.GeneralSecurityException.class,()->new VoiceHistory(local));
    }
  }
}
