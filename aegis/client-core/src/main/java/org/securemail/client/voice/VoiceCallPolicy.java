package org.securemail.client.voice;

import java.util.*;
import org.securemail.protocol.Limits;

/** Local consent rules. Organization roles are never inferred from client fields. */
public record VoiceCallPolicy(Rule incoming,Rule outgoing) {
  public enum Mode {ALL_CONTACTS,SELECTED_CONTACTS,NONE;
    @Override public String toString(){return switch(this){case ALL_CONTACTS->"Все контакты";case SELECTED_CONTACTS->"Выбранные контакты";case NONE->"Звонки запрещены";};}
  }
  public static final int MAX_CONTACTS=256;
  public record Rule(Mode mode,Set<String> selectedContactIds,Set<String> deniedContactIds,boolean organizationGrantsAllowed) {
    public Rule {
      Objects.requireNonNull(mode);selectedContactIds=checked(selectedContactIds);deniedContactIds=checked(deniedContactIds);
    }
    private static Set<String> checked(Set<String> source){Objects.requireNonNull(source);if(source.size()>MAX_CONTACTS)throw new IllegalArgumentException("Слишком много правил звонков");for(String id:source)Limits.userId(id);return Set.copyOf(source);}
    public boolean allowsLocally(String peerId){return !deniedContactIds.contains(peerId)&&(mode==Mode.ALL_CONTACTS||mode==Mode.SELECTED_CONTACTS&&selectedContactIds.contains(peerId));}
    public boolean permitsOrganizationCheck(String peerId){return mode!=Mode.NONE&&organizationGrantsAllowed&&!deniedContactIds.contains(peerId);}
    public static Rule allContacts(){return new Rule(Mode.ALL_CONTACTS,Set.of(),Set.of(),false);}
    public static Rule nobody(){return new Rule(Mode.NONE,Set.of(),Set.of(),false);}
  }
  public VoiceCallPolicy {Objects.requireNonNull(incoming);Objects.requireNonNull(outgoing);}
  public static VoiceCallPolicy defaults(){return new VoiceCallPolicy(Rule.allContacts(),Rule.allContacts());}
  public Rule rule(VoiceCallService.Direction direction){return direction==VoiceCallService.Direction.INCOMING?incoming:outgoing;}
}
