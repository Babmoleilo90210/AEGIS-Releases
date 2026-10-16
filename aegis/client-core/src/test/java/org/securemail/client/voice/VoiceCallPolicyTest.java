package org.securemail.client.voice;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.securemail.client.crypto.Identity;

class VoiceCallPolicyTest {
  @Test void directionRulesAndExplicitDenialOverrideSelectionOrOrganization()throws Exception{
    String alice=Identity.create().userId(),bob=Identity.create().userId();
    var incoming=new VoiceCallPolicy.Rule(VoiceCallPolicy.Mode.SELECTED_CONTACTS,Set.of(alice),Set.of(bob),true);
    var policy=new VoiceCallPolicy(incoming,VoiceCallPolicy.Rule.nobody());
    assertTrue(policy.incoming().allowsLocally(alice));assertFalse(policy.incoming().allowsLocally(bob));assertFalse(policy.incoming().permitsOrganizationCheck(bob));
    assertFalse(policy.outgoing().allowsLocally(alice));assertFalse(policy.outgoing().permitsOrganizationCheck(alice));
    var deniedSelected=new VoiceCallPolicy.Rule(VoiceCallPolicy.Mode.ALL_CONTACTS,Set.of(alice),Set.of(alice),true);assertFalse(deniedSelected.allowsLocally(alice));assertFalse(deniedSelected.permitsOrganizationCheck(alice));
  }
  @Test void policyOwnsCollectionsAndRejectsMalformedOrOversizedIds()throws Exception{
    String id=Identity.create().userId();Set<String> selected=new HashSet<>(Set.of(id));var rule=new VoiceCallPolicy.Rule(VoiceCallPolicy.Mode.SELECTED_CONTACTS,selected,Set.of(),false);selected.clear();assertTrue(rule.allowsLocally(id));assertThrows(UnsupportedOperationException.class,()->rule.selectedContactIds().clear());
    assertThrows(IllegalArgumentException.class,()->new VoiceCallPolicy.Rule(VoiceCallPolicy.Mode.ALL_CONTACTS,Set.of("nickname"),Set.of(),false));
    Set<String> many=new HashSet<>();for(int n=0;n<=VoiceCallPolicy.MAX_CONTACTS;n++)many.add(String.format("%064x",n));assertThrows(IllegalArgumentException.class,()->new VoiceCallPolicy.Rule(VoiceCallPolicy.Mode.SELECTED_CONTACTS,many,Set.of(),false));
  }
  @Test void organizationalDecisionIsShortLivedIdentityAndDirectionBound()throws Exception{
    String self=Identity.create().userId(),peer=Identity.create().userId(),stranger=Identity.create().userId();long issued=100_000;
    var decision=new VoiceOrganizationAuthorizer.Decision(self,peer,VoiceCallService.Direction.INCOMING,issued,issued+30_000,true);
    assertTrue(decision.permits(self,peer,VoiceCallService.Direction.INCOMING,issued));assertFalse(decision.permits(self,peer,VoiceCallService.Direction.OUTGOING,issued));assertFalse(decision.permits(self,stranger,VoiceCallService.Direction.INCOMING,issued));assertFalse(decision.permits(stranger,peer,VoiceCallService.Direction.INCOMING,issued));assertFalse(decision.permits(self,peer,VoiceCallService.Direction.INCOMING,issued-1));assertFalse(decision.permits(self,peer,VoiceCallService.Direction.INCOMING,issued+30_000));
    assertThrows(IllegalArgumentException.class,()->new VoiceOrganizationAuthorizer.Decision(self,peer,VoiceCallService.Direction.INCOMING,issued,issued+30_001,true));
    assertFalse(new VoiceOrganizationAuthorizer.Decision(self,peer,VoiceCallService.Direction.INCOMING,issued,issued+1000,false).permits(self,peer,VoiceCallService.Direction.INCOMING,issued));
  }
}
