package org.securemail.community.library600;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.community.access.*;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.*;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Real SQLite/content/ACL; injected Identity authority is a fixture, NOT Tor or cross-service acceptance. */
class LibraryController600Test {
    @TempDir Path dir;
    CommunityStore store; AccessControl access; ContentService content; LibraryController600 controller;
    String editor,reader,other;long now=1_800_000_000_000L;boolean sessionValid=true;long generation=1;
    @BeforeEach void setup()throws Exception {
        store=new CommunityStore(dir.resolve("library.db"),Clock.fixed(Instant.ofEpochMilli(now),ZoneOffset.UTC));access=new AccessControl(store);content=new ContentService(store,access);
        editor=identity("Редактор");reader=identity("Читатель");other=identity("Другой");
        grant(editor,Set.of("LIBRARY_CREATE","LIBRARY_EDIT","LIBRARY_PUBLISH","LIBRARY_ACCESS_MANAGE","LIBRARY_EXPORT","LIBRARY_PROPOSE"));
        controller=new LibraryController600(store,access,content,this::verify);
    }
    @AfterEach void close()throws Exception{store.close();}
    String identity(String name)throws Exception{return store.ensureIdentity(KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded(),name);}
    LibraryController600.Verified verify(Object evidence,String action,Map<String,Object>args)throws Exception {
        if(!sessionValid||!(evidence instanceof Token t)||t.generation()!=generation)throw CommunityException.denied();
        return new LibraryController600.Verified(t.actor(),"device",generation,now+300000,access.authorizationEpoch(t.actor()));
    }
    record Token(String actor,long generation){}
    Map<String,Object>call(String actor,String op,Map<String,Object>args)throws Exception {
        @SuppressWarnings("unchecked")var result=(Map<String,Object>)controller.handle(new Token(actor,generation),"library600."+op,args).get("data");return result;
    }
    void grant(String actor,Set<String>rights)throws Exception{store.tx(db->{String role=UUID.randomUUID().toString();sql(db,"INSERT INTO roles(id,scope,name) VALUES(?,'GLOBAL',?)",role,role);for(String right:rights)sql(db,"INSERT INTO role_permissions VALUES(?,?)",role,right);sql(db,"INSERT INTO assignments VALUES(?,?)",actor,role);return null;});}
    static void sql(java.sql.Connection db,String s,Object...args)throws Exception{try(var q=db.prepareStatement(s)){for(int i=0;i<args.length;i++)q.setObject(i+1,args[i]);q.executeUpdate();}}
    Map<String,Object>doc(boolean hidden)throws Exception {
        Map<String,Object> args=new HashMap<>(Map.of("title","Секретное название","body","закрытый текст"));if(hidden)args.put("policy",Map.of("users",List.of(editor)));
        var d=content.handle(editor,"content.library.create",args);return content.handle(editor,"content.library.publish",Map.of("id",d.get("id"),"revision",d.get("revision")));
    }
    @SuppressWarnings("unchecked") List<Map<String,Object>>items(Map<String,Object>d,String field){return (List<Map<String,Object>>)d.get(field);}
    String discover(String material,String subject)throws Exception{return (String)call(editor,"discovery.grant",Map.of("materialId",material,"subject",subject,"displayTitle","Разрешённое название")).get("opaqueId");}
    @Test void hiddenContentNotReturnedByReadFileExportCatalogOrGraph()throws Exception {
        var d=doc(true);String id=(String)d.get("id");for(String op:List.of("read","export","revisions"))assertThrows(CommunityException.class,()->call(reader,op,Map.of("id",id)));
        assertTrue(items(call(reader,"catalog",Map.of()),"items").isEmpty());assertTrue(items(call(reader,"catalog",Map.of()),"locked").isEmpty());assertTrue(items(call(reader,"graph",Map.of()),"nodes").isEmpty());
    }
    @Test void explicitDiscoveryContainsOnlyApprovedTitleAndNoBodyOrInternalMaterialId()throws Exception {
        String material=(String)doc(true).get("id"),opaque=discover(material,reader);var locked=items(call(reader,"catalog",Map.of()),"locked");assertEquals(1,locked.size());assertEquals(Set.of("opaqueId","displayTitle","locked","canRequest"),locked.getFirst().keySet());assertEquals(opaque,locked.getFirst().get("opaqueId"));assertNotEquals(material,opaque);assertEquals("Разрешённое название",locked.getFirst().get("displayTitle"));assertThrows(CommunityException.class,()->call(reader,"read",Map.of("id",material)));assertTrue(items(call(other,"catalog",Map.of()),"locked").isEmpty());
    }
    @Test void noRoleCannotGrantDiscoveryAndClientActorFieldRejected()throws Exception {
        String material=(String)doc(false).get("id");assertThrows(CommunityException.class,()->call(reader,"discovery.grant",Map.of("materialId",material,"subject",reader,"displayTitle","x")));assertThrows(CommunityException.class,()->call(reader,"read",Map.of("id",material,"actor",editor)));
    }
    @Test void accessRequestIsScopedIdempotentAndDecisionCannotBypassAcl()throws Exception {
        String material=(String)doc(true).get("id"),opaque=discover(material,reader);Map<String,Object>args=Map.of("opaqueId",opaque,"reason","Прошу доступ");var request=call(reader,"access.request",args);assertEquals(request,call(reader,"access.request",args));assertThrows(CommunityException.class,()->call(other,"access.request",args));
        var decision=call(editor,"access.decide",Map.of("requestId",request.get("id"),"decision","APPROVE"));assertEquals("APPROVED_PENDING_GRANT",decision.get("state"));assertEquals(false,decision.get("accessGranted"));assertThrows(CommunityException.class,()->call(reader,"read",Map.of("id",material)));
    }
    @Test void discoveryRevocationInvalidatesTitleAndRequests()throws Exception {
        String material=(String)doc(true).get("id"),opaque=discover(material,reader);call(editor,"discovery.revoke",Map.of("materialId",material,"subject",reader));assertTrue(items(call(reader,"catalog",Map.of()),"locked").isEmpty());assertThrows(CommunityException.class,()->call(reader,"access.request",Map.of("opaqueId",opaque,"reason","x")));
    }
    @Test void proposalRequiresSeparateRightAndNeverPublishesBeforeApproval()throws Exception {
        var d=doc(false);Map<String,Object>args=Map.of("materialId",d.get("id"),"baseRevision",d.get("revision"),"changeId",UUID.randomUUID().toString(),"title","Новый","body","предложение");
        assertThrows(CommunityException.class,()->call(reader,"proposal.create",args));grant(reader,Set.of("LIBRARY_PROPOSE"));var proposal=call(reader,"proposal.create",args);assertEquals("PENDING",proposal.get("state"));assertEquals("закрытый текст",call(other,"read",Map.of("id",d.get("id"))).get("body"));assertEquals(proposal,call(reader,"proposal.create",args));
        assertThrows(CommunityException.class,()->call(reader,"proposal.decide",Map.of("proposalId",proposal.get("id"),"decision","APPROVE")));
        call(editor,"proposal.decide",Map.of("proposalId",proposal.get("id"),"decision","APPROVE"));assertEquals("предложение",call(other,"read",Map.of("id",d.get("id"))).get("body"));assertEquals("CORRECTED",call(other,"read",Map.of("id",d.get("id"))).get("state"));assertTrue(((List<?>)call(editor,"revisions",Map.of("id",d.get("id"))).get("items")).size()>=3);
    }
    @Test void staleProposalDoesNotOverwriteNewerRevision()throws Exception {
        var d=doc(false);grant(reader,Set.of("LIBRARY_PROPOSE"));var proposal=call(reader,"proposal.create",Map.of("materialId",d.get("id"),"baseRevision",d.get("revision"),"changeId",UUID.randomUUID().toString(),"title","x","body","proposed"));
        content.handle(editor,"content.library.update",Map.of("id",d.get("id"),"revision",d.get("revision"),"title","newer","body","committed"));assertThrows(CommunityException.class,()->call(editor,"proposal.decide",Map.of("proposalId",proposal.get("id"),"decision","APPROVE")));assertEquals("committed",call(editor,"read",Map.of("id",d.get("id"))).get("body"));assertEquals("PENDING",call(editor,"proposal.get",Map.of("proposalId",proposal.get("id"))).get("state"));
    }
    @Test void changedRetryPayloadRejectedAndProposalsDoNotLeakAcrossUsers()throws Exception {
        var d=doc(false);grant(reader,Set.of("LIBRARY_PROPOSE"));Map<String,Object>args=new HashMap<>(Map.of("materialId",d.get("id"),"baseRevision",d.get("revision"),"changeId",UUID.randomUUID().toString(),"title","x","body","first"));var proposal=call(reader,"proposal.create",args);args.put("body","changed");assertThrows(CommunityException.class,()->call(reader,"proposal.create",args));assertThrows(CommunityException.class,()->call(other,"proposal.get",Map.of("proposalId",proposal.get("id"))));assertTrue(items(call(other,"proposal.list",Map.of("materialId",d.get("id"))),"items").isEmpty());
    }
    @Test void revokedSessionOrGenerationNeverReachesContent()throws Exception {
        String material=(String)doc(false).get("id");var token=new Token(reader,1);generation=2;assertThrows(CommunityException.class,()->controller.handle(token,"library600.read",Map.of("id",material)));sessionValid=false;assertThrows(CommunityException.class,()->call(reader,"read",Map.of("id",material)));
    }
    @Test void postDispatchIdentityRecheckRollsBackMutation()throws Exception {
        var d=doc(false);AtomicInteger calls=new AtomicInteger();var adapter=new LibraryController600(store,access,content,(e,a,r)->{if(calls.incrementAndGet()==2)throw CommunityException.denied();return verify(e,a,r);});
        assertThrows(CommunityException.class,()->adapter.handle(new Token(editor,1),"library600.discovery.grant",Map.of("materialId",d.get("id"),"subject",reader,"displayTitle","x")));assertTrue(items(call(reader,"catalog",Map.of()),"locked").isEmpty());
    }
    @Test void identityContextNotArbitraryClientObjectAndDefaultAuthorityMissing()throws Exception {
        assertThrows(CommunityException.class,()->controller.handle(Map.of("actor",editor),"library600.catalog",Map.of()));assertThrows(NullPointerException.class,()->new LibraryController600(store,access,content,null));
    }
    @Test void actualSqlitePersistenceAndMigrationAreIdempotent()throws Exception {
        String material=(String)doc(true).get("id"),opaque=discover(material,reader);var request=call(reader,"access.request",Map.of("opaqueId",opaque,"reason","x"));controller=new LibraryController600(store,access,content,this::verify);assertEquals(opaque,items(call(reader,"catalog",Map.of()),"locked").getFirst().get("opaqueId"));assertEquals(request.get("id"),items(call(editor,"access.list",Map.of("materialId",material)),"items").getFirst().get("id"));assertTrue(store.verifyAudit());
    }
    @Test void requestBoundsAndStrictIntegerInputRejectMalformedValues()throws Exception {
        for(Object limit:List.of(0,101,1.5,"10"))assertThrows(CommunityException.class,()->call(reader,"catalog",Map.of("limit",limit)));
        assertThrows(CommunityException.class,()->call(reader,"catalog",Map.of("lockedCursor","../../data")));assertThrows(CommunityException.class,()->call(reader,"catalog",Map.of("role",Map.of("admin",true))));
    }
    @Test void fileDownloadsRecheckLibraryAclAndCannotReadNewsFiles()throws Exception {
        var draft=content.handle(editor,"content.library.create",Map.of("title","Файл","body","x","policy",Map.of("users",List.of(editor))));
        var attachment=content.handle(editor,"content.files.upload",Map.of("materialId",draft.get("id"),"name","x.txt","mime","text/plain","base64","eA=="));
        content.handle(editor,"content.library.publish",Map.of("id",draft.get("id"),"revision",draft.get("revision")));
        assertEquals("eA==",call(editor,"file",Map.of("id",attachment.get("id"))).get("base64"));
        assertThrows(CommunityException.class,()->call(reader,"file",Map.of("id",attachment.get("id"))));
        assertThrows(CommunityException.class,()->call(reader,"file",Map.of("id",UUID.randomUUID().toString())));
        grant(editor,Set.of("NEWS_CREATE","NEWS_EDIT","NEWS_PUBLISH","NEWS_GLOBAL_PUBLISH"));
        var news=content.handle(editor,"content.news.create",Map.of("title","Новость","body","x"));
        var file=content.handle(editor,"content.files.upload",Map.of("materialId",news.get("id"),"name","x.txt","mime","text/plain","base64","eA=="));
        content.handle(editor,"content.news.publish",Map.of("id",news.get("id"),"revision",news.get("revision")));
        assertThrows(CommunityException.class,()->call(editor,"file",Map.of("id",file.get("id"))));
    }
    @Test void expiredOrStaleAuthorityEpochDeniedEvenIfCallerIsEditor()throws Exception {
        var expired=new LibraryController600(store,access,content,(e,a,r)->new LibraryController600.Verified(editor,"device",1,now,access.authorizationEpoch(editor)));
        assertThrows(CommunityException.class,()->expired.handle(new Object(),"library600.catalog",Map.of()));
        var stale=new LibraryController600(store,access,content,(e,a,r)->new LibraryController600.Verified(editor,"device",1,now+1000,0));
        assertThrows(CommunityException.class,()->stale.handle(new Object(),"library600.catalog",Map.of()));
    }
    @Test void retractedProposalAuthorCannotContinueReadingAfterAclRevocation()throws Exception {
        var d=doc(false);grant(reader,Set.of("LIBRARY_PROPOSE"));var proposal=call(reader,"proposal.create",Map.of("materialId",d.get("id"),"baseRevision",d.get("revision"),"changeId",UUID.randomUUID().toString(),"title","x","body","draft"));
        content.handle(editor,"content.library.update",Map.of("id",d.get("id"),"revision",d.get("revision"),"title","x","body","closed","policy",Map.of("users",List.of(editor))));
        assertThrows(CommunityException.class,()->call(reader,"proposal.get",Map.of("proposalId",proposal.get("id"))));
        assertThrows(CommunityException.class,()->call(reader,"proposal.list",Map.of("materialId",d.get("id"))));
    }
    @Test void proposalPaginationExcludesBodyAndReturnsEveryOwnedProposal()throws Exception {
        var d=doc(false);grant(reader,Set.of("LIBRARY_PROPOSE"));Set<String>expected=new HashSet<>();for(int i=0;i<7;i++)expected.add((String)call(reader,"proposal.create",Map.of("materialId",d.get("id"),"baseRevision",d.get("revision"),"changeId",UUID.randomUUID().toString(),"title","x"+i,"body","body"+i)).get("id"));
        Set<String>found=new HashSet<>();String cursor="";do{var page=call(reader,"proposal.list",Map.of("materialId",d.get("id"),"cursor",cursor,"limit",2));for(var item:items(page,"items")){assertFalse(item.containsKey("body"));assertTrue(found.add((String)item.get("id")));}cursor=(String)page.get("nextCursor");}while(!cursor.isEmpty());assertEquals(expected,found);
    }

    @Test void plaintextProjectionRequiresOfflinePolicyAndIndependentExportPermission()throws Exception {
        var publicDoc=doc(false);assertThrows(CommunityException.class,()->call(editor,"project",Map.of("id",publicDoc.get("id"))));
        var draft=content.handle(editor,"content.library.create",Map.of("title","Offline","body","body","policy",Map.of("offlineAllowed",true)));
        var m=content.handle(editor,"content.library.publish",Map.of("id",draft.get("id"),"revision",draft.get("revision")));
        assertThrows(CommunityException.class,()->call(reader,"project",Map.of("id",m.get("id"))));grant(reader,Set.of("LIBRARY_EXPORT"));var projection=call(reader,"project",Map.of("id",m.get("id")));assertEquals(true,projection.get("offlineAllowed"));assertEquals("# Offline\n\nbody",projection.get("markdown"));
        content.handle(editor,"content.library.update",Map.of("id",m.get("id"),"revision",m.get("revision"),"title","Offline","body","body","policy",Map.of("offlineAllowed",false)));
        assertThrows(CommunityException.class,()->call(reader,"project",Map.of("id",m.get("id"))));
    }

    @Test void proposalLimitsMatchExistingContentBeforePersistingUnapprovableDraft()throws Exception {
        var d=doc(false);grant(reader,Set.of("LIBRARY_PROPOSE"));for(String body:List.of("x".repeat(250001),"я".repeat(250000)," ")) {
            if(body.length()==250000)body="界".repeat(200000); // under char bound, over existing UTF-8 byte bound
            Map<String,Object>args=Map.of("materialId",d.get("id"),"baseRevision",d.get("revision"),"changeId",UUID.randomUUID().toString(),"title","x","body",body);
            assertThrows(CommunityException.class,()->call(reader,"proposal.create",args));
        }
        assertTrue(items(call(reader,"proposal.list",Map.of("materialId",d.get("id"))),"items").isEmpty());
    }

}
