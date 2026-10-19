package org.securemail.community.library600;

import org.securemail.community.access.AccessControl;
import org.securemail.community.content.ContentService;
import org.securemail.community.core.CommunityException;
import org.securemail.community.core.CommunityStore;

import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;

/** ACL-first adapter over existing production content. Requires a REAL external Identity authority;
 * no default authority, caller actor parameter, client role, or nickname can grant access.
 * The integration must serialize Identity revocation and this handler, or use a shared transaction gate.
 * No Syncthing peer receives a universal content directory through this controller. */
public final class LibraryController600 {
    public record Verified(String accountId, String deviceId, long generation, long leaseUntil, long aclEpoch) {
        public Verified {
            if (accountId==null || !accountId.matches("[a-f0-9]{64}") || deviceId==null
                    || !deviceId.matches("[A-Za-z0-9_-]{1,128}") || generation<1 || leaseUntil<1 || aclEpoch<0)
                throw new IllegalArgumentException("Некорректный проверенный контекст");
        }
    }
    @FunctionalInterface public interface Authority {
        /** Must verify proof, body, scope, device trust and LIVE session generation; not decode unchecked client fields. */
        Verified verify(Object evidence, String action, Map<String,Object> request) throws Exception;
    }
    private final CommunityStore store;
    private final AccessControl access;
    private final ContentService content;
    private final Authority authority;
    private static final Set<String> READ_OPS=Set.of("read","export","list","graph","revisions","file","link.list");
    private static final Set<String> MUTATE_OPS=Set.of("create","update","submit","moderate","publish","retract","delete","revert","link.propose","link.decide");
    public LibraryController600(CommunityStore store, AccessControl access, ContentService content, Authority authority) throws Exception {
        this.store=Objects.requireNonNull(store); this.access=Objects.requireNonNull(access);
        this.content=Objects.requireNonNull(content); this.authority=Objects.requireNonNull(authority);
        store.tx(db->{for(String sql:List.of(
            "CREATE TABLE IF NOT EXISTS library600_schema(version INTEGER PRIMARY KEY,applied INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS library600_discovery(id TEXT PRIMARY KEY,material TEXT NOT NULL REFERENCES content_material(id),subject TEXT NOT NULL REFERENCES identities(identity),title TEXT NOT NULL,issuer TEXT NOT NULL,UNIQUE(material,subject))",
            "CREATE INDEX IF NOT EXISTS library600_discovery_subject ON library600_discovery(subject,id)",
            "CREATE TABLE IF NOT EXISTS library600_access(id TEXT PRIMARY KEY,material TEXT NOT NULL REFERENCES content_material(id),subject TEXT NOT NULL REFERENCES identities(identity),reason TEXT NOT NULL,state TEXT NOT NULL,reviewer TEXT,created INTEGER NOT NULL,UNIQUE(material,subject))",
            "CREATE TABLE IF NOT EXISTS library600_proposals(id TEXT PRIMARY KEY,change_id TEXT NOT NULL,material TEXT NOT NULL REFERENCES content_material(id),author TEXT NOT NULL REFERENCES identities(identity),base_revision INTEGER NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,reviewer TEXT,created INTEGER NOT NULL,UNIQUE(author,change_id))",
            "CREATE INDEX IF NOT EXISTS library600_proposals_material ON library600_proposals(material,id)",
            "INSERT OR IGNORE INTO library600_schema VALUES(1,0)")) try(var s=db.createStatement()){s.execute(sql);} return null;});
    }
    public boolean supports(String action){return action!=null&&action.startsWith("library600.");}
    public Map<String,Object> handle(Object evidence, String action, Map<String,Object> request) throws Exception {
        if(!supports(action)||request==null)throw CommunityException.invalid();
        // Defensive immutable snapshot prevents caller changing the signed request during authorization.
        Map<String,Object> args=snapshot(request); String op=action.substring("library600.".length());
        return store.tx(db->{
            Verified actor=checked(authority.verify(evidence,action,args));
            Map<String,Object> result;
            if(READ_OPS.contains(op)) {
                String target=switch(op){case "read"->"get";case "file"->"files.download";default->op;};
                if(op.equals("file")){
                    keys(args,"id");String file=id(args,"id"),material;
                    try(var q=db.prepareStatement("SELECT material FROM content_file WHERE id=?")){q.setString(1,file);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.missing();material=r.getString(1);}}
                    read(actor,material); // reject news/event attachments even with a Library capability
                }
                result=content.handle(actor.accountId(),op.equals("file")?"content."+target:"content.library."+target,args);
            } else if(MUTATE_OPS.contains(op))result=content.handle(actor.accountId(),"content.library."+op,args);
            else result=switch(op) {
                case "capabilities"->capabilities(db,actor,args);
                case "permissions"->permissions(actor,args);
                case "file.upload"->upload(actor,args);
                case "catalog"->catalog(db,actor,args);
                case "project"->project(actor,args);
                case "cache.authorize"->cacheAuthorize(actor,args);
                case "read.authorize"->readAuthorize(actor,args);
                case "discovery.grant"->discoveryGrant(db,actor,args);
                case "discovery.revoke"->discoveryRevoke(db,actor,args);
                case "access.request"->accessRequest(db,actor,args);
                case "access.list"->accessList(db,actor,args);
                case "access.decide"->accessDecide(db,actor,args);
                case "proposal.create"->proposalCreate(db,actor,args);
                case "proposal.list"->proposalList(db,actor,args);
                case "proposal.get"->proposalGet(db,actor,args);
                case "proposal.decide"->proposalDecide(db,actor,args);
                default->throw CommunityException.invalid();
            };
            Verified after=checked(authority.verify(evidence,action,args));
            if(!actor.accountId().equals(after.accountId())||!actor.deviceId().equals(after.deviceId())
                    ||actor.generation()!=after.generation())throw CommunityException.denied();
            // Content mutation may legitimately advance Community authorizationEpoch; stale Identity epoch is rejected by authority.
            long epoch=access.authorizationEpoch(actor.accountId());
            return Map.of("data",result,"accountId",actor.accountId(),"deviceId",actor.deviceId(),
                    "generation",actor.generation(),"leaseUntil",Math.min(actor.leaseUntil(),after.leaseUntil()),
                    "serverNow",store.clock().millis(),"aclEpoch",epoch);
        });
    }
    private Verified checked(Verified v)throws Exception {
        if(v==null || v.leaseUntil()<=store.clock().millis() || v.leaseUntil()-store.clock().millis()>86_400_000L)throw CommunityException.denied();
        if(v.aclEpoch()!=access.authorizationEpoch(v.accountId()))throw CommunityException.denied();
        return v;
    }
    private Map<String,Object> read(Verified v,String id)throws Exception{return content.handle(v.accountId(),"content.library.get",Map.of("id",id));}
    private String scope(Map<String,Object> m){String org=(String)m.get("organization");return org.isEmpty()?"GLOBAL":"ORG:"+org;}
    private void require(Verified v,Map<String,Object>m,String right)throws Exception{access.require(v.accountId(),right,scope(m));}
    private Map<String,Object> capabilities(Connection db,Verified actor,Map<String,Object>args)throws Exception {
        keys(args);List<Map<String,Object>>organizations=new ArrayList<>();try(var q=db.prepareStatement("SELECT id,name FROM organizations ORDER BY id LIMIT 1000");var rows=q.executeQuery()){while(rows.next()&&organizations.size()<100)if(access.has(actor.accountId(),"LIBRARY_CREATE","ORG:"+rows.getString(1)))organizations.add(Map.of("id",rows.getString(1),"title",rows.getString(2)));}return Map.of("canCreateGlobal",access.has(actor.accountId(),"LIBRARY_CREATE","GLOBAL"),"organizations",organizations,"types",List.of("NOTE","ARTICLE","DOCUMENT","PDF","IMAGE","VIDEO","PERSON","ORGANIZATION","TOPIC"));
    }
    private Map<String,Object> permissions(Verified actor,Map<String,Object>args)throws Exception {
        keys(args,"id");Map<String,Object>material=read(actor,id(args,"id"));Map<String,Object>rights=new LinkedHashMap<>();for(String right:List.of("CREATE","EDIT","PUBLISH","MODERATE","DELETE","EXPORT","LINK","PROPOSE","ACCESS_MANAGE"))rights.put(right,access.has(actor.accountId(),"LIBRARY_"+right,scope(material)));return Map.of("id",material.get("id"),"revision",material.get("revision"),"rights",rights);
    }
    private Map<String,Object> upload(Verified actor,Map<String,Object>args)throws Exception {read(actor,id(args,"materialId"));return content.handle(actor.accountId(),"content.files.upload",args);}
    /** One atomic server-side decision for an explicitly offline-exportable Obsidian projection. */
    private Map<String,Object> project(Verified v,Map<String,Object>d)throws Exception {
        keys(d,"id");String id=id(d,"id");Map<String,Object>m=read(v,id);
        Object raw=m.get("policy");if(!(raw instanceof Map<?,?>p)||!Boolean.TRUE.equals(p.get("offlineAllowed")))
            throw new CommunityException("DENIED","Материал не разрешён для локального vault");
        Map<String,Object>export=content.handle(v.accountId(),"content.library.export",Map.of("id",id));
        return Map.of("id",id,"revision",export.get("revision"),"markdown",export.get("text"),"offlineAllowed",true);
    }
    private Map<String,Object> cacheAuthorize(Verified actor,Map<String,Object>args)throws Exception {
        Map<String,Object>project=project(actor,args);byte[]bytes=((String)project.get("markdown")).getBytes(StandardCharsets.UTF_8);
        return Map.of("id",project.get("id"),"revision",project.get("revision"),"offlineAllowed",true,"sha256",CommunityStore.hex(CommunityStore.hash(bytes)));
    }
    private Map<String,Object> readAuthorize(Verified actor,Map<String,Object>args)throws Exception {
        keys(args,"id");String id=id(args,"id");Map<String,Object>material=read(actor,id);boolean offline=false;
        if(material.get("policy") instanceof Map<?,?>policy&&Boolean.TRUE.equals(policy.get("offlineAllowed")))offline=access.has(actor.accountId(),"LIBRARY_EXPORT",scope(material));
        return Map.of("id",id,"revision",material.get("revision"),"sha256",CommunityStore.hex(CommunityStore.hash(((String)material.get("body")).getBytes(StandardCharsets.UTF_8))),"offlineAllowed",offline);
    }
    private Map<String,Object> catalog(Connection db,Verified v,Map<String,Object>d)throws Exception {
        keys(d,"cursor","lockedCursor","limit");int limit=limit(d);String cursor=text(d,"cursor",80,false),lockedCursor=text(d,"lockedCursor",36,false);
        if(!lockedCursor.isEmpty())uuid(lockedCursor);
        Map<String,Object> page=content.handle(v.accountId(),"content.library.list",Map.of("cursor",cursor,"limit",limit));
        List<Map<String,Object>>locked=new ArrayList<>();String last="";boolean more=false;
        try(var q=db.prepareStatement("SELECT id,title,material FROM library600_discovery WHERE subject=? AND id>? ORDER BY id LIMIT ?")) {
            q.setString(1,v.accountId());q.setString(2,lockedCursor);q.setInt(3,limit+1);
            try(var r=q.executeQuery()){int scanned=0;while(r.next()) {if(scanned++==limit){more=true;break;}last=r.getString(1);
                try{read(v,r.getString(3));continue;}catch(CommunityException missing){if(!missing.code().equals("NOT_FOUND"))throw missing;}
                locked.add(Map.of("opaqueId",last,"displayTitle",r.getString(2),"locked",true,"canRequest",true));}}
        }
        return Map.of("items",page.get("items"),"nextCursor",page.get("nextCursor"),"locked",locked,"nextLockedCursor",more?last:"");
    }
    private Map<String,Object> discoveryGrant(Connection db,Verified v,Map<String,Object>d)throws Exception {
        keys(d,"materialId","subject","displayTitle");String id=id(d,"materialId"),subject=identity(d,"subject"),title=text(d,"displayTitle",300,true);
        Map<String,Object>m=read(v,id);require(v,m,"LIBRARY_ACCESS_MANAGE");
        try(var q=db.prepareStatement("SELECT 1 FROM identities WHERE identity=?")){q.setString(1,subject);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.missing();}}
        String opaque=UUID.randomUUID().toString();
        try(var q=db.prepareStatement("INSERT INTO library600_discovery VALUES(?,?,?,?,?) ON CONFLICT(material,subject) DO UPDATE SET title=excluded.title,issuer=excluded.issuer")) {
            q.setString(1,opaque);q.setString(2,id);q.setString(3,subject);q.setString(4,title);q.setString(5,v.accountId());q.executeUpdate();
        }
        try(var q=db.prepareStatement("SELECT id FROM library600_discovery WHERE material=? AND subject=?")){q.setString(1,id);q.setString(2,subject);try(var r=q.executeQuery()){r.next();opaque=r.getString(1);}}
        store.bumpEpoch(db,subject);store.audit(db,v.accountId(),"LIBRARY_TITLE_DISCOVERY_GRANTED",id,"Explicit title-only metadata permission");
        return Map.of("opaqueId",opaque,"readGranted",false);
    }
    private Map<String,Object> discoveryRevoke(Connection db,Verified v,Map<String,Object>d)throws Exception {
        keys(d,"materialId","subject");String id=id(d,"materialId"),subject=identity(d,"subject");require(v,read(v,id),"LIBRARY_ACCESS_MANAGE");
        sql(db,"DELETE FROM library600_discovery WHERE material=? AND subject=?",id,subject);store.bumpEpoch(db,subject);
        store.audit(db,v.accountId(),"LIBRARY_TITLE_DISCOVERY_REVOKED",id,"Title-only permission revoked");return Map.of("revoked",true);
    }
    private Map<String,Object> accessRequest(Connection db,Verified v,Map<String,Object>d)throws Exception {
        keys(d,"opaqueId","reason");String opaque=id(d,"opaqueId"),reason=text(d,"reason",2000,true),material;
        try(var q=db.prepareStatement("SELECT material FROM library600_discovery WHERE id=? AND subject=?")){q.setString(1,opaque);q.setString(2,v.accountId());try(var r=q.executeQuery()){if(!r.next())throw CommunityException.missing();material=r.getString(1);}}
        try(var q=db.prepareStatement("SELECT count(*) FROM library600_access WHERE subject=?")){q.setString(1,v.accountId());try(var r=q.executeQuery()){r.next();if(r.getInt(1)>=1000)throw new CommunityException("LIMIT","Лимит запросов доступа");}}
        String id=UUID.randomUUID().toString();
        try(var q=db.prepareStatement("INSERT INTO library600_access VALUES(?,?,?,?,?,NULL,?) ON CONFLICT(material,subject) DO NOTHING")) {
            q.setString(1,id);q.setString(2,material);q.setString(3,v.accountId());q.setString(4,reason);q.setString(5,"REQUESTED");q.setLong(6,store.clock().millis());q.executeUpdate();
        }
        try(var q=db.prepareStatement("SELECT id,state FROM library600_access WHERE material=? AND subject=?")){q.setString(1,material);q.setString(2,v.accountId());try(var r=q.executeQuery()){r.next();return Map.of("id",r.getString(1),"state",r.getString(2),"accessGranted",false);}}
    }
    private Map<String,Object> accessList(Connection db,Verified v,Map<String,Object>d)throws Exception {
        keys(d,"materialId","cursor","limit");String material=id(d,"materialId");require(v,read(v,material),"LIBRARY_ACCESS_MANAGE");
        return paged(db,"SELECT id,subject,reason,state,created FROM library600_access WHERE material=? AND id>? ORDER BY id LIMIT ?",material,text(d,"cursor",36,false),limit(d));
    }
    private Map<String,Object> accessDecide(Connection db,Verified v,Map<String,Object>d)throws Exception {
        keys(d,"requestId","decision");String id=id(d,"requestId"),decision=decision(d),material;
        try(var q=db.prepareStatement("SELECT material FROM library600_access WHERE id=? AND state='REQUESTED'")){q.setString(1,id);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.missing();material=r.getString(1);}}
        require(v,read(v,material),"LIBRARY_ACCESS_MANAGE");
        String state=decision.equals("APPROVE")?"APPROVED_PENDING_GRANT":"REJECTED";
        sql(db,"UPDATE library600_access SET state=?,reviewer=? WHERE id=? AND state='REQUESTED'",state,v.accountId(),id);
        store.audit(db,v.accountId(),"LIBRARY_ACCESS_REVIEWED",material,state);
        // Approval is a recorded workflow decision, not an implicit bypass of levels/roles/document ACL.
        return Map.of("id",id,"state",state,"accessGranted",false);
    }
    private Map<String,Object> proposalCreate(Connection db,Verified v,Map<String,Object>d)throws Exception {
        keys(d,"materialId","changeId","baseRevision","title","body");String material=id(d,"materialId"),change=id(d,"changeId");
        String title=text(d,"title",300,true).strip(),body=text(d,"body",250000,true);if(body.getBytes(StandardCharsets.UTF_8).length>512000)throw CommunityException.invalid();long revision=number(d,"baseRevision",1,Long.MAX_VALUE);
        Map<String,Object>m=read(v,material);require(v,m,"LIBRARY_PROPOSE");
        String digest=CommunityStore.hex(CommunityStore.hash(org.securemail.community.core.CanonicalJson.encode(Map.of("material",material,"revision",revision,"title",title,"body",body)).getBytes(StandardCharsets.UTF_8)));
        try(var q=db.prepareStatement("SELECT id,digest,state FROM library600_proposals WHERE author=? AND change_id=?")){q.setString(1,v.accountId());q.setString(2,change);try(var r=q.executeQuery()){if(r.next()){if(!digest.equals(r.getString(2)))throw CommunityException.conflict();return Map.of("id",r.getString(1),"state",r.getString(3));}}}
        if(((Number)m.get("revision")).longValue()!=revision)throw CommunityException.conflict();
        try(var q=db.prepareStatement("SELECT count(*) FROM library600_proposals WHERE author=? AND state='PENDING'")){q.setString(1,v.accountId());try(var r=q.executeQuery()){r.next();if(r.getInt(1)>=100)throw new CommunityException("LIMIT","Слишком много предложений");}}
        String id=UUID.randomUUID().toString();sql(db,"INSERT INTO library600_proposals VALUES(?,?,?,?,?,?,?,?,?,NULL,?)",id,change,material,v.accountId(),revision,title,body,digest,"PENDING",store.clock().millis());
        store.audit(db,v.accountId(),"LIBRARY_CHANGE_PROPOSED",material,id);return Map.of("id",id,"state","PENDING");
    }
    private Map<String,Object> proposalList(Connection db,Verified v,Map<String,Object>d)throws Exception {
        keys(d,"materialId","cursor","limit");String material=id(d,"materialId");Map<String,Object>m=read(v,material);boolean editor=access.has(v.accountId(),"LIBRARY_EDIT",scope(m));
        String cursor=text(d,"cursor",36,false);if(!cursor.isEmpty())uuid(cursor);int limit=limit(d);
        List<Map<String,Object>>out=new ArrayList<>();boolean more=false;
        try(var q=db.prepareStatement("SELECT id,author,base_revision,title,state,created FROM library600_proposals WHERE material=? AND id>?"+(editor?"":" AND author=?")+" ORDER BY id LIMIT ?")) {
            q.setString(1,material);q.setString(2,cursor);if(!editor)q.setString(3,v.accountId());q.setInt(editor?3:4,limit+1);
            try(var r=q.executeQuery()){while(r.next()){if(out.size()==limit){more=true;break;}out.add(Map.of("id",r.getString(1),"author",r.getString(2),"baseRevision",r.getLong(3),"title",r.getString(4),"state",r.getString(5),"created",r.getLong(6)));}}
        }
        return Map.of("items",out,"nextCursor",more?out.getLast().get("id"):"");
    }
    private Map<String,Object> proposalGet(Connection db,Verified v,Map<String,Object>d)throws Exception {
        keys(d,"proposalId");Map<String,Object>p=proposal(db,id(d,"proposalId"));Map<String,Object>m=read(v,(String)p.get("materialId"));
        if(!p.get("author").equals(v.accountId())&&!access.has(v.accountId(),"LIBRARY_EDIT",scope(m)))throw CommunityException.missing();return p;
    }
    private Map<String,Object> proposalDecide(Connection db,Verified v,Map<String,Object>d)throws Exception {
        keys(d,"proposalId","decision");Map<String,Object>p=proposal(db,id(d,"proposalId"));String decision=decision(d),material=(String)p.get("materialId");
        Map<String,Object>m=read(v,material);require(v,m,"LIBRARY_EDIT");if(!p.get("state").equals("PENDING"))throw CommunityException.conflict();
        if(decision.equals("APPROVE")) {
            if(!m.get("revision").equals(p.get("baseRevision")))throw CommunityException.conflict();
            boolean published=Set.of("PUBLISHED","CORRECTED").contains(m.get("state"));if(published)require(v,m,"LIBRARY_PUBLISH");
            Map<String,Object>changed=content.handle(v.accountId(),"content.library.update",Map.of("id",material,"revision",p.get("baseRevision"),"title",p.get("title"),"body",p.get("body")));
            if(published)content.handle(v.accountId(),"content.library.publish",Map.of("id",material,"revision",changed.get("revision")));
        }
        String state=decision.equals("APPROVE")?"APPROVED":"REJECTED";sql(db,"UPDATE library600_proposals SET state=?,reviewer=? WHERE id=? AND state='PENDING'",state,v.accountId(),p.get("id"));
        store.audit(db,v.accountId(),"LIBRARY_CHANGE_REVIEWED",material,state);return Map.of("id",p.get("id"),"state",state);
    }
    private Map<String,Object> proposal(Connection db,String id)throws Exception {
        try(var q=db.prepareStatement("SELECT * FROM library600_proposals WHERE id=?")){q.setString(1,id);try(var r=q.executeQuery()){if(!r.next())throw CommunityException.missing();return Map.of("id",id,"materialId",r.getString("material"),"author",r.getString("author"),"baseRevision",r.getLong("base_revision"),"title",r.getString("title"),"body",r.getString("body"),"state",r.getString("state"));}}
    }
    private Map<String,Object> paged(Connection db,String sql,String material,String cursor,int limit)throws Exception {
        if(!cursor.isEmpty())uuid(cursor);List<Map<String,Object>>out=new ArrayList<>();boolean more=false;
        try(var q=db.prepareStatement(sql)){q.setString(1,material);q.setString(2,cursor);q.setInt(3,limit+1);try(var r=q.executeQuery()){while(r.next()){if(out.size()==limit){more=true;break;}out.add(Map.of("id",r.getString(1),"subject",r.getString(2),"reason",r.getString(3),"state",r.getString(4),"created",r.getLong(5)));}}}
        return Map.of("items",out,"nextCursor",more?out.getLast().get("id"):"");
    }
    private static String decision(Map<String,Object>d)throws Exception {String s=text(d,"decision",10,true);if(!Set.of("APPROVE","REJECT").contains(s))throw CommunityException.invalid();return s;}
    private static int limit(Map<String,Object>d)throws Exception{return d.containsKey("limit")?(int)number(d,"limit",1,100):25;}
    private static String id(Map<String,Object>d,String key)throws Exception{return uuid(text(d,key,36,true));}
    private static String uuid(String s)throws Exception {try{if(!UUID.fromString(s).toString().equals(s))throw new IllegalArgumentException();return s;}catch(RuntimeException e){throw CommunityException.invalid();}}
    private static String identity(Map<String,Object>d,String key)throws Exception{String s=text(d,key,64,true);if(!s.matches("[a-f0-9]{64}"))throw CommunityException.invalid();return s;}
    private static long number(Map<String,Object>d,String k,long min,long max)throws Exception {
        Object v=d.get(k);if(!(v instanceof Number))throw CommunityException.invalid();try{long n=new java.math.BigDecimal(v.toString()).longValueExact();if(n<min||n>max)throw new ArithmeticException();return n;}catch(RuntimeException e){throw CommunityException.invalid();}
    }
    private static String text(Map<String,Object>d,String k,int max,boolean required)throws Exception {
        Object v=d.get(k);if(v==null&&!required)return "";if(!(v instanceof String s)||s.length()>max||required&&s.isBlank()||s.indexOf('\0')>=0)throw CommunityException.invalid();
        for(int i=0;i<s.length();i++)if(Character.isSurrogate(s.charAt(i))&&(!Character.isHighSurrogate(s.charAt(i))||i+1>=s.length()||!Character.isLowSurrogate(s.charAt(++i))))throw CommunityException.invalid();return s;
    }
    private static void keys(Map<String,Object>d,String...keys)throws Exception {Set<String>allowed=Set.of(keys);if(!allowed.containsAll(d.keySet()))throw CommunityException.invalid();}
    private static void sql(Connection db,String sql,Object...args)throws Exception {try(var q=db.prepareStatement(sql)){for(int i=0;i<args.length;i++)q.setObject(i+1,args[i]);q.executeUpdate();}}
    @SuppressWarnings("unchecked") private static Map<String,Object> snapshot(Map<String,Object>source)throws Exception {return (Map<String,Object>)copyValue(source,0);}
    private static Object copyValue(Object value,int depth)throws Exception {
        if(depth>4)throw CommunityException.invalid();
        if(value instanceof Map<?,?>map){if(map.size()>16)throw CommunityException.invalid();Map<String,Object>copy=new LinkedHashMap<>();for(var entry:map.entrySet()){if(!(entry.getKey()instanceof String key))throw CommunityException.invalid();copy.put(key,copyValue(entry.getValue(),depth+1));}return Collections.unmodifiableMap(copy);}
        if(value instanceof List<?>list){if(list.size()>64)throw CommunityException.invalid();List<Object>copy=new ArrayList<>();for(Object item:list)copy.add(copyValue(item,depth+1));return Collections.unmodifiableList(copy);}
        if(value instanceof String||value instanceof Number||value instanceof Boolean)return value;throw CommunityException.invalid();
    }
}
