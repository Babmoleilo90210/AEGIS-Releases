package org.aegis.android;

import android.content.Context;
import org.json.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Local, encrypted, bounded metadata queue. No FCM or remote-delivery claim. */
final class EventQueue {
    private static EventQueue instance;
    static synchronized EventQueue get(Context c){if(instance==null)instance=new EventQueue(c.getApplicationContext());return instance;}
    private final PrivateVault vault;private final LinkedHashMap<String,Integer> counts=new LinkedHashMap<>();private final LinkedHashSet<String> seen=new LinkedHashSet<>();
    private EventQueue(Context c){vault=new PrivateVault(c);try{byte[] b=vault.get("event-queue");if(b!=null)try{JSONObject j=new JSONObject(new String(b,StandardCharsets.UTF_8));JSONObject values=j.getJSONObject("counts");for(String p:List.of(AndroidPolicy.MAIL,AndroidPolicy.GLAS,AndroidPolicy.STRAZH))counts.put(p,Math.max(0,Math.min(999,values.optInt(p,0))));JSONArray ids=j.getJSONArray("seen");for(int i=0;i<Math.min(256,ids.length());i++)seen.add(ids.getString(i));}finally{Arrays.fill(b,(byte)0);}}catch(Exception damaged){counts.clear();seen.clear();}}
    synchronized boolean accept(String pkg,String id,int count)throws Exception {AndroidPolicy.app(pkg);if(AndroidPolicy.CORE.equals(pkg)||!id.matches("[a-f0-9]{32}")||count<0||count>999)throw new SecurityException("Событие недопустимо");String key=pkg+":"+id;if(!seen.add(key))return false;while(seen.size()>256)seen.remove(seen.iterator().next());counts.put(pkg,count);save();return true;}
    synchronized int count(String pkg){return counts.getOrDefault(pkg,0);}
    synchronized void clear()throws Exception{counts.clear();seen.clear();save();}
    private void save()throws Exception {JSONObject j=new JSONObject(),c=new JSONObject();for(Map.Entry<String,Integer> e:counts.entrySet())c.put(e.getKey(),e.getValue());j.put("counts",c);j.put("seen",new JSONArray(seen));byte[] b=j.toString().getBytes(StandardCharsets.UTF_8);try{vault.put("event-queue",b);}finally{Arrays.fill(b,(byte)0);}}
}
