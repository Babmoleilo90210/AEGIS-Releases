package org.securemail.community.content;

import org.securemail.community.http.StrictJson;
import java.util.*;

/** Leave room for the signed envelope under both production JSON decoders (8192 values/8 MiB). */
final class ContentResponseBudget {
    private static final long MAX_VALUES=7000,MAX_BYTES=7L*1024*1024;
    private long values=32,bytes=4096;
    boolean take(Object value){return takeAll(List.of(value));}
    boolean takeAll(Collection<?> additional){
        long nextValues=values,nextBytes=bytes;
        for(Object value:additional){nextValues+=count(value);nextBytes+=StrictJson.bytes(value).length+1L;}
        if(nextValues>MAX_VALUES||nextBytes>MAX_BYTES)return false;
        values=nextValues;bytes=nextBytes;return true;
    }
    private static long count(Object value){
        long count=1;
        if(value instanceof Map<?,?> map)for(Object child:map.values())count+=count(child);
        else if(value instanceof Collection<?> list)for(Object child:list)count+=count(child);
        return count;
    }
}
