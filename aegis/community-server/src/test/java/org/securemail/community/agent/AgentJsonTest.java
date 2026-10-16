package org.securemail.community.agent;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
final class AgentJsonTest{
 @Test void duplicateFieldsAndTrailingDataAreRejected(){for(String json:List.of("{\"a\":1,\"a\":2}","{}{}","{\"a\":01}","{\"a\":NaN}","{\"a\":1e2147483647}","{\"a\":1e-2147483647}","{\"a\":1١}","{\"a\":\"\\u+001\"}","{\"a\":\"\\u٠٠٤١\"}","{\"a\":\"\\ud800\"}"))assertThrows(IOException.class,()->AgentJson.object(json.getBytes(StandardCharsets.UTF_8),1000));}
 @Test void invalidUtf8DepthAndSizeRejected(){assertThrows(IOException.class,()->AgentJson.object(new byte[]{'{','"','a','"',':','"',(byte)0xc0,(byte)0x80,'"','}'},100));assertThrows(IOException.class,()->AgentJson.object(("{\"a\":"+"[".repeat(18)+"0"+"]".repeat(18)+"}").getBytes(StandardCharsets.UTF_8),1000));assertThrows(IOException.class,()->AgentJson.object("{}".getBytes(StandardCharsets.UTF_8),1));}
 @Test void russianSupplementaryUnicodeAndNumbersRoundTrip()throws Exception{var m=Map.of("text","Русский текст 🕸","list",List.of(1,true,"x"));assertEquals(m.get("text"),AgentJson.object(AgentJson.bytes(m),1000).get("text"));}
}
