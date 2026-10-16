package org.securemail.client.community;
import static org.junit.jupiter.api.Assertions.*;
import com.google.gson.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class CommunityJsonTest {
 private JsonObject parse(String text)throws IOException{return CommunityJson.parse(text.getBytes(StandardCharsets.UTF_8));}
 @Test void russianUnicodeAndExactLongAccepted()throws Exception {JsonObject o=parse("{\"текст\":\"АЕГИС 🕊\",\"revision\":9223372036854775807,\"n\":-0.125,\"ok\":true,\"none\":null}");assertEquals("АЕГИС 🕊",o.get("текст").getAsString());assertEquals(Long.MAX_VALUE,o.get("revision").getAsLong());}
 @Test void duplicateNamesAtAnyDepthRejected(){for(String s:new String[]{"{\"x\":1,\"x\":2}","{\"a\":{\"x\":1,\"x\":2}}","{\"x\":1,\"\\u0078\":2}"})assertThrows(IOException.class,()->parse(s));}
 @Test void malformedUtf8DoesNotBecomeReplacementCharacter(){assertThrows(IOException.class,()->CommunityJson.parse(new byte[]{'{','"','x','"',':','"',(byte)0xc0,(byte)0xaf,'"','}'}));}
 @Test void unpairedEscapedSurrogatesRejected(){for(String s:new String[]{"{\"x\":\"\\ud800\"}","{\"x\":\"\\udc00\"}","{\"\\ud800\":1}"})assertThrows(IOException.class,()->parse(s));}
 @Test void validSurrogatePairAccepted()throws Exception {assertEquals("🕊",parse("{\"x\":\"\\ud83d\\udd4a\"}").get("x").getAsString());}
 @Test void strictSyntaxNoCommentsTrailingValuesOrLenientNumbers(){for(String s:new String[]{"{x:1}","{\"x\":1,}","{\"x\":NaN}","{\"x\":Infinity}","{\"x\":01}","{}{}","[]","//x\n{}","{'x':1}"})assertThrows(IOException.class,()->parse(s));}
 @Test void depthBoundBeforeRecursiveStackOverflow(){String text="{\"a\":"+"[".repeat(17)+"0"+"]".repeat(17)+"}";assertThrows(IOException.class,()->parse(text));}
 @Test void nodeLimitIsBounded(){String text="{\"a\":["+"0,".repeat(8192)+"0]}";assertThrows(IOException.class,()->parse(text));}
 @Test void numberExponentsAndHugePrecisionBounded(){for(String n:new String[]{"1e2147483647","1e-2147483647","1".repeat(129)})assertThrows(IOException.class,()->parse("{\"x\":"+n+"}"));}
 @Test void stringLimitCountsUtf8Bytes(){String body="я".repeat(3*1024*1024+1);assertThrows(IOException.class,()->parse("{\"x\":\""+body+"\"}"));}
 @Test void largeMeasuredFileResponseSupported()throws Exception {String encoded="A".repeat(5_600_000);assertEquals(encoded.length(),parse("{\"base64\":\""+encoded+"\"}").get("base64").getAsString().length());}
 @Test void oversizedEmptyAndNullDocumentsRejected(){assertThrows(IOException.class,()->CommunityJson.parse(null));assertThrows(IOException.class,()->CommunityJson.parse(new byte[0]));assertThrows(IOException.class,()->CommunityJson.parse(new byte[CommunityJson.MAX_BYTES+1]));}
}
