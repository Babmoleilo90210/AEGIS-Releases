package org.securemail.community.access;
import org.junit.jupiter.api.Test;
import org.securemail.community.core.Totp;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;
class TotpTest {
 @Test void officialRfc6238Sha256Vectors()throws Exception{
  byte[]seed="12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);long[]times={59,1111111109L,1111111111L,1234567890L,2000000000L,20000000000L};String[]expected={"46119246","68084774","67062674","91819424","90698825","77737706"};for(int i=0;i<times.length;i++)assertEquals(expected[i],Totp.code(seed,times[i]*1000),"RFC6238 time "+times[i]);
 }
 @Test void windowReplayAndMalformedRejection()throws Exception{byte[]seed="12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);long now=1234567890000L,counter=now/30000;String code=Totp.code(seed,now);assertEquals(counter,Totp.match(seed,code,now,-1));assertEquals(-1,Totp.match(seed,code,now,counter));assertEquals(-1,Totp.match(seed,code,now+90000,-1));assertEquals(-1,Totp.match(seed,"123",now,-1));}
}
