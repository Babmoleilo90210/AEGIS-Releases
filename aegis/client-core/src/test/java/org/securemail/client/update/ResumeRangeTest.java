package org.securemail.client.update;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
class ResumeRangeTest {
  @Test void exactRangeRequired(){assertDoesNotThrow(()->TorHttpsClient.checkRange("bytes 10-99/100",10,100));}
  @Test void mismatchedOrAmbiguousRangeRejected(){for(String value:new String[]{"bytes 0-99/100","bytes 10-98/100","bytes 10-99/101","bytes */100","bytes 10-99/100, 200-300/400","bytes 9999999999999999999999-99/100"})assertThrows(java.io.IOException.class,()->TorHttpsClient.checkRange(value,10,100));}
}
