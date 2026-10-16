package org.securemail.community.access;
import org.junit.jupiter.api.Test;
import org.securemail.community.core.*;
import java.math.BigDecimal;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
class CoreInputTest {
 @Test void exactIntegerFieldsRejectFractionHiddenByDoubleRoundingAndOverflow()throws Exception{assertEquals(1,Values.number(Map.of("n",new BigDecimal("1.000")),"n"));assertThrows(CommunityException.class,()->Values.number(Map.of("n",new BigDecimal("1.0000000000000000001")),"n"));assertThrows(CommunityException.class,()->Values.number(Map.of("n",new BigDecimal("9223372036854775808")),"n"));assertThrows(CommunityException.class,()->Values.number(Map.of("n",Double.NaN),"n"));}
 @Test void canonicalNumbersPreserveFractionsAndBoundExpansionBeforeAllocation()throws Exception{assertEquals("{\"n\":1.0000000000000000001}",CanonicalJson.encode(Map.of("n",new BigDecimal("1.0000000000000000001"))));assertEquals("{\"n\":0.9}",CanonicalJson.encode(Map.of("n",new BigDecimal("0.9000"))));assertThrows(CommunityException.class,()->CanonicalJson.encode(Map.of("n",new BigDecimal("1e99999999"))));assertThrows(CommunityException.class,()->CanonicalJson.encode(Map.of("n",new BigDecimal("1e-99999999"))));assertThrows(CommunityException.class,()->CanonicalJson.encode(Map.of("n",Double.POSITIVE_INFINITY)));}
 @Test void malformedUnicodeCannotAliasAnotherCriticalOperation()throws Exception{assertThrows(CommunityException.class,()->CanonicalJson.encode(Map.of("text","\ud800")));assertEquals("{\"text\":\"😀\"}",CanonicalJson.encode(Map.of("text","😀")));}
}
