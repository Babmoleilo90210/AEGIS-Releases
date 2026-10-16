package org.securemail.community.core;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Locale;
/** RFC 6238, SHA-256, 8 digits, 30 seconds. The persisted highest counter prevents replay. */
public final class Totp {
 private Totp(){}
 public static String code(byte[]seed,long unixMillis)throws Exception{return atCounter(seed,Math.floorDiv(unixMillis,30000));}
 public static String atCounter(byte[]seed,long counter)throws Exception{
  if(seed.length!=32||counter<0)throw new IllegalArgumentException("TOTP parameters");Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(seed,"HmacSHA256"));byte[]digest=mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());try{int p=digest[digest.length-1]&15;int binary=((digest[p]&127)<<24)|((digest[p+1]&255)<<16)|((digest[p+2]&255)<<8)|(digest[p+3]&255);return String.format(Locale.ROOT,"%08d",binary%100000000);}finally{Arrays.fill(digest,(byte)0);}
 }
 public static long match(byte[]seed,String code,long now,long lastCounter)throws Exception{
  if(code==null||!code.matches("[0-9]{8}"))return -1;long current=Math.floorDiv(now,30000),found=-1;
  for(long c=Math.max(0,current-1);c<=current+1;c++){String expected=atCounter(seed,c);boolean same=java.security.MessageDigest.isEqual(expected.getBytes(java.nio.charset.StandardCharsets.US_ASCII),code.getBytes(java.nio.charset.StandardCharsets.US_ASCII));if(same&&c>lastCounter)found=c;}return found;
 }
}
