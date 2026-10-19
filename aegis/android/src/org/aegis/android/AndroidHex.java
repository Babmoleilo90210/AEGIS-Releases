package org.aegis.android;
/** API-33 compatible formatting only; no cryptographic algorithm. */
public final class AndroidHex {
 public static final AndroidHex INSTANCE=new AndroidHex(false);private final boolean upper;private AndroidHex(boolean upper){this.upper=upper;}
 public AndroidHex withUpperCase(){return upper?this:new AndroidHex(true);}
 public String formatHex(byte[] bytes){return formatHex(bytes,0,bytes.length);}
 public String formatHex(byte[] bytes,int from,int to){if(from<0||to<from||to>bytes.length)throw new IndexOutOfBoundsException();char[] out=new char[(to-from)*2];char[] digits=(upper?"0123456789ABCDEF":"0123456789abcdef").toCharArray();for(int i=from;i<to;i++){out[(i-from)*2]=digits[(bytes[i]>>>4)&15];out[(i-from)*2+1]=digits[bytes[i]&15];}return new String(out);}
 public byte[] parseHex(String s){if((s.length()&1)!=0)throw new IllegalArgumentException("Hex");byte[] out=new byte[s.length()/2];for(int i=0;i<out.length;i++){int h=Character.digit(s.charAt(i*2),16),l=Character.digit(s.charAt(i*2+1),16);if(h<0||l<0)throw new IllegalArgumentException("Hex");out[i]=(byte)((h<<4)|l);}return out;}
}
