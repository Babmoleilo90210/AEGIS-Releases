package org.aegis.android;
/** Reviewed upstream lwIP/hev engine with explicit protect and domain/UDP restrictions. */
final class NativeTun {
    static {System.loadLibrary("hev-socks5-tunnel");}
    interface Protector {boolean protectDescriptor(int fd);}
    static native int run(byte[] privateConfig,int tunDescriptor,String blockRules,Protector protector);
    static native void quit();
}
