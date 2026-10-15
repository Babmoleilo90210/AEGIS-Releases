package org.securemail.relay;
final class Rejection extends java.io.IOException { final int code; Rejection(int code){super("Request rejected");this.code=code;} }
