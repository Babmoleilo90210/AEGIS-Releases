package org.securemail.identity;
/** Public errors intentionally do not reveal account/device existence. */
public final class IdentityException extends RuntimeException {
    private static final long serialVersionUID=1L;
    private final String code;
    public IdentityException(String code){super(code);this.code=code;}
    public String code(){return code;}
}
