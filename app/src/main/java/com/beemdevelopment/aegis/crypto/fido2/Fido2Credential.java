package com.beemdevelopment.aegis.crypto.fido2;

/**
 * A FIDO2 credential that was created with the hmac-secret extension.
 */
public interface Fido2Credential {
    String getRpId();

    byte[] getCredentialId();

    /**
     * Returns the salt that is passed to the hmac-secret extension.
     */
    byte[] getSalt();

    /**
     * Reports whether user verification (PIN) is used to obtain the hmac-secret output.
     * The authenticator yields a different output with and without user verification.
     */
    boolean isUv();
}
