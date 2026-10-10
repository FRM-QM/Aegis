package com.beemdevelopment.aegis.crypto.fido2;

/**
 * A credential that was just created on an authenticator, but for which the hmac-secret output
 * has not been obtained yet. See {@link Fido2HmacSecret#register} and {@link Fido2HmacSecret#confirm}.
 */
public class Fido2Registration {
    private final String _rpId;
    private final byte[] _credentialId;
    private final boolean _uv;

    public Fido2Registration(String rpId, byte[] credentialId, boolean uv) {
        _rpId = rpId;
        _credentialId = credentialId;
        _uv = uv;
    }

    public String getRpId() {
        return _rpId;
    }

    public byte[] getCredentialId() {
        return _credentialId;
    }

    public boolean isUv() {
        return _uv;
    }
}
