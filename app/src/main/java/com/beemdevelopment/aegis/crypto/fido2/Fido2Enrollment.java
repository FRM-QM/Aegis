package com.beemdevelopment.aegis.crypto.fido2;

import java.util.Arrays;

/**
 * The result of enrolling a security key: a new credential and its hmac-secret output for a fresh salt.
 */
public class Fido2Enrollment implements Fido2Credential {
    private final String _rpId;
    private final byte[] _credentialId;
    private final byte[] _salt;
    private final boolean _uv;
    private final byte[] _secret;

    public Fido2Enrollment(String rpId, byte[] credentialId, byte[] salt, boolean uv, byte[] secret) {
        _rpId = rpId;
        _credentialId = credentialId;
        _salt = salt;
        _uv = uv;
        _secret = secret;
    }

    @Override
    public String getRpId() {
        return _rpId;
    }

    @Override
    public byte[] getCredentialId() {
        return _credentialId;
    }

    @Override
    public byte[] getSalt() {
        return _salt;
    }

    @Override
    public boolean isUv() {
        return _uv;
    }

    public byte[] getSecret() {
        return _secret;
    }

    /**
     * Overwrites the hmac-secret output in memory.
     */
    public void wipe() {
        Arrays.fill(_secret, (byte) 0);
    }
}
