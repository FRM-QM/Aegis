package com.beemdevelopment.aegis.crypto.fido2;

import androidx.annotation.Nullable;

/**
 * The parts of an authenticatorGetAssertion response that are relevant for hmac-secret.
 */
public class Fido2Assertion {
    @Nullable
    private final byte[] _credentialId;
    private final byte[] _authenticatorData;

    public Fido2Assertion(@Nullable byte[] credentialId, byte[] authenticatorData) {
        _credentialId = credentialId;
        _authenticatorData = authenticatorData;
    }

    /**
     * Returns the ID of the credential that was used, or null if the authenticator omitted it.
     * Authenticators may omit it if the allow list contained exactly one credential.
     */
    @Nullable
    public byte[] getCredentialId() {
        return _credentialId;
    }

    public byte[] getAuthenticatorData() {
        return _authenticatorData;
    }
}
