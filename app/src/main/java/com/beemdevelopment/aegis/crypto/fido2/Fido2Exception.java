package com.beemdevelopment.aegis.crypto.fido2;

import androidx.annotation.Nullable;

public class Fido2Exception extends Exception {
    public enum Reason {
        /** The device does not support CTAP2 (e.g. a U2F-only key or a non-FIDO NFC tag). */
        UNSUPPORTED_DEVICE,
        /** The authenticator does not support the hmac-secret extension. */
        HMAC_SECRET_UNSUPPORTED,
        /** None of the given credentials belong to this authenticator. */
        NOT_ENROLLED,
        /** The authenticator already holds one of the given credentials. */
        ALREADY_ENROLLED,
        /** A PIN is needed to continue. */
        PIN_REQUIRED,
        /** The PIN is shorter than the minimum PIN length of the authenticator. */
        PIN_TOO_SHORT,
        PIN_INVALID,
        /** Too many wrong PINs in a row. The authenticator has to be power cycled (re-plugged or re-tapped). */
        PIN_AUTH_BLOCKED,
        /** The PIN retry counter is exhausted. The authenticator can only be used again after a reset. */
        PIN_BLOCKED,
        /** The authenticator requires user verification, but no PIN has been set. */
        PIN_NOT_SET,
        /** The authenticator requires the PIN to be changed before it can be used. */
        PIN_CHANGE_REQUIRED,
        /** The user verification setting of the authenticator no longer matches the one used during enrollment. */
        UV_MISMATCH,
        /** The authenticator returned a secret that does not decrypt the slot. */
        SECRET_MISMATCH,
        /** The credential was created, but the authenticator has to be tapped again to obtain its secret. */
        CONFIRM_REQUIRED,
        CANCELLED,
        TIMEOUT,
        DENIED,
        PROTOCOL_ERROR
    }

    private final Reason _reason;
    private final int _pinRetries;
    private final int _minPinLength;
    @Nullable
    private final Fido2Credential _credential;

    public Fido2Exception(Reason reason) {
        this(reason, null);
    }

    public Fido2Exception(Reason reason, @Nullable Throwable cause) {
        this(reason, -1, -1, null, cause);
    }

    private Fido2Exception(Reason reason, int pinRetries, int minPinLength, @Nullable Fido2Credential credential, @Nullable Throwable cause) {
        super(reason.toString(), cause);
        _reason = reason;
        _pinRetries = pinRetries;
        _minPinLength = minPinLength;
        _credential = credential;
    }

    public static Fido2Exception withPinRetries(Reason reason, int pinRetries, @Nullable Throwable cause) {
        return new Fido2Exception(reason, pinRetries, -1, null, cause);
    }

    public static Fido2Exception withMinPinLength(Reason reason, int minPinLength) {
        return new Fido2Exception(reason, -1, minPinLength, null, null);
    }

    public static Fido2Exception withCredential(Reason reason, @Nullable Fido2Credential credential) {
        return new Fido2Exception(reason, -1, -1, credential, null);
    }

    public Reason getReason() {
        return _reason;
    }

    /**
     * Returns the number of remaining PIN attempts, or -1 if unknown.
     */
    public int getPinRetries() {
        return _pinRetries;
    }

    /**
     * Returns the minimum PIN length of the authenticator, or -1 if unknown.
     */
    public int getMinPinLength() {
        return _minPinLength;
    }

    /**
     * Returns the credential this error relates to, if any.
     */
    @Nullable
    public Fido2Credential getCredential() {
        return _credential;
    }

    /**
     * Reports whether this error represents a failed attempt to unlock the vault that should be
     * recorded in the audit log.
     */
    public boolean isAuditable() {
        switch (_reason) {
            case NOT_ENROLLED:
            case PIN_INVALID:
            case PIN_AUTH_BLOCKED:
            case PIN_BLOCKED:
            case UV_MISMATCH:
            case SECRET_MISMATCH:
                return true;
            default:
                return false;
        }
    }
}
