package com.beemdevelopment.aegis.vault.slots;

import androidx.annotation.NonNull;

import com.beemdevelopment.aegis.crypto.CryptParameters;
import com.beemdevelopment.aegis.crypto.MasterKey;
import com.beemdevelopment.aegis.crypto.fido2.Fido2Credential;
import com.beemdevelopment.aegis.encoding.Hex;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * A slot that wraps the master key with the output of the hmac-secret extension of a FIDO2
 * security key. The 32-byte hmac-secret output is used directly as the AES-256 wrapping key.
 */
public class Fido2Slot extends RawSlot implements Fido2Credential {
    public static final String DEFAULT_RP_ID = "com.beemdevelopment.aegis";
    public static final int SECRET_SIZE = 32;
    public static final int SALT_SIZE = 32;

    private String _name;
    private String _rpId;
    private byte[] _credentialId;
    private byte[] _salt;
    private boolean _uv;
    private long _createdAt;

    public Fido2Slot(@NonNull String name, @NonNull String rpId, @NonNull byte[] credentialId, @NonNull byte[] salt, boolean uv, long createdAt) {
        super();
        _name = name;
        _rpId = rpId;
        _credentialId = credentialId;
        _salt = salt;
        _uv = uv;
        _createdAt = createdAt;
    }

    protected Fido2Slot(UUID uuid, byte[] key, CryptParameters keyParams, String name, String rpId, byte[] credentialId, byte[] salt, boolean uv, long createdAt) {
        super(uuid, key, keyParams);
        _name = name;
        _rpId = rpId;
        _credentialId = credentialId;
        _salt = salt;
        _uv = uv;
        _createdAt = createdAt;
    }

    @Override
    public JSONObject toJson() {
        try {
            JSONObject obj = super.toJson();
            obj.put("name", _name);
            obj.put("rp_id", _rpId);
            obj.put("credential_id", Hex.encode(_credentialId));
            obj.put("salt", Hex.encode(_salt));
            obj.put("uv", _uv);
            obj.put("created", _createdAt);
            return obj;
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Turns the given hmac-secret output into the key that wraps the master key.
     */
    public SecretKey deriveKey(byte[] secret) {
        if (secret.length != SECRET_SIZE) {
            throw new IllegalArgumentException(String.format("Bad hmac-secret output length: %d", secret.length));
        }
        return new SecretKeySpec(secret, "AES");
    }

    /**
     * Encrypts the given master key with the given hmac-secret output and stores the result in this slot.
     */
    public void wrap(MasterKey masterKey, byte[] secret) throws SlotException {
        Cipher cipher = Slot.createEncryptCipher(deriveKey(secret));
        setKey(masterKey, cipher);
    }

    /**
     * Decrypts the master key in this slot with the given hmac-secret output.
     */
    public MasterKey unwrap(byte[] secret) throws SlotException, SlotIntegrityException {
        Cipher cipher = createDecryptCipher(deriveKey(secret));
        return getKey(cipher);
    }

    public String getName() {
        return _name;
    }

    public void setName(@NonNull String name) {
        _name = name;
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

    /**
     * Returns the time this slot was created at in milliseconds since the epoch, or 0 if unknown.
     */
    public long getCreatedAt() {
        return _createdAt;
    }

    @Override
    public byte getType() {
        return TYPE_FIDO2;
    }
}
