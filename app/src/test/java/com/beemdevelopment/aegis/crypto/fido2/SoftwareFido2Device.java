package com.beemdevelopment.aegis.crypto.fido2;

import androidx.annotation.Nullable;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * A software implementation of the parts of a CTAP2 authenticator that are needed for hmac-secret.
 * It does not implement any public key cryptography, as that's not needed to test the protocol logic.
 */
public class SoftwareFido2Device implements Fido2Device {
    private static final int MAX_PIN_RETRIES = 8;
    private static final byte FLAG_UP = 0x01;
    private static final byte FLAG_UV = 0x04;
    private static final byte FLAG_AT = 0x40;
    private static final byte FLAG_ED = (byte) 0x80;
    private static final int CRED_PROTECT_UV_REQUIRED = 3;

    private final SecureRandom _random = new SecureRandom();
    private final Map<String, Credential> _credentials = new HashMap<>();
    private final List<PinToken> _tokens = new ArrayList<>();
    private final Map<Integer, byte[]> _sharedSecrets = new HashMap<>();

    // configuration
    private List<String> _versions = Arrays.asList("FIDO_2_0", "FIDO_2_1");
    private List<String> _extensions = Arrays.asList("credProtect", "hmac-secret");
    private List<Integer> _protocols = Arrays.asList(2, 1);
    private Integer _maxCredentialCountInList = 8;
    private Integer _maxCredentialIdLength = 128;
    private int _minPinLength = 4;
    private boolean _forcePinChange;
    private boolean _alwaysUv;
    private boolean _silentAssertions = true;
    private boolean _omitSingleCredential;
    private int _credentialIdLength = 64;
    private boolean _nfc;
    private byte _nfcPresenceError = CtapException.ERR_OPERATION_DENIED;
    private boolean _reportUpNeeded = true;

    // state
    private char[] _pin;
    private int _pinRetries = MAX_PIN_RETRIES;
    private int _consecutivePinFailures;
    private boolean _powerCycleRequired;
    private boolean _nfcUserPresent = true;

    // statistics
    private int _touches;
    private int _silentAssertionCount;
    private Map<Integer, ?> _lastHmacSecretInput;
    private Map<String, ?> _lastMakeCredentialExtensions;

    @Override
    public Fido2Info getInfo() {
        Map<String, Object> options = new HashMap<>();
        options.put("rk", true);
        options.put("up", true);
        options.put("pinUvAuthToken", _versions.contains("FIDO_2_1"));
        options.put("clientPin", _pin != null);
        if (_alwaysUv) {
            options.put("alwaysUv", true);
        }
        return new Fido2Info(_versions, _extensions, options, _protocols, _maxCredentialCountInList,
                _maxCredentialIdLength, _minPinLength, _forcePinChange);
    }

    @Override
    public byte[] makeCredential(byte[] clientDataHash, Map<String, ?> rp, Map<String, ?> user,
                                 List<Map<String, ?>> pubKeyCredParams, @Nullable List<Map<String, ?>> excludeList,
                                 @Nullable Map<String, ?> extensions, @Nullable Map<String, ?> options,
                                 @Nullable byte[] pinUvAuthParam, @Nullable Integer pinUvAuthProtocol,
                                 @Nullable CommandState state) throws IOException, CommandException {
        String rpId = (String) rp.get("id");
        _lastMakeCredentialExtensions = extensions;

        boolean uv = false;
        if (pinUvAuthParam != null) {
            verifyToken(pinUvAuthParam, pinUvAuthProtocol, clientDataHash, ClientPin.PIN_PERMISSION_MC, rpId);
            uv = true;
        } else if (_pin != null || _alwaysUv) {
            throw new CtapException(CtapException.ERR_PUAT_REQUIRED);
        }

        if (excludeList != null) {
            for (Map<String, ?> descriptor : excludeList) {
                Credential cred = findCredential(rpId, (byte[]) descriptor.get("id"), uv);
                if (cred != null) {
                    touch(state);
                    throw new CtapException(CtapException.ERR_CREDENTIAL_EXCLUDED);
                }
            }
        }

        touch(state);

        int credProtect = 1;
        if (extensions != null && extensions.get("credProtect") instanceof Integer && _extensions.contains("credProtect")) {
            credProtect = (Integer) extensions.get("credProtect");
        }

        Credential cred = new Credential(rpId, randomBytes(_credentialIdLength), randomBytes(32), randomBytes(32), credProtect);
        _credentials.put(key(rpId, cred.id), cred);

        boolean hmacSecret = extensions != null && Boolean.TRUE.equals(extensions.get("hmac-secret"))
                && _extensions.contains("hmac-secret");

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
        out.write(FLAG_UP | (uv ? FLAG_UV : 0) | FLAG_AT | (hmacSecret ? FLAG_ED : 0));
        out.write(new byte[4]);
        out.write(new byte[16]);
        out.write(ByteBuffer.allocate(2).putShort((short) cred.id.length).array());
        out.write(cred.id);

        Map<Integer, Object> coseKey = new HashMap<>();
        coseKey.put(1, 2);
        coseKey.put(3, -7);
        coseKey.put(-1, 1);
        coseKey.put(-2, new byte[32]);
        coseKey.put(-3, new byte[32]);
        out.write(Cbor.encode(coseKey));

        if (hmacSecret) {
            Map<String, Object> outputs = new HashMap<>();
            outputs.put("hmac-secret", true);
            out.write(Cbor.encode(outputs));
        }

        return out.toByteArray();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Fido2Assertion> getAssertions(String rpId, byte[] clientDataHash, List<Map<String, ?>> allowList,
                                              @Nullable Map<String, ?> extensions, @Nullable Map<String, ?> options,
                                              @Nullable byte[] pinUvAuthParam, @Nullable Integer pinUvAuthProtocol,
                                              @Nullable CommandState state) throws IOException, CommandException {
        boolean up = options == null || !Boolean.FALSE.equals(options.get("up"));
        if (!up) {
            if (!_silentAssertions) {
                throw new CtapException(CtapException.ERR_INVALID_OPTION);
            }
            _silentAssertionCount++;
        }

        boolean uv = false;
        if (pinUvAuthParam != null) {
            verifyToken(pinUvAuthParam, pinUvAuthProtocol, clientDataHash, ClientPin.PIN_PERMISSION_GA, rpId);
            uv = true;
        } else if (_alwaysUv && up) {
            throw new CtapException(CtapException.ERR_PUAT_REQUIRED);
        }

        if (_maxCredentialCountInList != null && allowList.size() > _maxCredentialCountInList) {
            throw new CtapException(CtapException.ERR_LIMIT_EXCEEDED);
        }

        Credential cred = null;
        for (Map<String, ?> descriptor : allowList) {
            cred = findCredential(rpId, (byte[]) descriptor.get("id"), uv);
            if (cred != null) {
                break;
            }
        }
        if (cred == null) {
            throw new CtapException(CtapException.ERR_NO_CREDENTIALS);
        }

        if (up) {
            touch(state);
        }

        byte[] extOutput = null;
        if (extensions != null && extensions.containsKey("hmac-secret")) {
            if (!up) {
                throw new CtapException(CtapException.ERR_UNSUPPORTED_OPTION);
            }

            Map<Integer, ?> input = (Map<Integer, ?>) extensions.get("hmac-secret");
            _lastHmacSecretInput = input;
            int version = input.containsKey(4) ? (Integer) input.get(4) : 1;
            PinUvAuthProtocol protocol = getProtocol(version);
            byte[] sharedSecret = _sharedSecrets.get(version);
            if (sharedSecret == null) {
                throw new CtapException(CtapException.ERR_INVALID_PARAMETER);
            }

            byte[] saltEnc = (byte[]) input.get(2);
            byte[] saltAuth = (byte[]) input.get(3);
            if (!Arrays.equals(protocol.authenticate(sharedSecret, saltEnc), saltAuth)) {
                throw new CtapException(CtapException.ERR_PIN_AUTH_INVALID);
            }

            byte[] salt = protocol.decrypt(sharedSecret, saltEnc);
            byte[] output = hmac(uv ? cred.credRandomUv : cred.credRandomNoUv, salt);
            Map<String, Object> outputs = new HashMap<>();
            outputs.put("hmac-secret", protocol.encrypt(sharedSecret, output));
            extOutput = Cbor.encode(outputs);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
        out.write((up ? FLAG_UP : 0) | (uv ? FLAG_UV : 0) | (extOutput != null ? FLAG_ED : 0));
        out.write(new byte[4]);
        if (extOutput != null) {
            out.write(extOutput);
        }

        byte[] id = _omitSingleCredential && allowList.size() == 1 ? null : cred.id;
        List<Fido2Assertion> res = new ArrayList<>();
        res.add(new Fido2Assertion(id, out.toByteArray()));
        return res;
    }

    @Override
    public byte[] getPinToken(PinUvAuthProtocol protocol, char[] pin, int permissions, String rpId) throws IOException, CommandException {
        if (_pin == null) {
            throw new CtapException(CtapException.ERR_PIN_NOT_SET);
        }
        if (_pinRetries == 0) {
            throw new CtapException(CtapException.ERR_PIN_BLOCKED);
        }
        if (_powerCycleRequired) {
            throw new CtapException(CtapException.ERR_PIN_AUTH_BLOCKED);
        }

        if (!Arrays.equals(_pin, pin)) {
            _pinRetries--;
            _consecutivePinFailures++;
            if (_pinRetries == 0) {
                throw new CtapException(CtapException.ERR_PIN_BLOCKED);
            }
            if (_consecutivePinFailures >= 3) {
                _powerCycleRequired = true;
                throw new CtapException(CtapException.ERR_PIN_AUTH_BLOCKED);
            }
            throw new CtapException(CtapException.ERR_PIN_INVALID);
        }

        _pinRetries = MAX_PIN_RETRIES;
        _consecutivePinFailures = 0;

        PinToken token = new PinToken(randomBytes(32), permissions, rpId);
        _tokens.add(token);
        return token.token.clone();
    }

    @Override
    public int getPinRetries(PinUvAuthProtocol protocol) throws CommandException {
        if (_pin == null) {
            throw new CtapException(CtapException.ERR_PIN_NOT_SET);
        }
        return _pinRetries;
    }

    @Override
    public Pair<Map<Integer, ?>, byte[]> getSharedSecret(PinUvAuthProtocol protocol) {
        byte[] secret = randomBytes(protocol.getVersion() == 1 ? 32 : 64);
        _sharedSecrets.put(protocol.getVersion(), secret);

        Map<Integer, Object> keyAgreement = new HashMap<>();
        keyAgreement.put(1, 2);
        keyAgreement.put(3, -25);
        return new Pair<>(keyAgreement, secret.clone());
    }

    private void verifyToken(byte[] pinUvAuthParam, @Nullable Integer version, byte[] clientDataHash, int permission, String rpId) throws CtapException {
        if (version == null) {
            throw new CtapException(CtapException.ERR_MISSING_PARAMETER);
        }

        PinUvAuthProtocol protocol = getProtocol(version);
        for (PinToken token : _tokens) {
            if (Arrays.equals(protocol.authenticate(token.token, clientDataHash), pinUvAuthParam)) {
                if ((token.permissions & permission) == 0 || !token.rpId.equals(rpId)) {
                    throw new CtapException(CtapException.ERR_PIN_AUTH_INVALID);
                }
                // CTAP 2.1: permissions are cleared after use
                token.permissions = 0;
                return;
            }
        }

        throw new CtapException(CtapException.ERR_PIN_AUTH_INVALID);
    }

    private void touch(@Nullable CommandState state) throws CtapException {
        if (_nfc) {
            // CTAP 2.1: placing the authenticator in the NFC field only counts as user presence once
            if (!_nfcUserPresent) {
                throw new CtapException(_nfcPresenceError);
            }
            _nfcUserPresent = false;
            _touches++;
            return;
        }

        if (state != null) {
            if (_reportUpNeeded) {
                state.onKeepAliveStatus(CommandState.STATUS_UPNEEDED);
            }
            if (state.waitForCancel(0)) {
                throw new CtapException(CtapException.ERR_KEEPALIVE_CANCEL);
            }
        }
        _touches++;
    }

    /**
     * Returns the credential with the given ID. As specified by CTAP 2.1, credentials that require
     * user verification (credProtect level 3) are ignored if it wasn't performed.
     */
    @Nullable
    private Credential findCredential(String rpId, byte[] id, boolean uv) {
        Credential cred = _credentials.get(key(rpId, id));
        if (cred != null && cred.credProtect == CRED_PROTECT_UV_REQUIRED && !uv) {
            return null;
        }
        return cred;
    }

    private static String key(String rpId, byte[] id) {
        return rpId + ":" + Arrays.toString(id);
    }

    private static PinUvAuthProtocol getProtocol(int version) throws CtapException {
        switch (version) {
            case 1:
                return new PinUvAuthProtocolV1();
            case 2:
                return new PinUvAuthProtocolV2();
            default:
                throw new CtapException(CtapException.ERR_INVALID_PARAMETER);
        }
    }

    private byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        _random.nextBytes(bytes);
        return bytes;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public SoftwareFido2Device setPin(@Nullable String pin) {
        _pin = pin == null ? null : pin.toCharArray();
        return this;
    }

    public SoftwareFido2Device setVersions(String... versions) {
        _versions = Arrays.asList(versions);
        return this;
    }

    public SoftwareFido2Device setExtensions(String... extensions) {
        _extensions = Arrays.asList(extensions);
        return this;
    }

    public SoftwareFido2Device setProtocols(Integer... protocols) {
        _protocols = Arrays.asList(protocols);
        return this;
    }

    public SoftwareFido2Device setMaxCredentialCountInList(@Nullable Integer count) {
        _maxCredentialCountInList = count;
        return this;
    }

    public SoftwareFido2Device setMaxCredentialIdLength(@Nullable Integer length) {
        _maxCredentialIdLength = length;
        return this;
    }

    public SoftwareFido2Device setForcePinChange(boolean forcePinChange) {
        _forcePinChange = forcePinChange;
        return this;
    }

    public SoftwareFido2Device setAlwaysUv(boolean alwaysUv) {
        _alwaysUv = alwaysUv;
        return this;
    }

    public SoftwareFido2Device setSilentAssertions(boolean supported) {
        _silentAssertions = supported;
        return this;
    }

    public SoftwareFido2Device setOmitSingleCredential(boolean omit) {
        _omitSingleCredential = omit;
        return this;
    }

    public SoftwareFido2Device setCredentialIdLength(int length) {
        _credentialIdLength = length;
        return this;
    }

    public void powerCycle() {
        _powerCycleRequired = false;
        _consecutivePinFailures = 0;
        _tokens.clear();
        _sharedSecrets.clear();
    }

    /**
     * Simulates communicating with the authenticator over NFC, where user presence is only
     * granted once per tap. See {@link #tap()}.
     */
    public SoftwareFido2Device setNfc(boolean nfc) {
        _nfc = nfc;
        return this;
    }

    /**
     * Sets the error that is returned over NFC if user presence is needed again during the same tap.
     * Authenticators return either OPERATION_DENIED or UP_REQUIRED (as specified by CTAP 2.1).
     */
    public SoftwareFido2Device setNfcPresenceError(byte error) {
        _nfcPresenceError = error;
        return this;
    }

    /**
     * Sets whether the authenticator reports that it's waiting for a touch. Some authenticators
     * only report that they're processing a command instead.
     */
    public SoftwareFido2Device setReportUpNeeded(boolean report) {
        _reportUpNeeded = report;
        return this;
    }

    /**
     * Simulates removing the authenticator from the NFC field and tapping it again.
     */
    public void tap() {
        powerCycle();
        _nfcUserPresent = true;
    }

    public int getTouches() {
        return _touches;
    }

    public int getSilentAssertionCount() {
        return _silentAssertionCount;
    }

    public int getRemainingPinRetries() {
        return _pinRetries;
    }

    @Nullable
    public Map<Integer, ?> getLastHmacSecretInput() {
        return _lastHmacSecretInput;
    }

    @Nullable
    public Map<String, ?> getLastMakeCredentialExtensions() {
        return _lastMakeCredentialExtensions;
    }

    private static class Credential {
        final String rpId;
        final byte[] id;
        final byte[] credRandomNoUv;
        final byte[] credRandomUv;
        final int credProtect;

        Credential(String rpId, byte[] id, byte[] credRandomNoUv, byte[] credRandomUv, int credProtect) {
            this.rpId = rpId;
            this.id = id;
            this.credRandomNoUv = credRandomNoUv;
            this.credRandomUv = credRandomUv;
            this.credProtect = credProtect;
        }
    }

    private static class PinToken {
        final byte[] token;
        int permissions;
        final String rpId;

        PinToken(byte[] token, int permissions, String rpId) {
            this.token = token;
            this.permissions = permissions;
            this.rpId = rpId;
        }
    }
}
