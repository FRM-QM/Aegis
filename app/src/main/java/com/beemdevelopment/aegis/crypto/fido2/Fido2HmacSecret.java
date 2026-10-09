package com.beemdevelopment.aegis.crypto.fido2;

import androidx.annotation.Nullable;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.fido.webauthn.AttestedCredentialData;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Implements enrollment and unlocking with the CTAP2 hmac-secret extension.
 *
 * Enrollment creates a non-discoverable credential with hmac-secret enabled and immediately
 * obtains the hmac-secret output for a fresh random salt. Unlocking first finds out which of the
 * enrolled credentials belong to the connected authenticator (without requiring a touch) and then
 * obtains the hmac-secret output for the salt of that credential.
 *
 * If the authenticator has a PIN, user verification is performed with the PIN during enrollment
 * and every unlock, because the hmac-secret output differs with and without user verification.
 */
public class Fido2HmacSecret {
    public static final String EXT_HMAC_SECRET = "hmac-secret";
    private static final String EXT_CRED_PROTECT = "credProtect";
    private static final String RP_NAME = "Aegis Authenticator";
    private static final int CLIENT_DATA_HASH_SIZE = 32;
    private static final int USER_ID_SIZE = 16;
    private static final int SECRET_SIZE = 32;
    private static final int SALT_SIZE = 32;
    private static final int COSE_ALG_ES256 = -7;
    private static final int MAX_STRING_LENGTH = 64;

    private final Fido2Device _device;
    private final Fido2Info _info;
    private final SecureRandom _random;
    private boolean _silentAssertionsUnsupported;

    public Fido2HmacSecret(Fido2Device device) {
        this(device, new SecureRandom());
    }

    Fido2HmacSecret(Fido2Device device, SecureRandom random) {
        _device = device;
        _info = device.getInfo();
        _random = random;
    }

    public Fido2Info getInfo() {
        return _info;
    }

    /**
     * Throws if the authenticator does not support CTAP2 or the hmac-secret extension.
     */
    public void checkSupported() throws Fido2Exception {
        if (!_info.isFido2()) {
            throw new Fido2Exception(Fido2Exception.Reason.UNSUPPORTED_DEVICE);
        }
        if (!_info.hasExtension(EXT_HMAC_SECRET)) {
            throw new Fido2Exception(Fido2Exception.Reason.HMAC_SECRET_UNSUPPORTED);
        }
    }

    /**
     * Creates a new credential on the authenticator and obtains its hmac-secret output for a fresh salt.
     * This requires the user to touch the authenticator twice (except for NFC, where the tap suffices).
     *
     * @param rpId the relying party ID to create the credential for.
     * @param name a name for the credential, which some authenticators may display.
     * @param existing the credentials that are already enrolled, used to detect duplicate enrollments.
     * @param pin the PIN of the authenticator, or null if not known yet.
     * @throws Fido2Exception with reason PIN_REQUIRED if the authenticator has a PIN and none was given.
     */
    public Fido2Enrollment enroll(String rpId, String name, List<? extends Fido2Credential> existing,
                                  @Nullable char[] pin, Fido2CommandState state) throws Fido2Exception, IOException {
        checkSupported();

        boolean uv = _info.isClientPinSet();
        if (_info.isAlwaysUv() && !uv) {
            throw new Fido2Exception(Fido2Exception.Reason.PIN_NOT_SET);
        }
        if (uv && _info.isForcePinChange()) {
            throw new Fido2Exception(Fido2Exception.Reason.PIN_CHANGE_REQUIRED);
        }

        List<Fido2Credential> sameRp = new ArrayList<>();
        for (Fido2Credential cred : existing) {
            if (cred.getRpId().equals(rpId)) {
                sameRp.add(cred);
            }
        }

        // detect duplicate enrollments before asking the user to do anything
        Fido2Credential duplicate = findCredential(sameRp, state);
        if (duplicate != null) {
            throw Fido2Exception.withCredential(Fido2Exception.Reason.ALREADY_ENROLLED, duplicate);
        }

        PinUvAuthProtocol protocol = selectProtocol();
        if (uv) {
            checkPin(protocol, pin);
        }

        byte[] clientDataHash = randomBytes(CLIENT_DATA_HASH_SIZE);
        byte[] pinToken = null;
        byte[] pinUvAuthParam = null;
        byte[] authData;
        try {
            if (uv) {
                pinToken = getPinToken(protocol, pin, ClientPin.PIN_PERMISSION_MC, rpId);
                pinUvAuthParam = protocol.authenticate(pinToken, clientDataHash);
            }

            Map<String, Object> rp = new HashMap<>();
            rp.put("id", rpId);
            rp.put("name", RP_NAME);

            Map<String, Object> user = new HashMap<>();
            user.put("id", randomBytes(USER_ID_SIZE));
            user.put("name", truncate(name));
            user.put("displayName", truncate(name));

            Map<String, Object> params = new HashMap<>();
            params.put("type", "public-key");
            params.put("alg", COSE_ALG_ES256);

            Map<String, Object> extensions = new HashMap<>();
            extensions.put(EXT_HMAC_SECRET, true);
            if (_info.hasExtension(EXT_CRED_PROTECT)) {
                // make sure the credential can be found without user verification
                extensions.put(EXT_CRED_PROTECT, 1);
            }

            List<Map<String, ?>> excludeList = null;
            Integer maxCount = _info.getMaxCredentialCountInList();
            if (!sameRp.isEmpty() && sameRp.size() <= (maxCount != null ? maxCount : 1)) {
                excludeList = toDescriptors(sameRp);
            }

            state.setStep(Fido2CommandState.Step.REGISTER);
            authData = _device.makeCredential(clientDataHash, rp, user, Collections.singletonList(params),
                    excludeList, extensions, null, pinUvAuthParam, uv ? protocol.getVersion() : null, state);
        } catch (CommandException e) {
            throw toFido2Exception(e, protocol);
        } finally {
            wipe(pinToken);
            wipe(pinUvAuthParam);
        }

        AuthenticatorData parsedAuthData = parseAuthData(authData);
        AttestedCredentialData credData = parsedAuthData.getAttestedCredentialData();
        if (credData == null) {
            throw new Fido2Exception(Fido2Exception.Reason.PROTOCOL_ERROR, new IllegalStateException("No attested credential data"));
        }
        Map<String, ?> extOutputs = parsedAuthData.getExtensions();
        if (extOutputs == null || !Boolean.TRUE.equals(extOutputs.get(EXT_HMAC_SECRET))) {
            throw new Fido2Exception(Fido2Exception.Reason.HMAC_SECRET_UNSUPPORTED);
        }

        byte[] credentialId = credData.getCredentialId();
        byte[] salt = randomBytes(SALT_SIZE);
        Fido2Enrollment enrollment = new Fido2Enrollment(rpId, credentialId, salt, uv, new byte[SECRET_SIZE]);

        state.setStep(Fido2CommandState.Step.CONFIRM);
        byte[] secret = getSecret(enrollment, pin, state);
        enrollment = new Fido2Enrollment(rpId, credentialId, salt, uv, secret);
        return enrollment;
    }

    /**
     * Finds out which of the given credentials belongs to the authenticator and obtains its
     * hmac-secret output. This requires the user to touch the authenticator once (except for NFC).
     *
     * @param pin the PIN of the authenticator, or null if not known yet.
     * @throws Fido2Exception with reason PIN_REQUIRED if the matching credential requires user
     *                        verification and no PIN was given.
     */
    public <T extends Fido2Credential> Pair<T, byte[]> unlock(List<T> candidates, @Nullable char[] pin,
                                                             Fido2CommandState state) throws Fido2Exception, IOException {
        checkSupported();
        state.setStep(Fido2CommandState.Step.UNLOCK);

        T cred = findCredential(candidates, state);
        if (cred != null) {
            checkUv(cred);
            return new Pair<>(cred, getSecret(cred, pin, state));
        }

        if (_silentAssertionsUnsupported) {
            // fall back to trying the credentials one by one
            for (T candidate : candidates) {
                try {
                    checkUv(candidate);
                    return new Pair<>(candidate, getSecret(candidate, pin, state));
                } catch (Fido2Exception e) {
                    if (e.getReason() != Fido2Exception.Reason.NOT_ENROLLED
                            && e.getReason() != Fido2Exception.Reason.UV_MISMATCH) {
                        throw e;
                    }
                }
            }
        }

        throw new Fido2Exception(Fido2Exception.Reason.NOT_ENROLLED);
    }

    /**
     * Returns the first of the given credentials that belongs to the authenticator, or null if there is none.
     * Uses assertions without user presence, so no touch is needed.
     */
    @Nullable
    <T extends Fido2Credential> T findCredential(List<T> candidates, Fido2CommandState state) throws Fido2Exception, IOException {
        if (candidates.isEmpty() || _silentAssertionsUnsupported) {
            return null;
        }

        Integer maxIdLength = _info.getMaxCredentialIdLength();
        Map<String, List<T>> byRpId = new LinkedHashMap<>();
        for (T cred : candidates) {
            if (maxIdLength != null && cred.getCredentialId().length > maxIdLength) {
                // the authenticator can't have created this credential
                continue;
            }

            List<T> list = byRpId.get(cred.getRpId());
            if (list == null) {
                list = new ArrayList<>();
                byRpId.put(cred.getRpId(), list);
            }
            list.add(cred);
        }

        Integer maxCount = _info.getMaxCredentialCountInList();
        int batchSize = maxCount != null && maxCount > 0 ? maxCount : 1;
        Map<String, Object> options = Collections.singletonMap("up", false);

        for (Map.Entry<String, List<T>> entry : byRpId.entrySet()) {
            List<T> creds = entry.getValue();
            for (int i = 0; i < creds.size(); i += batchSize) {
                List<T> batch = creds.subList(i, Math.min(i + batchSize, creds.size()));

                List<Fido2Assertion> assertions;
                try {
                    assertions = _device.getAssertions(entry.getKey(), randomBytes(CLIENT_DATA_HASH_SIZE),
                            toDescriptors(batch), null, options, null, null, state);
                } catch (CtapException e) {
                    byte error = e.getCtapError();
                    if (error == CtapException.ERR_NO_CREDENTIALS) {
                        continue;
                    }
                    if (error == CtapException.ERR_UNSUPPORTED_OPTION
                            || error == CtapException.ERR_INVALID_OPTION) {
                        _silentAssertionsUnsupported = true;
                        return null;
                    }
                    throw toFido2Exception(e, null);
                } catch (CommandException e) {
                    throw toFido2Exception(e, null);
                }

                for (Fido2Assertion assertion : assertions) {
                    byte[] credentialId = assertion.getCredentialId();
                    if (credentialId == null && batch.size() == 1) {
                        return batch.get(0);
                    }
                    for (T cred : batch) {
                        if (Arrays.equals(cred.getCredentialId(), credentialId)) {
                            return cred;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Obtains the hmac-secret output of the given credential for its salt.
     */
    byte[] getSecret(Fido2Credential cred, @Nullable char[] pin, Fido2CommandState state) throws Fido2Exception, IOException {
        byte[] salt = cred.getSalt();
        if (salt.length != SALT_SIZE) {
            throw new Fido2Exception(Fido2Exception.Reason.PROTOCOL_ERROR, new IllegalArgumentException("Bad salt length"));
        }

        PinUvAuthProtocol protocol = selectProtocol();
        if (cred.isUv()) {
            checkPin(protocol, pin);
        }

        byte[] clientDataHash = randomBytes(CLIENT_DATA_HASH_SIZE);
        byte[] pinToken = null;
        byte[] pinUvAuthParam = null;
        Pair<Map<Integer, ?>, byte[]> keyAgreement = null;
        try {
            if (cred.isUv()) {
                pinToken = getPinToken(protocol, pin, ClientPin.PIN_PERMISSION_GA, cred.getRpId());
                pinUvAuthParam = protocol.authenticate(pinToken, clientDataHash);
            }

            keyAgreement = _device.getSharedSecret(protocol);
            byte[] saltEnc = protocol.encrypt(keyAgreement.second, salt);
            byte[] saltAuth = protocol.authenticate(keyAgreement.second, saltEnc);

            Map<Integer, Object> input = new HashMap<>();
            input.put(1, keyAgreement.first);
            input.put(2, saltEnc);
            input.put(3, saltAuth);
            if (protocol.getVersion() != PinUvAuthProtocolV1.VERSION) {
                input.put(4, protocol.getVersion());
            }

            List<Fido2Assertion> assertions = _device.getAssertions(cred.getRpId(), clientDataHash,
                    toDescriptors(Collections.singletonList(cred)), Collections.singletonMap(EXT_HMAC_SECRET, input),
                    null, pinUvAuthParam, cred.isUv() ? protocol.getVersion() : null, state);
            if (assertions.isEmpty()) {
                throw new Fido2Exception(Fido2Exception.Reason.PROTOCOL_ERROR, new IllegalStateException("No assertion"));
            }

            AuthenticatorData authData = parseAuthData(assertions.get(0).getAuthenticatorData());
            if (!authData.isUp()) {
                throw new Fido2Exception(Fido2Exception.Reason.PROTOCOL_ERROR, new IllegalStateException("User presence flag not set"));
            }
            if (authData.isUv() != cred.isUv()) {
                throw Fido2Exception.withCredential(Fido2Exception.Reason.UV_MISMATCH, cred);
            }

            Map<String, ?> outputs = authData.getExtensions();
            Object output = outputs != null ? outputs.get(EXT_HMAC_SECRET) : null;
            if (!(output instanceof byte[])) {
                throw new Fido2Exception(Fido2Exception.Reason.HMAC_SECRET_UNSUPPORTED);
            }

            byte[] secret;
            try {
                secret = protocol.decrypt(keyAgreement.second, (byte[]) output);
            } catch (IllegalStateException e) {
                throw new Fido2Exception(Fido2Exception.Reason.PROTOCOL_ERROR, e);
            }
            if (secret.length != SECRET_SIZE) {
                wipe(secret);
                throw new Fido2Exception(Fido2Exception.Reason.PROTOCOL_ERROR, new IllegalStateException("Bad hmac-secret output length"));
            }

            return secret;
        } catch (CommandException e) {
            throw toFido2Exception(e, protocol);
        } finally {
            wipe(pinToken);
            wipe(pinUvAuthParam);
            if (keyAgreement != null) {
                wipe(keyAgreement.second);
            }
        }
    }

    PinUvAuthProtocol selectProtocol() {
        if (_info.getPinUvAuthProtocols().contains(PinUvAuthProtocolV2.VERSION)) {
            return new PinUvAuthProtocolV2();
        }
        return new PinUvAuthProtocolV1();
    }

    private void checkUv(Fido2Credential cred) throws Fido2Exception {
        if (cred.isUv()) {
            if (!_info.isClientPinSet()) {
                throw Fido2Exception.withCredential(Fido2Exception.Reason.UV_MISMATCH, cred);
            }
            if (_info.isForcePinChange()) {
                throw new Fido2Exception(Fido2Exception.Reason.PIN_CHANGE_REQUIRED);
            }
        } else if (_info.isAlwaysUv()) {
            throw Fido2Exception.withCredential(Fido2Exception.Reason.UV_MISMATCH, cred);
        }
    }

    private void checkPin(PinUvAuthProtocol protocol, @Nullable char[] pin) throws Fido2Exception, IOException {
        if (pin == null) {
            throw Fido2Exception.withPinRetries(Fido2Exception.Reason.PIN_REQUIRED, getPinRetries(protocol), null);
        }
        if (pin.length < _info.getMinPinLength()) {
            throw Fido2Exception.withMinPinLength(Fido2Exception.Reason.PIN_TOO_SHORT, _info.getMinPinLength());
        }
    }

    private byte[] getPinToken(PinUvAuthProtocol protocol, char[] pin, int permissions, String rpId) throws Fido2Exception, IOException, CommandException {
        try {
            return _device.getPinToken(protocol, pin, permissions, rpId);
        } catch (IllegalArgumentException e) {
            // thrown by ClientPin if the PIN is too short or too long
            throw new Fido2Exception(Fido2Exception.Reason.PIN_INVALID, e);
        }
    }

    private int getPinRetries(PinUvAuthProtocol protocol) throws IOException {
        try {
            return _device.getPinRetries(protocol);
        } catch (CommandException e) {
            return -1;
        }
    }

    private Fido2Exception toFido2Exception(CommandException e, @Nullable PinUvAuthProtocol protocol) throws IOException {
        if (!(e instanceof CtapException)) {
            return new Fido2Exception(Fido2Exception.Reason.PROTOCOL_ERROR, e);
        }

        switch (((CtapException) e).getCtapError()) {
            case CtapException.ERR_NO_CREDENTIALS:
                return new Fido2Exception(Fido2Exception.Reason.NOT_ENROLLED, e);
            case CtapException.ERR_CREDENTIAL_EXCLUDED:
                return new Fido2Exception(Fido2Exception.Reason.ALREADY_ENROLLED, e);
            case CtapException.ERR_PIN_INVALID:
                int retries = protocol != null ? getPinRetries(protocol) : -1;
                return Fido2Exception.withPinRetries(Fido2Exception.Reason.PIN_INVALID, retries, e);
            case CtapException.ERR_PIN_AUTH_BLOCKED:
                return new Fido2Exception(Fido2Exception.Reason.PIN_AUTH_BLOCKED, e);
            case CtapException.ERR_PIN_BLOCKED:
                return new Fido2Exception(Fido2Exception.Reason.PIN_BLOCKED, e);
            case CtapException.ERR_PIN_NOT_SET:
            case CtapException.ERR_PUAT_REQUIRED:
                return new Fido2Exception(Fido2Exception.Reason.PIN_NOT_SET, e);
            case CtapException.ERR_PIN_POLICY_VIOLATION:
                return new Fido2Exception(Fido2Exception.Reason.PIN_CHANGE_REQUIRED, e);
            case CtapException.ERR_KEEPALIVE_CANCEL:
                return new Fido2Exception(Fido2Exception.Reason.CANCELLED, e);
            case CtapException.ERR_USER_ACTION_TIMEOUT:
            case CtapException.ERR_ACTION_TIMEOUT:
                return new Fido2Exception(Fido2Exception.Reason.TIMEOUT, e);
            case CtapException.ERR_OPERATION_DENIED:
                return new Fido2Exception(Fido2Exception.Reason.DENIED, e);
            case CtapException.ERR_UNSUPPORTED_EXTENSION:
                return new Fido2Exception(Fido2Exception.Reason.HMAC_SECRET_UNSUPPORTED, e);
            default:
                return new Fido2Exception(Fido2Exception.Reason.PROTOCOL_ERROR, e);
        }
    }

    private static AuthenticatorData parseAuthData(byte[] data) throws Fido2Exception {
        try {
            return AuthenticatorData.parseFrom(ByteBuffer.wrap(data));
        } catch (RuntimeException e) {
            throw new Fido2Exception(Fido2Exception.Reason.PROTOCOL_ERROR, e);
        }
    }

    /**
     * Truncates the given string to the maximum length that authenticators are required to store,
     * without splitting a code point.
     */
    static String truncate(String s) {
        StringBuilder sb = new StringBuilder();
        int length = 0;
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            String c = new String(Character.toChars(cp));
            length += c.getBytes(StandardCharsets.UTF_8).length;
            if (length > MAX_STRING_LENGTH) {
                break;
            }
            sb.append(c);
            i += Character.charCount(cp);
        }
        return sb.toString();
    }

    private static List<Map<String, ?>> toDescriptors(List<? extends Fido2Credential> creds) {
        List<Map<String, ?>> list = new ArrayList<>();
        for (Fido2Credential cred : creds) {
            Map<String, Object> descriptor = new HashMap<>();
            descriptor.put("type", "public-key");
            descriptor.put("id", cred.getCredentialId());
            list.add(descriptor);
        }
        return list;
    }

    private byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        _random.nextBytes(bytes);
        return bytes;
    }

    private static void wipe(@Nullable byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
}
