package com.beemdevelopment.aegis.crypto.fido2;

import androidx.annotation.Nullable;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A {@link Fido2Device} backed by a yubikit {@link Ctap2Session}. Works with any CTAP2
 * authenticator, not just YubiKeys.
 */
public class YubiKitFido2Device implements Fido2Device {
    private final Ctap2Session _session;
    private final Fido2Info _info;

    private YubiKitFido2Device(Ctap2Session session) {
        _session = session;

        Ctap2Session.InfoData info = session.getCachedInfo();
        _info = new Fido2Info(
                info.getVersions(),
                info.getExtensions(),
                info.getOptions(),
                info.getPinUvAuthProtocols(),
                info.getMaxCredentialCountInList(),
                info.getMaxCredentialIdLength(),
                info.getMinPinLength(),
                info.getForcePinChange()
        );
    }

    /**
     * Opens a CTAP2 session over USB HID.
     */
    public static YubiKitFido2Device open(FidoConnection connection) throws IOException, Fido2Exception {
        try {
            return new YubiKitFido2Device(new Ctap2Session(connection));
        } catch (CommandException e) {
            // U2F-only authenticators reject authenticatorGetInfo
            throw new Fido2Exception(Fido2Exception.Reason.UNSUPPORTED_DEVICE, e);
        }
    }

    /**
     * Opens a CTAP2 session over NFC.
     */
    public static YubiKitFido2Device open(SmartCardConnection connection) throws IOException, Fido2Exception {
        try {
            return new YubiKitFido2Device(new Ctap2Session(connection));
        } catch (CommandException e) {
            // thrown if the tag doesn't have a FIDO applet, or if it only supports U2F
            throw new Fido2Exception(Fido2Exception.Reason.UNSUPPORTED_DEVICE, e);
        }
    }

    @Override
    public Fido2Info getInfo() {
        return _info;
    }

    @Override
    public byte[] makeCredential(byte[] clientDataHash, Map<String, ?> rp, Map<String, ?> user,
                                 List<Map<String, ?>> pubKeyCredParams, @Nullable List<Map<String, ?>> excludeList,
                                 @Nullable Map<String, ?> extensions, @Nullable Map<String, ?> options,
                                 @Nullable byte[] pinUvAuthParam, @Nullable Integer pinUvAuthProtocol,
                                 @Nullable CommandState state) throws IOException, CommandException {
        Ctap2Session.CredentialData data = _session.makeCredential(clientDataHash, rp, user, pubKeyCredParams,
                excludeList, extensions, options, pinUvAuthParam, pinUvAuthProtocol, null, state);
        return data.getAuthenticatorData();
    }

    @Override
    public List<Fido2Assertion> getAssertions(String rpId, byte[] clientDataHash, List<Map<String, ?>> allowList,
                                              @Nullable Map<String, ?> extensions, @Nullable Map<String, ?> options,
                                              @Nullable byte[] pinUvAuthParam, @Nullable Integer pinUvAuthProtocol,
                                              @Nullable CommandState state) throws IOException, CommandException {
        List<Ctap2Session.AssertionData> assertions = _session.getAssertions(rpId, clientDataHash, allowList,
                extensions, options, pinUvAuthParam, pinUvAuthProtocol, state);

        List<Fido2Assertion> res = new ArrayList<>();
        for (Ctap2Session.AssertionData assertion : assertions) {
            byte[] credentialId = null;
            Map<String, ?> credential = assertion.getCredential();
            if (credential != null && credential.get("id") instanceof byte[]) {
                credentialId = (byte[]) credential.get("id");
            }
            res.add(new Fido2Assertion(credentialId, assertion.getAuthenticatorData()));
        }
        return res;
    }

    @Override
    public byte[] getPinToken(PinUvAuthProtocol protocol, char[] pin, int permissions, String rpId) throws IOException, CommandException {
        return new ClientPin(_session, protocol).getPinToken(pin, permissions, rpId);
    }

    @Override
    public int getPinRetries(PinUvAuthProtocol protocol) throws IOException, CommandException {
        return new ClientPin(_session, protocol).getPinRetries().getCount();
    }

    @Override
    public Pair<Map<Integer, ?>, byte[]> getSharedSecret(PinUvAuthProtocol protocol) throws IOException, CommandException {
        return new ClientPin(_session, protocol).getSharedSecret();
    }
}
