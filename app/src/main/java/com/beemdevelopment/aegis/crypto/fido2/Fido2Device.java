package com.beemdevelopment.aegis.crypto.fido2;

import androidx.annotation.Nullable;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * A thin abstraction over the CTAP2 commands that are needed for hmac-secret, so that the
 * protocol logic in {@link Fido2HmacSecret} can be tested without hardware.
 */
public interface Fido2Device {
    Fido2Info getInfo();

    /**
     * Sends authenticatorMakeCredential and returns the authenticator data of the new credential.
     */
    byte[] makeCredential(byte[] clientDataHash, Map<String, ?> rp, Map<String, ?> user,
                          List<Map<String, ?>> pubKeyCredParams, @Nullable List<Map<String, ?>> excludeList,
                          @Nullable Map<String, ?> extensions, @Nullable Map<String, ?> options,
                          @Nullable byte[] pinUvAuthParam, @Nullable Integer pinUvAuthProtocol,
                          @Nullable CommandState state) throws IOException, CommandException;

    List<Fido2Assertion> getAssertions(String rpId, byte[] clientDataHash, List<Map<String, ?>> allowList,
                                       @Nullable Map<String, ?> extensions, @Nullable Map<String, ?> options,
                                       @Nullable byte[] pinUvAuthParam, @Nullable Integer pinUvAuthProtocol,
                                       @Nullable CommandState state) throws IOException, CommandException;

    byte[] getPinToken(PinUvAuthProtocol protocol, char[] pin, int permissions, String rpId) throws IOException, CommandException;

    int getPinRetries(PinUvAuthProtocol protocol) throws IOException, CommandException;

    /**
     * Performs key agreement with the authenticator. Returns the platform's COSE key and the shared secret.
     */
    Pair<Map<Integer, ?>, byte[]> getSharedSecret(PinUvAuthProtocol protocol) throws IOException, CommandException;
}
