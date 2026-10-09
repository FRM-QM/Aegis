package com.beemdevelopment.aegis.crypto.fido2;

import androidx.annotation.Nullable;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The subset of the authenticatorGetInfo response that is relevant for hmac-secret.
 */
public class Fido2Info {
    private final List<String> _versions;
    private final List<String> _extensions;
    private final Map<String, ?> _options;
    private final List<Integer> _pinUvAuthProtocols;
    @Nullable
    private final Integer _maxCredentialCountInList;
    @Nullable
    private final Integer _maxCredentialIdLength;
    private final int _minPinLength;
    private final boolean _forcePinChange;

    public Fido2Info(List<String> versions, List<String> extensions, Map<String, ?> options,
                     List<Integer> pinUvAuthProtocols, @Nullable Integer maxCredentialCountInList,
                     @Nullable Integer maxCredentialIdLength, int minPinLength, boolean forcePinChange) {
        _versions = versions != null ? versions : Collections.emptyList();
        _extensions = extensions != null ? extensions : Collections.emptyList();
        _options = options != null ? options : Collections.emptyMap();
        _pinUvAuthProtocols = pinUvAuthProtocols != null ? pinUvAuthProtocols : Collections.emptyList();
        _maxCredentialCountInList = maxCredentialCountInList;
        _maxCredentialIdLength = maxCredentialIdLength;
        _minPinLength = minPinLength;
        _forcePinChange = forcePinChange;
    }

    public List<String> getVersions() {
        return _versions;
    }

    public List<String> getExtensions() {
        return _extensions;
    }

    public Map<String, ?> getOptions() {
        return _options;
    }

    public List<Integer> getPinUvAuthProtocols() {
        return _pinUvAuthProtocols;
    }

    @Nullable
    public Integer getMaxCredentialCountInList() {
        return _maxCredentialCountInList;
    }

    @Nullable
    public Integer getMaxCredentialIdLength() {
        return _maxCredentialIdLength;
    }

    public int getMinPinLength() {
        return _minPinLength;
    }

    public boolean isForcePinChange() {
        return _forcePinChange;
    }

    public boolean isFido2() {
        for (String version : _versions) {
            if (version.startsWith("FIDO_2_")) {
                return true;
            }
        }
        return false;
    }

    public boolean hasExtension(String extension) {
        return _extensions.contains(extension);
    }

    public boolean isClientPinSet() {
        return Boolean.TRUE.equals(_options.get("clientPin"));
    }

    public boolean isAlwaysUv() {
        return Boolean.TRUE.equals(_options.get("alwaysUv"));
    }
}
