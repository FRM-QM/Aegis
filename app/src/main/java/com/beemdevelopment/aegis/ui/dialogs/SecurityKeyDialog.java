package com.beemdevelopment.aegis.ui.dialogs;

import android.content.Context;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.activity.ComponentActivity;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.appcompat.app.AlertDialog;
import androidx.lifecycle.DefaultLifecycleObserver;
import androidx.lifecycle.LifecycleOwner;

import com.beemdevelopment.aegis.R;
import com.beemdevelopment.aegis.crypto.MasterKey;
import com.beemdevelopment.aegis.crypto.fido2.Fido2CommandState;
import com.beemdevelopment.aegis.crypto.fido2.Fido2Credential;
import com.beemdevelopment.aegis.crypto.fido2.Fido2Enrollment;
import com.beemdevelopment.aegis.crypto.fido2.Fido2Exception;
import com.beemdevelopment.aegis.crypto.fido2.Fido2HmacSecret;
import com.beemdevelopment.aegis.crypto.fido2.Fido2Registration;
import com.beemdevelopment.aegis.crypto.fido2.YubiKitFido2Device;
import com.beemdevelopment.aegis.helpers.EditTextHelper;
import com.beemdevelopment.aegis.helpers.SecurityKeyConnector;
import com.beemdevelopment.aegis.vault.slots.Fido2Slot;
import com.beemdevelopment.aegis.vault.slots.SlotIntegrityException;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.progressindicator.CircularProgressIndicator;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.util.Pair;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A dialog that guides the user through registering a security key or unlocking the vault with one.
 * It listens for security keys over USB and NFC, asks for the PIN of the key if needed and runs the
 * CTAP2 operations in the background.
 */
public class SecurityKeyDialog<T> {
    private static final String TAG = SecurityKeyDialog.class.getSimpleName();
    private static final int MAX_ERROR_CAUSES = 4;

    public interface Listener<T> {
        void onSuccess(T result);

        /**
         * Called when an attempt failed in a way that is relevant for the audit log.
         * The dialog stays open, so that the user can try again.
         */
        default void onAttemptFailed(Fido2Exception e) {

        }

        /**
         * Called when the user dismissed the dialog without completing the operation.
         */
        default void onCancelled() {

        }
    }

    public static class UnlockResult {
        private final Fido2Slot _slot;
        private final MasterKey _key;

        private UnlockResult(Fido2Slot slot, MasterKey key) {
            _slot = slot;
            _key = key;
        }

        public Fido2Slot getSlot() {
            return _slot;
        }

        public MasterKey getKey() {
            return _key;
        }
    }

    private interface Operation<T> {
        T run(Fido2HmacSecret fido, @Nullable char[] pin, Fido2CommandState state, boolean nfc) throws Exception;
    }

    private final ComponentActivity _activity;
    private final Operation<T> _operation;
    private final Listener<T> _listener;
    private final SecurityKeyConnector _connector;
    private final Handler _handler = new Handler(Looper.getMainLooper());
    private final LifecycleObserver _lifecycleObserver = new LifecycleObserver();

    private AlertDialog _dialog;
    private ImageView _imgKey;
    private CircularProgressIndicator _progress;
    private TextView _textStatus;
    private TextView _textHint;
    private TextInputLayout _pinLayout;
    private TextInputEditText _textPin;
    private Button _buttonPositive;

    private boolean _usbSupported;
    private SecurityKeyConnector.NfcState _nfcState = SecurityKeyConnector.NfcState.UNAVAILABLE;
    @Nullable
    private UsbYubiKeyDevice _usbDevice;
    @Nullable
    private YubiKeyDevice _lastDevice;
    @Nullable
    private YubiKeyDevice _pinDevice;
    @Nullable
    private Fido2CommandState _state;
    @Nullable
    private char[] _pin;
    private boolean _busy;
    private boolean _awaitingPin;
    private boolean _succeeded;
    private boolean _closed;
    private boolean _silentDismiss;

    private SecurityKeyDialog(ComponentActivity activity, Operation<T> operation, Listener<T> listener) {
        _activity = activity;
        _operation = operation;
        _listener = listener;
        _connector = new SecurityKeyConnector(activity);
    }

    /**
     * Shows a dialog that registers a new security key and returns a FIDO2 slot that wraps the given master key.
     */
    public static SecurityKeyDialog<Fido2Slot> showEnroll(ComponentActivity activity, String name, MasterKey masterKey,
                                                          List<Fido2Slot> existing, Listener<Fido2Slot> listener) {
        // the credential that was created on the key, if obtaining its secret is still pending
        AtomicReference<Fido2Registration> pending = new AtomicReference<>();
        Operation<Fido2Slot> operation = (fido, pin, state, nfc) -> {
            Fido2Registration registration = pending.get();
            if (registration == null) {
                registration = fido.register(Fido2Slot.DEFAULT_RP_ID, name, existing, pin, state);
                pending.set(registration);

                // over NFC, a tap only counts as user presence for a single command, so obtaining the secret needs another tap
                if (nfc) {
                    throw new Fido2Exception(Fido2Exception.Reason.CONFIRM_REQUIRED);
                }
            }

            Fido2Enrollment enrollment = fido.confirm(registration, pin, state);
            try {
                Fido2Slot slot = new Fido2Slot(name, enrollment.getRpId(), enrollment.getCredentialId(),
                        enrollment.getSalt(), enrollment.isUv(), System.currentTimeMillis());
                slot.wrap(masterKey, enrollment.getSecret());

                // make sure that the master key can be recovered from the slot
                MasterKey key = slot.unwrap(enrollment.getSecret());
                if (!Arrays.equals(key.getBytes(), masterKey.getBytes())) {
                    throw new Fido2Exception(Fido2Exception.Reason.SECRET_MISMATCH);
                }

                return slot;
            } finally {
                enrollment.wipe();
            }
        };

        SecurityKeyDialog<Fido2Slot> dialog = new SecurityKeyDialog<>(activity, operation, listener);
        dialog.show(R.string.security_key_enroll_title);
        return dialog;
    }

    /**
     * Shows a dialog that decrypts the master key with one of the given FIDO2 slots.
     */
    public static SecurityKeyDialog<UnlockResult> showUnlock(ComponentActivity activity, List<Fido2Slot> candidates,
                                                             Listener<UnlockResult> listener) {
        Operation<UnlockResult> operation = (fido, pin, state, nfc) -> {
            Pair<Fido2Slot, byte[]> res = fido.unlock(candidates, pin, state);
            try {
                return new UnlockResult(res.first, res.first.unwrap(res.second));
            } catch (SlotIntegrityException e) {
                throw Fido2Exception.withCredential(Fido2Exception.Reason.SECRET_MISMATCH, res.first);
            } finally {
                Arrays.fill(res.second, (byte) 0);
            }
        };

        SecurityKeyDialog<UnlockResult> dialog = new SecurityKeyDialog<>(activity, operation, listener);
        dialog.show(R.string.security_key_unlock_title);
        return dialog;
    }

    public boolean isShowing() {
        return _dialog != null && _dialog.isShowing();
    }

    public void dismiss() {
        if (_dialog != null) {
            _dialog.dismiss();
        }
    }

    private void show(@StringRes int titleId) {
        View view = LayoutInflater.from(_activity).inflate(R.layout.dialog_security_key, null);
        _imgKey = view.findViewById(R.id.img_security_key);
        _progress = view.findViewById(R.id.progress_security_key);
        _textStatus = view.findViewById(R.id.text_security_key_status);
        _textHint = view.findViewById(R.id.text_security_key_hint);
        _pinLayout = view.findViewById(R.id.text_security_key_pin_layout);
        _textPin = view.findViewById(R.id.text_security_key_pin);
        _textPin.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                onPositiveClicked();
                return true;
            }
            return false;
        });

        _dialog = new MaterialAlertDialogBuilder(_activity)
                .setTitle(titleId)
                .setView(view)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.security_key_continue, null)
                .create();
        _dialog.setCanceledOnTouchOutside(false);
        _dialog.setOnDismissListener(d -> onDismissed());
        _dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        Dialogs.showSecureDialog(_dialog);

        // the buttons are available as soon as show() returns
        _buttonPositive = _dialog.getButton(AlertDialog.BUTTON_POSITIVE);
        _buttonPositive.setOnClickListener(v -> onPositiveClicked());
        _buttonPositive.setVisibility(View.GONE);

        _activity.getLifecycle().addObserver(_lifecycleObserver);

        SecurityKeyConnector.Listener listener = new SecurityKeyConnector.Listener() {
            @Override
            public void onDevice(YubiKeyDevice device) {
                onDeviceConnected(device);
            }

            @Override
            public void onUsbPermissionPending() {
                if (!_busy && !_awaitingPin) {
                    setHint(_activity.getString(R.string.security_key_hint_usb_permission), false);
                }
            }
        };

        _usbSupported = SecurityKeyConnector.isUsbHostSupported(_activity);
        _nfcState = _connector.startNfc(_activity, listener);
        if (!_usbSupported && _nfcState == SecurityKeyConnector.NfcState.UNAVAILABLE) {
            setStatus(_activity.getString(R.string.security_key_status_no_transport));
            return;
        }

        showWaiting(false);
        _connector.startUsb(listener);
    }

    private void onDeviceConnected(YubiKeyDevice device) {
        if (_closed) {
            return;
        }

        if (device instanceof UsbYubiKeyDevice) {
            UsbYubiKeyDevice usbDevice = (UsbYubiKeyDevice) device;
            _usbDevice = usbDevice;
            usbDevice.setOnClosed(() -> _handler.post(() -> {
                if (_usbDevice == usbDevice) {
                    _usbDevice = null;
                    if (!_busy && !_awaitingPin && !_closed) {
                        _buttonPositive.setVisibility(View.GONE);
                    }
                }
            }));
        }

        if (_busy || _awaitingPin) {
            return;
        }

        run(device);
    }

    private void run(YubiKeyDevice device) {
        // never send a PIN to a different USB key than the one it was entered for, as a wrong PIN costs a retry
        if (_pin != null && _pinDevice != device
                && (_pinDevice instanceof UsbYubiKeyDevice || device instanceof UsbYubiKeyDevice)) {
            wipePin();
        }

        _busy = true;
        _lastDevice = device;
        setStatus(_activity.getString(device instanceof UsbYubiKeyDevice
                ? R.string.security_key_status_communicating
                : R.string.security_key_status_communicating_nfc));
        setHint(null, false);
        _progress.setVisibility(View.VISIBLE);
        _imgKey.setVisibility(View.INVISIBLE);
        _buttonPositive.setVisibility(View.GONE);

        Fido2CommandState state = new Fido2CommandState(step -> _handler.post(() -> onTouchRequired(step)));
        _state = state;
        char[] pin = _pin != null ? _pin.clone() : null;
        boolean nfc = !(device instanceof UsbYubiKeyDevice);

        try {
            if (device.supportsConnection(FidoConnection.class)) {
                device.requestConnection(FidoConnection.class, result -> {
                    Object value = null;
                    Exception error = null;
                    try {
                        value = _operation.run(new Fido2HmacSecret(YubiKitFido2Device.open(result.getValue())), pin, state, nfc);
                    } catch (Exception e) {
                        error = e;
                    } finally {
                        wipe(pin);
                    }
                    postResult(state, device, value, error);
                });
            } else if (device.supportsConnection(SmartCardConnection.class)) {
                device.requestConnection(SmartCardConnection.class, result -> {
                    Object value = null;
                    Exception error = null;
                    try {
                        value = _operation.run(new Fido2HmacSecret(YubiKitFido2Device.open(result.getValue())), pin, state, nfc);
                    } catch (Exception e) {
                        error = e;
                    } finally {
                        wipe(pin);
                    }
                    postResult(state, device, value, error);
                });
            } else {
                wipe(pin);
                postResult(state, device, null, new Fido2Exception(Fido2Exception.Reason.UNSUPPORTED_DEVICE));
            }
        } catch (RuntimeException e) {
            // thrown if the device was removed or permission was revoked
            wipe(pin);
            postResult(state, device, null, new IOException(e));
        }
    }

    private void postResult(Fido2CommandState state, YubiKeyDevice device, @Nullable Object value, @Nullable Exception error) {
        _handler.post(() -> onResult(state, device, value, error));
    }

    @SuppressWarnings("unchecked")
    private void onResult(Fido2CommandState state, YubiKeyDevice device, @Nullable Object value, @Nullable Exception error) {
        if (state != _state || _closed) {
            return;
        }

        _busy = false;
        _state = null;
        _progress.setVisibility(View.GONE);
        _imgKey.setVisibility(View.VISIBLE);

        if (error == null) {
            _succeeded = true;
            _dialog.dismiss();
            _listener.onSuccess((T) value);
            return;
        }

        if (error instanceof Fido2Exception) {
            onFido2Error((Fido2Exception) error, state.getStep(), device);
            return;
        }

        String details = getErrorDetails(error, state.getStep(), device);
        Log.e(TAG, String.format("Security key operation failed: %s", details), error);
        int messageId = error instanceof IOException
                ? R.string.security_key_error_connection_lost
                : R.string.security_key_error_protocol;
        showError(withDetails(_activity.getString(messageId), details));
    }

    private void onFido2Error(Fido2Exception e, Fido2CommandState.Step step, YubiKeyDevice device) {
        if (e.isAuditable()) {
            _listener.onAttemptFailed(e);
        }

        switch (e.getReason()) {
            case CONFIRM_REQUIRED:
                showWaitingForConfirmation();
                break;
            case PIN_REQUIRED:
                showPinPrompt(null, e.getPinRetries());
                break;
            case PIN_INVALID:
                wipePin();
                showPinPrompt(_activity.getString(R.string.security_key_error_pin_invalid), e.getPinRetries());
                break;
            case PIN_TOO_SHORT:
                wipePin();
                showPinPrompt(_activity.getResources().getQuantityString(R.plurals.security_key_error_pin_too_short, e.getMinPinLength(), e.getMinPinLength()), -1);
                break;
            case PIN_AUTH_BLOCKED:
                wipePin();
                _usbDevice = null;
                showError(_activity.getString(R.string.security_key_error_pin_auth_blocked));
                break;
            case PIN_BLOCKED:
                wipePin();
                showError(_activity.getString(R.string.security_key_error_pin_blocked));
                break;
            default:
                String message = getErrorMessage(e, step, device);
                switch (e.getReason()) {
                    case UNSUPPORTED_DEVICE:
                    case HMAC_SECRET_UNSUPPORTED:
                    case TIMEOUT:
                    case DENIED:
                    case PROTOCOL_ERROR:
                        String details = getErrorDetails(e, step, device);
                        Log.e(TAG, String.format("Security key operation failed: %s", details), e);
                        message = withDetails(message, details);
                        break;
                }
                showError(message);
                break;
        }
    }

    private String getErrorMessage(Fido2Exception e, Fido2CommandState.Step step, YubiKeyDevice device) {
        switch (e.getReason()) {
            case UNSUPPORTED_DEVICE:
                return _activity.getString(R.string.security_key_error_unsupported_device);
            case HMAC_SECRET_UNSUPPORTED:
                return _activity.getString(R.string.security_key_error_hmac_secret_unsupported);
            case NOT_ENROLLED:
                if (step == Fido2CommandState.Step.CONFIRM) {
                    return _activity.getString(R.string.security_key_error_confirm_other_key);
                }
                return _activity.getString(R.string.security_key_error_not_enrolled);
            case ALREADY_ENROLLED:
                Fido2Credential cred = e.getCredential();
                if (cred instanceof Fido2Slot) {
                    return _activity.getString(R.string.security_key_error_already_enrolled_name, ((Fido2Slot) cred).getName());
                }
                return _activity.getString(R.string.security_key_error_already_enrolled);
            case PIN_NOT_SET:
                return _activity.getString(R.string.security_key_error_pin_not_set);
            case PIN_CHANGE_REQUIRED:
                return _activity.getString(R.string.security_key_error_pin_change_required);
            case UV_MISMATCH:
                return _activity.getString(R.string.security_key_error_uv_mismatch);
            case SECRET_MISMATCH:
                return _activity.getString(R.string.security_key_error_secret_mismatch);
            case CANCELLED:
                return _activity.getString(R.string.security_key_error_cancelled);
            case TIMEOUT:
                return _activity.getString(R.string.security_key_error_timeout);
            case DENIED:
                // there's no way to deny an operation over NFC, so the key didn't consider the tap as user presence
                if (!(device instanceof UsbYubiKeyDevice)) {
                    return _activity.getString(R.string.security_key_error_tap_not_accepted);
                }
                return _activity.getString(R.string.security_key_error_denied);
            default:
                return _activity.getString(R.string.security_key_error_protocol);
        }
    }

    private String withDetails(String message, String details) {
        return message + "\n\n" + _activity.getString(R.string.security_key_error_details, details);
    }

    /**
     * Describes an error in a way that helps to diagnose problems with specific security keys.
     * The result doesn't contain any secrets.
     */
    private static String getErrorDetails(Throwable error, Fido2CommandState.Step step, YubiKeyDevice device) {
        List<String> parts = new ArrayList<>();
        parts.add("step: " + step.toString().toLowerCase(Locale.ROOT));

        List<String> causes = new ArrayList<>();
        Throwable cause = error;
        while (cause != null && causes.size() < MAX_ERROR_CAUSES) {
            String desc;
            if (cause instanceof CtapException) {
                desc = String.format(Locale.ROOT, "CTAP 0x%02X", ((CtapException) cause).getCtapError() & 0xFF);
            } else if (cause instanceof Fido2Exception) {
                desc = ((Fido2Exception) cause).getReason().toString();
            } else {
                desc = cause.getMessage() != null
                        ? cause.getClass().getSimpleName() + ": " + cause.getMessage()
                        : cause.getClass().getSimpleName();
            }
            if (!causes.contains(desc)) {
                causes.add(desc);
            }
            cause = cause.getCause() != cause ? cause.getCause() : null;
        }
        parts.add(TextUtils.join(" / ", causes));

        if (device instanceof UsbYubiKeyDevice) {
            parts.add(describeUsbDevice(((UsbYubiKeyDevice) device).getUsbDevice()));
        } else {
            parts.add("nfc");
        }

        return TextUtils.join("; ", parts);
    }

    /**
     * Describes the USB IDs and the interfaces of a USB device, for example:
     * "usb 1050:0407, if0 03/00/00 [int in 64, int out 64]".
     */
    private static String describeUsbDevice(UsbDevice device) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(Locale.ROOT, "usb %04x:%04x", device.getVendorId(), device.getProductId()));
        for (int i = 0; i < device.getInterfaceCount(); i++) {
            UsbInterface usbInterface = device.getInterface(i);
            sb.append(String.format(Locale.ROOT, ", if%d %02x/%02x/%02x [", usbInterface.getId(), usbInterface.getInterfaceClass(),
                    usbInterface.getInterfaceSubclass(), usbInterface.getInterfaceProtocol()));
            for (int j = 0; j < usbInterface.getEndpointCount(); j++) {
                UsbEndpoint endpoint = usbInterface.getEndpoint(j);
                if (j > 0) {
                    sb.append(", ");
                }
                sb.append(String.format(Locale.ROOT, "%s %s %d", getEndpointTypeName(endpoint.getType()),
                        endpoint.getDirection() == UsbConstants.USB_DIR_IN ? "in" : "out",
                        endpoint.getMaxPacketSize()));
            }
            sb.append("]");
        }
        return sb.toString();
    }

    private static String getEndpointTypeName(int type) {
        switch (type) {
            case UsbConstants.USB_ENDPOINT_XFER_CONTROL:
                return "ctrl";
            case UsbConstants.USB_ENDPOINT_XFER_ISOC:
                return "isoc";
            case UsbConstants.USB_ENDPOINT_XFER_BULK:
                return "bulk";
            case UsbConstants.USB_ENDPOINT_XFER_INT:
                return "int";
            default:
                return String.valueOf(type);
        }
    }

    private void onTouchRequired(Fido2CommandState.Step step) {
        if (!_busy || _closed) {
            return;
        }

        switch (step) {
            case REGISTER:
                setStatus(_activity.getString(R.string.security_key_status_touch_register));
                break;
            case CONFIRM:
                setStatus(_activity.getString(R.string.security_key_status_touch_confirm));
                break;
            default:
                setStatus(_activity.getString(R.string.security_key_status_touch));
                break;
        }
    }

    private void showWaiting(boolean again) {
        boolean nfc = _nfcState == SecurityKeyConnector.NfcState.ENABLED;
        int statusId;
        if (_usbSupported && nfc) {
            statusId = again ? R.string.security_key_status_insert_or_tap_again : R.string.security_key_status_insert_or_tap;
        } else if (nfc) {
            statusId = again ? R.string.security_key_status_tap_again : R.string.security_key_status_tap;
        } else {
            statusId = R.string.security_key_status_insert;
        }

        setStatus(_activity.getString(statusId));
        if (_nfcState == SecurityKeyConnector.NfcState.DISABLED) {
            setHint(_activity.getString(R.string.security_key_hint_nfc_disabled), false);
        } else {
            setHint(null, false);
        }
    }

    private void showWaitingForConfirmation() {
        // keep the PIN, as it's needed again to obtain the secret
        _awaitingPin = false;
        _pinLayout.setVisibility(View.GONE);
        _buttonPositive.setVisibility(View.GONE);
        setStatus(_activity.getString(R.string.security_key_status_tap_again_finish));
        setHint(null, false);
    }

    private void showError(String message) {
        wipePin();
        _awaitingPin = false;
        _pinLayout.setVisibility(View.GONE);
        showWaiting(false);
        setHint(message, true);

        // offer to try again if the USB key is still connected
        if (_usbDevice != null) {
            _buttonPositive.setText(R.string.security_key_retry);
            _buttonPositive.setVisibility(View.VISIBLE);
        } else {
            _buttonPositive.setVisibility(View.GONE);
        }
    }

    private void showPinPrompt(@Nullable String error, int retries) {
        _awaitingPin = true;
        _pinDevice = _lastDevice;
        setStatus(_activity.getString(R.string.security_key_status_enter_pin));
        setHint(null, false);

        String helper = retries >= 0
                ? _activity.getResources().getQuantityString(R.plurals.security_key_pin_retries, retries, retries)
                : null;
        _pinLayout.setVisibility(View.VISIBLE);
        _pinLayout.setError(error);
        _pinLayout.setHelperText(helper);
        _textPin.setText("");
        _textPin.requestFocus();
        InputMethodManager imm = (InputMethodManager) _activity.getSystemService(Context.INPUT_METHOD_SERVICE);
        _textPin.post(() -> imm.showSoftInput(_textPin, InputMethodManager.SHOW_IMPLICIT));

        _buttonPositive.setText(R.string.security_key_continue);
        _buttonPositive.setVisibility(View.VISIBLE);
    }

    private void onPositiveClicked() {
        if (_busy || _closed) {
            return;
        }

        if (_awaitingPin) {
            char[] pin = EditTextHelper.getEditTextChars(_textPin);
            if (pin.length == 0) {
                return;
            }

            wipePin();
            _pin = pin;
            _textPin.setText("");
            _awaitingPin = false;
            _pinLayout.setVisibility(View.GONE);
            _pinLayout.setError(null);
            InputMethodManager imm = (InputMethodManager) _activity.getSystemService(Context.INPUT_METHOD_SERVICE);
            imm.hideSoftInputFromWindow(_textPin.getWindowToken(), 0);

            // continue right away if the key is still plugged in, otherwise ask the user to tap it again
            if (_usbDevice != null && _pinDevice == _usbDevice) {
                run(_usbDevice);
            } else {
                _buttonPositive.setVisibility(View.GONE);
                showWaiting(true);
            }
        } else if (_usbDevice != null) {
            run(_usbDevice);
        }
    }

    private void setStatus(String status) {
        _textStatus.setText(status);
    }

    private void setHint(@Nullable String hint, boolean error) {
        if (hint == null) {
            _textHint.setVisibility(View.GONE);
            return;
        }

        _textHint.setText(hint);
        int colorAttr = error
                ? androidx.appcompat.R.attr.colorError
                : com.google.android.material.R.attr.colorOnSurfaceVariant;
        _textHint.setTextColor(MaterialColors.getColor(_textHint, colorAttr));
        _textHint.setVisibility(View.VISIBLE);
    }

    private void onDismissed() {
        if (_closed) {
            return;
        }
        _closed = true;

        if (_state != null) {
            _state.cancel();
            _state = null;
        }
        _connector.stopUsb();
        _connector.stopNfc(_activity);
        _activity.getLifecycle().removeObserver(_lifecycleObserver);
        _textPin.setText("");
        wipePin();

        if (!_succeeded && !_silentDismiss) {
            _listener.onCancelled();
        }
    }

    private void wipePin() {
        wipe(_pin);
        _pin = null;
    }

    private static void wipe(@Nullable char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    private class LifecycleObserver implements DefaultLifecycleObserver {
        @Override
        public void onStop(@NonNull LifecycleOwner owner) {
            // The USB permission prompt only pauses the activity, so don't dismiss on pause
            if (!_activity.isChangingConfigurations()) {
                dismiss();
            }
        }

        @Override
        public void onDestroy(@NonNull LifecycleOwner owner) {
            _silentDismiss = true;
            dismiss();
        }
    }
}
