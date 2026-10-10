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
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;

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
 *
 * The dialog survives configuration changes of its activity, like a rotation of the screen. It keeps
 * its state and any operation that's in progress, and shows itself again as soon as the recreated
 * activity calls {@link #restoreEnroll} or {@link #restoreUnlock}. If it doesn't, the dialog is closed.
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

    /**
     * Keeps the dialog of an activity while the activity is recreated after a configuration change.
     */
    public static class Retainer extends ViewModel {
        @Nullable
        private SecurityKeyDialog<?> _retained;

        @Override
        protected void onCleared() {
            if (_retained != null) {
                _retained.close(false);
            }
        }
    }

    private final Class<T> _resultType;
    @StringRes
    private final int _titleId;
    private final Operation<T> _operation;
    private final SecurityKeyConnector _connector;
    private final Handler _handler = new Handler(Looper.getMainLooper());
    private final LifecycleObserver _lifecycleObserver = new LifecycleObserver();
    private final SecurityKeyConnector.Listener _deviceListener = new SecurityKeyConnector.Listener() {
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

    // replaced when the activity is recreated
    private ComponentActivity _activity;
    private Listener<T> _listener;
    private Retainer _retainer;

    // the views are null while the activity is being recreated
    @Nullable
    private AlertDialog _dialog;
    private ImageView _imgKey;
    private CircularProgressIndicator _progress;
    private TextView _textStatus;
    private TextView _textHint;
    private TextInputLayout _pinLayout;
    private TextInputEditText _textPin;
    private Button _buttonPositive;

    // what the views show, so that it can be shown again after the activity has been recreated
    @Nullable
    private String _status;
    @Nullable
    private String _hint;
    private boolean _hintError;
    @Nullable
    private String _pinError;
    @Nullable
    private String _pinHelper;
    @StringRes
    private int _buttonTextId;

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
    // the result of an operation that finished while the activity was being recreated
    @Nullable
    private Runnable _pendingResult;

    private SecurityKeyDialog(ComponentActivity activity, Class<T> resultType, @StringRes int titleId,
                              Operation<T> operation, Listener<T> listener) {
        _activity = activity;
        _resultType = resultType;
        _titleId = titleId;
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

        SecurityKeyDialog<Fido2Slot> dialog = new SecurityKeyDialog<>(activity, Fido2Slot.class,
                R.string.security_key_enroll_title, operation, listener);
        dialog.show();
        return dialog;
    }

    /**
     * Shows the dialog of {@link #showEnroll} again if it was open when the given activity was
     * recreated after a configuration change. Returns null if there's no such dialog.
     */
    @Nullable
    public static SecurityKeyDialog<Fido2Slot> restoreEnroll(ComponentActivity activity, Listener<Fido2Slot> listener) {
        return restore(activity, Fido2Slot.class, listener);
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

        SecurityKeyDialog<UnlockResult> dialog = new SecurityKeyDialog<>(activity, UnlockResult.class,
                R.string.security_key_unlock_title, operation, listener);
        dialog.show();
        return dialog;
    }

    /**
     * Shows the dialog of {@link #showUnlock} again if it was open when the given activity was
     * recreated after a configuration change. Returns null if there's no such dialog.
     */
    @Nullable
    public static SecurityKeyDialog<UnlockResult> restoreUnlock(ComponentActivity activity, Listener<UnlockResult> listener) {
        return restore(activity, UnlockResult.class, listener);
    }

    @Nullable
    @SuppressWarnings("unchecked")
    private static <T> SecurityKeyDialog<T> restore(ComponentActivity activity, Class<T> resultType, Listener<T> listener) {
        Retainer retainer = new ViewModelProvider(activity).get(Retainer.class);
        SecurityKeyDialog<?> retained = retainer._retained;
        // only a dialog that was removed from the previous instance of the activity can be shown again
        if (retained == null || retained._resultType != resultType || retained._dialog != null || retained._closed) {
            return null;
        }

        SecurityKeyDialog<T> dialog = (SecurityKeyDialog<T>) retained;
        dialog._activity = activity;
        dialog._listener = listener;
        dialog.attach();

        if (dialog._pendingResult != null) {
            dialog._handler.post(dialog._pendingResult);
            dialog._pendingResult = null;
        }
        return dialog;
    }

    public boolean isShowing() {
        return _dialog != null && _dialog.isShowing();
    }

    /**
     * Closes the dialog and stops listening for security keys.
     */
    public void dismiss() {
        close(true);
    }

    private void show() {
        _retainer = new ViewModelProvider(_activity).get(Retainer.class);
        _retainer._retained = this;
        _usbSupported = SecurityKeyConnector.isUsbHostSupported(_activity);

        attach();
        if (!_usbSupported && _nfcState == SecurityKeyConnector.NfcState.UNAVAILABLE) {
            setStatus(_activity.getString(R.string.security_key_status_no_transport));
            return;
        }

        showWaiting(false);
        _connector.startUsb(_deviceListener);
    }

    /**
     * Shows the dialog in the current activity and starts listening for security keys over NFC there.
     */
    private void attach() {
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

        AlertDialog dialog = new MaterialAlertDialogBuilder(_activity)
                .setTitle(_titleId)
                .setView(view)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.security_key_continue, null)
                .create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.setOnDismissListener(d -> close(true));
        dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        Dialogs.showSecureDialog(dialog);
        _dialog = dialog;

        // the buttons are available as soon as show() returns
        _buttonPositive = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
        _buttonPositive.setOnClickListener(v -> onPositiveClicked());

        _textStatus.setText(_status);
        renderHint();
        renderButton();
        renderBusy();
        renderPinPrompt();

        _activity.getLifecycle().addObserver(_lifecycleObserver);
        _nfcState = _connector.startNfc(_activity, _deviceListener);
    }

    /**
     * Removes the dialog from the activity, which is about to be recreated after a configuration
     * change. The rest keeps running, so that the recreated activity can show the dialog again.
     */
    private void detach() {
        // Android doesn't allow this anymore once the activity has been destroyed
        _connector.stopNfc(_activity);
        _activity.getLifecycle().removeObserver(_lifecycleObserver);
        removeViews();

        // the activity has been recreated by the time this runs, so if it didn't show the dialog again, nothing will
        _handler.post(() -> {
            if (_dialog == null) {
                close(false);
            }
        });
    }

    /**
     * Closes the dialog for good: cancels the current operation, stops listening for security keys
     * and wipes the PIN.
     */
    private void close(boolean notifyCancelled) {
        if (_closed) {
            return;
        }
        _closed = true;

        if (_retainer._retained == this) {
            _retainer._retained = null;
        }
        if (_state != null) {
            _state.cancel();
            _state = null;
        }
        _pendingResult = null;
        _connector.stopUsb();

        // this happens synchronously, as the activity may no longer exist once a dismissed dialog reports it
        if (_dialog != null) {
            _connector.stopNfc(_activity);
            _activity.getLifecycle().removeObserver(_lifecycleObserver);
            removeViews();
        }
        wipePin();

        if (notifyCancelled && !_succeeded) {
            _listener.onCancelled();
        }
    }

    private void removeViews() {
        if (_dialog == null) {
            return;
        }

        _textPin.setText("");
        // the dismiss listener is called asynchronously, and the dialog has been taken care of already
        _dialog.setOnDismissListener(null);
        _dialog.dismiss();
        _dialog = null;
        _imgKey = null;
        _progress = null;
        _textStatus = null;
        _textHint = null;
        _pinLayout = null;
        _textPin = null;
        _buttonPositive = null;
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
                        setButton(0);
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

        setBusy(true);
        _lastDevice = device;
        setStatus(_activity.getString(device instanceof UsbYubiKeyDevice
                ? R.string.security_key_status_communicating
                : R.string.security_key_status_communicating_nfc));
        setHint(null, false);
        setButton(0);

        boolean nfc = !(device instanceof UsbYubiKeyDevice);
        Fido2CommandState state = new Fido2CommandState((step, reported) -> {
            // over NFC, the tap counts as the touch, so only ask for one if the key explicitly waits for it
            if (reported || !nfc) {
                _handler.post(() -> onTouchRequired(step));
            }
        });
        _state = state;
        char[] pin = _pin != null ? _pin.clone() : null;

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
        if (_dialog == null) {
            // the activity is being recreated, so wait until it shows the dialog again
            _pendingResult = () -> onResult(state, device, value, error);
            return;
        }

        _state = null;
        setBusy(false);

        if (error == null) {
            _succeeded = true;
            close(false);
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
        hidePinPrompt();
        setButton(0);
        setStatus(_activity.getString(R.string.security_key_status_tap_again_finish));
        setHint(null, false);
    }

    private void showError(String message) {
        wipePin();
        hidePinPrompt();
        showWaiting(false);
        setHint(message, true);

        // offer to try again if the USB key is still connected
        setButton(_usbDevice != null ? R.string.security_key_retry : 0);
    }

    private void showPinPrompt(@Nullable String error, int retries) {
        _awaitingPin = true;
        _pinDevice = _lastDevice;
        _pinError = error;
        _pinHelper = retries >= 0
                ? _activity.getResources().getQuantityString(R.plurals.security_key_pin_retries, retries, retries)
                : null;
        setStatus(_activity.getString(R.string.security_key_status_enter_pin));
        setHint(null, false);
        setButton(R.string.security_key_continue);

        if (_dialog != null) {
            _textPin.setText("");
            renderPinPrompt();
        }
    }

    private void hidePinPrompt() {
        _awaitingPin = false;
        _pinError = null;
        _pinHelper = null;
        if (_dialog != null) {
            renderPinPrompt();
        }
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
            InputMethodManager imm = (InputMethodManager) _activity.getSystemService(Context.INPUT_METHOD_SERVICE);
            imm.hideSoftInputFromWindow(_textPin.getWindowToken(), 0);
            hidePinPrompt();

            // continue right away if the key is still plugged in, otherwise ask the user to tap it again
            if (_usbDevice != null && _pinDevice == _usbDevice) {
                run(_usbDevice);
            } else {
                setButton(0);
                showWaiting(true);
            }
        } else if (_usbDevice != null) {
            run(_usbDevice);
        }
    }

    // The setters below remember what they show, and only update the views while the dialog is shown.

    private void setStatus(String status) {
        _status = status;
        if (_dialog != null) {
            _textStatus.setText(status);
        }
    }

    private void setHint(@Nullable String hint, boolean error) {
        _hint = hint;
        _hintError = error;
        if (_dialog != null) {
            renderHint();
        }
    }

    /**
     * Shows the positive button with the given text, or hides it if the text is 0.
     */
    private void setButton(@StringRes int textId) {
        _buttonTextId = textId;
        if (_dialog != null) {
            renderButton();
        }
    }

    private void setBusy(boolean busy) {
        _busy = busy;
        if (_dialog != null) {
            renderBusy();
        }
    }

    private void renderHint() {
        if (_hint == null) {
            _textHint.setVisibility(View.GONE);
            return;
        }

        _textHint.setText(_hint);
        int colorAttr = _hintError
                ? androidx.appcompat.R.attr.colorError
                : com.google.android.material.R.attr.colorOnSurfaceVariant;
        _textHint.setTextColor(MaterialColors.getColor(_textHint, colorAttr));
        _textHint.setVisibility(View.VISIBLE);
    }

    private void renderButton() {
        if (_buttonTextId == 0) {
            _buttonPositive.setVisibility(View.GONE);
            return;
        }

        _buttonPositive.setText(_buttonTextId);
        _buttonPositive.setVisibility(View.VISIBLE);
    }

    private void renderBusy() {
        _progress.setVisibility(_busy ? View.VISIBLE : View.GONE);
        _imgKey.setVisibility(_busy ? View.INVISIBLE : View.VISIBLE);
    }

    private void renderPinPrompt() {
        _pinLayout.setError(_pinError);
        _pinLayout.setHelperText(_pinHelper);
        if (!_awaitingPin) {
            _pinLayout.setVisibility(View.GONE);
            return;
        }

        _pinLayout.setVisibility(View.VISIBLE);
        TextInputEditText textPin = _textPin;
        textPin.requestFocus();
        InputMethodManager imm = (InputMethodManager) _activity.getSystemService(Context.INPUT_METHOD_SERVICE);
        textPin.post(() -> imm.showSoftInput(textPin, InputMethodManager.SHOW_IMPLICIT));
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
                close(true);
            }
        }

        @Override
        public void onDestroy(@NonNull LifecycleOwner owner) {
            if (_activity.isChangingConfigurations()) {
                detach();
            } else {
                close(false);
            }
        }
    }
}
