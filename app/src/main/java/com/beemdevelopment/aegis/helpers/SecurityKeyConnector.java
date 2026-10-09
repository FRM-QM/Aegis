package com.beemdevelopment.aegis.helpers;

import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.usb.UsbManager;
import android.os.Handler;
import android.os.Looper;

import com.yubico.yubikit.android.YubiKitManager;
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration;
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable;
import com.yubico.yubikit.android.transport.usb.UsbConfiguration;
import com.yubico.yubikit.core.YubiKeyDevice;

/**
 * Discovers FIDO2 security keys connected over USB or NFC. All listener callbacks are invoked on the main thread.
 */
public class SecurityKeyConnector {
    private static final int NFC_TIMEOUT = 5000;

    public enum NfcState {
        ENABLED,
        DISABLED,
        UNAVAILABLE
    }

    public interface Listener {
        void onDevice(YubiKeyDevice device);

        void onUsbPermissionPending();
    }

    private final Context _context;
    private final YubiKitManager _manager;
    private final Handler _handler = new Handler(Looper.getMainLooper());
    private Listener _usbListener;
    private Listener _nfcListener;

    public SecurityKeyConnector(Context context) {
        _context = context.getApplicationContext();
        _manager = new YubiKitManager(_context);
    }

    public static boolean isUsbHostSupported(Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_USB_HOST);
    }

    /**
     * Starts listening for security keys connected over USB. Keys that are already connected are reported right away.
     * The listener stays registered while the activity is paused, so that the result of a USB permission prompt is not lost.
     */
    public void startUsb(Listener listener) {
        stopUsb();
        if (!isUsbHostSupported(_context)) {
            return;
        }

        _usbListener = listener;
        UsbManager usbManager = (UsbManager) _context.getSystemService(Context.USB_SERVICE);
        FidoUsbDeviceFilter filter = new FidoUsbDeviceFilter(usbManager, () -> post(listener, listener::onUsbPermissionPending, true));
        UsbConfiguration config = new UsbConfiguration().setDeviceFilter(filter);
        _manager.startUsbDiscovery(config, device -> post(listener, () -> listener.onDevice(device), true));
    }

    public void stopUsb() {
        if (_usbListener != null) {
            _usbListener = null;
            _manager.stopUsbDiscovery();
        }
    }

    /**
     * Starts listening for security keys that are tapped against the device. Requires the activity to be in the foreground.
     */
    public NfcState startNfc(Activity activity, Listener listener) {
        stopNfc(activity);

        NfcConfiguration config = new NfcConfiguration()
                .skipNdefCheck(true)
                .timeout(NFC_TIMEOUT);
        try {
            _nfcListener = listener;
            _manager.startNfcDiscovery(config, activity, device -> post(listener, () -> listener.onDevice(device), false));
            return NfcState.ENABLED;
        } catch (NfcNotAvailable e) {
            _nfcListener = null;
            return e.isDisabled() ? NfcState.DISABLED : NfcState.UNAVAILABLE;
        }
    }

    public void stopNfc(Activity activity) {
        if (_nfcListener != null) {
            _nfcListener = null;
            _manager.stopNfcDiscovery(activity);
        }
    }

    private void post(Listener listener, Runnable runnable, boolean usb) {
        _handler.post(() -> {
            // drop events that arrive after discovery was stopped
            if ((usb ? _usbListener : _nfcListener) == listener) {
                runnable.run();
            }
        });
    }
}
