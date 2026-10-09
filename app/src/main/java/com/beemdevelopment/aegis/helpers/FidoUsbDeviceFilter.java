package com.beemdevelopment.aegis.helpers;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;

import androidx.annotation.Nullable;

import com.yubico.yubikit.android.transport.usb.DeviceFilter;

/**
 * A yubikit DeviceFilter that accepts USB devices of any vendor, as long as they have a HID
 * interface that could be a FIDO interface. The default filter of yubikit only accepts YubiKeys.
 *
 * The filter is consulted before yubikit asks the user for permission to access the device, so
 * this prevents permission prompts for unrelated devices like USB flash drives.
 */
public class FidoUsbDeviceFilter extends DeviceFilter {
    private final UsbManager _usbManager;
    @Nullable
    private final Runnable _onPermissionPending;

    /**
     * @param onPermissionPending called when an accepted device was found that Aegis does not have permission to access yet.
     */
    public FidoUsbDeviceFilter(UsbManager usbManager, @Nullable Runnable onPermissionPending) {
        _usbManager = usbManager;
        _onPermissionPending = onPermissionPending;
    }

    @Override
    public boolean checkVendorProductIds(int vendorId, int productId) {
        for (UsbDevice device : _usbManager.getDeviceList().values()) {
            // yubikit 3.1.0 passes the device ID instead of the product ID for devices that were attached before discovery started
            if (device.getVendorId() == vendorId
                    && (device.getProductId() == productId || device.getDeviceId() == productId)
                    && hasFidoInterface(device)) {
                if (_onPermissionPending != null && !_usbManager.hasPermission(device)) {
                    _onPermissionPending.run();
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Reports whether the given device has a HID interface without a boot protocol subclass.
     * The FIDO HID interface is identified by its usage page, but reading the HID report
     * descriptor requires permission to access the device.
     */
    private static boolean hasFidoInterface(UsbDevice device) {
        for (int i = 0; i < device.getInterfaceCount(); i++) {
            UsbInterface usbInterface = device.getInterface(i);
            if (usbInterface.getInterfaceClass() == UsbConstants.USB_CLASS_HID
                    && usbInterface.getInterfaceSubclass() == 0) {
                return true;
            }
        }

        return false;
    }
}
