package com.beemdevelopment.aegis.helpers;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.text.TextUtils;
import android.util.Log;

import androidx.annotation.Nullable;

import com.yubico.yubikit.android.transport.usb.connection.ConnectionManager;
import com.yubico.yubikit.android.transport.usb.connection.FidoConnectionHandler;
import com.yubico.yubikit.android.transport.usb.connection.UsbFidoConnection;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Finds the FIDO HID interface of a USB security key more leniently than yubikit does.
 *
 * yubikit recognizes the FIDO interface by the usage page in its HID report descriptor. It gives up
 * if the security key doesn't respond to its request for the report descriptor, which happens with
 * some security keys that aren't made by Yubico. This handler requests the report descriptor with
 * its exact length (like the Linux kernel does) and tries again if that fails. If the security key
 * still doesn't respond, it falls back to recognizing the FIDO interface by its shape: a HID
 * interface without a boot protocol and with 64-byte interrupt endpoints in both directions. In
 * that case, the CTAPHID handshake that follows verifies whether it actually is a FIDO interface.
 */
public class FidoUsbConnectionHandler extends FidoConnectionHandler {
    private static final String TAG = FidoUsbConnectionHandler.class.getSimpleName();

    private static final int USB_RECIPIENT_INTERFACE = 0x01;
    private static final int USB_REQUEST_GET_DESCRIPTOR = 0x06;
    private static final int HID_DESC_TYPE_REPORT = 0x22;
    // enough for the report descriptor of any FIDO interface
    private static final int DEFAULT_REPORT_DESC_LENGTH = 255;
    private static final int REPORT_DESC_ATTEMPTS = 3;
    private static final int REPORT_DESC_TIMEOUT = 2000;
    private static final int CTAPHID_PACKET_SIZE = 64;

    /**
     * Replaces the FIDO connection handler of yubikit with this one. Must be called after a
     * YubiKitManager has been created, because that registers the default handlers.
     */
    public static void register() {
        ConnectionManager.registerConnectionHandler(UsbFidoConnection.class, new FidoUsbConnectionHandler());
    }

    @Override
    protected UsbInterface getClaimedInterface(UsbDevice device, UsbDeviceConnection connection) throws IOException {
        List<String> problems = new ArrayList<>();
        for (int i = 0; i < device.getInterfaceCount(); i++) {
            UsbInterface usbInterface = device.getInterface(i);
            int id = usbInterface.getId();
            if (usbInterface.getInterfaceClass() != UsbConstants.USB_CLASS_HID) {
                continue;
            }
            if (!hasCtapHidEndpoints(usbInterface)) {
                problems.add(String.format(Locale.ROOT, "if%d: no 64-byte interrupt endpoints", id));
                continue;
            }
            if (!connection.claimInterface(usbInterface, true)) {
                problems.add(String.format(Locale.ROOT, "if%d: unable to claim", id));
                continue;
            }

            boolean fido = false;
            try {
                byte[] reportDescriptor = readReportDescriptor(connection, usbInterface);
                if (reportDescriptor != null) {
                    fido = HidDescriptorParser.hasFidoUsagePage(reportDescriptor);
                    if (!fido) {
                        problems.add(String.format(Locale.ROOT, "if%d: not a FIDO usage page", id));
                    }
                } else {
                    fido = usbInterface.getInterfaceSubclass() == 0 && usbInterface.getInterfaceProtocol() == 0;
                    if (fido) {
                        Log.w(TAG, String.format(Locale.ROOT, "Unable to read the HID report descriptor of interface %d, assuming it's the FIDO interface", id));
                    } else {
                        problems.add(String.format(Locale.ROOT, "if%d: unable to read report descriptor", id));
                    }
                }

                if (fido) {
                    return usbInterface;
                }
            } finally {
                if (!fido) {
                    connection.releaseInterface(usbInterface);
                }
            }
        }

        throw new IOException("No FIDO HID interface found (" + TextUtils.join(", ", problems) + ")");
    }

    @Nullable
    private static byte[] readReportDescriptor(UsbDeviceConnection connection, UsbInterface usbInterface) {
        int length = -1;
        byte[] rawDescriptors = connection.getRawDescriptors();
        if (rawDescriptors != null) {
            length = HidDescriptorParser.findReportDescriptorLength(rawDescriptors, usbInterface.getId());
        }
        if (length <= 0) {
            length = DEFAULT_REPORT_DESC_LENGTH;
        }

        byte[] buffer = new byte[length];
        for (int i = 0; i < REPORT_DESC_ATTEMPTS; i++) {
            int read = connection.controlTransfer(
                    UsbConstants.USB_DIR_IN | UsbConstants.USB_TYPE_STANDARD | USB_RECIPIENT_INTERFACE,
                    USB_REQUEST_GET_DESCRIPTOR, HID_DESC_TYPE_REPORT << 8, usbInterface.getId(),
                    buffer, buffer.length, REPORT_DESC_TIMEOUT);
            if (read > 0) {
                return Arrays.copyOf(buffer, read);
            }
        }

        return null;
    }

    /**
     * Reports whether the given interface has the interrupt endpoints that CTAPHID needs.
     */
    private static boolean hasCtapHidEndpoints(UsbInterface usbInterface) {
        boolean in = false;
        boolean out = false;
        for (int i = 0; i < usbInterface.getEndpointCount(); i++) {
            UsbEndpoint endpoint = usbInterface.getEndpoint(i);
            if (endpoint.getType() == UsbConstants.USB_ENDPOINT_XFER_INT && endpoint.getMaxPacketSize() == CTAPHID_PACKET_SIZE) {
                if (endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                    in = true;
                } else {
                    out = true;
                }
            }
        }

        return in && out;
    }
}
