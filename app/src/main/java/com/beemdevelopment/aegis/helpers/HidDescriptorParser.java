package com.beemdevelopment.aegis.helpers;

/**
 * Parses the USB descriptors that are needed to recognize the FIDO HID interface of a security key.
 */
public class HidDescriptorParser {
    private static final int DESC_TYPE_INTERFACE = 0x04;
    private static final int DESC_TYPE_HID = 0x21;
    private static final int DESC_TYPE_REPORT = 0x22;

    private static final int ITEM_LONG = 0xFE;
    private static final int ITEM_TAG_USAGE_PAGE = 0x04;
    private static final int FIDO_USAGE_PAGE = 0xF1D0;

    private HidDescriptorParser() {

    }

    /**
     * Returns the length of the HID report descriptor of the given interface, as listed in the HID
     * descriptor that follows the interface descriptor, or -1 if it can't be found.
     *
     * @param rawDescriptors the raw device and configuration descriptors of a USB device.
     */
    public static int findReportDescriptorLength(byte[] rawDescriptors, int interfaceNumber) {
        boolean inInterface = false;
        for (int i = 0; i + 1 < rawDescriptors.length; ) {
            int length = rawDescriptors[i] & 0xFF;
            int type = rawDescriptors[i + 1] & 0xFF;
            if (length < 2 || i + length > rawDescriptors.length) {
                return -1;
            }

            if (type == DESC_TYPE_INTERFACE && length >= 4) {
                // only consider the default alternate setting
                inInterface = (rawDescriptors[i + 2] & 0xFF) == interfaceNumber
                        && (rawDescriptors[i + 3] & 0xFF) == 0;
            } else if (type == DESC_TYPE_HID && inInterface && length >= 6) {
                int count = rawDescriptors[i + 5] & 0xFF;
                for (int j = 0; j < count; j++) {
                    int offset = i + 6 + j * 3;
                    if (offset + 3 > i + length) {
                        break;
                    }
                    if ((rawDescriptors[offset] & 0xFF) == DESC_TYPE_REPORT) {
                        return (rawDescriptors[offset + 1] & 0xFF) | ((rawDescriptors[offset + 2] & 0xFF) << 8);
                    }
                }
                return -1;
            }

            i += length;
        }

        return -1;
    }

    /**
     * Reports whether the given HID report descriptor declares the FIDO usage page (0xF1D0).
     */
    public static boolean hasFidoUsagePage(byte[] reportDescriptor) {
        for (int i = 0; i < reportDescriptor.length; ) {
            int prefix = reportDescriptor[i] & 0xFF;
            if (prefix == ITEM_LONG) {
                if (i + 1 >= reportDescriptor.length) {
                    return false;
                }
                i += 3 + (reportDescriptor[i + 1] & 0xFF);
                continue;
            }

            int size = prefix & 0x03;
            if (size == 3) {
                size = 4;
            }
            if (i + 1 + size > reportDescriptor.length) {
                return false;
            }

            if ((prefix & 0xFC) == ITEM_TAG_USAGE_PAGE) {
                int value = 0;
                for (int j = 0; j < size; j++) {
                    value |= (reportDescriptor[i + 1 + j] & 0xFF) << (8 * j);
                }
                if (value == FIDO_USAGE_PAGE) {
                    return true;
                }
            }

            i += 1 + size;
        }

        return false;
    }
}
