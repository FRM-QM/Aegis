package com.beemdevelopment.aegis.helpers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class HidDescriptorParserTest {
    // the report descriptor of a CTAPHID interface, as listed in the CTAP specification
    private static final int[] FIDO_REPORT_DESCRIPTOR = {
            0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
            0x09, 0x01,       // Usage (CTAPHID)
            0xA1, 0x01,       // Collection (Application)
            0x09, 0x20,       //   Usage (Input Report Data)
            0x15, 0x00,       //   Logical Minimum (0)
            0x26, 0xFF, 0x00, //   Logical Maximum (255)
            0x75, 0x08,       //   Report Size (8)
            0x95, 0x40,       //   Report Count (64)
            0x81, 0x02,       //   Input (Data, Var, Abs)
            0x09, 0x21,       //   Usage (Output Report Data)
            0x15, 0x00,       //   Logical Minimum (0)
            0x26, 0xFF, 0x00, //   Logical Maximum (255)
            0x75, 0x08,       //   Report Size (8)
            0x95, 0x40,       //   Report Count (64)
            0x91, 0x02,       //   Output (Data, Var, Abs)
            0xC0              // End Collection
    };

    private static final int[] KEYBOARD_REPORT_DESCRIPTOR = {
            0x05, 0x01,       // Usage Page (Generic Desktop)
            0x09, 0x06,       // Usage (Keyboard)
            0xA1, 0x01,       // Collection (Application)
            0x05, 0x07,       //   Usage Page (Keyboard)
            0x19, 0xE0,       //   Usage Minimum (224)
            0x29, 0xE7,       //   Usage Maximum (231)
            0x15, 0x00,       //   Logical Minimum (0)
            0x25, 0x01,       //   Logical Maximum (1)
            0x75, 0x01,       //   Report Size (1)
            0x95, 0x08,       //   Report Count (8)
            0x81, 0x02,       //   Input (Data, Var, Abs)
            0xC0              // End Collection
    };

    @Test
    public void testHasFidoUsagePage() {
        assertTrue(HidDescriptorParser.hasFidoUsagePage(bytes(FIDO_REPORT_DESCRIPTOR)));
        assertFalse(HidDescriptorParser.hasFidoUsagePage(bytes(KEYBOARD_REPORT_DESCRIPTOR)));
        assertFalse(HidDescriptorParser.hasFidoUsagePage(new byte[0]));

        // a 4-byte usage page item
        assertTrue(HidDescriptorParser.hasFidoUsagePage(bytes(0x07, 0xD0, 0xF1, 0x00, 0x00, 0x09, 0x01)));

        // the bytes of a FIDO usage page item inside the data of other items don't count
        assertFalse(HidDescriptorParser.hasFidoUsagePage(bytes(0x27, 0x06, 0xD0, 0xF1, 0x00, 0x09, 0x01)));
        assertFalse(HidDescriptorParser.hasFidoUsagePage(bytes(0xFE, 0x03, 0x00, 0x06, 0xD0, 0xF1, 0x09, 0x01)));

        // truncated items
        assertFalse(HidDescriptorParser.hasFidoUsagePage(bytes(0x06, 0xD0)));
        assertFalse(HidDescriptorParser.hasFidoUsagePage(bytes(0xFE)));
    }

    @Test
    public void testFindReportDescriptorLength() {
        byte[] raw = getRawDescriptors();
        assertEquals(KEYBOARD_REPORT_DESCRIPTOR.length, HidDescriptorParser.findReportDescriptorLength(raw, 0));
        assertEquals(FIDO_REPORT_DESCRIPTOR.length, HidDescriptorParser.findReportDescriptorLength(raw, 1));
        assertEquals(-1, HidDescriptorParser.findReportDescriptorLength(raw, 3));
        assertEquals(-1, HidDescriptorParser.findReportDescriptorLength(new byte[0], 1));

        // malformed descriptors
        assertEquals(-1, HidDescriptorParser.findReportDescriptorLength(Arrays.copyOf(raw, 40), 1));
        byte[] zeroLength = raw.clone();
        zeroLength[18] = 0;
        assertEquals(-1, HidDescriptorParser.findReportDescriptorLength(zeroLength, 1));
    }

    /**
     * Returns the descriptors of a security key with a HID keyboard interface, a FIDO HID interface and a CCID interface.
     */
    private static byte[] getRawDescriptors() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // device
        write(out, 0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x50, 0x10, 0x07, 0x04, 0x00, 0x01, 0x01, 0x02, 0x00, 0x01);
        // configuration (the total length isn't checked)
        write(out, 0x09, 0x02, 0x00, 0x00, 0x03, 0x01, 0x00, 0x80, 0x1E);

        // keyboard: interface, HID and endpoint descriptors
        write(out, 0x09, 0x04, 0x00, 0x00, 0x01, 0x03, 0x01, 0x01, 0x00);
        write(out, 0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, KEYBOARD_REPORT_DESCRIPTOR.length, 0x00);
        write(out, 0x07, 0x05, 0x81, 0x03, 0x08, 0x00, 0x0A);

        // FIDO: interface, HID and endpoint descriptors
        write(out, 0x09, 0x04, 0x01, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00);
        write(out, 0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, FIDO_REPORT_DESCRIPTOR.length, 0x00);
        write(out, 0x07, 0x05, 0x02, 0x03, 0x40, 0x00, 0x01);
        write(out, 0x07, 0x05, 0x82, 0x03, 0x40, 0x00, 0x01);

        // CCID: interface, (truncated) functional descriptor, which also has type 0x21
        write(out, 0x09, 0x04, 0x02, 0x00, 0x03, 0x0B, 0x00, 0x00, 0x00);
        write(out, 0x08, 0x21, 0x10, 0x01, 0x00, 0x07, 0x03, 0x00);
        return out.toByteArray();
    }

    private static void write(ByteArrayOutputStream out, int... values) {
        byte[] bytes = bytes(values);
        out.write(bytes, 0, bytes.length);
    }

    private static byte[] bytes(int... values) {
        byte[] bytes = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            bytes[i] = (byte) values[i];
        }
        return bytes;
    }
}
