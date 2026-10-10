package com.beemdevelopment.aegis.crypto.fido2;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.util.Pair;

import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class Fido2HmacSecretTest {
    private static final String RP_ID = "com.beemdevelopment.aegis";
    private static final String PIN = "123456";

    @Test
    public void testEnrollAndUnlockWithoutPin() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device();
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);
        assertFalse(enrollment.isUv());
        assertEquals(32, enrollment.getSalt().length);
        assertEquals(32, enrollment.getSecret().length);
        assertEquals(2, device.getTouches());

        Pair<Fido2Enrollment, byte[]> res = unlock(device, Collections.singletonList(enrollment), null);
        assertSame(enrollment, res.first);
        assertArrayEquals(enrollment.getSecret(), res.second);
        assertEquals(3, device.getTouches());
    }

    @Test
    public void testUnlockWithOtherKey() throws Fido2Exception, IOException {
        Fido2Enrollment enrollment = enroll(new SoftwareFido2Device(), Collections.emptyList(), null);

        SoftwareFido2Device other = new SoftwareFido2Device();
        Fido2Exception e = assertThrows(Fido2Exception.class, () -> unlock(other, Collections.singletonList(enrollment), null));
        assertEquals(Fido2Exception.Reason.NOT_ENROLLED, e.getReason());
        assertTrue(e.isAuditable());
        assertEquals(0, other.getTouches());
    }

    @Test
    public void testEnrollAndUnlockWithPin() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setPin(PIN);

        Fido2Exception e = assertThrows(Fido2Exception.class, () -> enroll(device, Collections.emptyList(), null));
        assertEquals(Fido2Exception.Reason.PIN_REQUIRED, e.getReason());
        assertEquals(8, e.getPinRetries());
        assertEquals(0, device.getTouches());

        // the pin token is single-use, so this also verifies that a fresh token is used for each command
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), PIN.toCharArray());
        assertTrue(enrollment.isUv());

        e = assertThrows(Fido2Exception.class, () -> unlock(device, Collections.singletonList(enrollment), null));
        assertEquals(Fido2Exception.Reason.PIN_REQUIRED, e.getReason());

        Pair<Fido2Enrollment, byte[]> res = unlock(device, Collections.singletonList(enrollment), PIN.toCharArray());
        assertArrayEquals(enrollment.getSecret(), res.second);
    }

    @Test
    public void testWrongPin() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setPin(PIN);
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), PIN.toCharArray());
        List<Fido2Enrollment> candidates = Collections.singletonList(enrollment);

        Fido2Exception e = assertThrows(Fido2Exception.class, () -> unlock(device, candidates, "000000".toCharArray()));
        assertEquals(Fido2Exception.Reason.PIN_INVALID, e.getReason());
        assertEquals(7, e.getPinRetries());
        assertTrue(e.isAuditable());

        e = assertThrows(Fido2Exception.class, () -> unlock(device, candidates, "000000".toCharArray()));
        assertEquals(Fido2Exception.Reason.PIN_INVALID, e.getReason());
        assertEquals(6, e.getPinRetries());

        e = assertThrows(Fido2Exception.class, () -> unlock(device, candidates, "000000".toCharArray()));
        assertEquals(Fido2Exception.Reason.PIN_AUTH_BLOCKED, e.getReason());

        // a power cycle is needed to try again
        e = assertThrows(Fido2Exception.class, () -> unlock(device, candidates, PIN.toCharArray()));
        assertEquals(Fido2Exception.Reason.PIN_AUTH_BLOCKED, e.getReason());
        device.powerCycle();
        unlock(device, candidates, PIN.toCharArray());
        assertEquals(8, device.getRemainingPinRetries());

        // exhaust the retry counter
        for (int i = 0; i < 8; i++) {
            if (i % 3 == 0) {
                device.powerCycle();
            }
            e = assertThrows(Fido2Exception.class, () -> unlock(device, candidates, "000000".toCharArray()));
        }
        assertEquals(Fido2Exception.Reason.PIN_BLOCKED, e.getReason());
    }

    @Test
    public void testPinTooShort() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setPin(PIN);
        Fido2Exception e = assertThrows(Fido2Exception.class, () -> enroll(device, Collections.emptyList(), "123".toCharArray()));
        assertEquals(Fido2Exception.Reason.PIN_TOO_SHORT, e.getReason());
        assertEquals(4, e.getMinPinLength());
        assertEquals(8, device.getRemainingPinRetries());
    }

    @Test
    public void testDuplicateEnrollment() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device();
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);
        int touches = device.getTouches();

        Fido2Exception e = assertThrows(Fido2Exception.class, () -> enroll(device, Collections.singletonList(enrollment), null));
        assertEquals(Fido2Exception.Reason.ALREADY_ENROLLED, e.getReason());
        assertSame(enrollment, e.getCredential());
        assertEquals(touches, device.getTouches());
    }

    @Test
    public void testDuplicateEnrollmentExcludeList() throws Fido2Exception, IOException {
        // without silent assertions, the authenticator detects duplicates through the exclude list
        SoftwareFido2Device device = new SoftwareFido2Device().setSilentAssertions(false);
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);

        Fido2Exception e = assertThrows(Fido2Exception.class, () -> enroll(device, Collections.singletonList(enrollment), null));
        assertEquals(Fido2Exception.Reason.ALREADY_ENROLLED, e.getReason());
    }

    @Test
    public void testEnrollSecondKey() throws Fido2Exception, IOException {
        SoftwareFido2Device device1 = new SoftwareFido2Device();
        SoftwareFido2Device device2 = new SoftwareFido2Device();
        Fido2Enrollment enrollment1 = enroll(device1, Collections.emptyList(), null);
        Fido2Enrollment enrollment2 = enroll(device2, Collections.singletonList(enrollment1), null);

        List<Fido2Enrollment> candidates = Arrays.asList(enrollment1, enrollment2);
        assertSame(enrollment1, unlock(device1, candidates, null).first);
        assertSame(enrollment2, unlock(device2, candidates, null).first);
        assertArrayEquals(enrollment2.getSecret(), unlock(device2, candidates, null).second);
    }

    @Test
    public void testUnsupportedDevices() {
        SoftwareFido2Device u2f = new SoftwareFido2Device().setVersions("U2F_V2");
        Fido2Exception e = assertThrows(Fido2Exception.class, () -> enroll(u2f, Collections.emptyList(), null));
        assertEquals(Fido2Exception.Reason.UNSUPPORTED_DEVICE, e.getReason());

        SoftwareFido2Device noHmacSecret = new SoftwareFido2Device().setExtensions("credProtect");
        e = assertThrows(Fido2Exception.class, () -> enroll(noHmacSecret, Collections.emptyList(), null));
        assertEquals(Fido2Exception.Reason.HMAC_SECRET_UNSUPPORTED, e.getReason());
    }

    @Test
    public void testAlwaysUvWithoutPin() {
        SoftwareFido2Device device = new SoftwareFido2Device().setAlwaysUv(true);
        Fido2Exception e = assertThrows(Fido2Exception.class, () -> enroll(device, Collections.emptyList(), null));
        assertEquals(Fido2Exception.Reason.PIN_NOT_SET, e.getReason());
    }

    @Test
    public void testForcePinChange() {
        SoftwareFido2Device device = new SoftwareFido2Device().setPin(PIN).setForcePinChange(true);
        Fido2Exception e = assertThrows(Fido2Exception.class, () -> enroll(device, Collections.emptyList(), PIN.toCharArray()));
        assertEquals(Fido2Exception.Reason.PIN_CHANGE_REQUIRED, e.getReason());
    }

    @Test
    public void testUvMismatch() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device();
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);

        // the user later sets a PIN and enables alwaysUv
        device.setPin(PIN).setAlwaysUv(true);
        Fido2Exception e = assertThrows(Fido2Exception.class, () -> unlock(device, Collections.singletonList(enrollment), PIN.toCharArray()));
        assertEquals(Fido2Exception.Reason.UV_MISMATCH, e.getReason());
    }

    @Test
    public void testPinSetAfterEnrollment() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device();
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);

        // a PIN without alwaysUv doesn't affect credentials that were enrolled without user verification
        device.setPin(PIN);
        Pair<Fido2Enrollment, byte[]> res = unlock(device, Collections.singletonList(enrollment), null);
        assertArrayEquals(enrollment.getSecret(), res.second);
    }

    @Test
    public void testPinRemovedAfterEnrollment() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setPin(PIN);
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), PIN.toCharArray());

        // simulates a reset that keeps the credentials, which can't happen in practice, but tests the check
        device.setPin(null);
        Fido2Exception e = assertThrows(Fido2Exception.class, () -> unlock(device, Collections.singletonList(enrollment), null));
        assertEquals(Fido2Exception.Reason.UV_MISMATCH, e.getReason());
    }

    @Test
    public void testBatching() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setMaxCredentialCountInList(8);
        List<Fido2Enrollment> candidates = enrollOthers(10);
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);
        candidates.add(enrollment);

        Pair<Fido2Enrollment, byte[]> res = unlock(device, candidates, null);
        assertSame(enrollment, res.first);
        assertEquals(2, device.getSilentAssertionCount());
    }

    @Test
    public void testBatchingUnknownMax() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setMaxCredentialCountInList(null);
        List<Fido2Enrollment> candidates = enrollOthers(5);
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);
        candidates.add(enrollment);

        Pair<Fido2Enrollment, byte[]> res = unlock(device, candidates, null);
        assertSame(enrollment, res.first);
        assertEquals(6, device.getSilentAssertionCount());
    }

    @Test
    public void testCredentialIdTooLong() throws Fido2Exception, IOException {
        Fido2Enrollment longId = enroll(new SoftwareFido2Device().setCredentialIdLength(200).setMaxCredentialIdLength(null), Collections.emptyList(), null);

        SoftwareFido2Device device = new SoftwareFido2Device().setMaxCredentialIdLength(128);
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);

        Pair<Fido2Enrollment, byte[]> res = unlock(device, Arrays.asList(longId, enrollment), null);
        assertSame(enrollment, res.first);
    }

    @Test
    public void testOmittedCredentialId() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setOmitSingleCredential(true).setMaxCredentialCountInList(1);
        List<Fido2Enrollment> candidates = enrollOthers(2);
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);
        candidates.add(1, enrollment);

        Pair<Fido2Enrollment, byte[]> res = unlock(device, candidates, null);
        assertSame(enrollment, res.first);
        assertArrayEquals(enrollment.getSecret(), res.second);
    }

    @Test
    public void testSilentAssertionsUnsupported() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setSilentAssertions(false);
        List<Fido2Enrollment> candidates = enrollOthers(3);
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);
        candidates.add(enrollment);

        Pair<Fido2Enrollment, byte[]> res = unlock(device, candidates, null);
        assertSame(enrollment, res.first);
        assertArrayEquals(enrollment.getSecret(), res.second);
    }

    @Test
    public void testProtocolVersions() throws Fido2Exception, IOException {
        SoftwareFido2Device v1 = new SoftwareFido2Device().setProtocols(1).setPin(PIN);
        Fido2Enrollment enrollment = enroll(v1, Collections.emptyList(), PIN.toCharArray());
        Map<Integer, ?> input = v1.getLastHmacSecretInput();
        assertNotNull(input);
        assertFalse(input.containsKey(4));
        assertArrayEquals(enrollment.getSecret(), unlock(v1, Collections.singletonList(enrollment), PIN.toCharArray()).second);

        SoftwareFido2Device v2 = new SoftwareFido2Device().setProtocols(2, 1).setPin(PIN);
        enrollment = enroll(v2, Collections.emptyList(), PIN.toCharArray());
        input = v2.getLastHmacSecretInput();
        assertNotNull(input);
        assertEquals(2, input.get(4));
        assertArrayEquals(enrollment.getSecret(), unlock(v2, Collections.singletonList(enrollment), PIN.toCharArray()).second);
    }

    @Test
    public void testCredProtect() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device();
        enroll(device, Collections.emptyList(), null);
        Map<String, ?> extensions = device.getLastMakeCredentialExtensions();
        assertNotNull(extensions);
        assertEquals(1, extensions.get("credProtect"));

        device = new SoftwareFido2Device().setExtensions("hmac-secret");
        enroll(device, Collections.emptyList(), null);
        extensions = device.getLastMakeCredentialExtensions();
        assertNotNull(extensions);
        assertFalse(extensions.containsKey("credProtect"));
    }

    @Test
    public void testCancel() {
        SoftwareFido2Device device = new SoftwareFido2Device();
        List<String> events = new ArrayList<>();
        Fido2CommandState[] state = new Fido2CommandState[1];
        state[0] = new Fido2CommandState((step, reported) -> {
            events.add(describeTouch(step, reported));
            state[0].cancel();
        });

        Fido2Exception e = assertThrows(Fido2Exception.class, () ->
                new Fido2HmacSecret(device).enroll(RP_ID, "test", Collections.emptyList(), null, state[0]));
        assertEquals(Fido2Exception.Reason.CANCELLED, e.getReason());
        assertEquals(Arrays.asList("REGISTER command", "REGISTER reported"), events);
        assertEquals(0, device.getTouches());
    }

    @Test
    public void testTouchSteps() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device();
        List<String> events = new ArrayList<>();
        Fido2CommandState state = new Fido2CommandState((step, reported) -> events.add(describeTouch(step, reported)));
        Fido2Enrollment enrollment = new Fido2HmacSecret(device).enroll(RP_ID, "test", Collections.emptyList(), null, state);
        new Fido2HmacSecret(device).unlock(Collections.singletonList(enrollment), null, state);

        assertEquals(Arrays.asList(
                "REGISTER command", "REGISTER reported",
                "CONFIRM command", "CONFIRM reported",
                "UNLOCK command", "UNLOCK reported"), events);
    }

    @Test
    public void testTouchStepsWithoutUpNeeded() throws Fido2Exception, IOException {
        // the touch prompt must not depend on the authenticator reporting that it's waiting for a touch
        SoftwareFido2Device device = new SoftwareFido2Device().setReportUpNeeded(false).setPin(PIN);
        List<String> events = new ArrayList<>();
        Fido2CommandState state = new Fido2CommandState((step, reported) -> events.add(describeTouch(step, reported)));
        Fido2Enrollment enrollment = new Fido2HmacSecret(device).enroll(RP_ID, "test", Collections.emptyList(), PIN.toCharArray(), state);
        new Fido2HmacSecret(device).unlock(Collections.singletonList(enrollment), PIN.toCharArray(), state);

        // the presence-free lookup that precedes the unlock doesn't ask for a touch
        assertEquals(Arrays.asList("REGISTER command", "CONFIRM command", "UNLOCK command"), events);
        assertEquals(3, device.getTouches());
    }

    @Test
    public void testEnrollOverNfcRequiresSecondTap() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setNfc(true);

        // a single tap only grants user presence for a single command
        Fido2Exception e = assertThrows(Fido2Exception.class, () -> enroll(device, Collections.emptyList(), null));
        assertEquals(Fido2Exception.Reason.DENIED, e.getReason());
        assertFalse(e.isAuditable());

        device.tap();
        Fido2CommandState state = new Fido2CommandState(null);
        assertEquals(Fido2CommandState.Step.CONNECT, state.getStep());
        Fido2Registration registration = new Fido2HmacSecret(device).register(RP_ID, "test", Collections.emptyList(), null, state);
        assertEquals(Fido2CommandState.Step.REGISTER, state.getStep());
        assertFalse(registration.isUv());

        device.tap();
        Fido2Enrollment enrollment = new Fido2HmacSecret(device).confirm(registration, null, state);
        assertEquals(Fido2CommandState.Step.CONFIRM, state.getStep());
        assertArrayEquals(registration.getCredentialId(), enrollment.getCredentialId());
        assertEquals(32, enrollment.getSecret().length);

        device.tap();
        Pair<Fido2Enrollment, byte[]> res = unlock(device, Collections.singletonList(enrollment), null);
        assertArrayEquals(enrollment.getSecret(), res.second);
    }

    @Test
    public void testEnrollOverNfcWithPin() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setNfc(true).setPin(PIN);
        Fido2CommandState state = new Fido2CommandState(null);

        Fido2Exception e = assertThrows(Fido2Exception.class, () ->
                new Fido2HmacSecret(device).register(RP_ID, "test", Collections.emptyList(), null, state));
        assertEquals(Fido2Exception.Reason.PIN_REQUIRED, e.getReason());
        assertEquals(0, device.getTouches());

        device.tap();
        Fido2Registration registration = new Fido2HmacSecret(device).register(RP_ID, "test", Collections.emptyList(), PIN.toCharArray(), state);
        assertTrue(registration.isUv());

        device.tap();
        Fido2Enrollment enrollment = new Fido2HmacSecret(device).confirm(registration, PIN.toCharArray(), state);
        assertTrue(enrollment.isUv());
        assertEquals(2, device.getTouches());

        // unlocking only needs one tap once the PIN is known
        device.tap();
        Pair<Fido2Enrollment, byte[]> res = unlock(device, Collections.singletonList(enrollment), PIN.toCharArray());
        assertArrayEquals(enrollment.getSecret(), res.second);
        assertEquals(3, device.getTouches());
    }

    @Test
    public void testConfirmWithOtherKey() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setNfc(true);
        Fido2Registration registration = new Fido2HmacSecret(device).register(RP_ID, "test", Collections.emptyList(), null, new Fido2CommandState(null));

        SoftwareFido2Device other = new SoftwareFido2Device().setNfc(true);
        Fido2CommandState state = new Fido2CommandState(null);
        Fido2Exception e = assertThrows(Fido2Exception.class, () -> new Fido2HmacSecret(other).confirm(registration, null, state));
        assertEquals(Fido2Exception.Reason.NOT_ENROLLED, e.getReason());
        assertEquals(Fido2CommandState.Step.CONFIRM, state.getStep());

        // the registration can still be confirmed with the right key
        device.tap();
        Fido2Enrollment enrollment = new Fido2HmacSecret(device).confirm(registration, null, state);
        assertEquals(32, enrollment.getSecret().length);
    }

    @Test
    public void testUnlockOverNfcSingleTap() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device().setNfc(true);
        List<Fido2Enrollment> others = enrollOthers(3);
        Fido2Registration registration = new Fido2HmacSecret(device).register(RP_ID, "test", others, null, new Fido2CommandState(null));
        device.tap();
        Fido2Enrollment enrollment = new Fido2HmacSecret(device).confirm(registration, null, new Fido2CommandState(null));

        // the preflight doesn't use up the user presence of the tap
        List<Fido2Enrollment> candidates = new ArrayList<>(others);
        candidates.add(enrollment);
        device.tap();
        Pair<Fido2Enrollment, byte[]> res = unlock(device, candidates, null);
        assertSame(enrollment, res.first);
        assertArrayEquals(enrollment.getSecret(), res.second);
    }

    @Test
    public void testUpRequiredMapsToDenied() {
        SoftwareFido2Device device = new SoftwareFido2Device().setNfc(true)
                .setNfcPresenceError(CtapException.ERR_UP_REQUIRED);
        Fido2Exception e = assertThrows(Fido2Exception.class, () -> enroll(device, Collections.emptyList(), null));
        assertEquals(Fido2Exception.Reason.DENIED, e.getReason());
    }

    @Test
    public void testDifferentSalts() throws Fido2Exception, IOException {
        SoftwareFido2Device device = new SoftwareFido2Device();
        Fido2Enrollment enrollment = enroll(device, Collections.emptyList(), null);

        byte[] otherSalt = enrollment.getSalt().clone();
        otherSalt[0] ^= 1;
        Fido2Enrollment other = new Fido2Enrollment(enrollment.getRpId(), enrollment.getCredentialId(), otherSalt, false, new byte[32]);

        byte[] secret = new Fido2HmacSecret(device).getSecret(other, null, new Fido2CommandState(null));
        assertFalse(Arrays.equals(enrollment.getSecret(), secret));
    }

    @Test
    public void testTruncate() {
        assertEquals("YubiKey", Fido2HmacSecret.truncate("YubiKey"));

        String longName = repeat('a', 100);
        assertEquals(64, Fido2HmacSecret.truncate(longName).length());

        // a multi-byte code point must not be split
        String key = new String(Character.toChars(0x1F511));
        assertEquals(repeat('a', 61), Fido2HmacSecret.truncate(repeat('a', 61) + key));
        assertEquals(repeat('a', 60) + key, Fido2HmacSecret.truncate(repeat('a', 60) + key + "b"));
    }

    private static String repeat(char c, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, c);
        return new String(chars);
    }

    private static List<Fido2Enrollment> enrollOthers(int count) throws Fido2Exception, IOException {
        List<Fido2Enrollment> list = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            list.add(enroll(new SoftwareFido2Device(), Collections.emptyList(), null));
        }
        return list;
    }

    private static String describeTouch(Fido2CommandState.Step step, boolean reported) {
        return step + (reported ? " reported" : " command");
    }

    private static Fido2Enrollment enroll(Fido2Device device, List<? extends Fido2Credential> existing, char[] pin) throws Fido2Exception, IOException {
        return new Fido2HmacSecret(device).enroll(RP_ID, "test", existing, pin, new Fido2CommandState(null));
    }

    private static <T extends Fido2Credential> Pair<T, byte[]> unlock(Fido2Device device, List<T> candidates, char[] pin) throws Fido2Exception, IOException {
        return new Fido2HmacSecret(device).unlock(candidates, pin, new Fido2CommandState(null));
    }
}
