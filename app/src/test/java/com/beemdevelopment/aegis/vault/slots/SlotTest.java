package com.beemdevelopment.aegis.vault.slots;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.beemdevelopment.aegis.crypto.CryptoUtils;
import com.beemdevelopment.aegis.crypto.MasterKey;
import com.beemdevelopment.aegis.crypto.SCryptParameters;
import com.beemdevelopment.aegis.vault.VaultFileCredentials;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SlotTest {
    private MasterKey _masterKey;

    @Before
    public void init() {
        _masterKey = MasterKey.generate();
    }

    @Test
    public void testRawSlotCrypto() throws
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchPaddingException,
            SlotException, SlotIntegrityException {
        RawSlot slot = new RawSlot();
        SecretKey rawKey = CryptoUtils.generateKey();
        Cipher cipher = CryptoUtils.createEncryptCipher(rawKey);
        slot.setKey(_masterKey, cipher);

        cipher = slot.createDecryptCipher(rawKey);
        MasterKey decryptedKey = slot.getKey(cipher);

        assertArrayEquals(_masterKey.getBytes(), decryptedKey.getBytes());
    }

    @Test
    public void testPasswordSlotCrypto() throws
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchPaddingException,
            SlotException, SlotIntegrityException {
        final char[] password = "test".toCharArray();
        final SCryptParameters scryptParams = new SCryptParameters(
                CryptoUtils.CRYPTO_SCRYPT_N,
                CryptoUtils.CRYPTO_SCRYPT_p,
                CryptoUtils.CRYPTO_SCRYPT_r,
                new byte[CryptoUtils.CRYPTO_AEAD_KEY_SIZE]
        );

        PasswordSlot slot = new PasswordSlot();
        SecretKey passwordKey = slot.deriveKey(password, scryptParams);
        Cipher cipher = CryptoUtils.createEncryptCipher(passwordKey);
        slot.setKey(_masterKey, cipher);

        cipher = slot.createDecryptCipher(passwordKey);
        MasterKey decryptedKey = slot.getKey(cipher);

        assertArrayEquals(_masterKey.getBytes(), decryptedKey.getBytes());
    }

    @Test
    public void testSlotIntegrity() throws
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchPaddingException,
            SlotException, SlotIntegrityException {
        RawSlot slot = new RawSlot();
        SecretKey rawKey = CryptoUtils.generateKey();
        Cipher cipher = CryptoUtils.createEncryptCipher(rawKey);
        slot.setKey(_masterKey, cipher);

        // try to decrypt with good key/ciphertext first
        final Cipher decryptCipher = slot.createDecryptCipher(rawKey);
        slot.getKey(decryptCipher);

        // garble the first byte of the key and try to decrypt
        byte[] garbledKeyBytes = rawKey.getEncoded();
        garbledKeyBytes[0] = (byte) ~garbledKeyBytes[0];
        SecretKey garbledKey = new SecretKeySpec(garbledKeyBytes, "AES");
        final Cipher garbledDecryptCipher = slot.createDecryptCipher(garbledKey);
        assertThrows(SlotIntegrityException.class, () -> slot.getKey(garbledDecryptCipher));

        // garble the first byte of the ciphertext and try to decrypt
        byte[] garbledCiphertext = slot.getEncryptedMasterKey();
        garbledCiphertext[0] = (byte) ~garbledCiphertext[0];
        assertThrows(SlotIntegrityException.class, () -> slot.getKey(decryptCipher));
    }

    @Test
    public void testNonExportableSlotsExclusion() {
        // If a backup password slot, multiple regular password slots and a biometric slot are present:
        // -> The Regular password slots and the biometric slot get stripped
        Slot passwordSlot = new PasswordSlot();
        Slot passwordSlot2 = new PasswordSlot();
        Slot biometricSlot = new BiometricSlot();
        PasswordSlot backupSlot = new PasswordSlot();
        backupSlot.setIsBackup(true);
        SlotList slots = new SlotList();
        slots.add(passwordSlot);
        slots.add(passwordSlot2);
        slots.add(biometricSlot);
        slots.add(backupSlot);
        SlotList actual = slots.exportable();
        SlotList expected = new SlotList();
        expected.add(backupSlot);
        assertArrayEquals(expected.getValues().toArray(), actual.getValues().toArray());

        // If a backup password slot, a regular password slot and a biometric slot are present:
        // -> The Regular password slot and the biometric slot get stripped
        slots = new SlotList();
        slots.add(passwordSlot);
        slots.add(biometricSlot);
        slots.add(backupSlot);
        actual = slots.exportable();
        expected = new SlotList();
        expected.add(backupSlot);
        assertArrayEquals(expected.getValues().toArray(), actual.getValues().toArray());

        // If a backup password slot and a regular password slot are present:
        // -> The regular password slot get stripped
        slots = new SlotList();
        slots.add(passwordSlot);
        slots.add(backupSlot);
        actual = slots.exportable();
        expected = new SlotList();
        expected.add(backupSlot);
        assertArrayEquals(expected.getValues().toArray(), actual.getValues().toArray());

        // If a backup password slot and multiple regular password slot are present:
        // -> The regular password slots get stripped
        slots = new SlotList();
        slots.add(passwordSlot);
        slots.add(passwordSlot2);
        slots.add(backupSlot);
        actual = slots.exportable();
        expected = new SlotList();
        expected.add(backupSlot);
        assertArrayEquals(expected.getValues().toArray(), actual.getValues().toArray());

        // If multiple regular password slots and a biometric slot are present:
        // -> The biometric slot gets stripped
        slots = new SlotList();
        slots.add(passwordSlot);
        slots.add(passwordSlot2);
        slots.add(biometricSlot);
        actual = slots.exportable();
        expected = new SlotList();
        expected.add(passwordSlot);
        expected.add(passwordSlot2);
        assertArrayEquals(expected.getValues().toArray(), actual.getValues().toArray());

        // If a regular password slot and a biometric slot are present
        // -> The biometric slot gets stripped
        slots = new SlotList();
        slots.add(passwordSlot);
        slots.add(biometricSlot);
        actual = slots.exportable();
        expected = new SlotList();
        expected.add(passwordSlot);
        assertArrayEquals(expected.getValues().toArray(), actual.getValues().toArray());

        // If a regular password slot is present
        // -> No slots get stripped
        slots = new SlotList();
        slots.add(passwordSlot);
        actual = slots.exportable();
        expected = new SlotList();
        expected.add(passwordSlot);
        assertArrayEquals(expected.getValues().toArray(), actual.getValues().toArray());
    }

    @Test
    public void testFido2SlotsExportable() {
        // If a regular password slot, a biometric slot and FIDO2 slots are present:
        // -> The biometric slot gets stripped
        Slot passwordSlot = new PasswordSlot();
        Slot biometricSlot = new BiometricSlot();
        Fido2Slot fido2Slot = newFido2Slot("Key 1");
        Fido2Slot fido2Slot2 = newFido2Slot("Key 2");
        SlotList slots = new SlotList();
        slots.add(passwordSlot);
        slots.add(biometricSlot);
        slots.add(fido2Slot);
        slots.add(fido2Slot2);
        SlotList actual = slots.exportable();
        SlotList expected = new SlotList();
        expected.add(passwordSlot);
        expected.add(fido2Slot);
        expected.add(fido2Slot2);
        assertArrayEquals(expected.getValues().toArray(), actual.getValues().toArray());

        // If a backup password slot, a regular password slot and FIDO2 slots are present:
        // -> The regular password slot and the FIDO2 slots get stripped
        PasswordSlot backupSlot = new PasswordSlot();
        backupSlot.setIsBackup(true);
        slots = new SlotList();
        slots.add(passwordSlot);
        slots.add(backupSlot);
        slots.add(fido2Slot);
        slots.add(fido2Slot2);
        actual = slots.exportable();
        expected = new SlotList();
        expected.add(backupSlot);
        assertArrayEquals(expected.getValues().toArray(), actual.getValues().toArray());
    }

    @Test
    public void testFido2SlotCrypto() throws SlotException, SlotIntegrityException {
        Fido2Slot slot = newFido2Slot("YubiKey");
        byte[] secret = new byte[Fido2Slot.SECRET_SIZE];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) i;
        }

        slot.wrap(_masterKey, secret);
        MasterKey decryptedKey = slot.unwrap(secret);
        assertArrayEquals(_masterKey.getBytes(), decryptedKey.getBytes());

        byte[] wrongSecret = secret.clone();
        wrongSecret[0] = (byte) ~wrongSecret[0];
        assertThrows(SlotIntegrityException.class, () -> slot.unwrap(wrongSecret));
        assertThrows(IllegalArgumentException.class, () -> slot.unwrap(new byte[16]));
    }

    @Test
    public void testFido2SlotJson() throws SlotException, SlotIntegrityException {
        Fido2Slot slot = newFido2Slot("YubiKey 5 NFC");
        byte[] secret = new byte[Fido2Slot.SECRET_SIZE];
        slot.wrap(_masterKey, secret);

        Slot parsed = Slot.fromJson(slot.toJson());
        assertTrue(parsed instanceof Fido2Slot);
        Fido2Slot fido2Slot = (Fido2Slot) parsed;
        assertEquals(slot.getUUID(), fido2Slot.getUUID());
        assertEquals(Slot.TYPE_FIDO2, fido2Slot.getType());
        assertEquals(slot.getName(), fido2Slot.getName());
        assertEquals(slot.getRpId(), fido2Slot.getRpId());
        assertArrayEquals(slot.getCredentialId(), fido2Slot.getCredentialId());
        assertArrayEquals(slot.getSalt(), fido2Slot.getSalt());
        assertEquals(slot.isUv(), fido2Slot.isUv());
        assertEquals(slot.getCreatedAt(), fido2Slot.getCreatedAt());
        assertArrayEquals(_masterKey.getBytes(), fido2Slot.unwrap(secret).getBytes());
    }

    @Test
    public void testFido2SlotJsonFormat() throws JSONException, SlotException {
        JSONObject obj = new JSONObject("{\n" +
                "    \"type\": 3,\n" +
                "    \"uuid\": \"01234567-89ab-cdef-0123-456789abcdef\",\n" +
                "    \"key\": \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\n" +
                "    \"key_params\": {\n" +
                "        \"nonce\": \"0123456789abcdef01234567\",\n" +
                "        \"tag\": \"0123456789abcdef0123456789abcdef\"\n" +
                "    },\n" +
                "    \"name\": \"My key\",\n" +
                "    \"rp_id\": \"com.beemdevelopment.aegis\",\n" +
                "    \"credential_id\": \"00112233\",\n" +
                "    \"salt\": \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\n" +
                "    \"uv\": true,\n" +
                "    \"created\": 1760000000000\n" +
                "}");

        Fido2Slot slot = (Fido2Slot) Slot.fromJson(obj);
        assertEquals("My key", slot.getName());
        assertEquals("com.beemdevelopment.aegis", slot.getRpId());
        assertArrayEquals(new byte[]{0x00, 0x11, 0x22, 0x33}, slot.getCredentialId());
        assertEquals(Fido2Slot.SALT_SIZE, slot.getSalt().length);
        assertTrue(slot.isUv());
        assertEquals(1760000000000L, slot.getCreatedAt());

        // 'created' is optional
        obj.remove("created");
        slot = (Fido2Slot) Slot.fromJson(obj);
        assertEquals(0, slot.getCreatedAt());

        // only the relying party ID of Aegis is accepted
        obj.put("rp_id", "example.com");
        assertThrows(SlotException.class, () -> Slot.fromJson(obj));
        obj.put("rp_id", Fido2Slot.DEFAULT_RP_ID);

        // the other fields are required
        obj.remove("credential_id");
        assertThrows(SlotException.class, () -> Slot.fromJson(obj));
    }

    @Test
    public void testFido2SlotFind() {
        Fido2Slot fido2Slot = newFido2Slot("Key");
        SlotList slots = new SlotList();
        slots.add(new PasswordSlot());
        slots.add(fido2Slot);

        assertEquals(1, slots.findAll(Fido2Slot.class).size());
        assertSame(fido2Slot, slots.find(Fido2Slot.class));
        assertNull(slots.find(RawSlot.class));
        assertEquals(1, slots.findAll(PasswordSlot.class).size());
    }

    @Test
    public void testFido2SlotClone() throws SlotException, SlotIntegrityException {
        Fido2Slot slot = newFido2Slot("Key");
        byte[] secret = new byte[Fido2Slot.SECRET_SIZE];
        slot.wrap(_masterKey, secret);

        SlotList slots = new SlotList();
        slots.add(slot);
        VaultFileCredentials creds = new VaultFileCredentials(_masterKey, slots).clone();

        Fido2Slot clone = creds.getSlots().find(Fido2Slot.class);
        assertNotSame(slot, clone);
        assertEquals(slot.getName(), clone.getName());
        assertArrayEquals(slot.getCredentialId(), clone.getCredentialId());
        assertArrayEquals(slot.getSalt(), clone.getSalt());
        assertArrayEquals(_masterKey.getBytes(), clone.unwrap(secret).getBytes());
    }

    private static Fido2Slot newFido2Slot(String name) {
        byte[] credentialId = new byte[64];
        Arrays.fill(credentialId, (byte) name.hashCode());
        return new Fido2Slot(name, Fido2Slot.DEFAULT_RP_ID, credentialId, CryptoUtils.generateSalt(), false, System.currentTimeMillis());
    }
}
