package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123";
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword";
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("Argon2id: Should use the OWASP parameters and a unique salt per hash")
    void argon2id_UniqueSaltAndValidation() {
        String password = "mySecretPassword";
        String hash1 = PasswordHashingUtils.argon2idHash(password);
        String hash2 = PasswordHashingUtils.argon2idHash(password);

        assertTrue(hash1.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"), hash1);
        assertNotEquals(hash1, hash2);
        assertTrue(PasswordHashingUtils.verifyPassword(password, hash1));
        assertTrue(PasswordHashingUtils.verifyPassword(password, hash2));
        assertFalse(PasswordHashingUtils.verifyPassword("wrongPass", hash1));
    }

    @Test
    @DisplayName("verifyPassword: Should accept bcrypt and reject non-adaptive stored formats")
    void verifyPassword_RejectsWeakFormats() {
        String password = "mySecretPassword";
        assertTrue(
                PasswordHashingUtils.verifyPassword(
                        password, PasswordHashingUtils.bCryptHash(password)));
        assertFalse(PasswordHashingUtils.verifyPassword(password, password));
        assertFalse(PasswordHashingUtils.verifyPassword(password, "bXlTZWNyZXRQYXNzd29yZA=="));
        assertFalse(
                PasswordHashingUtils.verifyPassword(
                        password, PasswordHashingUtils.sha256Hex("", password)));
        assertFalse(PasswordHashingUtils.verifyPassword(null, "$argon2id$"));
        assertFalse(PasswordHashingUtils.verifyPassword(password, null));
    }

    @Test
    @DisplayName("Hex Utility: Should convert byte arrays to lowercase hex strings")
    void bytesToHex_Conversion() {
        byte[] input = {0, 15, 16, 127, -1}; // 00, 0f, 10, 7f, ff
        String expected = "000f107fff";
        assertEquals(expected, EncodingUtils.bytesToHex(input));
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
    }
}
