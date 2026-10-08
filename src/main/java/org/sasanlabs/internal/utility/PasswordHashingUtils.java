package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Password hashing helpers following the OWASP Password Storage Cheat Sheet: Argon2id (m=19 MiB,
 * t=2, p=1, 128-bit random salt) as the primary algorithm, bcrypt (cost &ge; 10) as the accepted
 * fallback, and an optional secret pepper (HMAC-SHA-256) taken from the environment.
 */
public final class PasswordHashingUtils {

    private static final String HASH_SEPARATOR = ":";
    private static final int bcryptWorkFactor = 12;

    /** OWASP Argon2id minimum configuration: 19 MiB memory, 2 iterations, parallelism 1. */
    private static final int ARGON2_SALT_BYTES = 16;

    private static final int ARGON2_HASH_BYTES = 32;
    private static final int ARGON2_PARALLELISM = 1;
    private static final int ARGON2_MEMORY_KIB = 19 * 1024;
    private static final int ARGON2_ITERATIONS = 2;

    /** Optional pepper, never stored with the hashes; set it outside the code base. */
    private static final String PEPPER_ENV = "VULNERABLEAPP_PASSWORD_PEPPER";

    private static final Argon2PasswordEncoder ARGON2ID =
            new Argon2PasswordEncoder(
                    ARGON2_SALT_BYTES,
                    ARGON2_HASH_BYTES,
                    ARGON2_PARALLELISM,
                    ARGON2_MEMORY_KIB,
                    ARGON2_ITERATIONS);

    private PasswordHashingUtils() {}

    // Registers Bouncy Castle as provider
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static String getHashAsHex(String rawPassword) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", "BC");
            byte[] digest = messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Security Provider Bouncy Castle not found", e);
        }
    }

    public static boolean isValidSaltedSha256(String rawPassword, String saltedSha256Hash) {
        if (saltedSha256Hash == null || rawPassword == null) {
            return false;
        }

        String[] saltAndHash = saltedSha256Hash.split(HASH_SEPARATOR, 2);
        if (saltAndHash.length != 2) {
            // Backward compatibility for old plaintext test data.
            return saltedSha256Hash.equals(rawPassword);
        }

        String calculatedHash = sha256Hex(saltAndHash[0], rawPassword);
        return MessageDigest.isEqual(
                saltAndHash[1].toLowerCase().getBytes(StandardCharsets.UTF_8),
                calculatedHash.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256Hex(String salt, String rawPassword) {
        return getHashAsHex(salt + rawPassword);
    }

    /**
     * Applies the optional pepper (HMAC-SHA-256 keyed with the secret from {@value #PEPPER_ENV}).
     * Without a configured pepper the password is returned unchanged.
     */
    private static String pepper(String rawPassword) {
        String pepper = System.getenv(PEPPER_ENV);
        if (pepper == null || pepper.isEmpty()) {
            return rawPassword;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getEncoder()
                    .encodeToString(mac.doFinal(rawPassword.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to apply password pepper", e);
        }
    }

    /** Argon2id hash (unique 128-bit salt per call) of the (peppered) password. */
    public static String argon2idHash(String rawPassword) {
        return ARGON2ID.encode(pepper(rawPassword));
    }

    /**
     * Verifies a password against a stored Argon2id or bcrypt hash. Any other stored format
     * (plaintext, encodings, ciphers, fast or unsalted digests) is rejected.
     */
    public static boolean verifyPassword(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null) {
            return false;
        }
        if (storedHash.startsWith("$argon2id$")) {
            return ARGON2ID.matches(pepper(rawPassword), storedHash);
        }
        if (storedHash.startsWith("$2a$")
                || storedHash.startsWith("$2b$")
                || storedHash.startsWith("$2y$")) {
            return isValidBcrypt(rawPassword, storedHash);
        }
        return false;
    }

    // BC not used for bcrypt due to extra complexity for BC implementation
    public static int getbcryptWorkFactor() {
        return bcryptWorkFactor;
    }

    public static String bCryptHash(String rawPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(bcryptWorkFactor);
        return encoder.encode(rawPassword);
    }

    public static boolean isValidBcrypt(String rawPassword, String bcryptHash) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(bcryptWorkFactor);
        return encoder.matches(rawPassword, bcryptHash);
    }
}
