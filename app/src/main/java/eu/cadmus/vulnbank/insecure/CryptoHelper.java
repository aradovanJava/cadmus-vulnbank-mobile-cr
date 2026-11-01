package eu.cadmus.vulnbank.insecure;

import android.util.Base64;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CADMUS VulnBank - cryptographic helper.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defects: M10 (Insufficient Cryptography), M1 (Improper Credential
 *                  Usage)
 *
 * ---------------------------------------------------------------------------
 * N1 TEACHING NOTE
 *
 * Every method in this class compiles, runs, produces plausible-looking
 * ciphertext, and passes a functional test suite. That is the point.
 *
 * Cryptographic defects are uniquely resistant to functional testing: the
 * output of AES-256-GCM and the output of DES-ECB are both "unreadable
 * bytes". A QA engineer cannot tell them apart, and neither can a product
 * owner. This is a category where the ONLY effective controls are design
 * review, a vetted library choice, and SAST rules.
 *
 * Use this to introduce the idea of a "secure default" - the reason modern
 * guidance says "use Tink / Jetpack Security, do not assemble primitives"
 * is precisely that this class is what assembling primitives looks like when
 * a competent developer with no cryptographic training does it.
 * ---------------------------------------------------------------------------
 */
public final class CryptoHelper {

    private static final String TAG = "VulnBank.Crypto";

    // =======================================================================
    // PLANTED DEFECT (M1 + M10) - hardcoded key material.
    //
    // A key compiled into the application is not a key, it is an encoding.
    // Every installation shares it, it appears in classes.dex as a literal,
    // and it cannot be rotated. Key material belongs in the Android Keystore,
    // where the private key is generated in and never leaves hardware.
    // =======================================================================
    private static final String DES_KEY  = "cadmus01";                 // 8 bytes, DES
    private static final String AES_KEY  = "0123456789abcdef";         // 16 bytes, AES-128
    private static final byte[] STATIC_IV = "AAAAAAAAAAAAAAAA".getBytes(StandardCharsets.UTF_8);

    private CryptoHelper() { }

    /**
     * PLANTED DEFECT (M10 - Insufficient Cryptography)
     *
     * DES with a 56-bit effective key, in ECB mode, with a hardcoded key.
     * Three independent failures:
     *
     *   1. DES is broken. Exhaustive search is a commodity service.
     *   2. ECB encrypts identical plaintext blocks to identical ciphertext
     *      blocks, so structure survives encryption. This is the mode that
     *      produces the famous recognisable-penguin image.
     *   3. The key is in the binary.
     *
     * Scanner behaviour worth noting in N3: SonarQube flags this on the
     * algorithm string alone. That is a TRUE positive that participants
     * sometimes dismiss because "it's only the PIN".
     */
    public static String weakEncrypt(String plaintext) {
        try {
            DESKeySpec keySpec = new DESKeySpec(DES_KEY.getBytes(StandardCharsets.UTF_8));
            SecretKey key = SecretKeyFactory.getInstance("DES").generateSecret(keySpec);

            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] out = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeToString(out, Base64.NO_WRAP);
        } catch (Exception e) {
            Log.e(TAG, "weakEncrypt failed", e);
            return plaintext;   // PLANTED DEFECT: fails OPEN, returning cleartext
        }
    }

    /**
     * PLANTED DEFECT (M10 - Insufficient Cryptography)
     *
     * AES-CBC with a hardcoded key AND a fixed IV. The fixed IV is the subtle
     * one: it makes the encryption deterministic, so equal plaintexts yield
     * equal ciphertexts and an attacker can detect repeated values without
     * recovering them. It also enables chosen-plaintext attacks against CBC.
     *
     * There is no authentication tag, so the ciphertext is malleable - an
     * attacker can flip bits in the first block by flipping bits in the IV.
     * Use an AEAD mode (GCM) instead: see secure/SecureCryptoHelper.java.
     */
    public static String encryptField(String plaintext) {
        try {
            SecretKeySpec key = new SecretKeySpec(
                    AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(STATIC_IV));

            byte[] out = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeToString(out, Base64.NO_WRAP);
        } catch (Exception e) {
            Log.e(TAG, "encryptField failed", e);
            return plaintext;
        }
    }

    /**
     * PLANTED DEFECT (M10 - Insufficient Cryptography)
     *
     * MD5, unsalted, single iteration, used for password hashing.
     *
     * MD5 is collision-broken, but that is not even the primary problem here.
     * The primary problem is that MD5 is FAST - billions of guesses per second
     * on a consumer GPU - and password hashing requires deliberate slowness.
     * An unsalted fast hash of a human-chosen password is recoverable from a
     * rainbow table without any computation at all.
     *
     * The correct primitive is a memory-hard KDF: Argon2id, scrypt, or
     * PBKDF2-HMAC-SHA256 with a high iteration count and a per-user salt.
     */
    public static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hashed = digest.digest(password.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (byte b : hashed) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "hashPassword failed", e);
            return password;
        }
    }

    /**
     * PLANTED DEFECT (M10 - Insufficient Cryptography)
     *
     * java.util.Random is a linear congruential generator seeded from the
     * clock. It is statistically reasonable and cryptographically useless:
     * observing a small number of outputs lets an attacker recover the
     * internal state and predict every subsequent value.
     *
     * This method generates transaction reference tokens, so predictability
     * here means an attacker can pre-compute the reference for a transfer
     * they have not yet observed.
     *
     * The correct primitive is java.security.SecureRandom.
     */
    public static String generateTransactionToken() {
        Random random = new Random(System.currentTimeMillis());
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            token.append(Integer.toHexString(random.nextInt(16)));
        }
        return token.toString();
    }
}
