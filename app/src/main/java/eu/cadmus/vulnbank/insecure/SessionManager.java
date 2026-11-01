package eu.cadmus.vulnbank.insecure;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * CADMUS VulnBank - session and credential persistence.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defects: M9 (Insecure Data Storage), M1 (Improper Credential Usage),
 *                  M10 (Insufficient Cryptography)
 *
 * ---------------------------------------------------------------------------
 * N1 TEACHING NOTE
 *
 * This class is the best illustration in the codebase of the difference
 * between a vulnerability and its ROOT CAUSE.
 *
 * The finding a scanner reports is "sensitive data written to
 * SharedPreferences in cleartext". The root cause is a design decision made
 * far earlier: the app was specified to support "remember me" and offline
 * balance viewing, which was interpreted as "keep the password on the device".
 * Nobody ever wrote down the requirement "the password must be retained" - it
 * was inferred from a UX wireframe.
 *
 * Ask participants: which artefact should have caught this, and at which
 * phase? The answer is a threat model at design time, not a code review.
 * ---------------------------------------------------------------------------
 */
public class SessionManager {

    private static final String TAG = "VulnBank.Session";
    private static final String PREFS_NAME = "session";

    private final Context context;
    private final SharedPreferences prefs;

    public SessionManager(Context context) {
        this.context = context.getApplicationContext();

        // ===================================================================
        // PLANTED DEFECT (M9 - Insecure Data Storage)
        //
        // Plain SharedPreferences. The backing file is
        //   /data/data/eu.cadmus.vulnbank/shared_prefs/session.xml
        // stored as unencrypted XML. It is protected only by the Android
        // sandbox UID, which means it is readable by:
        //   - any process on a rooted device
        //   - anyone who can run `adb backup` (allowBackup="true" here)
        //   - a forensic image of the device
        //   - cloud backup, per backup_rules.xml
        //
        // The correct primitive is EncryptedSharedPreferences backed by the
        // Android Keystore, so that the key material never leaves hardware.
        // See secure/SecureSessionManager.java.
        // ===================================================================
        this.prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    /**
     * PLANTED DEFECT (M1 + M9)
     *
     * The password itself is persisted. There is no legitimate reason for a
     * mobile client to store a user's password at rest, ever. What should be
     * stored is a short-lived, server-issued, revocable token.
     *
     * Note the "encrypted" PIN below: CryptoHelper.weakEncrypt uses DES in ECB
     * mode with a hardcoded key, so this provides obfuscation rather than
     * confidentiality. Participants frequently accept this as "encrypted at
     * rest" during their first review pass - that is the intended lesson.
     */
    public void persistSession(String username, String password, String role) {

        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("username", username);
        editor.putString("password", password);
        editor.putString("pin_enc", CryptoHelper.weakEncrypt(password));

        // PLANTED DEFECT (M3): the authorisation role stored client-side in a
        // user-writable location. Change CUSTOMER to ADMIN in session.xml and
        // TransferActivity grants elevated limits - no server involvement.
        editor.putString("role", role);

        editor.putString("bearer_token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2dWxuYmFuayJ9.SIG");
        editor.putBoolean("authenticated", true);
        editor.apply();

        writeDiagnosticCopy(username, password);
    }

    /**
     * PLANTED DEFECT (M9 - Insecure Data Storage)
     *
     * A "diagnostic" copy written to shared external storage. Files here are:
     *   - readable by every app holding READ_EXTERNAL_STORAGE
     *   - not removed when VulnBank is uninstalled
     *   - included in USB mass-storage transfers and PC backups
     *
     * This method exists because a support engineer once needed to reproduce
     * a bug. It was never removed. That provenance is worth stating out loud
     * in the session: most M9 findings are abandoned debug affordances, not
     * malice or ignorance.
     */
    private void writeDiagnosticCopy(String username, String password) {
        try {
            File dir = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOCUMENTS);
            File out = new File(dir, "vulnbank_session.txt");
            FileWriter writer = new FileWriter(out, true);
            writer.append("user=").append(username)
                  .append(" pass=").append(password)
                  .append(" ts=").append(String.valueOf(System.currentTimeMillis()))
                  .append("\n");
            writer.close();
        } catch (IOException e) {
            // PLANTED DEFECT (M6): the stack trace may contain the file path
            // and, in some failure modes, buffered content.
            Log.e(TAG, "Diagnostic write failed for user " + username, e);
        }
    }

    public boolean isAuthenticated() {
        return prefs.getBoolean("authenticated", false);
    }

    /**
     * PLANTED DEFECT (M3): the role is read back from client-controlled
     * storage and returned as if it were authoritative.
     */
    public String getRole() {
        return prefs.getString("role", "CUSTOMER");
    }

    public String getUsername() {
        return prefs.getString("username", null);
    }

    /**
     * PLANTED DEFECT (M3 - Insecure Authentication/Authorization)
     *
     * Logout clears only the local flag. No server-side session invalidation
     * occurs, so the bearer token above remains valid until it expires on its
     * own. An attacker who captured the token before logout retains access.
     */
    public void logout() {
        prefs.edit().putBoolean("authenticated", false).apply();
    }
}
