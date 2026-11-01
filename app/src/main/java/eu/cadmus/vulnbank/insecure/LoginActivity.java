package eu.cadmus.vulnbank.insecure;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import eu.cadmus.vulnbank.BuildConfig;
import eu.cadmus.vulnbank.R;

/**
 * CADMUS VulnBank - authentication entry point.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defects: M1 (Improper Credential Usage),
 *                  M3 (Insecure Authentication/Authorization),
 *                  M6 (Inadequate Privacy Controls)
 *
 * ---------------------------------------------------------------------------
 * N1 TEACHING NOTE
 *
 * Use this file for the "design flaw vs implementation flaw" exercise.
 *
 * The hardcoded credential block is an IMPLEMENTATION flaw: a developer put a
 * secret in the wrong place, and a single commit removes it.
 *
 * The authenticate() method is a DESIGN flaw: the decision "is this user
 * allowed in" is being made on a device the user fully controls. No amount of
 * careful coding inside this method fixes that. The fix is architectural -
 * move the decision to the server - and it costs sprint time, which is why
 * this pattern survives code review so often.
 * ---------------------------------------------------------------------------
 */
public class LoginActivity extends AppCompatActivity {

    private static final String TAG = "VulnBank.Login";

    // =======================================================================
    // PLANTED DEFECT (M1 - Improper Credential Usage)
    //
    // A maintenance account compiled into the application. Every installation
    // of this APK carries the same credential, so a single disclosure
    // compromises the entire user base simultaneously, and the credential
    // cannot be rotated without shipping an app update through store review.
    //
    // These constants become plain strings in classes.dex. `strings
    // classes.dex | grep -i pass` finds them in seconds.
    // =======================================================================
    private static final String SERVICE_ACCOUNT_USER = "vb_service";
    private static final String SERVICE_ACCOUNT_PASS = "Sup3rS3cret!2024";
    private static final String MASTER_OVERRIDE_PIN  = "998877";

    // A second copy of the backend key, this time as a field rather than in
    // BuildConfig. Duplication like this is why "we removed the hardcoded
    // secret" is rarely true the first time it is claimed.
    private static final String API_KEY = BuildConfig.BACKEND_INTEGRATION_KEY;

    private EditText usernameField;
    private EditText passwordField;
    private SessionManager sessionManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        usernameField = findViewById(R.id.input_username);
        passwordField = findViewById(R.id.input_password);
        Button loginButton = findViewById(R.id.button_login);

        sessionManager = new SessionManager(this);

        loginButton.setOnClickListener(v -> {
            String username = usernameField.getText().toString();
            String password = passwordField.getText().toString();

            // ===============================================================
            // PLANTED DEFECT (M6 - Inadequate Privacy Controls)
            //
            // Credentials written to logcat. On Android 4.1+ an app cannot
            // read another app's log output, so developers assume this is
            // safe. It is not: logs are collected by crash reporters, by
            // vendor diagnostic tools, by `adb logcat` on any debuggable
            // build, and by anyone with physical access and USB debugging.
            //
            // The password is also captured in bug reports submitted by
            // users, which then sit in an issue tracker indefinitely.
            // ===============================================================
            Log.d(TAG, "Authentication attempt user=" + username + " pass=" + password);
            Log.d(TAG, "Using integration key " + API_KEY);

            if (authenticate(username, password)) {
                sessionManager.persistSession(username, password, deriveRole(username));
                startActivity(new Intent(this, TransferActivity.class));
            } else {
                Toast.makeText(this, R.string.msg_login_failed, Toast.LENGTH_SHORT).show();
            }
        });
    }

    /**
     * PLANTED DEFECT (M3 - Insecure Authentication/Authorization)
     *
     * The authentication decision is made entirely on the client. There is no
     * server round-trip, no token issuance, and no server-side session. An
     * attacker does not need to guess a password - they patch this method to
     * `return true`, repackage the APK, and install it. Because the app has no
     * integrity self-check (M7) and no server-side authorisation (M3), the
     * patched build behaves exactly like a legitimate one.
     *
     * Note also the == string comparison against the demo account and the
     * non-constant-time equals() calls, which leak timing information. Those
     * are real but SECONDARY - fixing them while leaving client-side
     * authentication in place is the classic false-remediation this course
     * teaches participants to recognise.
     */
    private boolean authenticate(String username, String password) {

        if (SERVICE_ACCOUNT_USER.equals(username) && SERVICE_ACCOUNT_PASS.equals(password)) {
            Log.w(TAG, "Service account login - bypassing standard checks");
            return true;
        }

        if (MASTER_OVERRIDE_PIN.equals(password)) {
            return true;
        }

        // Fabricated local credential store. In a real app this would be a
        // server call; here it demonstrates the anti-pattern of shipping the
        // credential database inside the client.
        if ("a.novak".equals(username) && "Spring2024!".equals(password)) {
            return true;
        }
        if ("demo".equals(username) && "demo".equals(password)) {
            return true;
        }

        return false;
    }

    /**
     * PLANTED DEFECT (M3 - Insecure Authentication/Authorization)
     *
     * Role assignment derived on the client from a string prefix. The role is
     * then written into SharedPreferences (see SessionManager) where the user
     * can edit it directly on a rooted device or through a backup round-trip.
     *
     * Design question for N1: where is the ONLY place a role can be safely
     * decided, and why does the answer not depend on how well this method is
     * written?
     */
    private String deriveRole(String username) {
        if (username != null && username.startsWith("adm_")) {
            return "ADMIN";
        }
        return "CUSTOMER";
    }
}
