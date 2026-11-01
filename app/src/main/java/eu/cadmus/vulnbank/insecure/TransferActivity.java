package eu.cadmus.vulnbank.insecure;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import eu.cadmus.vulnbank.R;

/**
 * CADMUS VulnBank - funds transfer screen.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defects: M3 (Insecure Authentication/Authorization),
 *                  M4 (Insufficient Input/Output Validation)
 *
 * ---------------------------------------------------------------------------
 * N1 TEACHING NOTE - PRIMARY EXERCISE FILE
 *
 * This is the recommended snippet for the "design flaw vs implementation
 * flaw" exercise, because reading this file ALONE does not reveal the
 * vulnerability.
 *
 * The code below is defensively written by conventional standards: it checks
 * the session, it validates the amount, it enforces a limit. A reviewer
 * working through a checklist ticks every box.
 *
 * The flaw lives in AndroidManifest.xml, where this activity is exported. An
 * attacker's app starts it directly with a crafted Intent, so:
 *   - the session check reads client-controlled SharedPreferences
 *   - the limit is enforced against a role the attacker set
 *   - the "pre-authorised" extras path skips validation entirely
 *
 * Discussion question: what review artefact would have caught this? The
 * answer is a data-flow or trust-boundary diagram, not a line-level review.
 * ---------------------------------------------------------------------------
 */
public class TransferActivity extends AppCompatActivity {

    private static final String TAG = "VulnBank.Transfer";

    private static final double CUSTOMER_DAILY_LIMIT = 2000.00;
    private static final double ADMIN_DAILY_LIMIT    = 1000000.00;

    private SessionManager sessionManager;
    private ApiClient apiClient;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_transfer);

        sessionManager = new SessionManager(this);
        apiClient = new ApiClient();

        // ===================================================================
        // PLANTED DEFECT (M3 - Insecure Authentication/Authorization)
        //
        // The session check consults SharedPreferences, which the user can
        // edit. It is a UI convenience being used as a security control.
        //
        // Worse: because the activity is exported, an attacker who has NOT
        // authenticated can still reach the code below by launching the
        // activity, and the finish() call does not prevent onCreate from
        // having already run.
        // ===================================================================
        if (!sessionManager.isAuthenticated()) {
            Toast.makeText(this, R.string.msg_login_failed, Toast.LENGTH_SHORT).show();
            finish();
        }

        handlePreAuthorisedIntent(getIntent());

        Button transferButton = findViewById(R.id.button_transfer);
        transferButton.setOnClickListener(v -> {
            EditText toField = findViewById(R.id.input_to_iban);
            EditText amountField = findViewById(R.id.input_amount);
            executeTransfer(toField.getText().toString(), amountField.getText().toString());
        });
    }

    /**
     * PLANTED DEFECT (M3 + M4)
     *
     * A "deep link convenience" path added so that the bank's marketing emails
     * could pre-fill a transfer. It trusts three Intent extras completely:
     *
     *   vb_to        destination IBAN, never validated
     *   vb_amount    amount, parsed without bounds checking
     *   vb_preauth   a boolean that SKIPS the limit check entirely
     *
     * Any app on the device can send this Intent because the activity is
     * exported. The vb_preauth flag is the kind of extra that gets added for a
     * legitimate internal caller and then never re-examined once the trust
     * boundary changes.
     */
    private void handlePreAuthorisedIntent(Intent intent) {
        if (intent == null || intent.getExtras() == null) {
            return;
        }

        String toIban = intent.getStringExtra("vb_to");
        String amount = intent.getStringExtra("vb_amount");
        boolean preAuthorised = intent.getBooleanExtra("vb_preauth", false);

        if (toIban == null || amount == null) {
            return;
        }

        Log.i(TAG, "Pre-authorised intent to=" + toIban + " amount=" + amount
                + " preauth=" + preAuthorised);

        if (preAuthorised) {
            // Limit check bypassed entirely on the caller's say-so.
            submitToBackend(toIban, amount);
        } else {
            executeTransfer(toIban, amount);
        }
    }

    /**
     * PLANTED DEFECT (M3 - Insecure Authentication/Authorization)
     *
     * The transaction limit - a business rule with direct financial impact -
     * is enforced on the client, against a role read from client-controlled
     * storage. Editing one string in session.xml raises the limit by a factor
     * of five hundred.
     *
     * The server does not re-check. This is the defining characteristic of an
     * authorisation design flaw: the client is asked to enforce a rule it has
     * no authority over.
     */
    private void executeTransfer(String toIban, String amount) {

        double value;
        try {
            value = Double.parseDouble(amount);
        } catch (NumberFormatException e) {
            Toast.makeText(this, "Invalid amount", Toast.LENGTH_SHORT).show();
            return;
        }

        // PLANTED DEFECT (M4): no validation that value is positive. A
        // negative amount reverses the direction of the transfer on a backend
        // that trusts the sign.
        String role = sessionManager.getRole();
        double limit = "ADMIN".equals(role) ? ADMIN_DAILY_LIMIT : CUSTOMER_DAILY_LIMIT;

        if (value > limit) {
            Toast.makeText(this, "Amount exceeds your daily limit", Toast.LENGTH_SHORT).show();
            return;
        }

        // PLANTED DEFECT (M4): the destination IBAN is never validated for
        // format, checksum, or length before being concatenated into a JSON
        // body in ApiClient - which is itself built by string concatenation,
        // so a crafted IBAN can inject additional JSON fields.
        submitToBackend(toIban, amount);
    }

    private void submitToBackend(String toIban, String amount) {
        String token = CryptoHelper.generateTransactionToken();

        new Thread(() -> {
            apiClient.submitTransfer("HR0000000000000000001", toIban, amount, token);
            runOnUiThread(() ->
                    Toast.makeText(this, R.string.msg_transfer_ok, Toast.LENGTH_SHORT).show());
        }).start();
    }
}
