package eu.cadmus.vulnbank.insecure;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * CADMUS VulnBank - session reset broadcast receiver.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defect: M8 (Security Misconfiguration)
 *
 * The receiver is exported with no permission attribute and no signature
 * check on the sender, so any app on the device can broadcast
 * eu.cadmus.vulnbank.RESET_SESSION and manipulate this app's state.
 *
 * Note the second defect: the receiver accepts a role from the broadcast
 * extras, which is a privilege-escalation primitive reachable from any
 * unprivileged app.
 */
public class SessionResetReceiver extends BroadcastReceiver {

    private static final String TAG = "VulnBank.Reset";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(TAG, "Session reset requested by external broadcast");

        SessionManager session = new SessionManager(context);

        String requestedRole = intent.getStringExtra("role");
        if (requestedRole != null) {
            // PLANTED DEFECT (M3 + M8): role supplied by an untrusted sender
            // is written straight into the session store.
            session.persistSession(
                    session.getUsername() == null ? "demo" : session.getUsername(),
                    "",
                    requestedRole);
        } else {
            session.logout();
        }
    }
}
