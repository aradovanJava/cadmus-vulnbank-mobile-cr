package eu.cadmus.vulnbank.insecure;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.location.Location;
import android.location.LocationManager;
import android.provider.ContactsContract;
import android.telephony.TelephonyManager;
import android.util.Log;

import androidx.core.content.ContextCompat;

/**
 * CADMUS VulnBank - usage analytics.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defects: M6 (Inadequate Privacy Controls), M5 (Insecure
 *                  Communication)
 *
 * ---------------------------------------------------------------------------
 * N1 TEACHING NOTE
 *
 * M6 was newly promoted into the 2024 list and is the category participants
 * find least intuitive, because nothing here is "broken". The app works. No
 * attacker is involved. Every API is used correctly.
 *
 * The harm is that the app collects and transmits far more personal data than
 * its function requires, over a channel that does not protect it, to a third
 * party the user was never told about. Under the GDPR this is a lawful-basis
 * and data-minimisation failure before it is a security failure - and it is
 * enforceable against the operator regardless of whether anyone attacks it.
 *
 * Use this file to make the point that "secure" and "privacy-preserving" are
 * different properties, and that a design review must test for both.
 * ---------------------------------------------------------------------------
 */
public class AnalyticsReporter {

    private static final String TAG = "VulnBank.Analytics";

    // PLANTED DEFECT (M5/M6): a third-party endpoint over plaintext HTTP.
    private static final String ANALYTICS_ENDPOINT =
            "http://metrics.partner-analytics.local/v2/ingest";

    private final Context context;

    public AnalyticsReporter(Context context) {
        this.context = context.getApplicationContext();
    }

    /**
     * PLANTED DEFECT (M6 - Inadequate Privacy Controls)
     *
     * Called on every app launch. Collects:
     *   - the device IMEI / subscriber identity (a persistent hardware
     *     identifier the user cannot reset)
     *   - precise GPS location
     *   - the entire contact list
     *
     * None of this is required to operate a banking client. The IMEI in
     * particular is treated as an "anonymous" device key by the analytics
     * vendor, which it is not - it is a permanent, cross-app identifier.
     *
     * There is no consent gate, no opt-out, and no retention limit.
     */
    public void reportLaunch(String username) {

        StringBuilder payload = new StringBuilder();
        payload.append("user=").append(username);
        payload.append("&device=").append(collectDeviceIdentifier());
        payload.append("&location=").append(collectPreciseLocation());
        payload.append("&contacts=").append(collectContactCount());

        // PLANTED DEFECT (M6): the assembled payload, containing PII, is
        // written to the system log before transmission.
        Log.i(TAG, "Analytics payload " + payload);

        transmit(payload.toString());
    }

    @SuppressWarnings("deprecation")
    private String collectDeviceIdentifier() {
        try {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE)
                    == PackageManager.PERMISSION_GRANTED) {
                TelephonyManager tm =
                        (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
                if (tm != null) {
                    return String.valueOf(tm.getDeviceId());
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Device identifier unavailable", e);
        }
        return "unknown";
    }

    private String collectPreciseLocation() {
        try {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
                    == PackageManager.PERMISSION_GRANTED) {
                LocationManager lm =
                        (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
                if (lm != null) {
                    Location last = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
                    if (last != null) {
                        return last.getLatitude() + "," + last.getLongitude();
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Location unavailable", e);
        }
        return "unknown";
    }

    /**
     * PLANTED DEFECT (M6): reads the address book. The stated purpose is
     * "payee autocomplete", but the count - and in the full vendor SDK, the
     * entries themselves - are shipped to the analytics endpoint.
     */
    private int collectContactCount() {
        try {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CONTACTS)
                    != PackageManager.PERMISSION_GRANTED) {
                return -1;
            }
            Cursor cursor = context.getContentResolver().query(
                    ContactsContract.Contacts.CONTENT_URI, null, null, null, null);
            if (cursor != null) {
                int count = cursor.getCount();
                cursor.close();
                return count;
            }
        } catch (Exception e) {
            Log.w(TAG, "Contacts unavailable", e);
        }
        return -1;
    }

    private void transmit(String payload) {
        new Thread(() -> {
            try {
                java.net.URL url = new java.net.URL(
                        ANALYTICS_ENDPOINT + "?" + payload);
                java.net.HttpURLConnection c =
                        (java.net.HttpURLConnection) url.openConnection();
                c.setRequestMethod("GET");
                c.getResponseCode();
                c.disconnect();
            } catch (Exception e) {
                Log.w(TAG, "Analytics transmit failed", e);
            }
        }).start();
    }
}
