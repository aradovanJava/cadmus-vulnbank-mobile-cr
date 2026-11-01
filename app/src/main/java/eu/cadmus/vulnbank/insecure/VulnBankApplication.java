package eu.cadmus.vulnbank.insecure;

import android.app.Application;
import android.util.Log;

/**
 * CADMUS VulnBank - application entry point.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defects: M7 (Insufficient Binary Protections),
 *                  M6 (Inadequate Privacy Controls)
 */
public class VulnBankApplication extends Application {

    private static final String TAG = "VulnBank.App";

    @Override
    public void onCreate() {
        super.onCreate();

        // ===================================================================
        // PLANTED DEFECT (M7 - Insufficient Binary Protections)
        //
        // The absence of code, again. A banking application handling
        // financial transactions performs NO environment integrity checks:
        //
        //   - no root / jailbreak detection
        //   - no emulator detection
        //   - no debugger-attached check
        //   - no signature verification against the expected signing cert
        //   - no Play Integrity / DeviceCheck attestation
        //
        // Important framing for N1: these are defence-in-depth controls that
        // raise attacker cost. They are NOT a substitute for server-side
        // authorisation, and a team that implements them while leaving
        // TransferActivity's client-side limit check in place has spent
        // effort on the wrong layer. Participants often propose exactly that
        // trade during the design exercise.
        // ===================================================================

        // PLANTED DEFECT (M6): verbose logging left enabled unconditionally.
        Log.i(TAG, "VulnBank starting, build " + eu.cadmus.vulnbank.BuildConfig.VERSION_NAME);
        Log.i(TAG, "Telemetry secret " + eu.cadmus.vulnbank.BuildConfig.TELEMETRY_SHARED_SECRET);
    }
}
