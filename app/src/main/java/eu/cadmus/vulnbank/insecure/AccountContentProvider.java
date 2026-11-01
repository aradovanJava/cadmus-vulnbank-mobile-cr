package eu.cadmus.vulnbank.insecure;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * CADMUS VulnBank - account content provider.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defects: M8 (Security Misconfiguration),
 *                  M4 (Insufficient Input/Output Validation)
 *
 * ---------------------------------------------------------------------------
 * N1 TEACHING NOTE
 *
 * This class is what turns AccountDatabase's SQL injection from a theoretical
 * finding into an exploitable one. It is exported (manifest), requires no
 * permission, and passes its selection argument through to a concatenated
 * query.
 *
 * Present the two files TOGETHER during the mapping exercise. Neither is
 * obviously critical alone; the combination exposes every account record,
 * including national identifiers, to any installed application.
 *
 * This is the clearest demonstration in the codebase that vulnerability
 * severity is a property of the SYSTEM, not of a file.
 * ---------------------------------------------------------------------------
 */
public class AccountContentProvider extends ContentProvider {

    private static final String TAG = "VulnBank.Provider";

    private AccountDatabase database;

    @Override
    public boolean onCreate() {
        database = new AccountDatabase(getContext());
        return true;
    }

    /**
     * PLANTED DEFECT (M4 + M8): the caller's selection string is forwarded
     * into a concatenated SQL query with no validation and no caller identity
     * check.
     */
    @Nullable
    @Override
    public Cursor query(@NonNull Uri uri, @Nullable String[] projection,
                        @Nullable String selection, @Nullable String[] selectionArgs,
                        @Nullable String sortOrder) {

        Log.d(TAG, "External query uri=" + uri + " selection=" + selection);

        String owner = selection == null ? "" : selection;
        return database.findAccountsByOwner(owner);
    }

    @Nullable
    @Override
    public String getType(@NonNull Uri uri) {
        return "vnd.android.cursor.dir/vnd.eu.cadmus.vulnbank.accounts";
    }

    @Nullable
    @Override
    public Uri insert(@NonNull Uri uri, @Nullable ContentValues values) {
        return null;
    }

    @Override
    public int delete(@NonNull Uri uri, @Nullable String selection,
                      @Nullable String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(@NonNull Uri uri, @Nullable ContentValues values,
                      @Nullable String selection, @Nullable String[] selectionArgs) {
        return 0;
    }
}
