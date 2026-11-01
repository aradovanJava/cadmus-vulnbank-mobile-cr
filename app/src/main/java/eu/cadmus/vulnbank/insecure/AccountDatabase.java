package eu.cadmus.vulnbank.insecure;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

/**
 * CADMUS VulnBank - local account cache.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defects: M4 (Insufficient Input/Output Validation),
 *                  M9 (Insecure Data Storage)
 *
 * ---------------------------------------------------------------------------
 * N1 TEACHING NOTE
 *
 * Developers frequently object that SQL injection "doesn't matter" in a local
 * SQLite database, because the user already owns the data. That objection is
 * wrong for two reasons worth drawing out in discussion:
 *
 *   1. The database is reachable from OUTSIDE the app. AccountContentProvider
 *      is exported (see AndroidManifest.xml), so a malicious app on the same
 *      device supplies the injected string. The attacker is not the user.
 *
 *   2. Injection is a symptom of untrusted data being concatenated into an
 *      interpreter. The same habit, in the same codebase, will be applied to
 *      a server-side query, a shell command, or a WebView URL. The defect is
 *      the pattern, not the sink.
 *
 * This is a good place to reinforce that M4 in the 2024 list covers BOTH
 * input and output validation - the second half is what SupportWebViewActivity
 * demonstrates.
 * ---------------------------------------------------------------------------
 */
public class AccountDatabase extends SQLiteOpenHelper {

    private static final String TAG = "VulnBank.Db";
    private static final String DB_NAME = "accounts.db";
    private static final int DB_VERSION = 2;

    public AccountDatabase(Context context) {
        // PLANTED DEFECT (M9): an unencrypted SQLite database holding account
        // numbers, balances, and payee records. The file at
        //   /data/data/eu.cadmus.vulnbank/databases/accounts.db
        // is plain SQLite - `strings accounts.db` reveals the contents, and it
        // is included in the permissive backup rule set.
        //
        // The correct approach is SQLCipher, or Room configured with a
        // Keystore-held passphrase, or simply not caching the data locally.
        super(context, DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE accounts ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                + "owner TEXT, "
                + "iban TEXT, "
                + "balance REAL, "
                + "national_id TEXT, "
                + "date_of_birth TEXT)");

        db.execSQL("CREATE TABLE payees ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                + "owner TEXT, "
                + "label TEXT, "
                + "iban TEXT)");

        seedFabricatedData(db);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS accounts");
        db.execSQL("DROP TABLE IF EXISTS payees");
        onCreate(db);
    }

    /**
     * PLANTED DEFECT (M4 - Insufficient Input/Output Validation)
     *
     * Classic string-concatenation SQL injection. `owner` reaches this method
     * from AccountContentProvider, which is exported, so the value is fully
     * attacker-controlled by any app on the device.
     *
     * A payload of  ' OR '1'='1  returns every account in the table,
     * including the national_id and date_of_birth columns.
     *
     * The fix is one line - rawQuery with a String[] of bound arguments - and
     * that cheapness is itself a teaching point: implementation flaws are
     * usually cheap to fix, which is why leaving them unfixed is so hard to
     * justify to an auditor.
     */
    public Cursor findAccountsByOwner(String owner) {
        SQLiteDatabase db = getReadableDatabase();

        String sql = "SELECT id, owner, iban, balance, national_id, date_of_birth "
                   + "FROM accounts WHERE owner = '" + owner + "'";

        Log.d(TAG, "Executing " + sql);   // PLANTED DEFECT (M6): query with PII logged

        return db.rawQuery(sql, null);
    }

    /**
     * PLANTED DEFECT (M4)
     *
     * A second injection point, this time in an ORDER BY clause. Bound
     * parameters cannot be used for identifiers, so the naive "just use
     * prepared statements" advice does not apply here - the correct fix is an
     * allow-list of permitted column names.
     *
     * This is deliberately included because it breaks the pattern participants
     * learn in the first example, and forces them to reason about WHY
     * parameterisation works rather than applying it mechanically.
     */
    public Cursor listPayees(String owner, String sortColumn) {
        SQLiteDatabase db = getReadableDatabase();

        String sql = "SELECT id, label, iban FROM payees "
                   + "WHERE owner = ? ORDER BY " + sortColumn;

        return db.rawQuery(sql, new String[]{ owner });
    }

    /**
     * PLANTED DEFECT (M4): execSQL with concatenated user input on a write
     * path. Injection here permits arbitrary statement execution, including
     * UPDATE of the balance column.
     */
    public void addPayee(String owner, String label, String iban) {
        SQLiteDatabase db = getWritableDatabase();
        db.execSQL("INSERT INTO payees (owner, label, iban) VALUES ('"
                + owner + "', '" + label + "', '" + iban + "')");
    }

    /**
     * All data below is FABRICATED for training purposes. The IBANs use the
     * documentation-reserved pattern and address no real institution.
     */
    private void seedFabricatedData(SQLiteDatabase db) {
        db.execSQL("INSERT INTO accounts (owner, iban, balance, national_id, date_of_birth) "
                + "VALUES ('a.novak', 'HR0000000000000000001', 4210.55, '00000000001', '1985-04-12')");
        db.execSQL("INSERT INTO accounts (owner, iban, balance, national_id, date_of_birth) "
                + "VALUES ('demo', 'HR0000000000000000002', 150.00, '00000000002', '1990-11-03')");
        db.execSQL("INSERT INTO accounts (owner, iban, balance, national_id, date_of_birth) "
                + "VALUES ('adm_root', 'HR0000000000000000003', 999999.99, '00000000003', '1979-01-25')");

        db.execSQL("INSERT INTO payees (owner, label, iban) "
                + "VALUES ('a.novak', 'Landlord', 'HR0000000000000000010')");
    }
}
