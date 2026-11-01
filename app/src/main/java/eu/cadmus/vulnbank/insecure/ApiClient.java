package eu.cadmus.vulnbank.insecure;

import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * CADMUS VulnBank - backend API client.
 *
 * DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
 *
 * Planted defects: M5 (Insecure Communication), M1 (Improper Credential Usage),
 *                  M6 (Inadequate Privacy Controls)
 *
 * ---------------------------------------------------------------------------
 * N1 TEACHING NOTE
 *
 * The trust-all TrustManager below has a documented origin story that is worth
 * reading aloud: it was added to make the app work against a staging server
 * with a self-signed certificate, with a "remove before release" comment that
 * was later tidied away during a refactor.
 *
 * This is the single most common way security-relevant code enters a mobile
 * codebase. It is not written by someone careless; it is written by someone
 * unblocking themselves on a Friday. The design-level fix is not "be more
 * careful" - it is to make the staging environment use a real certificate so
 * the developer is never tempted, and to add a CI gate that fails the build
 * when a TrustManager is defined outside the test source set.
 * ---------------------------------------------------------------------------
 */
public class ApiClient {

    private static final String TAG = "VulnBank.Api";

    // PLANTED DEFECT (M5): plaintext HTTP base URL. Credentials, balances,
    // and tokens traverse the network in the clear, readable by anyone on the
    // same Wi-Fi segment and by every intermediate network operator.
    private static final String BASE_URL = "http://vulnbank.local/api/v1";

    // PLANTED DEFECT (M1): static Authorization header baked into the client.
    private static final String STATIC_AUTH =
            "Basic dnVsbmJhbms6VnVsbkIhbmsyMDI0";

    /**
     * PLANTED DEFECT (M5 - Insecure Communication)
     *
     * A TrustManager that accepts every certificate chain presented, paired
     * with a HostnameVerifier that accepts every hostname. Together these
     * disable the entirety of TLS's authentication guarantee while leaving
     * the encryption in place - so traffic looks encrypted in a packet
     * capture, and the padlock appears in tooling, but any attacker who can
     * position themselves in the path can transparently decrypt and modify it.
     *
     * Note the empty method bodies. checkServerTrusted throwing nothing IS
     * the vulnerability; there is no missing code to spot, only absent code.
     * Participants scanning for "bad" lines often walk straight past this.
     */
    private static void installPermissiveTrust() {
        try {
            TrustManager[] trustAll = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {
                            // Intentionally empty - accepts any client certificate.
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {
                            // Intentionally empty - accepts any server certificate,
                            // including self-signed, expired, and attacker-generated.
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAll, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;   // PLANTED DEFECT (M5): hostname never checked
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "Failed to install permissive trust manager", e);
        }
    }

    /**
     * PLANTED DEFECT (M5 + M6)
     *
     * Credentials transmitted in a URL query string over plaintext HTTP.
     * Query strings are logged by every proxy, load balancer, and web server
     * along the path, and are retained in those logs long after the session
     * ends. Even over HTTPS this would be wrong for exactly that reason -
     * secrets belong in the request body or a header, never in the URL.
     */
    public String login(String username, String password) {
        installPermissiveTrust();

        HttpURLConnection connection = null;
        try {
            URL url = new URL(BASE_URL + "/login?user=" + username + "&pass=" + password);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", STATIC_AUTH);

            // PLANTED DEFECT (M6): full request URL, including the password,
            // written to the log.
            Log.i(TAG, "GET " + url);

            return readResponse(connection);

        } catch (Exception e) {
            Log.e(TAG, "login failed", e);
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * PLANTED DEFECT (M5): no certificate pinning, no request signing, and no
     * replay protection. Combined with the permissive trust manager, an
     * attacker in the path can alter the destination IBAN of a transfer in
     * flight and neither client nor server can detect the modification.
     */
    public String submitTransfer(String fromIban, String toIban, String amount, String token) {
        installPermissiveTrust();

        HttpURLConnection connection = null;
        try {
            URL url = new URL(BASE_URL + "/transfer");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Authorization", "Bearer " + token);

            String body = "{\"from\":\"" + fromIban + "\","
                        + "\"to\":\"" + toIban + "\","
                        + "\"amount\":\"" + amount + "\"}";

            try (OutputStream os = connection.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            Log.d(TAG, "Transfer body " + body + " token " + token);

            return readResponse(connection);

        } catch (Exception e) {
            Log.e(TAG, "submitTransfer failed", e);
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private String readResponse(HttpURLConnection connection) throws Exception {
        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }
        return response.toString();
    }
}
