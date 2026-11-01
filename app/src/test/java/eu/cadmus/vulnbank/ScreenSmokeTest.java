package eu.cadmus.vulnbank;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.robolectric.Shadows.shadowOf;

import android.content.Intent;
import android.view.View;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;

import eu.cadmus.vulnbank.insecure.LoginActivity;
import eu.cadmus.vulnbank.insecure.SupportWebViewActivity;
import eu.cadmus.vulnbank.insecure.TransferActivity;

/**
 * CADMUS-CR-16 - functional smoke tests (JVM, Robolectric).
 *
 * They exist for the CR3 D2 gate "the functional test suite passes": updating,
 * replacing or removing a library must not stop any screen from starting.
 * AppCompat, Material Components and the layouts are exactly what a careless
 * dependency change breaks at run time while the build still succeeds (for
 * example a theme that no longer derives from Theme.AppCompat).
 *
 * The tests check behaviour that stays true after the CR2 remediation, so
 * keep them passing on your branches rather than deleting them. Run:
 *
 *     ./gradlew test
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class ScreenSmokeTest {

    @Test
    public void loginScreenStartsWithItsControls() {
        LoginActivity activity = Robolectric.buildActivity(LoginActivity.class).setup().get();

        EditText user = activity.findViewById(R.id.input_username);
        EditText pass = activity.findViewById(R.id.input_password);
        Button login = activity.findViewById(R.id.button_login);

        assertNotNull("username field", user);
        assertNotNull("password field", pass);
        assertNotNull("sign-in button", login);
        assertEquals(View.VISIBLE, login.getVisibility());
        assertTrue("sign-in button enabled", login.isEnabled());
    }

    @Test
    public void wrongPasswordDoesNotOpenTheTransferScreen() {
        LoginActivity activity = Robolectric.buildActivity(LoginActivity.class).setup().get();

        ((EditText) activity.findViewById(R.id.input_username)).setText("demo");
        ((EditText) activity.findViewById(R.id.input_password)).setText("definitely-wrong");
        activity.findViewById(R.id.button_login).performClick();

        Intent next = shadowOf(activity).getNextStartedActivity();
        assertNull("a wrong password must not reach the transfer screen", next);
    }

    @Test
    public void transferScreenInflatesItsForm() {
        ActivityController<TransferActivity> controller =
                Robolectric.buildActivity(TransferActivity.class).setup();
        TransferActivity activity = controller.get();

        assertNotNull("destination IBAN field", activity.findViewById(R.id.input_to_iban));
        assertNotNull("amount field", activity.findViewById(R.id.input_amount));
        assertNotNull("transfer button", activity.findViewById(R.id.button_transfer));
    }

    @Test
    public void supportScreenShowsAWebView() {
        SupportWebViewActivity activity =
                Robolectric.buildActivity(SupportWebViewActivity.class).setup().get();

        View content = activity.findViewById(android.R.id.content);
        assertNotNull(content);
        assertTrue("support screen hosts a WebView", containsWebView(content));
    }

    private static boolean containsWebView(View view) {
        if (view instanceof WebView) {
            return true;
        }
        if (view instanceof android.view.ViewGroup) {
            android.view.ViewGroup group = (android.view.ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) {
                if (containsWebView(group.getChildAt(i))) {
                    return true;
                }
            }
        }
        return false;
    }
}
