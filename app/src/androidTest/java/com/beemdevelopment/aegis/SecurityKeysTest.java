package com.beemdevelopment.aegis;

import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.action.ViewActions.closeSoftKeyboard;
import static androidx.test.espresso.action.ViewActions.replaceText;
import static androidx.test.espresso.assertion.ViewAssertions.doesNotExist;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.hasDescendant;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withText;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.widget.TextView;

import androidx.test.core.app.ActivityScenario;
import androidx.test.espresso.contrib.RecyclerViewActions;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.SmallTest;

import com.beemdevelopment.aegis.crypto.CryptoUtils;
import com.beemdevelopment.aegis.ui.AuthActivity;
import com.beemdevelopment.aegis.ui.PreferencesActivity;
import com.beemdevelopment.aegis.vault.VaultFileCredentials;
import com.beemdevelopment.aegis.vault.VaultRepositoryException;
import com.beemdevelopment.aegis.vault.slots.Fido2Slot;
import com.beemdevelopment.aegis.vault.slots.SlotException;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;

import dagger.hilt.android.testing.HiltAndroidTest;

@RunWith(AndroidJUnit4.class)
@HiltAndroidTest
@SmallTest
public class SecurityKeysTest extends AegisTest {
    private static final String KEY_NAME = "Test key";
    private static final String KEY_NAME_CHANGED = "Renamed key";

    @Test
    public void testRenameAndRemoveSecurityKey() {
        initEncryptedVault();
        addSecurityKey(KEY_NAME);

        try (ActivityScenario<PreferencesActivity> ignored = ActivityScenario.launch(PreferencesActivity.class)) {
            openSecurityKeys();
            onView(withText(KEY_NAME)).check(matches(isDisplayed()));

            // rename
            onView(withText(KEY_NAME)).perform(click());
            onView(withText(R.string.security_key_action_rename)).perform(click());
            onView(withId(R.id.text_input)).perform(replaceText(KEY_NAME_CHANGED), closeSoftKeyboard());
            onView(withId(android.R.id.button1)).perform(click());
            onView(withText(KEY_NAME_CHANGED)).check(matches(isDisplayed()));

            List<Fido2Slot> slots = getSecurityKeys();
            assertEquals(1, slots.size());
            assertEquals(KEY_NAME_CHANGED, slots.get(0).getName());

            // remove
            onView(withText(KEY_NAME_CHANGED)).perform(click());
            onView(withText(R.string.security_key_action_remove)).perform(click());
            onView(withId(android.R.id.button1)).perform(click());
            onView(withText(KEY_NAME_CHANGED)).check(doesNotExist());
            onView(withText(R.string.pref_security_keys_empty)).check(matches(isDisplayed()));

            assertTrue(getSecurityKeys().isEmpty());
            assertEquals(1, _vaultManager.getVault().getCredentials().getSlots().findRegularPasswordSlots().size());
        }
    }

    @Test
    public void testSecurityKeyButtonOnAuthScreen() {
        initEncryptedVault();
        addSecurityKey(KEY_NAME);
        _vaultManager.lock(false);

        try (ActivityScenario<AuthActivity> ignored = ActivityScenario.launch(AuthActivity.class)) {
            onView(withId(R.id.button_security_key)).check(matches(isDisplayed()));
            onView(withId(R.id.button_security_key)).perform(click());
            onView(withText(R.string.security_key_unlock_title)).check(matches(isDisplayed()));

            // cancel the dialog
            onView(withId(android.R.id.button2)).perform(click());
            onView(withText(R.string.security_key_unlock_title)).check(doesNotExist());
            onView(withId(R.id.button_security_key)).check(matches(isDisplayed()));
        }
    }

    @Test
    public void testUnlockDialogSurvivesRecreation() {
        initEncryptedVault();
        addSecurityKey(KEY_NAME);
        _vaultManager.lock(false);

        try (ActivityScenario<AuthActivity> scenario = ActivityScenario.launch(AuthActivity.class)) {
            onView(withId(R.id.button_security_key)).perform(click());
            onView(withText(R.string.security_key_unlock_title)).check(matches(isDisplayed()));
            CharSequence status = getText(R.id.text_security_key_status);

            // like a rotation of the screen
            scenario.recreate();
            onView(withText(R.string.security_key_unlock_title)).check(matches(isDisplayed()));
            assertEquals(status.toString(), getText(R.id.text_security_key_status).toString());

            onView(withId(android.R.id.button2)).perform(click());
            onView(withText(R.string.security_key_unlock_title)).check(doesNotExist());

            // the dialog can be opened again
            onView(withId(R.id.button_security_key)).perform(click());
            onView(withText(R.string.security_key_unlock_title)).check(matches(isDisplayed()));
            onView(withId(android.R.id.button2)).perform(click());
        }
    }

    @Test
    public void testEnrollDialogSurvivesRecreation() {
        initEncryptedVault();

        try (ActivityScenario<PreferencesActivity> scenario = ActivityScenario.launch(PreferencesActivity.class)) {
            openSecurityKeys();
            onView(withText(R.string.pref_security_key_add_title)).perform(click());
            onView(withId(R.id.text_input)).perform(replaceText(KEY_NAME), closeSoftKeyboard());
            onView(withId(android.R.id.button1)).perform(click());
            onView(withText(R.string.security_key_enroll_title)).check(matches(isDisplayed()));

            scenario.recreate();
            onView(withText(R.string.security_key_enroll_title)).check(matches(isDisplayed()));

            onView(withId(android.R.id.button2)).perform(click());
            onView(withText(R.string.security_key_enroll_title)).check(doesNotExist());
            onView(withText(R.string.pref_security_keys_empty)).check(matches(isDisplayed()));
            assertTrue(getSecurityKeys().isEmpty());
        }
    }

    @Test
    public void testNoSecurityKeyButtonWithoutSecurityKeys() {
        initEncryptedVault();
        _vaultManager.lock(false);

        try (ActivityScenario<AuthActivity> ignored = ActivityScenario.launch(AuthActivity.class)) {
            onView(withId(R.id.button_security_key)).check(matches(org.hamcrest.Matchers.not(isDisplayed())));
        }
    }

    private void openSecurityKeys() {
        onView(withId(androidx.preference.R.id.recycler_view)).perform(RecyclerViewActions.actionOnItem(hasDescendant(withText(R.string.pref_section_security_title)), click()));
        onView(withId(androidx.preference.R.id.recycler_view)).perform(RecyclerViewActions.actionOnItem(hasDescendant(withText(R.string.pref_security_keys_title)), click()));
    }

    private void addSecurityKey(String name) {
        VaultFileCredentials creds = _vaultManager.getVault().getCredentials();
        Fido2Slot slot = new Fido2Slot(name, Fido2Slot.DEFAULT_RP_ID, CryptoUtils.generateRandomBytes(64),
                CryptoUtils.generateSalt(), false, System.currentTimeMillis());
        try {
            slot.wrap(creds.getKey(), CryptoUtils.generateRandomBytes(Fido2Slot.SECRET_SIZE));
        } catch (SlotException e) {
            throw new RuntimeException(e);
        }

        creds.getSlots().add(slot);
        _vaultManager.getVault().setCredentials(creds);
        try {
            _vaultManager.save();
        } catch (VaultRepositoryException e) {
            throw new RuntimeException(e);
        }
    }

    private static CharSequence getText(int viewId) {
        CharSequence[] text = new CharSequence[1];
        onView(withId(viewId)).check((view, e) -> {
            if (e != null) {
                throw e;
            }
            text[0] = ((TextView) view).getText();
        });
        return text[0];
    }

    private List<Fido2Slot> getSecurityKeys() {
        List<Fido2Slot> slots = _vaultManager.getVault().getCredentials().getSlots().findAll(Fido2Slot.class);
        assertNotNull(slots);
        return slots;
    }
}
