package com.beemdevelopment.aegis.ui.fragments.preferences;

import android.os.Bundle;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;

import com.beemdevelopment.aegis.R;
import com.beemdevelopment.aegis.ui.dialogs.Dialogs;
import com.beemdevelopment.aegis.ui.dialogs.SecurityKeyDialog;
import com.beemdevelopment.aegis.vault.VaultFileCredentials;
import com.beemdevelopment.aegis.vault.VaultRepositoryException;
import com.beemdevelopment.aegis.vault.slots.Fido2Slot;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.text.DateFormat;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Lists the FIDO2 security keys that can unlock the vault and allows the user to register,
 * rename and remove them.
 */
public class SecurityKeysPreferencesFragment extends PreferencesFragment {
    private PreferenceCategory _keysCategory;

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        addPreferencesFromResource(R.xml.preferences_security_keys);

        _keysCategory = requirePreference("pref_security_keys_list");
        Preference addPreference = requirePreference("pref_security_key_add");
        addPreference.setOnPreferenceClickListener(preference -> {
            startAddSecurityKey(null);
            return true;
        });

        // show the registration dialog again if it was open before the activity was recreated
        SecurityKeyDialog.restoreEnroll(requireActivity(), this::onSecurityKeyEnrolled);
    }

    @Override
    public void onResume() {
        super.onResume();

        // security keys can only be used if the vault is encrypted
        if (!_vaultManager.isVaultLoaded() || !_vaultManager.getVault().isEncryptionEnabled()) {
            getParentFragmentManager().popBackStack();
            return;
        }

        refreshSecurityKeys();
    }

    private void refreshSecurityKeys() {
        _keysCategory.removeAll();

        List<Fido2Slot> slots = getSecurityKeys();
        if (slots.isEmpty()) {
            Preference pref = new Preference(requireContext());
            pref.setTitle(R.string.pref_security_keys_empty);
            pref.setSelectable(false);
            pref.setPersistent(false);
            pref.setIconSpaceReserved(false);
            _keysCategory.addPreference(pref);
            return;
        }

        for (Fido2Slot slot : slots) {
            UUID uuid = slot.getUUID();
            Preference pref = new Preference(requireContext());
            pref.setKey(uuid.toString());
            pref.setTitle(slot.getName());
            pref.setSummary(getSummary(slot));
            pref.setIcon(R.drawable.ic_outline_key_24);
            pref.setPersistent(false);
            pref.setOnPreferenceClickListener(preference -> {
                showSecurityKeyActions(uuid);
                return true;
            });
            _keysCategory.addPreference(pref);
        }
    }

    private String getSummary(Fido2Slot slot) {
        String uv = getString(slot.isUv() ? R.string.security_key_pin_required : R.string.security_key_touch_only);
        if (slot.getCreatedAt() <= 0) {
            return uv;
        }

        String date = DateFormat.getDateInstance(DateFormat.MEDIUM).format(new Date(slot.getCreatedAt()));
        return getString(R.string.security_key_added_on, date) + "\n" + uv;
    }

    private void startAddSecurityKey(@Nullable String name) {
        Dialogs.showTextInputDialog(requireContext(), R.string.security_key_name_title, R.string.security_key_name_hint, text -> {
            String newName = new String(text).trim();
            if (newName.isEmpty()) {
                return;
            }
            if (isNameTaken(newName, null)) {
                Toast.makeText(requireContext(), R.string.security_key_name_exists, Toast.LENGTH_SHORT).show();
                startAddSecurityKey(newName);
                return;
            }

            enrollSecurityKey(newName);
        }, name);
    }

    private void enrollSecurityKey(String name) {
        VaultFileCredentials creds = _vaultManager.getVault().getCredentials();
        List<Fido2Slot> existing = creds.getSlots().findAll(Fido2Slot.class);

        SecurityKeyDialog.showEnroll(requireActivity(), name, creds.getKey(), existing, this::onSecurityKeyEnrolled);
    }

    private void onSecurityKeyEnrolled(Fido2Slot slot) {
        VaultFileCredentials creds = _vaultManager.getVault().getCredentials();
        creds.getSlots().add(slot);
        _vaultManager.getVault().setCredentials(creds);
        if (!isAdded()) {
            saveVault();
            return;
        }

        if (saveAndBackupVault()) {
            Toast.makeText(requireContext(), R.string.security_key_added, Toast.LENGTH_SHORT).show();
        }
        refreshSecurityKeys();
    }

    private void showSecurityKeyActions(UUID uuid) {
        Fido2Slot slot = findSecurityKey(uuid);
        if (slot == null) {
            return;
        }

        String[] items = new String[]{
                getString(R.string.security_key_action_rename),
                getString(R.string.security_key_action_remove)
        };
        Dialogs.showSecureDialog(new MaterialAlertDialogBuilder(requireContext())
                .setTitle(slot.getName())
                .setItems(items, (dialog, which) -> {
                    if (which == 0) {
                        renameSecurityKey(uuid);
                    } else {
                        removeSecurityKey(uuid);
                    }
                })
                .create());
    }

    private void renameSecurityKey(UUID uuid) {
        Fido2Slot slot = findSecurityKey(uuid);
        if (slot == null) {
            return;
        }

        Dialogs.showTextInputDialog(requireContext(), R.string.security_key_rename_title, R.string.security_key_name_hint, text -> {
            String newName = new String(text).trim();
            if (newName.isEmpty() || newName.equals(slot.getName())) {
                return;
            }
            if (isNameTaken(newName, uuid)) {
                Toast.makeText(requireContext(), R.string.security_key_name_exists, Toast.LENGTH_SHORT).show();
                return;
            }

            VaultFileCredentials creds = _vaultManager.getVault().getCredentials();
            ((Fido2Slot) creds.getSlots().getByUUID(uuid)).setName(newName);
            _vaultManager.getVault().setCredentials(creds);
            saveAndBackupVault();
            refreshSecurityKeys();
        }, slot.getName());
    }

    private void removeSecurityKey(UUID uuid) {
        Fido2Slot slot = findSecurityKey(uuid);
        if (slot == null) {
            return;
        }

        Dialogs.showSecureDialog(new MaterialAlertDialogBuilder(requireContext(), R.style.ThemeOverlay_Aegis_AlertDialog_Warning)
                .setTitle(R.string.security_key_remove_title)
                .setMessage(getString(R.string.security_key_remove_description, slot.getName()))
                .setIconAttribute(android.R.attr.alertDialogIcon)
                .setPositiveButton(android.R.string.yes, (dialog, which) -> {
                    VaultFileCredentials creds = _vaultManager.getVault().getCredentials();
                    creds.getSlots().remove(creds.getSlots().getByUUID(uuid));
                    _vaultManager.getVault().setCredentials(creds);
                    saveAndBackupVault();
                    refreshSecurityKeys();
                })
                .setNegativeButton(android.R.string.no, null)
                .create());
    }

    private List<Fido2Slot> getSecurityKeys() {
        List<Fido2Slot> slots = _vaultManager.getVault().getCredentials().getSlots().findAll(Fido2Slot.class);
        slots.sort(Comparator.comparingLong(Fido2Slot::getCreatedAt));
        return slots;
    }

    @Nullable
    private Fido2Slot findSecurityKey(UUID uuid) {
        for (Fido2Slot slot : getSecurityKeys()) {
            if (slot.getUUID().equals(uuid)) {
                return slot;
            }
        }
        return null;
    }

    private boolean isNameTaken(String name, @Nullable UUID except) {
        for (Fido2Slot slot : getSecurityKeys()) {
            if (!slot.getUUID().equals(except) && slot.getName().equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    private void saveVault() {
        try {
            _vaultManager.saveAndBackup();
        } catch (VaultRepositoryException e) {
            e.printStackTrace();
        }
    }
}
