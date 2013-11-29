package ru.valle.btc;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.preference.EditTextPreference;
import android.preference.ListPreference;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.view.MenuItem;

/**
 * Created with IntelliJ IDEA.
 * User: Valentin
 * Date: 9/15/13
 * Time: 2:15 PM
 */
public final class PreferencesActivity extends Activity {
    public static final String PREF_PRIVATE_KEY = "private_key_type_to_generate";
    public static final String PREF_PRIVATE_KEY_MINI = "mini";
    public static final String PREF_PRIVATE_KEY_WIF_COMPRESSED = "wif_compressed";
    public static final String PREF_PRIVATE_KEY_BIP38 = "bip38";

    public static final String PREF_FEE = "fee";


    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getFragmentManager().beginTransaction()
                .replace(android.R.id.content, new SettingsFragment())
                .commit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            getActionBar().setDisplayHomeAsUpEnabled(true);
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                navigateUpTo(new Intent(this, MainActivity.class));
                return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public static class SettingsFragment extends PreferenceFragment implements SharedPreferences.OnSharedPreferenceChangeListener {
        private SharedPreferences preferences;

        @Override
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            addPreferencesFromResource(R.xml.preferences);
            preferences = getPreferenceManager().getSharedPreferences();
            onSharedPreferenceChanged(preferences, PREF_PRIVATE_KEY);
            onSharedPreferenceChanged(preferences, PREF_FEE);
        }

        @Override
        public void onResume() {
            super.onResume();
            preferences.registerOnSharedPreferenceChangeListener(this);
        }

        @Override
        public void onPause() {
            super.onPause();
            preferences.unregisterOnSharedPreferenceChangeListener(this);
        }

        public void onSharedPreferenceChanged(final SharedPreferences sharedPreferences, final String key) {
            new Handler(Looper.getMainLooper()).post(
                    new Runnable() {

                        @Override
                        public void run() {
                            if (key.equals(PREF_PRIVATE_KEY)) {
                                ListPreference preference = (ListPreference) findPreference(key);
                                preference.setSummary(preference.getEntry());
                            } else if (key.equals(PREF_FEE)) {
                                FeePreference preference = (FeePreference) findPreference(key);
                                preference.setSummary(preference.getText());
                            }
                        }
                    });
        }
    }

}
