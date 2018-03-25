package ru.valle.btc;

import android.annotation.TargetApi;
import android.app.ActionBar;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.preference.ListPreference;
import android.preference.PreferenceFragment;
import android.preference.PreferenceManager;
import android.view.MenuItem;

/**
 * Created with IntelliJ IDEA.
 * User: Valentin
 * Date: 9/15/13
 * Time: 2:15 PM
 */
@TargetApi(Build.VERSION_CODES.HONEYCOMB)
public final class PreferencesActivity extends Activity {
    public static final String PREF_PRIVATE_KEY = "private_key_type_to_generate";
    public static final String PREF_PRIVATE_KEY_MINI = "mini";
    public static final String PREF_PRIVATE_KEY_WIF_COMPRESSED = "wif_compressed";
    public static final String PREF_PRIVATE_KEY_WIF_TEST_NET = "test_net";

    public static final String PREF_FEE_SAT_BYTE = "fee_sat_byte";

    public static final String PREF_SEGWIT = "segwit_address";

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getFragmentManager().beginTransaction()
                .replace(android.R.id.content, new SettingsFragment())
                .commit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            ActionBar actionBar = getActionBar();
            if (actionBar != null) {
                actionBar.setDisplayHomeAsUpEnabled(true);
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN)
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
            PreferenceManager pm = getPreferenceManager();
            if (pm != null) {
                preferences = pm.getSharedPreferences();
                onSharedPreferenceChanged(preferences, PREF_PRIVATE_KEY);
                onSharedPreferenceChanged(preferences, PREF_FEE_SAT_BYTE);
            }
        }

        @Override
        public void onResume() {
            super.onResume();
            if (preferences != null) {
                preferences.registerOnSharedPreferenceChangeListener(this);
            }
        }

        @Override
        public void onPause() {
            super.onPause();
            if (preferences != null) {
                preferences.unregisterOnSharedPreferenceChangeListener(this);
            }
        }

        public void onSharedPreferenceChanged(final SharedPreferences sharedPreferences, final String key) {
            new Handler(Looper.getMainLooper()).post(
                    () -> {
                        if (key.equals(PREF_PRIVATE_KEY)) {
                            ListPreference preference = (ListPreference) findPreference(key);
                            if (preference != null) {
                                preference.setSummary(preference.getEntry());
                            }
                        } else if (key.equals(PREF_FEE_SAT_BYTE)) {
                            FeePreference preference = (FeePreference) findPreference(key);
                            if (preference != null) {
                                preference.setSummary(preference.getText());
                            }
                        }
                    });
        }
    }

}
