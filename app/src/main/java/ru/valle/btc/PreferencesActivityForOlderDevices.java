package ru.valle.btc;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.preference.ListPreference;
import android.preference.PreferenceActivity;

/**
 * Created with IntelliJ IDEA.
 * User: Valentin
 * Date: 9/15/13
 * Time: 8:04 PM
 */
@SuppressWarnings("deprecation")
public final class PreferencesActivityForOlderDevices extends PreferenceActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private SharedPreferences preferences;

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.preferences);
        preferences = getPreferenceManager().getSharedPreferences();
        onSharedPreferenceChanged(preferences, PreferencesActivity.PREF_PRIVATE_KEY);
        onSharedPreferenceChanged(preferences, PreferencesActivity.PREF_FEE_SAT_BYTE);
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
                () -> {
                    if (key.equals(PreferencesActivity.PREF_PRIVATE_KEY)) {
                        ListPreference preference = (ListPreference) findPreference(key);
                        if (preference != null) {
                            preference.setSummary(preference.getEntry());
                        }
                    } else if (key.equals(PreferencesActivity.PREF_FEE_SAT_BYTE)) {
                        FeePreference preference = (FeePreference) findPreference(key);
                        if (preference != null) {
                            preference.setSummary(preference.getText());
                        }
                    }
                });
    }
}
