package ru.valle.btc;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
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

    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        if (key.equals(PreferencesActivity.PREF_PRIVATE_KEY)) {
            ListPreference preference = (ListPreference) findPreference(key);
            preference.setSummary(preference.getEntry());
        }
    }
}
