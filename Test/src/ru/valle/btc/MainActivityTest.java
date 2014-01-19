/**
 The MIT License (MIT)

 Copyright (c) 2013 Valentin Konovalov

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.*/

package ru.valle.btc;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.test.ActivityInstrumentationTestCase2;
import android.test.UiThreadTest;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import external.ExternalPrivateKeyStorage;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

/**
 * This is a simple framework for a test of an Application.  See
 * {@link android.test.ApplicationTestCase ApplicationTestCase} for more information on
 * how to write and extend Application tests.
 * <p/>
 * To run this test, you can type:
 * adb shell am instrument -w \
 * -e class ru.valle.btc.MainActivityTest \
 * ru.valle.btc.tests/android.test.InstrumentationTestRunner
 */
public class MainActivityTest extends ActivityInstrumentationTestCase2<MainActivity> {

    private EditText addressView;
    private EditText privateKeyTextEdit;

    @TargetApi(Build.VERSION_CODES.FROYO)
    public MainActivityTest() {
        super(MainActivity.class);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        MainActivity mainActivity = getActivity();
        addressView = (EditText) mainActivity.findViewById(R.id.address_label);
        privateKeyTextEdit = (EditText) mainActivity.findViewById(R.id.private_key_label);
    }

    public void testAlwaysGenerateNewAddress() {
        Activity activity = getActivity();
        String address = waitForAddress(activity);
        assertNotNull(address);
        activity.finish();
        setActivity(null);
        assertFalse(getActivity().isFinishing());
        activity = getActivity();
        String anotherAddress = waitForAddress(activity);
        assertNotNull(anotherAddress);
        assertNotSame(address, anotherAddress);
    }

    public void testLayoutOnStart() {
        Activity activity = getActivity();
        assertTrue(activity.findViewById(R.id.send_layout).getVisibility() == View.GONE);
        activity.finish();
    }

    public void testAddressGenerateOnStartup() {
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(getActivity());
        performGenerationTest(preferences, PreferencesActivity.PREF_PRIVATE_KEY_MINI);
        performGenerationTest(preferences, PreferencesActivity.PREF_PRIVATE_KEY_WIF_COMPRESSED);
        performGenerationTest(preferences, PreferencesActivity.PREF_PRIVATE_KEY_WIF_NOT_COMPRESSED);
    }

    private SharedPreferences performGenerationTest(SharedPreferences preferences, String privateKeyType) {
        preferences.edit().putString(PreferencesActivity.PREF_PRIVATE_KEY, privateKeyType).commit();
        getActivity().finish();
        setActivity(null);
        assertFalse(getActivity().isFinishing());
        preferences = PreferenceManager.getDefaultSharedPreferences(getActivity());
        assertEquals(privateKeyType, preferences.getString(PreferencesActivity.PREF_PRIVATE_KEY, PreferencesActivity.PREF_PRIVATE_KEY_MINI));
        checkIfGeneratedKeyIsValid(privateKeyType);
        return preferences;
    }

    private void checkIfGeneratedKeyIsValid(String privateKeyType) {
        String address = waitForAddress(getActivity());
        assertNotNull(address);
        assertTrue("Addresses must starts with '1', but generated address is '" + address + "'", address.startsWith("1"));
        String privateKey = getText(getActivity(), R.id.private_key_label);
        if (PreferencesActivity.PREF_PRIVATE_KEY_MINI.equals(privateKeyType)) {
            assertTrue("Private keys must starts with 'S', but generated key is '" + privateKey + "'", privateKey.startsWith("S"));
            assertEquals("Private keys should have length 30 characters ", 30, privateKey.length());
        } else if (PreferencesActivity.PREF_PRIVATE_KEY_WIF_COMPRESSED.equals(privateKeyType)) {
            assertTrue("WIF private keys (compressed public) must starts with 'K' or 'L', but generated key is '" + privateKey + "'", privateKey.startsWith("K") || privateKey.startsWith("L"));
            byte[] decoded = BTCUtils.decodeBase58(privateKey);
            assertNotNull(decoded);
            assertEquals("decoded private key (with compressed public key) should be 38 bytes length", 38, decoded.length);
        } else if (PreferencesActivity.PREF_PRIVATE_KEY_WIF_NOT_COMPRESSED.equals(privateKeyType)) {
            assertTrue("WIF private keys (not compressed public) must starts with '5', but generated key is '" + privateKey + "'", privateKey.startsWith("5"));
            byte[] decoded = BTCUtils.decodeBase58(privateKey);
            assertNotNull(decoded);
            assertTrue("decoded private key (with not compressed public key) should be 37 or 38 bytes length", decoded.length == 37 || decoded.length == 38);
        }
    }

    private String waitForAddress(Activity activity) {
        for (int i = 0; i < 150; i++) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            String generatedAddress = getText(activity, R.id.address_label);
            if (!TextUtils.isEmpty(generatedAddress) && generatedAddress.startsWith("1")) {
                return generatedAddress;
            }
        }
        return null;
    }

    private String getText(final Activity activity, final int id) {
        FutureTask<String> task = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {
                TextView textView = ((TextView) activity.findViewById(id));
                return textView.getVisibility() == View.VISIBLE ? textView.getText().toString() : null;
            }
        });
        activity.runOnUiThread(task);
        try {
            return task.get();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void testDecodeMiniKey() {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {
                privateKeyTextEdit.setText("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy");
            }
        });
        getInstrumentation().waitForIdleSync();
        String decodedAddress = waitForAddress(getActivity());
        assertEquals("1CciesT23BNionJeXrbxmjc7ywfiyM4oLW", decodedAddress);
    }

    public void testDecodeUncompressedWIF() {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {
                privateKeyTextEdit.setText("5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF");
            }
        });
        getInstrumentation().waitForIdleSync();
        String decodedAddress = waitForAddress(getActivity());
        assertEquals("1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj", decodedAddress);
    }

    public void testDecodeCompressedWIF() {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {
                privateKeyTextEdit.setText("KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp");
            }
        });
        getInstrumentation().waitForIdleSync();
        String decodedAddress = waitForAddress(getActivity());
        assertEquals("1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9", decodedAddress);
    }

    @UiThreadTest
    public void testDecodeAddress() {
        addressView.setText("1CciesT23BNionJeXrbxmjc7ywfiyM4oLW");
        assertEquals("You may edit address field", "1CciesT23BNionJeXrbxmjc7ywfiyM4oLW", addressView.getText().toString());
        assertEquals("Typing in address field should clean private key", "", privateKeyTextEdit.getText().toString());
    }

    public void testDecodeAddressAndWait() {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {
                testDecodeAddress();
            }
        });
        getInstrumentation().waitForIdleSync();
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        getActivity().runOnUiThread(new Runnable() {
            public void run() {
                assertEquals("You may edit address field and the change must persist", "1CciesT23BNionJeXrbxmjc7ywfiyM4oLW", addressView.getText().toString());
                assertEquals("Typing in address field should clean private key and the change must persist", "", privateKeyTextEdit.getText().toString());
            }
        });
    }

    public void testTxCreationFromUI() {
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(getActivity());
        preferences.edit().remove(PreferencesActivity.PREF_FEE).putString(PreferencesActivity.PREF_FEE, BTCUtils.formatValue(FeePreference.PREF_FEE_DEFAULT * 6)).commit();
        checkTxCreationFromUI();

        preferences.edit().putLong(PreferencesActivity.PREF_FEE, FeePreference.PREF_FEE_DEFAULT * 5).commit();
        checkTxCreationFromUI();
        preferences.edit().putLong(PreferencesActivity.PREF_FEE, FeePreference.PREF_FEE_DEFAULT).commit();
        getActivity().finish();
        setActivity(null);
        assertFalse(getActivity().isFinishing());
        checkTxCreationFromUI();
    }

    public void testTxCreationFromUIUsingBIP38Key() {
        checkTxCreationFromUI(ExternalPrivateKeyStorage.ENCRYPTED_PRIVATE_KEY_FOR_1AtPaarLahSNwujAzhcXutsDVDSczyYcj8, ExternalPrivateKeyStorage.PASSWORD_FOR_1AtPaarLahSNwujAzhcXutsDVDSczyYcj8, "1AtPaarLahSNwujAzhcXutsDVDSczyYcj8",
                "\n" +
                        "\n" +
                        "{\n" +
                        "\t \n" +
                        "\t\"unspent_outputs\":[\n" +
                        "\t\n" +
                        "\t\t{\n" +
                        "\t\t\t\"tx_hash\":\"ed6da4e0d02a098655325ec6cd287815149c87b4cbdb60a97a8e9f5c5b6fa3b0\",\n" +
                        "\t\t\t\"tx_index\":98596927,\n" +
                        "\t\t\t\"tx_output_n\": 1,\t\n" +
                        "\t\t\t\"script\":\"76a9146c7131b26c1fb961975ea3da258526877f3e865888ac\",\n" +
                        "\t\t\t\"value\": 200000,\n" +
                        "\t\t\t\"value_hex\": \"030d40\",\n" +
                        "\t\t\t\"confirmations\":0\n" +
                        "\t\t},\n" +
                        "\t  \n" +
                        "\t\t{\n" +
                        "\t\t\t\"tx_hash\":\"d0f5bab61cebeab11f1aa23d336ec68cff429d7dce2221049bb2393cf7ca91a9\",\n" +
                        "\t\t\t\"tx_index\":98596879,\n" +
                        "\t\t\t\"tx_output_n\": 1,\t\n" +
                        "\t\t\t\"script\":\"76a9146c7131b26c1fb961975ea3da258526877f3e865888ac\",\n" +
                        "\t\t\t\"value\": 100000,\n" +
                        "\t\t\t\"value_hex\": \"0186a0\",\n" +
                        "\t\t\t\"confirmations\":0\n" +
                        "\t\t}\n" +
                        "\t  \n" +
                        "\t]\n" +
                        "}",
                "18D5fLcryBDf8Vgov6JTd9Taj81gNekrex");
    }

    private void checkTxCreationFromUI() {
        checkTxCreationFromUI("L49guLBaJw8VSLnKGnMKVH5GjxTrkK4PBGc425yYwLqnU5cGpyxJ", null, "1NKkKeTDWWi5LQQdrSS7hghnbhfYtWiWHs",
                "0100000001ef9ea3e6b7a664ff910ed1177bfa81efa018df417fb1ee964b8165a05dc7ef5a000000008b4830450220385373efe509" +
                        "719e38cb63b86ca5d764be0f2bd2ffcfa03194978ca68488f57b0221009686e0b54d7831f9f06d36bfb81c5d2931a8ada079a3ff58c" +
                        "6109030ed0c4cd601410424161de67ec43e5bfd55f52d98d2a99a2131904b25aa08e70924d32ed44bfb4a71c94a7c4fdac886ca5bec7" +
                        "b7fac4209ab1443bc48ab6dec31656cd3e55b5dfcffffffff02707f0088000000001976a9143412c159747b9149e8f0726123e2939b68" +
                        "edb49e88ace0a6e001000000001976a914e9e64aae2d1e066db6c5ecb1a2781f418b18eef488ac00000000",
                "1AyyaMAyo5sbC73kdUjgBK9h3jDMoXzkcP");


        checkTxCreationFromUI("L49guLBaJw8VSLnKGnMKVH5GjxTrkK4PBGc425yYwLqnU5cGpyxJ", null, "1NKkKeTDWWi5LQQdrSS7hghnbhfYtWiWHs",
                "{\n" +
                        "\t \n" +
                        "\t\"unspent_outputs\":[\n" +
                        "\t\n" +
                        "\t\t{\n" +
                        "\t\t\t\"tx_hash\":\"088676b3e6cfb2f25e35f903b812ddae897ac922653c6ad6b74a188a08ffd253\",\n" +
                        "\t\t\t\"tx_output_n\": 1,\t\n" +
                        "\t\t\t\"script\":\"76a914e9e64aae2d1e066db6c5ecb1a2781f418b18eef488ac\",\n" +
                        "\t\t\t\"value\": 31500000\n" +
                        "\t\t}\n" +
                        "\t  \n" +
                        "\t]\n" +
                        "}",
                "18D5fLcryBDf8Vgov6JTd9Taj81gNekrex");

        checkTxCreationFromUI(ExternalPrivateKeyStorage.PRIVATE_KEY_FOR_1AtPaarLahSNwujAzhcXutsDVDSczyYcj8, null, "1AtPaarLahSNwujAzhcXutsDVDSczyYcj8",
                "\n" +
                        "\n" +
                        "{\n" +
                        "\t \n" +
                        "\t\"unspent_outputs\":[\n" +
                        "\t\n" +
                        "\t\t{\n" +
                        "\t\t\t\"tx_hash\":\"ed6da4e0d02a098655325ec6cd287815149c87b4cbdb60a97a8e9f5c5b6fa3b0\",\n" +
                        "\t\t\t\"tx_index\":98596927,\n" +
                        "\t\t\t\"tx_output_n\": 1,\t\n" +
                        "\t\t\t\"script\":\"76a9146c7131b26c1fb961975ea3da258526877f3e865888ac\",\n" +
                        "\t\t\t\"value\": 200000,\n" +
                        "\t\t\t\"value_hex\": \"030d40\",\n" +
                        "\t\t\t\"confirmations\":0\n" +
                        "\t\t},\n" +
                        "\t  \n" +
                        "\t\t{\n" +
                        "\t\t\t\"tx_hash\":\"d0f5bab61cebeab11f1aa23d336ec68cff429d7dce2221049bb2393cf7ca91a9\",\n" +
                        "\t\t\t\"tx_index\":98596879,\n" +
                        "\t\t\t\"tx_output_n\": 1,\t\n" +
                        "\t\t\t\"script\":\"76a9146c7131b26c1fb961975ea3da258526877f3e865888ac\",\n" +
                        "\t\t\t\"value\": 100000,\n" +
                        "\t\t\t\"value_hex\": \"0186a0\",\n" +
                        "\t\t\t\"confirmations\":0\n" +
                        "\t\t}\n" +
                        "\t  \n" +
                        "\t]\n" +
                        "}",
                "18D5fLcryBDf8Vgov6JTd9Taj81gNekrex");

    }

    private void checkTxCreationFromUI(final String privateKey, final String password, final String expectedAddressForTheKey, final String unspentTxInfo, final String recipientAddress) {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {
                ((EditText) getActivity().findViewById(R.id.address_label)).setText("");
                ((EditText) getActivity().findViewById(R.id.private_key_label)).setText(privateKey);
                if (!TextUtils.isEmpty(password)) {
                    ((EditText) getActivity().findViewById(R.id.password_edit)).setText(password);

                }
            }
        });
        getInstrumentation().waitForIdleSync();

        String decodedAddress = null;
        if (!TextUtils.isEmpty(password)) {
            boolean readyForDecryption = false;
            for (int i = 0; i < 100; i++) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                String generatedAddress = getText(getActivity(), R.id.address_label);
                if (!TextUtils.isEmpty(generatedAddress)) {
                    if (generatedAddress.startsWith("1")) {
                        decodedAddress = generatedAddress;
                        break;
                    } else if (getActivity().getString(R.string.not_decrypted_yet).equals(generatedAddress)) {
                        readyForDecryption = true;
                        break;
                    }
                }
            }
            if (readyForDecryption) {
                getActivity().runOnUiThread(new Runnable() {
                    public void run() {
                        Button button = (Button) getActivity().findViewById(R.id.password_button);
                        button.performClick();
                    }
                });
                getInstrumentation().waitForIdleSync();
                decodedAddress = waitForAddress(getActivity());
            }
        } else {
            decodedAddress = waitForAddress(getActivity());
        }

        assertEquals(expectedAddressForTheKey, decodedAddress);
        getActivity().runOnUiThread(new Runnable() {
            public void run() {
                ((EditText) getActivity().findViewById(R.id.amount)).setText("");
                ((EditText) getActivity().findViewById(R.id.raw_tx)).setText(unspentTxInfo);
                ((EditText) getActivity().findViewById(R.id.recipient_address)).setText(recipientAddress);
            }
        });
        String createdTx = null;
        for (int i = 0; i < 100; i++) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            createdTx = getText(getActivity(), R.id.spend_tx);
            if (!TextUtils.isEmpty(createdTx)) {
                break;
            }
        }
        assertNotNull(createdTx);

        ArrayList<UnspentOutputInfo> unspentOutputs = new ArrayList<UnspentOutputInfo>();
        byte[] rawTx = BTCUtils.fromHex(unspentTxInfo);
        if (rawTx != null) {
            Transaction baseTx = new Transaction(rawTx);
            byte[] rawTxReconstructed = baseTx.getBytes();
            if (!Arrays.equals(rawTxReconstructed, rawTx)) {
                throw new IllegalArgumentException("Unable to decode given transaction");
            }
            byte[] txHash = BTCUtils.reverse(BTCUtils.doubleSha256(rawTx));
            for (int outputIndex = 0; outputIndex < baseTx.outputs.length; outputIndex++) {
                Transaction.Output output = baseTx.outputs[outputIndex];
                unspentOutputs.add(new UnspentOutputInfo(txHash, output.script, output.value, outputIndex));
            }
        } else {
            try {
                JSONObject jsonObject = new JSONObject(unspentTxInfo);
                JSONArray unspentOutputsArray = jsonObject.getJSONArray("unspent_outputs");
                for (int i = 0; i < unspentOutputsArray.length(); i++) {
                    JSONObject unspentOutput = unspentOutputsArray.getJSONObject(i);
                    byte[] txHash = BTCUtils.reverse(BTCUtils.fromHex(unspentOutput.getString("tx_hash")));
                    Transaction.Script script = new Transaction.Script(BTCUtils.fromHex(unspentOutput.getString("script")));
                    long value = unspentOutput.getLong("value");
                    int outputIndex = unspentOutput.getInt("tx_output_n");
                    unspentOutputs.add(new UnspentOutputInfo(txHash, script, value, outputIndex));
                }
            } catch (Exception e) {
                assertFalse(e.getMessage(), true);
            }
        }

        Transaction spendTx = new Transaction(BTCUtils.fromHex(createdTx));
        long inValue = 0;
        for (Transaction.Input input : spendTx.inputs) {
            for (UnspentOutputInfo unspentOutput : unspentOutputs) {
                if (Arrays.equals(unspentOutput.txHash, input.outPoint.hash) && unspentOutput.outputIndex == input.outPoint.index) {
                    inValue += unspentOutput.value;
                }
            }
        }
        long outValue = 0;
        for (Transaction.Output output : spendTx.outputs) {
            outValue += output.value;
        }
        long fee = inValue - outValue;
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(getActivity());
        long requestedFee;
        try {
            requestedFee = preferences.getLong(PreferencesActivity.PREF_FEE, FeePreference.PREF_FEE_DEFAULT);
        } catch (ClassCastException e) {
            //fee set as String in older client
            try {
                requestedFee = BTCUtils.parseValue(preferences.getString(PreferencesActivity.PREF_FEE, BTCUtils.formatValue(FeePreference.PREF_FEE_DEFAULT)));
            } catch (Exception parseEx) {
                requestedFee = FeePreference.PREF_FEE_DEFAULT;
            }
        }
        assertEquals(requestedFee, fee);

        try {
            Transaction.Script[] relatedScripts = new Transaction.Script[spendTx.inputs.length];
            for (int i = 0; i < spendTx.inputs.length; i++) {
                Transaction.Input input = spendTx.inputs[i];
                for (UnspentOutputInfo unspentOutput : unspentOutputs) {
                    if (Arrays.equals(unspentOutput.txHash, input.outPoint.hash) && unspentOutput.outputIndex == input.outPoint.index) {
                        relatedScripts[i] = unspentOutput.script;
                        break;
                    }
                }
                assertNotNull("and where is unspent output's script for this input?", relatedScripts[i]);
            }
            BTCUtils.verify(relatedScripts, spendTx);
        } catch (Transaction.Script.ScriptInvalidException e) {
            assertFalse(e.getMessage(), true);
        }
    }

}
