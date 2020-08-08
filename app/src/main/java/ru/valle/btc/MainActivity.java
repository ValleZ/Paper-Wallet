/*
 * The MIT License (MIT)
 * <p/>
 * Copyright (c) 2013 Valentin Konovalov
 * <p/>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p/>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p/>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package ru.valle.btc;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.annotation.MainThread;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.Editable;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.LinkMovementMethod;
import android.text.method.MovementMethod;
import android.text.style.ClickableSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.text.style.URLSpan;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.ContextThemeWrapper;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ToggleButton;

import com.d_project.qrcode.ErrorCorrectLevel;
import com.d_project.qrcode.QRCode;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

@SuppressLint("StaticFieldLeak")
// there are deliberate short-lived memory leaks - loaders would make this even more complicated
public final class MainActivity extends Activity {

    private static final int REQUEST_SCAN_PRIVATE_KEY = 0;
    private static final int REQUEST_SCAN_RECIPIENT_ADDRESS = 1;
    private static final long SEND_MAX = -1;
    private static final long AMOUNT_ERR = -2;

    private EditText addressTextEdit;
    private TextView privateKeyTypeView;
    private EditText privateKeyTextEdit;
    private View sendLayout;
    private TextView rawTxDescriptionHeaderView, rawTxDescriptionView;
    private EditText rawTxToSpendEdit;
    private EditText recipientAddressView;
    private EditText amountEdit;
    private TextView spendBtcTxDescriptionView, spendBchTxDescriptionView;
    private View spendTxWarningView;
    private TextView spendBtcTxEdit, spendBchTxEdit;
    private View generateButton;

    private boolean insertingPrivateKeyProgrammatically, insertingAddressProgrammatically;
    @Nullable
    private AsyncTask<Void, Void, KeyPair> addressGenerateTask;
    @Nullable
    private AsyncTask<Void, Void, GenerateTransactionResult> generateTransactionTask;
    @Nullable
    private AsyncTask<Void, Void, KeyPair> switchingCompressionTypeTask;
    @Nullable
    private AsyncTask<Void, Void, KeyPair> switchingSegwitTask;
    @Nullable
    private AsyncTask<Void, Void, KeyPair> decodePrivateKeyTask;
    @Nullable
    private AsyncTask<Void, Void, Object> bip38Task;
    @Nullable
    private AsyncTask<Void, Void, ArrayList<UnspentOutputInfo>> decodeUnspentOutputsInfoTask;

    private KeyPair currentKeyPair;
    private View scanPrivateKeyButton, scanRecipientAddressButton;
    private ImageButton showQRCodeAddressButton, showQRCodePrivateKeyButton;
    private View enterPrivateKeyAck;
    private View rawTxToSpendPasteButton;
    private Runnable clipboardListener;
    private View sendBtcTxInBrowserButton, sendBchTxInBrowserButton;
    private TextView passwordButton;
    private EditText passwordEdit;
    private boolean lastBip38ActionWasDecryption;
    private ClipboardHelper clipboardHelper;

    //collected information for tx generation:
    private String verifiedRecipientAddressForTx;
    private KeyPair verifiedKeyPairForTx;
    private ArrayList<UnspentOutputInfo> verifiedUnspentOutputsForTx;
    private long verifiedAmountToSendForTx;
    private ViewGroup mainLayout;
    private CompoundButton segwitAddressSwitch;
    private SharedPreferences mainThreadPreferences;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        mainLayout = findViewById(R.id.main);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }
        segwitAddressSwitch = findViewById(R.id.segwit_address_switch);
        addressTextEdit = findViewById(R.id.address_label);
        generateButton = findViewById(R.id.generate_button);
        privateKeyTypeView = findViewById(R.id.private_key_type_label);
        privateKeyTypeView.setMovementMethod(getLinkMovementMethod());
        privateKeyTextEdit = findViewById(R.id.private_key_label);
        passwordButton = findViewById(R.id.password_button);
        passwordEdit = findViewById(R.id.password_edit);

        sendLayout = findViewById(R.id.send_layout);
        rawTxToSpendPasteButton = findViewById(R.id.paste_tx_button);
        rawTxToSpendEdit = findViewById(R.id.raw_tx);
        recipientAddressView = findViewById(R.id.recipient_address);
        amountEdit = findViewById(R.id.amount);
        rawTxDescriptionHeaderView = findViewById(R.id.raw_tx_description_header);
        rawTxDescriptionView = findViewById(R.id.raw_tx_description);
        spendBtcTxDescriptionView = findViewById(R.id.spend_btc_tx_description);
        spendBchTxDescriptionView = findViewById(R.id.spend_bch_tx_description);
        spendTxWarningView = findViewById(R.id.spend_tx_warning_footer);
        spendBtcTxEdit = findViewById(R.id.spend_btc_tx);
        spendBchTxEdit = findViewById(R.id.spend_bch_tx);
        sendBtcTxInBrowserButton = findViewById(R.id.send_btc_tx_button);
        sendBchTxInBrowserButton = findViewById(R.id.send_bch_tx_button);
        scanPrivateKeyButton = findViewById(R.id.scan_private_key_button);
        showQRCodeAddressButton = findViewById(R.id.qr_address_button);
        showQRCodePrivateKeyButton = findViewById(R.id.qr_private_key_button);
        scanRecipientAddressButton = findViewById(R.id.scan_recipient_address_button);
        enterPrivateKeyAck = findViewById(R.id.enter_private_key_to_spend_desc);

        mainThreadPreferences = PreferenceManager.getDefaultSharedPreferences(this);
        if (savedInstanceState == null) {
            segwitAddressSwitch.setChecked(mainThreadPreferences.getBoolean(PreferencesActivity.PREF_SEGWIT, false));
        }
        wireListeners();
        generateNewAddress();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                Configuration.UI_MODE_NIGHT_YES == (Configuration.UI_MODE_NIGHT_MASK & getResources().getConfiguration().uiMode)) {
            showQRCodeAddressButton.setColorFilter(Color.WHITE);
            showQRCodePrivateKeyButton.setColorFilter(Color.WHITE);
        }
    }


    @Override
    protected void onResume() {
        super.onResume();
        CharSequence textInClipboard = getTextInClipboard();
        boolean hasTextInClipboard = !TextUtils.isEmpty(textInClipboard);
        if (Build.VERSION.SDK_INT >= 11) {
            if (!hasTextInClipboard) {
                clipboardListener = () -> rawTxToSpendPasteButton.setEnabled(!TextUtils.isEmpty(getTextInClipboard()));
                clipboardHelper.runOnClipboardChange(clipboardListener);
            }
            rawTxToSpendPasteButton.setEnabled(hasTextInClipboard);
        } else {
            rawTxToSpendPasteButton.setVisibility(hasTextInClipboard ? View.VISIBLE : View.GONE);
        }
        tryToGenerateSpendingTransaction();
    }

    @SuppressLint("NewApi")
    @Override
    protected void onPause() {
        super.onPause();
        if (Build.VERSION.SDK_INT >= 11 && clipboardListener != null) {
            clipboardHelper.removeClipboardListener(clipboardListener);
        }
    }

    private String getTextInClipboard() {
        CharSequence textInClipboard = "";
        if (Build.VERSION.SDK_INT >= 11) {
            if (clipboardHelper.hasTextInClipboard()) {
                textInClipboard = clipboardHelper.getTextInClipboard();
            }
        } else {
            android.text.ClipboardManager clipboard = (android.text.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null && clipboard.hasText()) {
                textInClipboard = clipboard.getText();
            }
        }
        return textInClipboard == null ? "" : textInClipboard.toString();
    }

    private void copyTextToClipboard(String label, String text) {
        if (Build.VERSION.SDK_INT >= 11) {
            clipboardHelper.copyTextToClipboard(label, text);
        } else {
            android.text.ClipboardManager clipboard = (android.text.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setText(text);
            }
        }
    }

    @SuppressLint("NewApi")
    private void wireListeners() {
        if (Build.VERSION.SDK_INT >= 11) {
            clipboardHelper = new ClipboardHelper(this);
        }
        segwitAddressSwitch.setOnCheckedChangeListener((compoundButton, checked) -> {
            if (currentKeyPair != null) {
                mainThreadPreferences.edit().putBoolean(PreferencesActivity.PREF_SEGWIT, checked).apply();
                cancelAllRunningTasks();
                BTCUtils.PrivateKeyInfo privateKeyInfo = currentKeyPair.privateKey;
                switchingSegwitTask = new AsyncTask<Void, Void, KeyPair>() {
                    int addressType;

                    @Override
                    protected void onPreExecute() {
                        addressType = getSelectedPublicKeyRepresentation();
                    }

                    @Override
                    protected KeyPair doInBackground(Void... params) {
                        return new KeyPair(privateKeyInfo, addressType);
                    }

                    @Override
                    protected void onPostExecute(KeyPair keyPair) {
                        switchingSegwitTask = null;
                        onKeyPairModify(false, keyPair, addressType);
                    }
                };
                switchingSegwitTask.execute();
            }
        });
        addressTextEdit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (!insertingAddressProgrammatically) {
                    cancelAllRunningTasks();
                    insertingPrivateKeyProgrammatically = true;
                    privateKeyTextEdit.setText("");
                    insertingPrivateKeyProgrammatically = false;
                    privateKeyTypeView.setVisibility(View.GONE);
                    updatePasswordView(null);
                    showSpendPanelForKeyPair(null);
                }
                showQRCodeAddressButton.setVisibility(!TextUtils.isEmpty(s) && Address.verify(s.toString()) ? View.VISIBLE : View.GONE);
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });
        generateButton.setOnClickListener(v -> generateNewAddress());
        privateKeyTextEdit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (!insertingPrivateKeyProgrammatically) {
                    cancelAllRunningTasks();
                    insertingAddressProgrammatically = true;
                    setTextWithoutJumping(addressTextEdit, getString(R.string.decoding));
                    insertingAddressProgrammatically = false;
                    final String privateKeyToDecode = s.toString();
                    if (!TextUtils.isEmpty(privateKeyToDecode)) {
                        decodePrivateKeyTask = new AsyncTask<Void, Void, KeyPair>() {
                            int addressType;

                            @Override
                            protected void onPreExecute() {
                                addressType = getSelectedPublicKeyRepresentation();
                            }

                            @Override
                            protected KeyPair doInBackground(Void... params) {
                                try {
                                    boolean compressedPublicKeyForPaperWallets = addressType != Address.PUBLIC_KEY_TO_ADDRESS_LEGACY;
                                    BTCUtils.PrivateKeyInfo privateKeyInfo = BTCUtils.decodePrivateKey(privateKeyToDecode, compressedPublicKeyForPaperWallets);
                                    if (privateKeyInfo != null) {
                                        return new KeyPair(privateKeyInfo, addressType);
                                    }
                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                }
                                return null;
                            }

                            @Override
                            protected void onPostExecute(KeyPair keyPair) {
                                super.onPostExecute(keyPair);
                                decodePrivateKeyTask = null;
                                onKeyPairModify(false, keyPair, addressType);
                            }
                        };
                        decodePrivateKeyTask.execute();
                    } else {
                        onKeyPairModify(true, null, Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
                    }
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        passwordEdit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                updatePasswordView(currentKeyPair);
            }
        });

        passwordEdit.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == R.id.action_encrypt || actionId == R.id.action_decrypt) {
                encryptOrDecryptPrivateKey();
                return true;
            }
            return false;
        });
        passwordButton.setOnClickListener(v -> encryptOrDecryptPrivateKey());
        rawTxToSpendPasteButton.setOnClickListener(v -> {
            rawTxToSpendEdit.setText(getTextInClipboard());
            hideKeyboard();
        });
        rawTxToSpendEdit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                onUnspentOutputsInfoChanged();
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });
        recipientAddressView.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                onRecipientAddressChanged();
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });
        amountEdit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                onSendAmountChanged(getString(amountEdit));
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });
        scanPrivateKeyButton.setOnClickListener(v -> startActivityForResult(new Intent(
                MainActivity.this, ScanActivity.class), REQUEST_SCAN_PRIVATE_KEY));
        showQRCodeAddressButton.setOnClickListener(v -> showQRCodePopupForAddress(getString(addressTextEdit)));
        showQRCodePrivateKeyButton.setOnClickListener(v -> {
            if (currentKeyPair.address != null) {
                String[] dataTypes = getResources().getStringArray(R.array.private_keys_types_for_qr);
                String[] privateKeys = new String[3];
                if (currentKeyPair.privateKey.type == BTCUtils.PrivateKeyInfo.TYPE_MINI) {
                    privateKeys[0] = currentKeyPair.privateKey.privateKeyEncoded;
                } else if (currentKeyPair.privateKey.type == BTCUtils.Bip38PrivateKeyInfo.TYPE_BIP38) {
                    privateKeys[2] = currentKeyPair.privateKey.privateKeyEncoded;
                }
                if (currentKeyPair.privateKey.privateKeyDecoded != null) {
                    privateKeys[1] = BTCUtils.encodeWifKey(
                            currentKeyPair.privateKey.isPublicKeyCompressed,
                            BTCUtils.getPrivateKeyBytes(currentKeyPair.privateKey.privateKeyDecoded), false);
                }
                showQRCodePopupForPrivateKey(getString(R.string.private_key_for, currentKeyPair.address),
                        currentKeyPair.address.addressString, privateKeys, dataTypes);
            }
        });
        scanRecipientAddressButton.setOnClickListener(v -> startActivityForResult(
                new Intent(MainActivity.this, ScanActivity.class), REQUEST_SCAN_RECIPIENT_ADDRESS));
        sendBtcTxInBrowserButton.setOnClickListener(v -> {
            copyTextToClipboard(getString(R.string.btc_tx_description_for_clipboard, amountEdit.getText(), recipientAddressView.getText()), getString(spendBtcTxEdit));
            String url = "https://blockchain.info/pushtx";
            openBrowser(url);
        });
        sendBchTxInBrowserButton.setOnClickListener(v -> {
            copyTextToClipboard(getString(R.string.bch_tx_description_for_clipboard, amountEdit.getText(), recipientAddressView.getText()), getString(spendBchTxEdit));
            openBrowser("https://blockdozer.com/insight/tx/send");
        });

        if (!EclairHelper.canScan(this)) {
            scanPrivateKeyButton.setVisibility(View.GONE);
            scanRecipientAddressButton.setVisibility(View.GONE);
        }
    }

    private void hideKeyboard() {
        View view = getCurrentFocus();
        if (view != null) {
            InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
            if (imm != null) {
                imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
            }
        }
    }

    private void openBrowser(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception e) {
            Toast.makeText(MainActivity.this, R.string.unable_to_open_browser, Toast.LENGTH_LONG).show();
        }
    }

    private void onRecipientAddressChanged() {
        String addressStr = getString(recipientAddressView);
        TextView recipientAddressError = findViewById(R.id.err_recipient_address);
        if (Address.verify(addressStr)) {
            if (verifiedKeyPairForTx != null && verifiedKeyPairForTx.address != null &&
                    addressStr.equals(verifiedKeyPairForTx.address.addressString)) {
                recipientAddressError.setText(R.string.output_address_same_as_input);
            } else {
                recipientAddressError.setText("");
            }
            verifiedRecipientAddressForTx = addressStr;
            tryToGenerateSpendingTransaction();
        } else {
            verifiedRecipientAddressForTx = null;
            recipientAddressError.setText(TextUtils.isEmpty(addressStr) ? "" : getString(R.string.invalid_address));
        }
    }

    private void onUnspentOutputsInfoChanged() {
        final String unspentOutputsInfoStr = getString(rawTxToSpendEdit);
        final KeyPair keyPair = currentKeyPair;
        if (keyPair != null && keyPair.privateKey != null && keyPair.privateKey.privateKeyDecoded != null) {
            verifiedKeyPairForTx = keyPair;
            if (!TextUtils.isEmpty(verifiedRecipientAddressForTx) && verifiedKeyPairForTx.address != null &&
                    verifiedRecipientAddressForTx.equals(verifiedKeyPairForTx.address.addressString)) {
                ((TextView) findViewById(R.id.err_recipient_address)).setText(R.string.output_address_same_as_input);
            }
            final TextView rawTxToSpendErr = findViewById(R.id.err_raw_tx);
            if (TextUtils.isEmpty(unspentOutputsInfoStr)) {
                rawTxToSpendErr.setText("");
                verifiedUnspentOutputsForTx = null;
            } else {
                cancelAllRunningTasks();
                decodeUnspentOutputsInfoTask = new AsyncTask<Void, Void, ArrayList<UnspentOutputInfo>>() {
                    /**
                     * stores if input is a json.
                     * from Future interface spec: "Memory consistency effects: Actions taken by the asynchronous computation happen-before actions following the corresponding Future.get() in another thread."
                     * it means it don't have to be volatile, because AsyncTask uses FutureTask to deliver result.
                     */
                    boolean jsonInput;
                    String jsonParseError;

                    @Override
                    protected ArrayList<UnspentOutputInfo> doInBackground(Void... params) {
                        try {
                            if (keyPair.address == null) {
                                throw new RuntimeException("Address is null in decodeUnspentOutputsInfoTask");
                            }
                            byte[] outputScriptWeAreAbleToSpend = Transaction.Script.buildOutput(keyPair.address.addressString).bytes;
                            ArrayList<UnspentOutputInfo> unspentOutputs = new ArrayList<>();
                            //1. decode tx or json
                            String txs = unspentOutputsInfoStr.trim();
                            byte[] startBytes = txs.length() < 8 ? null : BTCUtils.fromHex(txs.substring(0, 8));
                            if (startBytes != null && startBytes.length == 4) {
                                String[] txList = txs.split("\\s+");
                                for (String rawTxStr : txList) {
                                    rawTxStr = rawTxStr.trim();
                                    if (rawTxStr.length() > 0) {
                                        byte[] rawTx = BTCUtils.fromHex(rawTxStr);
                                        if (rawTx != null && rawTx.length > 0) {
                                            Transaction baseTx = Transaction.decodeTransaction(rawTx);
                                            byte[] rawTxReconstructed = baseTx.getBytes();
                                            if (!Arrays.equals(rawTxReconstructed, rawTx)) {
                                                throw new IllegalArgumentException("Unable to decode given transaction");
                                            }
                                            jsonInput = false;
                                            byte[] txHash = baseTx.hash();
                                            for (int outputIndex = 0; outputIndex < baseTx.outputs.length; outputIndex++) {
                                                Transaction.Output output = baseTx.outputs[outputIndex];
                                                if (Arrays.equals(outputScriptWeAreAbleToSpend, output.scriptPubKey.bytes)) {
                                                    unspentOutputs.add(new UnspentOutputInfo(keyPair, txHash, output.scriptPubKey, output.value, outputIndex));
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                String jsonStr = unspentOutputsInfoStr.replace((char) 160, ' ').trim();//remove nbsp
                                if (!jsonStr.startsWith("{")) {
                                    jsonStr = "{" + jsonStr;
                                }
                                if (!jsonStr.endsWith("}")) {
                                    jsonStr += "}";
                                }
                                JSONObject jsonObject = new JSONObject(jsonStr);
                                jsonInput = true;
                                if (!jsonObject.has("unspent_outputs")) {
                                    jsonParseError = getString(R.string.json_err_no_unspent_outputs);
                                    return null;
                                }
                                JSONArray unspentOutputsArray = jsonObject.getJSONArray("unspent_outputs");
                                for (int i = 0; i < unspentOutputsArray.length(); i++) {
                                    JSONObject unspentOutput = unspentOutputsArray.getJSONObject(i);
                                    byte[] txHash = BTCUtils.reverse(BTCUtils.fromHex(unspentOutput.getString("tx_hash")));
                                    Transaction.Script script = new Transaction.Script(BTCUtils.fromHex(unspentOutput.getString("script")));
                                    if (Arrays.equals(outputScriptWeAreAbleToSpend, script.bytes)) {
                                        long value = unspentOutput.getLong("value");
                                        int outputIndex = (int) unspentOutput.getLong("tx_output_n");
                                        unspentOutputs.add(new UnspentOutputInfo(keyPair, txHash, script, value, outputIndex));
                                    }
                                }
                            }
                            jsonParseError = null;
                            return unspentOutputs;
                        } catch (Exception e) {
                            jsonParseError = e.getMessage();
                            return null;
                        }
                    }

                    @Override
                    protected void onPostExecute(ArrayList<UnspentOutputInfo> unspentOutputInfos) {
                        verifiedUnspentOutputsForTx = unspentOutputInfos;
                        if (unspentOutputInfos == null) {
                            if (jsonInput && !TextUtils.isEmpty(jsonParseError)) {
                                rawTxToSpendErr.setText(getString(R.string.error_unable_to_decode_json_transaction, jsonParseError));
                            } else {
                                rawTxToSpendErr.setText(R.string.error_unable_to_decode_transaction);
                            }
                        } else if (unspentOutputInfos.isEmpty()) {
                            rawTxToSpendErr.setText(getString(R.string.error_no_spendable_outputs_found, keyPair.address));
                        } else {
                            rawTxToSpendErr.setText("");
                            long availableAmount = 0;
                            for (UnspentOutputInfo unspentOutputInfo : unspentOutputInfos) {
                                availableAmount += unspentOutputInfo.value;
                            }
                            amountEdit.setHint(BTCUtils.formatValue(availableAmount));
                            if (TextUtils.isEmpty(getString(amountEdit))) {
                                verifiedAmountToSendForTx = SEND_MAX;
                            }
                            tryToGenerateSpendingTransaction();
                        }
                    }
                };
                decodeUnspentOutputsInfoTask.execute();
            }
        } else {
            verifiedKeyPairForTx = null;
        }
    }

    private void onSendAmountChanged(String amountStr) {
        TextView amountError = findViewById(R.id.err_amount);
        if (TextUtils.isEmpty(amountStr)) {
            verifiedAmountToSendForTx = SEND_MAX;
            amountError.setText("");
            tryToGenerateSpendingTransaction();
        } else {
            try {
                double requestedAmountToSendDouble = Double.parseDouble(amountStr);
                long requestedAmountToSend = (long) (requestedAmountToSendDouble * 1e8);
                if (requestedAmountToSendDouble > 0 && requestedAmountToSendDouble < 21000000 && requestedAmountToSend > 0) {
                    verifiedAmountToSendForTx = requestedAmountToSend;
                    amountError.setText("");
                    tryToGenerateSpendingTransaction();
                } else {
                    verifiedAmountToSendForTx = AMOUNT_ERR;
                    amountError.setText(R.string.error_amount_parsing);
                }
            } catch (Exception e) {
                verifiedAmountToSendForTx = AMOUNT_ERR;
                amountError.setText(R.string.error_amount_parsing);
            }
        }
    }

    private static String getString(TextView textView) {
        CharSequence charSequence = textView.getText();
        return charSequence == null ? "" : charSequence.toString();
    }

    private void encryptOrDecryptPrivateKey() {
        final KeyPair inputKeyPair = currentKeyPair;
        final String password = getString(passwordEdit);
        if (inputKeyPair != null && !TextUtils.isEmpty(password)) {
            cancelAllRunningTasks();
            final boolean decrypting = inputKeyPair.privateKey.type == BTCUtils.Bip38PrivateKeyInfo.TYPE_BIP38 && inputKeyPair.privateKey.privateKeyDecoded == null;
            lastBip38ActionWasDecryption = decrypting;
            passwordButton.setEnabled(false);
            passwordButton.setText(decrypting ? R.string.decrypting : R.string.encrypting);
            InputMethodManager inputMethodManager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
            if (inputMethodManager != null) {
                inputMethodManager.hideSoftInputFromWindow(passwordEdit.getWindowToken(), 0);
            }

            bip38Task = new AsyncTask<Void, Void, Object>() {
                @Address.PublicKeyRepresentation
                int addressType;
                ProgressDialog dialog;
                boolean sendLayoutVisible;

                @Override
                protected void onPreExecute() {
                    super.onPreExecute();
                    dialog = ProgressDialog.show(MainActivity.this, "", (decrypting ?
                            getString(R.string.decrypting) : getString(R.string.encrypting)), true);
                    dialog.setCancelable(true);
                    dialog.setOnCancelListener(dialog -> {
                        if (bip38Task != null) {
                            bip38Task.cancel(true);
                            bip38Task = null;
                        }
                    });
                    sendLayoutVisible = sendLayout.isShown();
                    addressType = getSelectedPublicKeyRepresentation();
                }

                @Override
                protected Object doInBackground(Void... params) {
                    try {
                        if (decrypting) {
                            return BTCUtils.bip38Decrypt(inputKeyPair.privateKey.privateKeyEncoded, password, addressType);
                        } else {
                            String encryptedPrivateKey = BTCUtils.bip38Encrypt(inputKeyPair, password);
                            return new KeyPair(new BTCUtils.Bip38PrivateKeyInfo(encryptedPrivateKey,
                                    inputKeyPair.privateKey.privateKeyDecoded, password, inputKeyPair.privateKey.isPublicKeyCompressed), addressType);
                        }
                    } catch (Throwable th) {
                        return th;
                    }
                }

                @Override
                protected void onPostExecute(Object result) {
                    bip38Task = null;
                    dialog.dismiss();
                    if (result instanceof KeyPair) {
                        KeyPair keyPair = (KeyPair) result;
                        insertingPrivateKeyProgrammatically = true;
                        privateKeyTextEdit.setText(keyPair.privateKey.privateKeyEncoded);
                        insertingPrivateKeyProgrammatically = false;
                        onKeyPairModify(false, keyPair, addressType);
                        if (!decrypting) {
                            sendLayout.setVisibility(sendLayoutVisible ? View.VISIBLE : View.GONE);
                        }
                    } else {
                        onKeyPairModify(false, inputKeyPair, addressType);
                        String msg = null;
                        if (result instanceof Throwable) {
                            if (result instanceof OutOfMemoryError || nonNullStr(((Throwable) result).getMessage()).contains("OutOfMemory")) {
                                msg = getString(R.string.error_oom_bip38);
                            } else if (result instanceof BitcoinException && ((BitcoinException) result).errorCode == BitcoinException.ERR_INCORRECT_PASSWORD) {
                                ((TextView) findViewById(R.id.err_password)).setText(R.string.incorrect_password);
                            } else if (result instanceof BitcoinException && ((BitcoinException) result).errorCode == BitcoinException.ERR_WRONG_TYPE
                                    && decrypting && addressType != Address.PUBLIC_KEY_TO_ADDRESS_LEGACY) {
                                insertingAddressProgrammatically = true;
                                addressTextEdit.setText(R.string.no_segwit_address_uncompressed_public_key);
                                insertingAddressProgrammatically = false;
                            } else {
                                msg = ((Throwable) result).getMessage();
                                if (msg == null) {
                                    msg = result.toString();
                                }
                            }
                        }
                        if (msg != null && msg.length() > 0) {
                            new AlertDialog.Builder(MainActivity.this)
                                    .setMessage(msg)
                                    .setPositiveButton(android.R.string.ok, null)
                                    .show();
                        }
                    }
                }

                @Override
                protected void onCancelled() {
                    super.onCancelled();
                    bip38Task = null;
                    dialog.dismiss();
                    onKeyPairModify(false, currentKeyPair, addressType);
                }
            }.execute();
        }
    }

    @NonNull
    private static String nonNullStr(@Nullable String s) {
        return s == null ? "" : s;
    }

    private void showQRCodePopupForAddress(final String address) {
        DisplayMetrics dm = getResources().getDisplayMetrics();
        final int screenSize = Math.min(dm.widthPixels, dm.heightPixels);
        final String uriStr = SCHEME_BITCOIN + address;
        new AsyncTask<Void, Void, Bitmap>() {

            @Override
            protected Bitmap doInBackground(Void... params) {
                return QRCode.getMinimumQRCode(uriStr, ErrorCorrectLevel.M).createImage(screenSize / 2);
            }

            @Override
            protected void onPostExecute(final Bitmap bitmap) {
                if (bitmap != null) {
                    View view = getLayoutInflater().inflate(R.layout.address_qr, mainLayout, false);
                    if (view != null) {
                        final ImageView qrView = view.findViewById(R.id.qr_code_image);
                        qrView.setImageBitmap(bitmap);

                        final TextView bitcoinProtocolLinkView = view.findViewById(R.id.link1);
                        SpannableStringBuilder labelUri = new SpannableStringBuilder(uriStr);
                        ClickableSpan urlSpan = new ClickableSpan() {
                            @Override
                            public void onClick(@NonNull View widget) {
                                Intent intent = new Intent(Intent.ACTION_VIEW);
                                intent.setData(Uri.parse(uriStr));
                                try {
                                    startActivity(intent);
                                } catch (Exception e) {
                                    Toast.makeText(MainActivity.this, R.string.no_apps_to_view_url, Toast.LENGTH_LONG).show();
                                }
                            }
                        };
                        labelUri.setSpan(urlSpan, 0, labelUri.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
                        bitcoinProtocolLinkView.setText(labelUri);
                        bitcoinProtocolLinkView.setMovementMethod(getLinkMovementMethod());

                        final TextView blockexplorerLinkView = view.findViewById(R.id.link2);
                        SpannableStringBuilder blockexplorerLinkText = new SpannableStringBuilder("blockexplorer.com");
                        setUrlSpanForAddress("blockexplorer.com", address, blockexplorerLinkText);
                        blockexplorerLinkView.setText(blockexplorerLinkText);
                        blockexplorerLinkView.setMovementMethod(getLinkMovementMethod());

                        final TextView blockchainLinkView = view.findViewById(R.id.link3);
                        SpannableStringBuilder blockchainLinkText = new SpannableStringBuilder("blockchain.info");
                        setUrlSpanForAddress("blockchain.info", address, blockchainLinkText);
                        blockchainLinkView.setText(blockchainLinkText);
                        blockchainLinkView.setMovementMethod(getLinkMovementMethod());


                        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                        builder.setTitle(address);
                        builder.setView(view);
                        if (systemSupportsPrint()) {
                            builder.setPositiveButton(R.string.print, (dialog, which) ->
                                    Renderer.printQR(MainActivity.this, SCHEME_BITCOIN + address));
                            builder.setNegativeButton(android.R.string.cancel, null);
                        } else {
                            builder.setPositiveButton(android.R.string.ok, null);
                        }

                        builder.show();
                    }
                }
            }
        }.execute();
    }

    private MovementMethod getLinkMovementMethod() {
        return new LinkMovementMethod() {
            @Override
            public boolean onTouchEvent(TextView widget, Spannable buffer, MotionEvent event) {
                try {
                    return super.onTouchEvent(widget, buffer, event);
                } catch (Exception ex) {
                    Toast.makeText(MainActivity.this, getString(R.string.could_not_open_link, buffer.toString()), Toast.LENGTH_LONG).show();
                    return true;
                }
            }
        };
    }

    private void showQRCodePopupForPrivateKey(final String label, final String address, final String[] data, final String[] dataTypes) {
        DisplayMetrics dm = getResources().getDisplayMetrics();
        final int screenSize = Math.min(dm.widthPixels, dm.heightPixels);
        new AsyncTask<Void, Void, Bitmap[]>() {

            @Override
            protected Bitmap[] doInBackground(Void... params) {
                try {
                    Bitmap[] result = new Bitmap[data.length];
                    for (int i = 0; i < data.length; i++) {
                        if (data[i] != null) {
                            QRCode qr = QRCode.getMinimumQRCode(data[i], ErrorCorrectLevel.M);
                            result[i] = qr.createImage(screenSize / 2);
                        }
                    }
                    return result;
                } catch (Exception e) {
                    Log.w("QRCODE", "error", e);
                    return null;
                }
            }

            @Override
            protected void onPostExecute(final Bitmap[] bitmap) {
                if (bitmap != null) {
                    View view = getLayoutInflater().inflate(R.layout.private_key_qr, mainLayout, false);
                    if (view != null) {
                        final ToggleButton toggle1 = view.findViewById(R.id.toggle_1);
                        final ToggleButton toggle2 = view.findViewById(R.id.toggle_2);
                        final ToggleButton toggle3 = view.findViewById(R.id.toggle_3);
                        final ImageView qrView = view.findViewById(R.id.qr_code_image);
                        final TextView dataView = view.findViewById(R.id.qr_code_data);

                        if (data[0] == null) {
                            toggle1.setVisibility(View.GONE);
                        } else {
                            toggle1.setTextOff(dataTypes[0]);
                            toggle1.setTextOn(dataTypes[0]);
                            toggle1.setOnCheckedChangeListener((buttonView, isChecked) -> {
                                if (isChecked) {
                                    toggle2.setChecked(false);
                                    toggle3.setChecked(false);
                                    qrView.setImageBitmap(bitmap[0]);
                                    dataView.setText(data[0]);
                                } else if (!toggle2.isChecked() && !toggle3.isChecked()) {
                                    buttonView.setChecked(true);
                                }
                            });
                        }
                        if (data[1] == null) {
                            toggle2.setVisibility(View.GONE);
                        } else {
                            toggle2.setTextOff(dataTypes[1]);
                            toggle2.setTextOn(dataTypes[1]);
                            toggle2.setOnCheckedChangeListener((buttonView, isChecked) -> {
                                if (isChecked) {
                                    toggle1.setChecked(false);
                                    toggle3.setChecked(false);
                                    qrView.setImageBitmap(bitmap[1]);
                                    dataView.setText(data[1]);
                                } else if (!toggle1.isChecked() && !toggle3.isChecked()) {
                                    buttonView.setChecked(true);
                                }
                            });
                        }
                        if (data[2] == null) {
                            toggle3.setVisibility(View.GONE);
                        } else {
                            toggle3.setTextOff(dataTypes[2]);
                            toggle3.setTextOn(dataTypes[2]);
                            toggle3.setOnCheckedChangeListener((buttonView, isChecked) -> {
                                if (isChecked) {
                                    toggle1.setChecked(false);
                                    toggle2.setChecked(false);
                                    qrView.setImageBitmap(bitmap[2]);
                                    dataView.setText(data[2]);
                                } else if (!toggle1.isChecked() && !toggle2.isChecked()) {
                                    buttonView.setChecked(true);
                                }
                            });
                        }
                        if (data[2] != null) {
                            toggle3.setChecked(true);
                        } else if (data[0] != null) {
                            toggle1.setChecked(true);
                        } else {
                            toggle2.setChecked(true);
                        }

                        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                        builder.setTitle(label);
                        builder.setView(view);
                        DialogInterface.OnClickListener shareClickListener = (dialog, which) -> {
                            int selectedIndex;
                            if (toggle1.isChecked()) {
                                selectedIndex = 0;
                            } else if (toggle2.isChecked()) {
                                selectedIndex = 1;
                            } else {
                                selectedIndex = 2;
                            }
                            Intent intent = new Intent(Intent.ACTION_SEND);
                            intent.setType("text/plain");
                            intent.putExtra(Intent.EXTRA_SUBJECT, label);
                            intent.putExtra(Intent.EXTRA_TEXT, data[selectedIndex]);
                            startActivity(Intent.createChooser(intent, getString(R.string.share_chooser_title)));
                        };
                        if (systemSupportsPrint()) {
                            builder.setPositiveButton(R.string.print, (dialog, which) -> {
                                int selectedIndex;
                                if (toggle1.isChecked()) {
                                    selectedIndex = 0;
                                } else if (toggle2.isChecked()) {
                                    selectedIndex = 1;
                                } else {
                                    selectedIndex = 2;
                                }
                                Renderer.printWallet(MainActivity.this, label, SCHEME_BITCOIN + address, data[selectedIndex]);
                            });
                            builder.setNeutralButton(R.string.share, shareClickListener);
                        } else {
                            builder.setPositiveButton(R.string.share, shareClickListener);
                        }
                        builder.setNegativeButton(android.R.string.cancel, null);
                        builder.show();
                    }
                } else {
                    Toast.makeText(MainActivity.this, "ERROR", Toast.LENGTH_LONG).show();
                }
            }
        }.execute();
    }

    private static boolean systemSupportsPrint() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT;
    }

    private static int getColor(Context context, int id) {
        if (Build.VERSION.SDK_INT >= 23) {
            return context.getColor(id);
        } else {
            //noinspection deprecation
            return context.getResources().getColor(id);
        }
    }

    private void onNewKeyPairGenerated(KeyPair keyPair) {
        insertingAddressProgrammatically = true;
        if (keyPair != null && keyPair.address != null) {
            addressTextEdit.setText(keyPair.address.addressString);
            privateKeyTypeView.setVisibility(View.VISIBLE);
            privateKeyTypeView.setText(getPrivateKeyTypeLabel(keyPair));
            insertingPrivateKeyProgrammatically = true;
            privateKeyTextEdit.setText(keyPair.privateKey.privateKeyEncoded);
            insertingPrivateKeyProgrammatically = false;
        } else {
            privateKeyTypeView.setVisibility(View.GONE);
            addressTextEdit.setText(getString(R.string.generating_failed));
        }
        insertingAddressProgrammatically = false;
        updatePasswordView(keyPair);
        showSpendPanelForKeyPair(keyPair);
    }

    private void onKeyPairModify(boolean noPrivateKeyEntered, KeyPair keyPair, @Address.PublicKeyRepresentation int publicKeyRepresentation) {
        insertingAddressProgrammatically = true;
        if (keyPair != null) {
            if (keyPair.address != null && !TextUtils.isEmpty(keyPair.address.addressString)) {
                addressTextEdit.setText(keyPair.address.addressString);
            } else {
                if (keyPair.publicKey != null && keyPair.publicKey.length > 40 && publicKeyRepresentation != Address.PUBLIC_KEY_TO_ADDRESS_LEGACY) {
                    addressTextEdit.setText(R.string.no_segwit_address_uncompressed_public_key);
                } else {
                    addressTextEdit.setText(R.string.not_decrypted_yet);
                }
            }
            privateKeyTypeView.setVisibility(View.VISIBLE);
            privateKeyTypeView.setText(getPrivateKeyTypeLabel(keyPair));
        } else {
            privateKeyTypeView.setVisibility(View.GONE);
            addressTextEdit.setText(noPrivateKeyEntered ? "" : getString(R.string.bad_private_key));
        }
        insertingAddressProgrammatically = false;
        updatePasswordView(keyPair);
        showSpendPanelForKeyPair(keyPair);
    }

    private void updatePasswordView(KeyPair keyPair) {
        currentKeyPair = keyPair;
        String encodedPrivateKey = keyPair == null ? null : keyPair.privateKey.privateKeyEncoded;
        passwordButton.setEnabled(!TextUtils.isEmpty(passwordEdit.getText()) && !TextUtils.isEmpty(encodedPrivateKey));
        showQRCodePrivateKeyButton.setVisibility(keyPair == null ? View.GONE : View.VISIBLE);
        ((TextView) findViewById(R.id.err_password)).setText("");
        if (keyPair != null && keyPair.privateKey.type == BTCUtils.Bip38PrivateKeyInfo.TYPE_BIP38) {
            if (keyPair.privateKey.privateKeyDecoded == null) {
                passwordButton.setText(R.string.decrypt_private_key);
                passwordEdit.setImeActionLabel(getString(R.string.ime_decrypt), R.id.action_decrypt);
            } else {
                if (getString(passwordEdit).equals(((BTCUtils.Bip38PrivateKeyInfo) keyPair.privateKey).password)) {
                    passwordButton.setText(getString(lastBip38ActionWasDecryption ? R.string.decrypted : R.string.encrypted));
                    passwordButton.setEnabled(false);
                } else {
                    passwordButton.setText(getString(R.string.encrypt_private_key));
                    passwordButton.setEnabled(true);
                }
                passwordEdit.setImeActionLabel(getString(R.string.ime_encrypt), R.id.action_encrypt);
            }
            passwordEdit.setEnabled(true);
        } else if (keyPair != null && keyPair.privateKey.testNet) {
            passwordEdit.setEnabled(false);
        } else {
            passwordButton.setText(R.string.encrypt_private_key);
            passwordEdit.setImeActionLabel(getString(R.string.ime_encrypt), R.id.action_encrypt);
            passwordEdit.setEnabled(true);
        }
        onUnspentOutputsInfoChanged();
    }

    private void cancelAllRunningTasks() {
        if (bip38Task != null) {
            bip38Task.cancel(true);
            bip38Task = null;
        }
        if (addressGenerateTask != null) {
            addressGenerateTask.cancel(true);
            addressGenerateTask = null;
        }
        if (generateTransactionTask != null) {
            generateTransactionTask.cancel(true);
            generateTransactionTask = null;
        }
        if (switchingCompressionTypeTask != null) {
            switchingCompressionTypeTask.cancel(false);
            switchingCompressionTypeTask = null;
        }
        if (decodePrivateKeyTask != null) {
            decodePrivateKeyTask.cancel(true);
            decodePrivateKeyTask = null;
        }
        if (decodeUnspentOutputsInfoTask != null) {
            decodeUnspentOutputsInfoTask.cancel(true);
            decodeUnspentOutputsInfoTask = null;
        }
        if (switchingSegwitTask != null) {
            switchingSegwitTask.cancel(true);
            switchingSegwitTask = null;
        }
    }

    static class GenerateTransactionResult {
        static final int ERROR_SOURCE_UNKNOWN = 0;
        static final int ERROR_SOURCE_INPUT_TX_FIELD = 1;
        static final int ERROR_SOURCE_ADDRESS_FIELD = 2;
        static final int HINT_FOR_ADDRESS_FIELD = 3;
        static final int ERROR_SOURCE_AMOUNT_FIELD = 4;

        final Transaction btcTx, bchTx;
        final String errorMessage;
        final int errorSource;
        final long fee;

        GenerateTransactionResult(String errorMessage, int errorSource) {
            btcTx = null;
            bchTx = null;
            this.errorMessage = errorMessage;
            this.errorSource = errorSource;
            fee = -1;
        }

        GenerateTransactionResult(Transaction btcTx, @Nullable Transaction bchTx, long fee) {
            this.btcTx = btcTx;
            this.bchTx = bchTx;
            errorMessage = null;
            errorSource = ERROR_SOURCE_UNKNOWN;
            this.fee = fee;
        }
    }

    private void tryToGenerateSpendingTransaction() {
        final ArrayList<UnspentOutputInfo> unspentOutputs = verifiedUnspentOutputsForTx;
        final String outputAddress = verifiedRecipientAddressForTx;
        final long requestedAmountToSend = verifiedAmountToSendForTx;
        final KeyPair keyPair = verifiedKeyPairForTx;

        spendBtcTxDescriptionView.setVisibility(View.GONE);
        spendBchTxDescriptionView.setVisibility(View.GONE);
        spendTxWarningView.setVisibility(View.GONE);
        spendBtcTxEdit.setText("");
        spendBtcTxEdit.setVisibility(View.GONE);
        spendBchTxEdit.setText("");
        spendBchTxEdit.setVisibility(View.GONE);
        sendBtcTxInBrowserButton.setVisibility(View.GONE);
        sendBchTxInBrowserButton.setVisibility(View.GONE);
//        https://blockchain.info/pushtx

        if (unspentOutputs != null && !unspentOutputs.isEmpty() && !TextUtils.isEmpty(outputAddress) &&
                keyPair != null && keyPair.address != null && requestedAmountToSend >= SEND_MAX && requestedAmountToSend != 0
                && !TextUtils.isEmpty(keyPair.address.addressString)) {
            cancelAllRunningTasks();
            generateTransactionTask = new AsyncTask<Void, Void, GenerateTransactionResult>() {

                @Override
                protected GenerateTransactionResult doInBackground(Void... voids) {
                    Transaction btcSpendTx;
                    Transaction bchSpendTx = null;
                    try {
                        long availableAmount = 0;
                        for (UnspentOutputInfo unspentOutputInfo : unspentOutputs) {
                            availableAmount += unspentOutputInfo.value;
                        }
                        long amount;
                        if (availableAmount == requestedAmountToSend || requestedAmountToSend == SEND_MAX) {
                            //transfer maximum possible amount
                            amount = -1;
                        } else {
                            amount = requestedAmountToSend;
                        }
                        float satoshisPerVirtualByte;
                        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
                        try {
                            satoshisPerVirtualByte = preferences.getInt(PreferencesActivity.PREF_FEE_SAT_BYTE, FeePreference.PREF_FEE_SAT_BYTE_DEFAULT);
                        } catch (ClassCastException e) {
                            preferences.edit()
                                    .remove(PreferencesActivity.PREF_FEE_SAT_BYTE)
                                    .putInt(PreferencesActivity.PREF_FEE_SAT_BYTE, FeePreference.PREF_FEE_SAT_BYTE_DEFAULT).apply();
                            satoshisPerVirtualByte = FeePreference.PREF_FEE_SAT_BYTE_DEFAULT;
                        }
                        //Always try to use segwit here even if it's disabled since the switch is only about generated address type
                        //Do we need another switch to disable segwit in tx?
                        btcSpendTx = BTCUtils.createTransaction(unspentOutputs,
                                outputAddress, keyPair.address.addressString, amount, satoshisPerVirtualByte, BTCUtils.TRANSACTION_TYPE_SEGWIT
                        );
                        try {
                            Address outputAddressDecoded = Address.decode(outputAddress);
                            if (outputAddressDecoded != null && outputAddressDecoded.keyhashType != Address.TYPE_P2SH) { //this check prevents sending BCH to SegWit
                                bchSpendTx = BTCUtils.createTransaction(unspentOutputs,
                                        outputAddress, keyPair.address.addressString, amount, satoshisPerVirtualByte, BTCUtils.TRANSACTION_TYPE_BITCOIN_CASH);
                            }
                        } catch (Exception ignored) {
                        }

                        //6. double check that generated transaction is valid
                        Transaction.Script[] relatedScripts = new Transaction.Script[btcSpendTx.inputs.length];
                        long[] amounts = new long[btcSpendTx.inputs.length];
                        for (int i = 0; i < btcSpendTx.inputs.length; i++) {
                            Transaction.Input input = btcSpendTx.inputs[i];
                            for (UnspentOutputInfo unspentOutput : unspentOutputs) {
                                if (Arrays.equals(unspentOutput.txHash, input.outPoint.hash) && unspentOutput.outputIndex == input.outPoint.index) {
                                    relatedScripts[i] = unspentOutput.scriptPubKey;
                                    amounts[i] = unspentOutput.value;
                                    break;
                                }
                            }
                        }
                        BTCUtils.verify(relatedScripts, amounts, btcSpendTx, false);
                        if (bchSpendTx != null) {
                            BTCUtils.verify(relatedScripts, amounts, bchSpendTx, true);
                        }
                    } catch (BitcoinException e) {
                        switch (e.errorCode) {
                            case BitcoinException.ERR_INSUFFICIENT_FUNDS:
                                return new GenerateTransactionResult(getString(R.string.error_not_enough_funds), GenerateTransactionResult.ERROR_SOURCE_AMOUNT_FIELD);
                            case BitcoinException.ERR_FEE_IS_TOO_BIG:
                                return new GenerateTransactionResult(getString(R.string.generated_tx_have_too_big_fee), GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD);
                            case BitcoinException.ERR_AMOUNT_TO_SEND_IS_LESS_THEN_ZERO:
                                return new GenerateTransactionResult(getString(R.string.fee_is_greater_than_available_balance), GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD);
                            case BitcoinException.ERR_MEANINGLESS_OPERATION://input, output and change addresses are same.
                                return new GenerateTransactionResult(getString(R.string.output_address_same_as_input), GenerateTransactionResult.ERROR_SOURCE_ADDRESS_FIELD);
//                            case BitcoinException.ERR_INCORRECT_PASSWORD
//                            case BitcoinException.ERR_WRONG_TYPE:
//                            case BitcoinException.ERR_FEE_IS_LESS_THEN_ZERO
//                            case BitcoinException.ERR_CHANGE_IS_LESS_THEN_ZERO
//                            case BitcoinException.ERR_AMOUNT_TO_SEND_IS_LESS_THEN_ZERO
                            default:
                                return new GenerateTransactionResult(getString(R.string.error_failed_to_create_transaction) + ": " + e.getMessage(), GenerateTransactionResult.ERROR_SOURCE_UNKNOWN);
                        }
                    } catch (Exception e) {
                        return new GenerateTransactionResult(getString(R.string.error_failed_to_create_transaction) + ": " + e, GenerateTransactionResult.ERROR_SOURCE_UNKNOWN);
                    }

                    long inValue = 0;
                    for (Transaction.Input input : btcSpendTx.inputs) {
                        for (UnspentOutputInfo unspentOutput : unspentOutputs) {
                            if (Arrays.equals(unspentOutput.txHash, input.outPoint.hash) && unspentOutput.outputIndex == input.outPoint.index) {
                                inValue += unspentOutput.value;
                            }
                        }
                    }
                    long outValue = 0;
                    for (Transaction.Output output : btcSpendTx.outputs) {
                        outValue += output.value;
                    }
                    long fee = inValue - outValue;
                    return new GenerateTransactionResult(btcSpendTx, bchSpendTx, fee);
                }

                @Override
                protected void onPostExecute(GenerateTransactionResult result) {
                    super.onPostExecute(result);
                    generateTransactionTask = null;
                    if (result != null) {
                        final TextView rawTxToSpendError = findViewById(R.id.err_raw_tx);
                        if (result.btcTx != null) {
                            String amountStr = null;
                            Transaction.Script out = null;
                            try {
                                out = Transaction.Script.buildOutput(outputAddress);
                            } catch (BitcoinException ignore) {
                            }
                            if (result.btcTx.outputs[0].scriptPubKey.equals(out)) {
                                amountStr = BTCUtils.formatValue(result.btcTx.outputs[0].value);
                            }
                            if (amountStr == null) {
                                rawTxToSpendError.setText(R.string.error_unknown);
                            } else {
                                String feeStr = BTCUtils.formatValue(result.fee);
                                SpannableStringBuilder descBuilderBtc = getTxDescription(amountStr, result.btcTx.outputs, feeStr,
                                        false, keyPair, outputAddress);
                                SpannableStringBuilder descBuilderBch = result.bchTx == null ? null :
                                        getTxDescription(amountStr, result.bchTx.outputs, feeStr,
                                                true, keyPair, outputAddress);
                                spendBtcTxDescriptionView.setText(descBuilderBtc);
                                spendBtcTxDescriptionView.setVisibility(View.VISIBLE);
                                if (descBuilderBch != null) {
                                    spendBchTxDescriptionView.setText(descBuilderBch);
                                    spendBchTxDescriptionView.setVisibility(View.VISIBLE);
                                } else {
                                    spendBchTxDescriptionView.setVisibility(View.GONE);
                                }
                                spendTxWarningView.setVisibility(View.VISIBLE);
                                spendBtcTxEdit.setText(BTCUtils.toHex(result.btcTx.getBytes()));
                                spendBtcTxEdit.setVisibility(View.VISIBLE);
                                if (result.bchTx != null) {
                                    spendBchTxEdit.setText(BTCUtils.toHex(result.bchTx.getBytes()));
                                    spendBchTxEdit.setVisibility(View.VISIBLE);
                                } else {
                                    spendBchTxEdit.setVisibility(View.GONE);
                                }
                                sendBtcTxInBrowserButton.setVisibility(View.VISIBLE);
                                sendBchTxInBrowserButton.setVisibility(result.bchTx != null ? View.VISIBLE : View.GONE);
                            }
                        } else if (result.errorSource == GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD) {
                            rawTxToSpendError.setText(result.errorMessage);
                        } else if (result.errorSource == GenerateTransactionResult.ERROR_SOURCE_ADDRESS_FIELD ||
                                result.errorSource == GenerateTransactionResult.HINT_FOR_ADDRESS_FIELD) {
                            ((TextView) findViewById(R.id.err_recipient_address)).setText(result.errorMessage);
                        } else if (!TextUtils.isEmpty(result.errorMessage) && result.errorSource == GenerateTransactionResult.ERROR_SOURCE_UNKNOWN) {
                            new AlertDialog.Builder(MainActivity.this)
                                    .setMessage(result.errorMessage)
                                    .setPositiveButton(android.R.string.ok, null)
                                    .show();
                        }

                        ((TextView) findViewById(R.id.err_amount)).setText(
                                result.errorSource == GenerateTransactionResult.ERROR_SOURCE_AMOUNT_FIELD ? result.errorMessage : "");
                    }
                }

            }.execute();
        }
    }

    @NonNull
    private SpannableStringBuilder getTxDescription(String amountStr, Transaction.Output[] outputs, String feeStr, boolean bitcoinCash, KeyPair keyPair, String outputAddress) {
        String changeStr;
        String descStr;
        if (outputs.length == 1) {
            changeStr = null;
            descStr = getString(bitcoinCash ? R.string.spend_bch_tx_description : R.string.spend_btc_tx_description,
                    amountStr,
                    keyPair.address,
                    outputAddress,
                    feeStr
            );
        } else if (outputs.length == 2) {
            changeStr = BTCUtils.formatValue(outputs[1].value);
            descStr = getString(bitcoinCash ? R.string.spend_bch_tx_with_change_description : R.string.spend_btc_tx_with_change_description,
                    amountStr,
                    keyPair.address,
                    outputAddress,
                    feeStr,
                    changeStr
            );
        } else {
            throw new RuntimeException();
        }
        String btcBch = bitcoinCash ? "BCH" : "BTC";
        SpannableStringBuilder descBuilderBtc = new SpannableStringBuilder(descStr);

        int spanBegin = keyPair.address == null ? -1 : descStr.indexOf(keyPair.address.addressString);
        if (spanBegin >= 0) {//from
            ForegroundColorSpan addressColorSpan = new ForegroundColorSpan(getColor(MainActivity.this, R.color.dark_orange));
            descBuilderBtc.setSpan(addressColorSpan, spanBegin, spanBegin + keyPair.address.addressString.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
        }
        if (spanBegin >= 0) {
            spanBegin = descStr.indexOf(keyPair.address.addressString, spanBegin + 1);
            if (spanBegin >= 0) {//change
                ForegroundColorSpan addressColorSpan = new ForegroundColorSpan(getColor(MainActivity.this, R.color.dark_orange));
                descBuilderBtc.setSpan(addressColorSpan, spanBegin, spanBegin + keyPair.address.addressString.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
            }
        }
        spanBegin = descStr.indexOf(outputAddress);
        if (spanBegin >= 0) {//dest
            ForegroundColorSpan addressColorSpan = new ForegroundColorSpan(getColor(MainActivity.this, R.color.dark_green));
            descBuilderBtc.setSpan(addressColorSpan, spanBegin, spanBegin + outputAddress.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
        }
        final String nbspBtc = "\u00a0" + btcBch;
        spanBegin = descStr.indexOf(amountStr + nbspBtc);
        if (spanBegin >= 0) {
            descBuilderBtc.setSpan(new StyleSpan(Typeface.BOLD), spanBegin, spanBegin + amountStr.length() + nbspBtc.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
        }
        spanBegin = descStr.indexOf(feeStr + nbspBtc, spanBegin);
        if (spanBegin >= 0) {
            descBuilderBtc.setSpan(new StyleSpan(Typeface.BOLD), spanBegin, spanBegin + feeStr.length() + nbspBtc.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
        }
        if (changeStr != null) {
            spanBegin = descStr.indexOf(changeStr + nbspBtc, spanBegin);
            if (spanBegin >= 0) {
                descBuilderBtc.setSpan(new StyleSpan(Typeface.BOLD), spanBegin, spanBegin + changeStr.length() + nbspBtc.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
            }
        }
        return descBuilderBtc;
    }

    @Override
    public void onConfigurationChanged(@NonNull Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        addressTextEdit.setMinLines(1);
        privateKeyTextEdit.setMinLines(1);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            startActivity(new Intent(this, Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB ?
                    PreferencesActivity.class : PreferencesActivityForOlderDevices.class));
            return true;
        } else {
            return super.onOptionsItemSelected(item);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == RESULT_OK) {
            String scannedResult = data.getStringExtra("data");
            String address = scannedResult;
            String privateKey = scannedResult;
            String amount = null;
            String message = "";
            if (scannedResult != null && scannedResult.startsWith(SCHEME_BITCOIN)) {
                scannedResult = scannedResult.substring(SCHEME_BITCOIN.length());
                while (scannedResult.startsWith("/")) {
                    scannedResult = scannedResult.substring(1);
                }
                privateKey = "";
                int queryStartIndex = scannedResult.indexOf('?');
                if (queryStartIndex == -1) {
                    address = scannedResult;
                } else {
                    address = scannedResult.substring(0, queryStartIndex);
                    while (address.endsWith("/")) {
                        address = address.substring(0, address.length() - 1);
                    }
                    String queryStr = scannedResult.substring(queryStartIndex + 1);
                    Map<String, String> query = splitQuery(queryStr);
                    String amountStr = query.get("amount");
                    if (!TextUtils.isEmpty(amountStr)) {
                        try {
                            amount = BTCUtils.formatValue(BTCUtils.parseValue(amountStr));
                        } catch (NumberFormatException e) {
                            Log.e("PaperWallet", "unable to parse " + amountStr);
                        }
                    }
                    StringBuilder messageSb = new StringBuilder();
                    String label = query.get("label");
                    if (!TextUtils.isEmpty(label)) {
                        messageSb.append(label);
                    }
                    String messageParam = query.get("message");
                    if (!TextUtils.isEmpty(messageParam)) {
                        if (messageSb.length() > 0) {
                            messageSb.append(": ");
                        }
                        messageSb.append(messageParam);
                    }
                    message = messageSb.toString();
                }
            }
            if (requestCode == REQUEST_SCAN_PRIVATE_KEY) {
                if (!TextUtils.isEmpty(privateKey)) {
                    privateKeyTextEdit.setText(privateKey);
                }
            } else if (requestCode == REQUEST_SCAN_RECIPIENT_ADDRESS) {
                recipientAddressView.setText(address);
                if (!TextUtils.isEmpty(amount)) {
                    amountEdit.setText(amount);
                }
                if (!TextUtils.isEmpty(message)) {
                    Toast.makeText(MainActivity.this, message, message.length() > 20 ? Toast.LENGTH_LONG : Toast.LENGTH_SHORT).show();
                }
            }
        }
    }

    private static final String SCHEME_BITCOIN = "bitcoin:";

    private static Map<String, String> splitQuery(String query) {
        Map<String, String> query_pairs = new LinkedHashMap<>();
        String[] pairs = query.split("&");
        try {
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return query_pairs;
    }

    @Address.PublicKeyRepresentation
    @MainThread
    private int getSelectedPublicKeyRepresentation() {
        return segwitAddressSwitch.isChecked() ?
                Address.PUBLIC_KEY_TO_ADDRESS_P2WKH : Address.PUBLIC_KEY_TO_ADDRESS_LEGACY;
    }

    private void generateNewAddress() {
        cancelAllRunningTasks();
        if (addressGenerateTask == null) {
            insertingPrivateKeyProgrammatically = true;
            setTextWithoutJumping(privateKeyTextEdit, "");
            insertingPrivateKeyProgrammatically = false;
            insertingAddressProgrammatically = true;
            setTextWithoutJumping(addressTextEdit, getString(R.string.generating));
            insertingAddressProgrammatically = false;
            addressGenerateTask = new AsyncTask<Void, Void, KeyPair>() {
                @Address.PublicKeyRepresentation
                int addressType;

                @Override
                protected void onPreExecute() {
                    addressType = getSelectedPublicKeyRepresentation();
                }

                @Override
                protected KeyPair doInBackground(Void... params) {
                    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
                    String privateKeyType = preferences.getString(PreferencesActivity.PREF_PRIVATE_KEY, PreferencesActivity.PREF_PRIVATE_KEY_WIF_COMPRESSED);
                    if (privateKeyType != null) {
                        switch (privateKeyType) {
                            case PreferencesActivity.PREF_PRIVATE_KEY_WIF_COMPRESSED:
                                return BTCUtils.generateWifKey(false, addressType);
                            case PreferencesActivity.PREF_PRIVATE_KEY_MINI:
                                return BTCUtils.generateMiniKey(addressType);
                            case PreferencesActivity.PREF_PRIVATE_KEY_WIF_TEST_NET:
                                return BTCUtils.generateWifKey(true, addressType);
                        }
                    }
                    return null;
                }

                @Override
                protected void onPostExecute(final KeyPair key) {
                    addressGenerateTask = null;
                    onNewKeyPairGenerated(key);
                }
            }.execute();
        }
    }

    private void setTextWithoutJumping(EditText editText, String text) {
        int lineCountBefore = editText.getLineCount();
        editText.setText(text);
        if (editText.getLineCount() < lineCountBefore) {
            editText.setMinLines(lineCountBefore);
        }
    }

    private CharSequence getPrivateKeyTypeLabel(final KeyPair keyPair) {
        int typeWithCompression = keyPair.privateKey.type == BTCUtils.PrivateKeyInfo.TYPE_BRAIN_WALLET && keyPair.privateKey.isPublicKeyCompressed ?
                keyPair.privateKey.type + 1 : keyPair.privateKey.type;
        CharSequence keyType = getResources().getTextArray(R.array.private_keys_types)[typeWithCompression];
        if (keyPair.privateKey.testNet) {
            keyType = getString(R.string.testnet_type_prefix) + ", " + keyType;
        }
        SpannableString keyTypeLabel = new SpannableString(getString(R.string.private_key_type, keyType));
        int keyTypeStart = keyTypeLabel.toString().indexOf(keyType.toString());
        keyTypeLabel.setSpan(new StyleSpan(Typeface.BOLD), keyTypeStart, keyTypeStart + keyType.length(),
                SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
        int addressType = getSelectedPublicKeyRepresentation();
        if (keyPair.privateKey.type == BTCUtils.PrivateKeyInfo.TYPE_BRAIN_WALLET &&
                (addressType == Address.PUBLIC_KEY_TO_ADDRESS_LEGACY ||
                        !keyPair.privateKey.isPublicKeyCompressed)) {
            String compressionStrToSpan = keyType.toString().substring(keyType.toString().indexOf(',') + 2);
            int start = keyTypeLabel.toString().indexOf(compressionStrToSpan);
            if (start >= 0) {
                ClickableSpan switchPublicKeyCompressionSpan = new ClickableSpan() {
                    @Override
                    public void onClick(@NonNull View widget) {
                        cancelAllRunningTasks();
                        switchingCompressionTypeTask = new AsyncTask<Void, Void, KeyPair>() {

                            @Override
                            protected KeyPair doInBackground(Void... params) {
                                return new KeyPair(new BTCUtils.PrivateKeyInfo(keyPair.privateKey.testNet,
                                        keyPair.privateKey.type, keyPair.privateKey.privateKeyEncoded,
                                        keyPair.privateKey.privateKeyDecoded, !keyPair.privateKey.isPublicKeyCompressed),
                                        addressType);
                            }

                            @Override
                            protected void onPostExecute(KeyPair keyPair) {
                                switchingCompressionTypeTask = null;
                                onKeyPairModify(false, keyPair, addressType);
                            }
                        };
                        switchingCompressionTypeTask.execute();
                    }
                };
                keyTypeLabel.setSpan(switchPublicKeyCompressionSpan, start, start + compressionStrToSpan.length(),
                        SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
            }
        }
        return keyTypeLabel;
    }

    private void showSpendPanelForKeyPair(KeyPair keyPair) {
        if (keyPair != null && keyPair.privateKey.privateKeyDecoded == null) {
            keyPair = null;
        }
        boolean hasAddress = keyPair != null && keyPair.address != null && !TextUtils.isEmpty(keyPair.address.addressString);
        if (hasAddress) {
            currentKeyPair = keyPair;
            final String address = keyPair.address.addressString;
            String descStr = getString(R.string.raw_tx_description_header, address);
            SpannableStringBuilder builder = new SpannableStringBuilder(descStr);
            int spanBegin = descStr.indexOf(address);
            if (spanBegin >= 0) {
                ForegroundColorSpan addressColorSpan = new ForegroundColorSpan(getColor(MainActivity.this, R.color.dark_orange));
                builder.setSpan(addressColorSpan, spanBegin, spanBegin + address.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
            }
            rawTxDescriptionHeaderView.setText(builder);
            String wutLink = getString(R.string.raw_tx_description_wut_link);
            String jsonLink = getString(R.string.raw_tx_description_json_link);
            builder = new SpannableStringBuilder(getString(R.string.raw_tx_description, wutLink));
            if (!keyPair.privateKey.testNet && keyPair.address.keyhashType != Address.TYPE_NONE) {
                builder.append("\n\n");
                builder.append(getString(R.string.raw_tx_description_2, jsonLink));
            }

            spanBegin = builder.toString().indexOf(wutLink);
            ClickableSpan urlSpan = new ClickableSpan() {
                @Override
                public void onClick(@NonNull View widget) {
                    SpannableStringBuilder builder = new SpannableStringBuilder(getText(R.string.raw_tx_description_wut));
                    setUrlSpanForAddress("blockexplorer.com", address, builder);
                    setUrlSpanForAddress("blockchain.info", address, builder);
                    TextView messageView = new TextView(new ContextThemeWrapper(MainActivity.this, R.style.DialogTheme));
                    messageView.setText(builder);
                    messageView.setMovementMethod(getLinkMovementMethod());
                    int padding = (int) (16 * (getResources().getDisplayMetrics().densityDpi / 160f));
                    messageView.setPadding(padding, padding, padding, padding);
                    new AlertDialog.Builder(MainActivity.this)
                            .setView(messageView)
                            .setPositiveButton(android.R.string.ok, null)
                            .show();
                }
            };
            builder.setSpan(urlSpan, spanBegin, spanBegin + wutLink.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);

            if (!keyPair.privateKey.testNet) {
                spanBegin = builder.toString().indexOf(jsonLink);
                if (spanBegin >= 0) {
                    urlSpan = new URLSpan("https://blockchain.info/unspent?active=" + address);
                    builder.setSpan(urlSpan, spanBegin, spanBegin + jsonLink.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
                }
            }

            rawTxDescriptionView.setText(builder);
            rawTxDescriptionView.setMovementMethod(getLinkMovementMethod());
            onUnspentOutputsInfoChanged();
        }
        sendLayout.setVisibility(hasAddress ? View.VISIBLE : View.GONE);
        enterPrivateKeyAck.setVisibility(keyPair == null ? View.VISIBLE : View.GONE);
    }

    private static void setUrlSpanForAddress(String domain, String address, SpannableStringBuilder builder) {
        int spanBegin = builder.toString().indexOf(domain);
        if (spanBegin >= 0) {
            URLSpan urlSpan = new URLSpan("https://" + domain + "/address/" + address);
            builder.setSpan(urlSpan, spanBegin, spanBegin + domain.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        cancelAllRunningTasks();
    }
}
