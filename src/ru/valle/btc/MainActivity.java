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
import android.graphics.Typeface;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v4.print.PrintHelper;
import android.text.Editable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.LinkMovementMethod;
import android.text.style.ClickableSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.text.style.URLSpan;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
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
    private TextView spendTxDescriptionView;
    private View spendTxWarningView;
    private TextView spendTxEdit;
    private View generateButton;

    private boolean insertingPrivateKeyProgrammatically, insertingAddressProgrammatically;
    private AsyncTask<Void, Void, KeyPair> addressGenerateTask;
    private AsyncTask<Void, Void, GenerateTransactionResult> generateTransactionTask;
    private AsyncTask<Void, Void, KeyPair> switchingCompressionTypeTask;
    private AsyncTask<Void, Void, KeyPair> decodePrivateKeyTask;
    private AsyncTask<Void, Void, Object> bip38Task;
    private AsyncTask<Void, Void, ArrayList<UnspentOutputInfo>> decodeUnspentOutputsInfoTask;

    private KeyPair currentKeyPair;
    private View scanPrivateKeyButton, scanRecipientAddressButton;
    private View showQRCodeAddressButton, showQRCodePrivateKeyButton;
    private View enterPrivateKeyAck;
    private View rawTxToSpendPasteButton;
    private Runnable clipboardListener;
    private View sendTxInBrowserButton;
    private TextView passwordButton;
    private EditText passwordEdit;
    private boolean lastBip38ActionWasDecryption;
    private ClipboardHelper clipboardHelper;

    //collected information for tx generation:
    private String verifiedRecipientAddressForTx;
    private KeyPair verifiedKeyPairForTx;
    private ArrayList<UnspentOutputInfo> verifiedUnspentOutputsForTx;
    private long verifiedAmountToSendForTx;
    private boolean verifiedUnspentOutputsComesFromJson;
    private int verifiedConfirmationsCount = -1;


    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }
        addressTextEdit = (EditText) findViewById(R.id.address_label);
        generateButton = findViewById(R.id.generate_button);
        privateKeyTypeView = (TextView) findViewById(R.id.private_key_type_label);
        privateKeyTypeView.setMovementMethod(LinkMovementMethod.getInstance());
        privateKeyTextEdit = (EditText) findViewById(R.id.private_key_label);
        passwordButton = (TextView) findViewById(R.id.password_button);
        passwordEdit = (EditText) findViewById(R.id.password_edit);

        sendLayout = findViewById(R.id.send_layout);
        rawTxToSpendPasteButton = findViewById(R.id.paste_tx_button);
        rawTxToSpendEdit = (EditText) findViewById(R.id.raw_tx);
        recipientAddressView = (EditText) findViewById(R.id.recipient_address);
        amountEdit = (EditText) findViewById(R.id.amount);
        rawTxDescriptionHeaderView = (TextView) findViewById(R.id.raw_tx_description_header);
        rawTxDescriptionView = (TextView) findViewById(R.id.raw_tx_description);
        spendTxDescriptionView = (TextView) findViewById(R.id.spend_tx_description);
        spendTxWarningView = findViewById(R.id.spend_tx_warning_footer);
        spendTxEdit = (TextView) findViewById(R.id.spend_tx);
        sendTxInBrowserButton = findViewById(R.id.send_tx_button);
        scanPrivateKeyButton = findViewById(R.id.scan_private_key_button);
        showQRCodeAddressButton = findViewById(R.id.qr_address_button);
        showQRCodePrivateKeyButton = findViewById(R.id.qr_private_key_button);
        scanRecipientAddressButton = findViewById(R.id.scan_recipient_address_button);
        enterPrivateKeyAck = findViewById(R.id.enter_private_key_to_spend_desc);

        wireListeners();
        generateNewAddress();
    }


    @Override
    protected void onResume() {
        super.onResume();

        CharSequence textInClipboard = getTextInClipboard();
        boolean hasTextInClipboard = !TextUtils.isEmpty(textInClipboard);
        if (Build.VERSION.SDK_INT >= 11) {
            if (!hasTextInClipboard) {
                clipboardListener = new Runnable() {
                    @Override
                    public void run() {
                        rawTxToSpendPasteButton.setEnabled(!TextUtils.isEmpty(getTextInClipboard()));
                    }
                };
                clipboardHelper.runOnClipboardChange(clipboardListener);
            }
            rawTxToSpendPasteButton.setEnabled(hasTextInClipboard);
        } else {
            rawTxToSpendPasteButton.setVisibility(hasTextInClipboard ? View.VISIBLE : View.GONE);
        }
    }

    @SuppressLint("NewApi")
    @Override
    protected void onPause() {
        super.onPause();
        if (Build.VERSION.SDK_INT >= 11 && clipboardListener != null) {
            clipboardHelper.removeClipboardListener(clipboardListener);
        }
    }

    @SuppressWarnings("deprecation")
    private String getTextInClipboard() {
        CharSequence textInClipboard = "";
        if (Build.VERSION.SDK_INT >= 11) {
            if (clipboardHelper.hasTextInClipboard()) {
                textInClipboard = clipboardHelper.getTextInClipboard();
            }
        } else {
            android.text.ClipboardManager clipboard = (android.text.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard.hasText()) {
                textInClipboard = clipboard.getText();
            }
        }
        return textInClipboard == null ? "" : textInClipboard.toString();
    }

    @SuppressWarnings("deprecation")
    private void copyTextToClipboard(String label, String text) {
        if (Build.VERSION.SDK_INT >= 11) {
            clipboardHelper.copyTextToClipboard(label, text);
        } else {
            android.text.ClipboardManager clipboard = (android.text.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setText(text);
        }
    }

    @SuppressLint("NewApi")
    private void wireListeners() {
        if (Build.VERSION.SDK_INT >= 11) {
            clipboardHelper = new ClipboardHelper(this);
        }
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
                showQRCodeAddressButton.setVisibility(!TextUtils.isEmpty(s) && BTCUtils.verifyBitcoinAddress(s.toString()) ? View.VISIBLE : View.GONE);
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });
        generateButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                generateNewAddress();
            }
        });
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
                            @Override
                            protected KeyPair doInBackground(Void... params) {
                                try {
                                    BTCUtils.PrivateKeyInfo privateKeyInfo = BTCUtils.decodePrivateKey(privateKeyToDecode);
                                    if (privateKeyInfo != null) {
                                        return new KeyPair(privateKeyInfo);
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
                                onKeyPairModify(false, keyPair);
                            }
                        };
                        decodePrivateKeyTask.execute();
                    } else {
                        onKeyPairModify(true, null);
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

        passwordEdit.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                if (actionId == R.id.action_encrypt || actionId == R.id.action_decrypt) {
                    encryptOrDecryptPrivateKey();
                    return true;
                }
                return false;
            }
        });
        passwordButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                encryptOrDecryptPrivateKey();
            }
        });
        rawTxToSpendPasteButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                rawTxToSpendEdit.setText(getTextInClipboard());
            }
        });
        rawTxToSpendEdit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                verifiedConfirmationsCount = -1;
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
        scanPrivateKeyButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivityForResult(new Intent(MainActivity.this, ScanActivity.class), REQUEST_SCAN_PRIVATE_KEY);
            }
        });
        showQRCodeAddressButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showQRCodePopupForAddress(getString(addressTextEdit));
            }
        });
        showQRCodePrivateKeyButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
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
                            BTCUtils.getPrivateKeyBytes(currentKeyPair.privateKey.privateKeyDecoded));
                }
                showQRCodePopupForPrivateKey(getString(R.string.private_key_for, currentKeyPair.address), currentKeyPair.address, privateKeys, dataTypes);
            }
        });
        scanRecipientAddressButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivityForResult(new Intent(MainActivity.this, ScanActivity.class), REQUEST_SCAN_RECIPIENT_ADDRESS);
            }
        });
        sendTxInBrowserButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                copyTextToClipboard(getString(R.string.tx_description_for_clipboard, amountEdit.getText(), recipientAddressView.getText()), getString(spendTxEdit));
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://blockchain.info/pushtx")));
            }
        });

        if (Build.VERSION.SDK_INT < 8 || !EclairHelper.canScan(this)) {
            scanPrivateKeyButton.setVisibility(View.GONE);
            scanRecipientAddressButton.setVisibility(View.GONE);
        }
    }

    private void onRecipientAddressChanged() {
        String addressStr = getString(recipientAddressView);
        TextView recipientAddressError = (TextView) findViewById(R.id.err_recipient_address);
        if (BTCUtils.verifyBitcoinAddress(addressStr)) {
            if (verifiedKeyPairForTx != null && addressStr.equals(verifiedKeyPairForTx.address)) {
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
            if (!TextUtils.isEmpty(verifiedRecipientAddressForTx) && verifiedRecipientAddressForTx.equals(verifiedKeyPairForTx.address)) {
                ((TextView) findViewById(R.id.err_recipient_address)).setText(R.string.output_address_same_as_input);
            }
            final TextView rawTxToSpendErr = (TextView) findViewById(R.id.err_raw_tx);
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
                            byte[] outputScriptWeAreAbleToSpend = Transaction.Script.buildOutput(keyPair.address).bytes;
                            ArrayList<UnspentOutputInfo> unspentOutputs = new ArrayList<UnspentOutputInfo>();
                            //1. decode tx or json
                            byte[] rawTx = BTCUtils.fromHex(unspentOutputsInfoStr.trim());
                            if (rawTx != null) {
                                Transaction baseTx = new Transaction(rawTx);
                                byte[] rawTxReconstructed = baseTx.getBytes();
                                if (!Arrays.equals(rawTxReconstructed, rawTx)) {
                                    throw new IllegalArgumentException("Unable to decode given transaction");
                                }
                                jsonInput = false;
                                byte[] txHash = BTCUtils.reverse(BTCUtils.doubleSha256(rawTx));
                                for (int outputIndex = 0; outputIndex < baseTx.outputs.length; outputIndex++) {
                                    Transaction.Output output = baseTx.outputs[outputIndex];
                                    if (Arrays.equals(outputScriptWeAreAbleToSpend, output.script.bytes)) {
                                        unspentOutputs.add(new UnspentOutputInfo(txHash, output.script, output.value, outputIndex, verifiedConfirmationsCount));
                                    }
                                }
                            } else {

                                String jsonStr = unspentOutputsInfoStr.replace((char) 160, ' ').trim();//remove nbsp
                                JSONObject jsonObject = new JSONObject(jsonStr);
                                jsonInput = true;
                                JSONArray unspentOutputsArray = jsonObject.getJSONArray("unspent_outputs");
                                if (unspentOutputsArray == null) {
                                    jsonParseError = getString(R.string.json_err_no_unspent_outputs);
                                    return null;
                                }
                                for (int i = 0; i < unspentOutputsArray.length(); i++) {
                                    JSONObject unspentOutput = unspentOutputsArray.getJSONObject(i);
                                    byte[] txHash = BTCUtils.reverse(BTCUtils.fromHex(unspentOutput.getString("tx_hash")));
                                    Transaction.Script script = new Transaction.Script(BTCUtils.fromHex(unspentOutput.getString("script")));
                                    if (Arrays.equals(outputScriptWeAreAbleToSpend, script.bytes)) {
                                        long value = unspentOutput.getLong("value");
                                        long confirmations = unspentOutput.getLong("confirmations");
                                        int outputIndex = (int) unspentOutput.getLong("tx_output_n");
                                        unspentOutputs.add(new UnspentOutputInfo(txHash, script, value, outputIndex, confirmations));
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
                        verifiedUnspentOutputsComesFromJson = jsonInput;
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
        TextView amountError = (TextView) findViewById(R.id.err_amount);
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
            inputMethodManager.hideSoftInputFromWindow(passwordEdit.getWindowToken(), 0);

            bip38Task = new AsyncTask<Void, Void, Object>() {
                ProgressDialog dialog;
                public int sendLayoutVisibility;

                @Override
                protected void onPreExecute() {
                    super.onPreExecute();
                    dialog = ProgressDialog.show(MainActivity.this, "", (decrypting ?
                            getString(R.string.decrypting) : getString(R.string.encrypting)), true);
                    dialog.setCancelable(true);
                    dialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
                        @Override
                        public void onCancel(DialogInterface dialog) {
                            bip38Task.cancel(true);
                            bip38Task = null;
                        }
                    });
                    sendLayoutVisibility = sendLayout.getVisibility();
                }

                @Override
                protected Object doInBackground(Void... params) {
                    try {
                        if (decrypting) {
                            return BTCUtils.bip38Decrypt(inputKeyPair.privateKey.privateKeyEncoded, password);
                        } else {
                            String encryptedPrivateKey = BTCUtils.bip38Encrypt(inputKeyPair, password);
                            return new KeyPair(new BTCUtils.Bip38PrivateKeyInfo(encryptedPrivateKey,
                                    inputKeyPair.privateKey.privateKeyDecoded, password, inputKeyPair.privateKey.isPublicKeyCompressed));
                        }
                    } catch (OutOfMemoryError e) {
                        return R.string.error_oom_bip38;
                    } catch (Throwable e) {
                        String msg = e.getMessage();
                        if (msg != null && msg.contains("OutOfMemoryError")) {
                            return R.string.error_oom_bip38;
                        } else {
                            return null;
                        }
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
                        onKeyPairModify(false, keyPair);
                        if (!decrypting) {
                            sendLayout.setVisibility(sendLayoutVisibility);
                        }
                    } else if (result instanceof Integer || !decrypting) {
                        onKeyPairModify(false, inputKeyPair);
                        new AlertDialog.Builder(MainActivity.this)
                                .setMessage(getString(result instanceof Integer ? (Integer) result : R.string.error_unknown))
                                .setPositiveButton(android.R.string.ok, null)
                                .show();
                    } else {
                        onKeyPairModify(false, inputKeyPair);
                        ((TextView) findViewById(R.id.err_password)).setText(R.string.incorrect_password);
                    }
                }

                @Override
                protected void onCancelled() {
                    super.onCancelled();
                    bip38Task = null;
                    dialog.dismiss();
                    onKeyPairModify(false, currentKeyPair);
                }
            }.execute();
        }
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
                    View view = getLayoutInflater().inflate(R.layout.address_qr, null);
                    if (view != null) {
                        final ImageView qrView = (ImageView) view.findViewById(R.id.qr_code_image);
                        qrView.setImageBitmap(bitmap);

                        final TextView bitcoinProtocolLinkView = (TextView) view.findViewById(R.id.link1);
                        SpannableStringBuilder labelUri = new SpannableStringBuilder(uriStr);
                        ClickableSpan urlSpan = new ClickableSpan() {
                            @Override
                            public void onClick(View widget) {
                                Intent intent = new Intent(Intent.ACTION_VIEW);
                                intent.setData(Uri.parse(uriStr));
                                startActivity(intent);
                            }
                        };
                        labelUri.setSpan(urlSpan, 0, labelUri.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
                        bitcoinProtocolLinkView.setText(labelUri);
                        bitcoinProtocolLinkView.setMovementMethod(LinkMovementMethod.getInstance());

                        final TextView blockexplorerLinkView = (TextView) view.findViewById(R.id.link2);
                        SpannableStringBuilder blockexplorerLinkText = new SpannableStringBuilder("blockexplorer.com");
                        setUrlSpanForAddress("blockexplorer.com", address, blockexplorerLinkText);
                        blockexplorerLinkView.setText(blockexplorerLinkText);
                        blockexplorerLinkView.setMovementMethod(LinkMovementMethod.getInstance());

                        final TextView blockchainLinkView = (TextView) view.findViewById(R.id.link3);
                        SpannableStringBuilder blockchainLinkText = new SpannableStringBuilder("blockchain.info");
                        setUrlSpanForAddress("blockchain.info", address, blockchainLinkText);
                        blockchainLinkView.setText(blockchainLinkText);
                        blockchainLinkView.setMovementMethod(LinkMovementMethod.getInstance());


                        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                        builder.setTitle(address);
                        builder.setView(view);
                        if (PrintHelper.systemSupportsPrint()) {
                            builder.setPositiveButton(R.string.print, new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    Renderer.printQR(MainActivity.this, SCHEME_BITCOIN + address);
                                }
                            });
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

    private void showQRCodePopupForPrivateKey(final String label, final String address, final String[] data, final String[] dataTypes) {
        DisplayMetrics dm = getResources().getDisplayMetrics();
        final int screenSize = Math.min(dm.widthPixels, dm.heightPixels);
        new AsyncTask<Void, Void, Bitmap[]>() {

            @Override
            protected Bitmap[] doInBackground(Void... params) {
                Bitmap[] result = new Bitmap[data.length];
                for (int i = 0; i < data.length; i++) {
                    if (data[i] != null) {
                        QRCode qr = QRCode.getMinimumQRCode(data[i], ErrorCorrectLevel.M);
                        result[i] = qr.createImage(screenSize / 2);
                    }
                }
                return result;
            }

            @Override
            protected void onPostExecute(final Bitmap[] bitmap) {
                if (bitmap != null) {
                    View view = getLayoutInflater().inflate(R.layout.private_key_qr, null);
                    if (view != null) {
                        final ToggleButton toggle1 = (ToggleButton) view.findViewById(R.id.toggle_1);
                        final ToggleButton toggle2 = (ToggleButton) view.findViewById(R.id.toggle_2);
                        final ToggleButton toggle3 = (ToggleButton) view.findViewById(R.id.toggle_3);
                        final ImageView qrView = (ImageView) view.findViewById(R.id.qr_code_image);
                        final TextView dataView = (TextView) view.findViewById(R.id.qr_code_data);

                        if (data[0] == null) {
                            toggle1.setVisibility(View.GONE);
                        } else {
                            toggle1.setTextOff(dataTypes[0]);
                            toggle1.setTextOn(dataTypes[0]);
                            toggle1.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                                @Override
                                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                                    if (isChecked) {
                                        toggle2.setChecked(false);
                                        toggle3.setChecked(false);
                                        qrView.setImageBitmap(bitmap[0]);
                                        dataView.setText(data[0]);
                                    } else if (!toggle2.isChecked() && !toggle3.isChecked()) {
                                        buttonView.setChecked(true);
                                    }
                                }
                            });
                        }
                        if (data[1] == null) {
                            toggle2.setVisibility(View.GONE);
                        } else {
                            toggle2.setTextOff(dataTypes[1]);
                            toggle2.setTextOn(dataTypes[1]);
                            toggle2.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                                @Override
                                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                                    if (isChecked) {
                                        toggle1.setChecked(false);
                                        toggle3.setChecked(false);
                                        qrView.setImageBitmap(bitmap[1]);
                                        dataView.setText(data[1]);
                                    } else if (!toggle1.isChecked() && !toggle3.isChecked()) {
                                        buttonView.setChecked(true);
                                    }
                                }
                            });
                        }
                        if (data[2] == null) {
                            toggle3.setVisibility(View.GONE);
                        } else {
                            toggle3.setTextOff(dataTypes[2]);
                            toggle3.setTextOn(dataTypes[2]);
                            toggle3.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                                @Override
                                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                                    if (isChecked) {
                                        toggle1.setChecked(false);
                                        toggle2.setChecked(false);
                                        qrView.setImageBitmap(bitmap[2]);
                                        dataView.setText(data[2]);
                                    } else if (!toggle1.isChecked() && !toggle2.isChecked()) {
                                        buttonView.setChecked(true);
                                    }
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
                        DialogInterface.OnClickListener shareClickListener = new DialogInterface.OnClickListener() {

                            @Override
                            public void onClick(DialogInterface dialog, int which) {
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
                            }
                        };
                        if (PrintHelper.systemSupportsPrint()) {
                            builder.setPositiveButton(R.string.print, new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    int selectedIndex;
                                    if (toggle1.isChecked()) {
                                        selectedIndex = 0;
                                    } else if (toggle2.isChecked()) {
                                        selectedIndex = 1;
                                    } else {
                                        selectedIndex = 2;
                                    }
                                    Renderer.printWallet(MainActivity.this, label, SCHEME_BITCOIN + address, data[selectedIndex]);
                                }
                            });
                            builder.setNeutralButton(R.string.share, shareClickListener);
                        } else {
                            builder.setPositiveButton(R.string.share, shareClickListener);
                        }
                        builder.setNegativeButton(android.R.string.cancel, null);
                        builder.show();
                    }
                }
            }
        }.execute();
    }

    private void onNewKeyPairGenerated(KeyPair keyPair) {
        insertingAddressProgrammatically = true;
        if (keyPair != null) {
            addressTextEdit.setText(keyPair.address);
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

    private void onKeyPairModify(boolean noPrivateKeyEntered, KeyPair keyPair) {
        insertingAddressProgrammatically = true;
        if (keyPair != null) {
            if (!TextUtils.isEmpty(keyPair.address)) {
                addressTextEdit.setText(keyPair.address);
            } else {
                addressTextEdit.setText(getString(R.string.not_decrypted_yet));
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
        } else {
            passwordButton.setText(R.string.encrypt_private_key);
            passwordEdit.setImeActionLabel(getString(R.string.ime_encrypt), R.id.action_encrypt);
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
    }

    static class GenerateTransactionResult {
        static final int ERROR_SOURCE_UNKNOWN = 0;
        static final int ERROR_SOURCE_INPUT_TX_FIELD = 1;
        static final int ERROR_SOURCE_ADDRESS_FIELD = 2;
        static final int HINT_FOR_ADDRESS_FIELD = 3;
        static final int ERROR_SOURCE_AMOUNT_FIELD = 4;

        final Transaction tx;
        final String errorMessage;
        final int errorSource;
        final long fee;

        public GenerateTransactionResult(String errorMessage, int errorSource) {
            tx = null;
            this.errorMessage = errorMessage;
            this.errorSource = errorSource;
            fee = -1;
        }

        public GenerateTransactionResult(Transaction tx, long fee) {
            this.tx = tx;
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
        final boolean inputsComesFromJson = verifiedUnspentOutputsComesFromJson;
        final int predefinedConfirmationsCount = verifiedConfirmationsCount;


        spendTxDescriptionView.setVisibility(View.GONE);
        spendTxWarningView.setVisibility(View.GONE);
        spendTxEdit.setText("");
        spendTxEdit.setVisibility(View.GONE);
        sendTxInBrowserButton.setVisibility(View.GONE);
        findViewById(R.id.spend_tx_required_age_for_free_tx).setVisibility(View.GONE);
//        https://blockchain.info/pushtx

        if (unspentOutputs != null && !unspentOutputs.isEmpty() && !TextUtils.isEmpty(outputAddress) && keyPair != null && requestedAmountToSend >= SEND_MAX && requestedAmountToSend != 0) {
            cancelAllRunningTasks();
            generateTransactionTask = new AsyncTask<Void, Void, GenerateTransactionResult>() {

                @Override
                protected GenerateTransactionResult doInBackground(Void... voids) {
                    final Transaction spendTx;
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
                        long extraFee;
                        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
                        try {
                            extraFee = preferences.getLong(PreferencesActivity.PREF_EXTRA_FEE, FeePreference.PREF_EXTRA_FEE_DEFAULT);
                        } catch (ClassCastException e) {
                            preferences.edit().remove(PreferencesActivity.PREF_EXTRA_FEE).putLong(PreferencesActivity.PREF_EXTRA_FEE, FeePreference.PREF_EXTRA_FEE_DEFAULT).commit();
                            extraFee = FeePreference.PREF_EXTRA_FEE_DEFAULT;
                        }
                        spendTx = BTCUtils.createTransaction(unspentOutputs,
                                outputAddress, keyPair.address, amount, extraFee, keyPair.publicKey, keyPair.privateKey);

                        //6. double check that generated transaction is valid
                        Transaction.Script[] relatedScripts = new Transaction.Script[spendTx.inputs.length];
                        for (int i = 0; i < spendTx.inputs.length; i++) {
                            Transaction.Input input = spendTx.inputs[i];
                            for (UnspentOutputInfo unspentOutput : unspentOutputs) {
                                if (Arrays.equals(unspentOutput.txHash, input.outPoint.hash) && unspentOutput.outputIndex == input.outPoint.index) {
                                    relatedScripts[i] = unspentOutput.script;
                                    break;
                                }
                            }
                        }
                        BTCUtils.verify(relatedScripts, spendTx);
                    } catch (BitcoinException e) {
                        switch (e.errorCode) {
                            case BitcoinException.ERR_INSUFFICIENT_FUNDS:
                                return new GenerateTransactionResult(getString(R.string.error_not_enough_funds), GenerateTransactionResult.ERROR_SOURCE_AMOUNT_FIELD);
                            case BitcoinException.ERR_FEE_IS_TOO_BIG:
                                return new GenerateTransactionResult(getString(R.string.generated_tx_have_too_big_fee), GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD);
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
                    return new GenerateTransactionResult(spendTx, fee);
                }

                @Override
                protected void onPostExecute(GenerateTransactionResult result) {
                    super.onPostExecute(result);
                    generateTransactionTask = null;
                    if (result != null) {
                        final TextView rawTxToSpendErr = (TextView) findViewById(R.id.err_raw_tx);
                        if (result.tx != null) {
                            String amountStr = null;
                            Transaction.Script out = null;
                            try {
                                out = Transaction.Script.buildOutput(outputAddress);
                            } catch (BitcoinException ignore) {
                            }
                            if (result.tx.outputs[0].script.equals(out)) {
                                amountStr = BTCUtils.formatValue(result.tx.outputs[0].value);
                            }
                            if (amountStr == null) {
                                rawTxToSpendErr.setText(R.string.error_unknown);
                            } else {
                                String descStr;
                                String feeStr = BTCUtils.formatValue(result.fee);
                                String changeStr;
                                if (result.tx.outputs.length == 1) {
                                    changeStr = null;
                                    descStr = getString(R.string.spend_tx_description,
                                            amountStr,
                                            keyPair.address,
                                            outputAddress,
                                            feeStr
                                    );
                                } else if (result.tx.outputs.length == 2) {
                                    changeStr = BTCUtils.formatValue(result.tx.outputs[1].value);
                                    descStr = getString(R.string.spend_tx_with_change_description,
                                            amountStr,
                                            keyPair.address,
                                            outputAddress,
                                            feeStr,
                                            changeStr
                                    );
                                } else {
                                    throw new RuntimeException();
                                }
                                SpannableStringBuilder descBuilder = new SpannableStringBuilder(descStr);

                                int spanBegin = descStr.indexOf(keyPair.address);
                                if (spanBegin >= 0) {//from
                                    ForegroundColorSpan addressColorSpan = new ForegroundColorSpan(getResources().getColor(R.color.dark_orange));
                                    descBuilder.setSpan(addressColorSpan, spanBegin, spanBegin + keyPair.address.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
                                }
                                if (spanBegin >= 0) {
                                    spanBegin = descStr.indexOf(keyPair.address, spanBegin + 1);
                                    if (spanBegin >= 0) {//change
                                        ForegroundColorSpan addressColorSpan = new ForegroundColorSpan(getResources().getColor(R.color.dark_orange));
                                        descBuilder.setSpan(addressColorSpan, spanBegin, spanBegin + keyPair.address.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
                                    }
                                }
                                spanBegin = descStr.indexOf(outputAddress);
                                if (spanBegin >= 0) {//dest
                                    ForegroundColorSpan addressColorSpan = new ForegroundColorSpan(getResources().getColor(R.color.dark_green));
                                    descBuilder.setSpan(addressColorSpan, spanBegin, spanBegin + outputAddress.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
                                }
                                final String nbspBtc = "\u00a0BTC";
                                spanBegin = descStr.indexOf(amountStr + nbspBtc);
                                if (spanBegin >= 0) {
                                    descBuilder.setSpan(new StyleSpan(Typeface.BOLD), spanBegin, spanBegin + amountStr.length() + nbspBtc.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
                                }
                                spanBegin = descStr.indexOf(feeStr + nbspBtc, spanBegin);
                                if (spanBegin >= 0) {
                                    descBuilder.setSpan(new StyleSpan(Typeface.BOLD), spanBegin, spanBegin + feeStr.length() + nbspBtc.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
                                }
                                if (changeStr != null) {
                                    spanBegin = descStr.indexOf(changeStr + nbspBtc, spanBegin);
                                    if (spanBegin >= 0) {
                                        descBuilder.setSpan(new StyleSpan(Typeface.BOLD), spanBegin, spanBegin + changeStr.length() + nbspBtc.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
                                    }
                                }
                                spendTxDescriptionView.setText(descBuilder);
                                spendTxDescriptionView.setVisibility(View.VISIBLE);
                                spendTxWarningView.setVisibility(View.VISIBLE);
                                spendTxEdit.setText(BTCUtils.toHex(result.tx.getBytes()));
                                spendTxEdit.setVisibility(View.VISIBLE);
                                sendTxInBrowserButton.setVisibility(View.VISIBLE);

                                TextView maxAgeView = (TextView) findViewById(R.id.spend_tx_required_age_for_free_tx);
                                CheckBox maxAgeCheckBox = (CheckBox) findViewById(R.id.spend_tx_required_age_for_free_tx_checkbox);
                                if (!inputsComesFromJson) {
                                    if (!showNotEligibleForNoFeeBecauseOfBasicConstrains(maxAgeView, result.tx)) {
                                        final int confirmations = (int) (BTCUtils.MIN_PRIORITY_FOR_NO_FEE * result.tx.getBytes().length / unspentOutputs.get(0).value);
                                        float daysFloat = confirmations / BTCUtils.EXPECTED_BLOCKS_PER_DAY;
                                        String timePeriodStr;
                                        if (daysFloat <= 1) {
                                            int hours = (int) Math.round(Math.ceil(daysFloat / 24));
                                            timePeriodStr = getResources().getQuantityString(R.plurals.hours, hours, hours);
                                        } else {
                                            int days = (int) Math.round(Math.ceil(daysFloat));
                                            timePeriodStr = getResources().getQuantityString(R.plurals.days, days, days);
                                        }
                                        maxAgeCheckBox.setText(getString(R.string.input_tx_is_old_enough, getResources().getQuantityString(R.plurals.confirmations, confirmations, confirmations), timePeriodStr));
                                        maxAgeCheckBox.setVisibility(View.VISIBLE);
                                        maxAgeCheckBox.setOnCheckedChangeListener(null);
                                        maxAgeCheckBox.setChecked(predefinedConfirmationsCount > 0);
                                        maxAgeCheckBox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                                            @Override
                                            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                                                verifiedConfirmationsCount = isChecked ? confirmations : -1;
                                                onUnspentOutputsInfoChanged();
                                            }
                                        });
                                    } else {
                                        maxAgeCheckBox.setVisibility(View.GONE);
                                    }
                                } else {
                                    showNotEligibleForNoFeeBecauseOfBasicConstrains(maxAgeView, result.tx);
                                }
                            }
                        } else if (result.errorSource == GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD) {
                            rawTxToSpendErr.setText(result.errorMessage);
                        } else if (result.errorSource == GenerateTransactionResult.ERROR_SOURCE_ADDRESS_FIELD ||
                                result.errorSource == GenerateTransactionResult.HINT_FOR_ADDRESS_FIELD) {
                            ((TextView) findViewById(R.id.err_recipient_address)).setText(result.errorMessage);
                        } else if (!TextUtils.isEmpty(result.errorMessage) && result.errorSource == GenerateTransactionResult.ERROR_SOURCE_UNKNOWN) {
                            new AlertDialog.Builder(MainActivity.this)
                                    .setMessage(result.errorMessage)
                                    .setPositiveButton(android.R.string.ok, null)
                                    .show();
                        }

                        ((TextView) findViewById(R.id.err_amount)).setText(result.errorSource == GenerateTransactionResult.ERROR_SOURCE_AMOUNT_FIELD ? result.errorMessage : "");
                    }
                }

                private boolean showNotEligibleForNoFeeBecauseOfBasicConstrains(TextView maxAgeView, Transaction tx) {
                    long minOutput = Long.MAX_VALUE;
                    for (Transaction.Output output : tx.outputs) {
                        minOutput = Math.min(output.value, minOutput);
                    }
                    int txLen = tx.getBytes().length;
                    if (txLen >= BTCUtils.MAX_TX_LEN_FOR_NO_FEE) {
                        maxAgeView.setText(getString(R.string.tx_size_too_big_to_be_free, txLen));
                        maxAgeView.setVisibility(View.VISIBLE);
                        return true;
                    } else if (minOutput < BTCUtils.MIN_MIN_OUTPUT_VALUE_FOR_NO_FEE) {
                        maxAgeView.setText(getString(R.string.tx_output_is_too_small, BTCUtils.formatValue(minOutput), BTCUtils.formatValue(BTCUtils.MIN_MIN_OUTPUT_VALUE_FOR_NO_FEE)));
                        maxAgeView.setVisibility(View.VISIBLE);
                        return true;
                    }
                    maxAgeView.setVisibility(View.GONE);
                    return false;
                }
            }.execute();
        }
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
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
        Map<String, String> query_pairs = new LinkedHashMap<String, String>();
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
                @Override
                protected KeyPair doInBackground(Void... params) {
                    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
                    String privateKeyType = preferences.getString(PreferencesActivity.PREF_PRIVATE_KEY, PreferencesActivity.PREF_PRIVATE_KEY_MINI);
                    if (PreferencesActivity.PREF_PRIVATE_KEY_WIF_COMPRESSED.equals(privateKeyType)) {
                        return BTCUtils.generateWifKey(true);
                    } else if (PreferencesActivity.PREF_PRIVATE_KEY_WIF_NOT_COMPRESSED.equals(privateKeyType)) {
                        return BTCUtils.generateWifKey(false);
                    } else {
                        return BTCUtils.generateMiniKey();
                    }
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
        int typeWithCompression = keyPair.privateKey.type == BTCUtils.PrivateKeyInfo.TYPE_BRAIN_WALLET && keyPair.privateKey.isPublicKeyCompressed ? keyPair.privateKey.type + 1 : keyPair.privateKey.type;
        CharSequence keyType = getResources().getTextArray(R.array.private_keys_types)[typeWithCompression];
        SpannableString keyTypeLabel = new SpannableString(getString(R.string.private_key_type, keyType));
        int keyTypeStart = keyTypeLabel.toString().indexOf(keyType.toString());
        keyTypeLabel.setSpan(new StyleSpan(Typeface.BOLD), keyTypeStart, keyTypeStart + keyType.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
        if (keyPair.privateKey.type == BTCUtils.PrivateKeyInfo.TYPE_BRAIN_WALLET) {
            String compressionStrToSpan = keyType.toString().substring(keyType.toString().indexOf(',') + 2);
            int start = keyTypeLabel.toString().indexOf(compressionStrToSpan);
            if (start >= 0) {

                ClickableSpan switchPublicKeyCompressionSpan = new ClickableSpan() {
                    @Override
                    public void onClick(View widget) {
                        cancelAllRunningTasks();
                        switchingCompressionTypeTask = new AsyncTask<Void, Void, KeyPair>() {

                            @Override
                            protected KeyPair doInBackground(Void... params) {
                                return new KeyPair(new BTCUtils.PrivateKeyInfo(keyPair.privateKey.type, keyPair.privateKey.privateKeyEncoded, keyPair.privateKey.privateKeyDecoded, !keyPair.privateKey.isPublicKeyCompressed));
                            }

                            @Override
                            protected void onPostExecute(KeyPair keyPair) {
                                switchingCompressionTypeTask = null;
                                onKeyPairModify(false, keyPair);
                            }
                        };
                        switchingCompressionTypeTask.execute();
                    }
                };
                keyTypeLabel.setSpan(switchPublicKeyCompressionSpan, start, start + compressionStrToSpan.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
            }
        }
        return keyTypeLabel;
    }

    private void showSpendPanelForKeyPair(KeyPair keyPair) {
        if (keyPair != null && keyPair.privateKey.privateKeyDecoded == null) {
            keyPair = null;
        }
        if (keyPair != null) {
            currentKeyPair = keyPair;
            final String address = keyPair.address;
            String descStr = getString(R.string.raw_tx_description_header, address);
            SpannableStringBuilder builder = new SpannableStringBuilder(descStr);
            int spanBegin = descStr.indexOf(address);
            if (spanBegin >= 0) {
                ForegroundColorSpan addressColorSpan = new ForegroundColorSpan(getResources().getColor(R.color.dark_orange));
                builder.setSpan(addressColorSpan, spanBegin, spanBegin + address.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
            }
            rawTxDescriptionHeaderView.setText(builder);
            String wutLink = getString(R.string.raw_tx_description_wut_link);
            String jsonLink = getString(R.string.raw_tx_description_json_link);
            builder = new SpannableStringBuilder(getString(R.string.raw_tx_description, wutLink, jsonLink));

            spanBegin = builder.toString().indexOf(wutLink);
            ClickableSpan urlSpan = new ClickableSpan() {
                @Override
                public void onClick(View widget) {
                    SpannableStringBuilder builder = new SpannableStringBuilder(getText(R.string.raw_tx_description_wut));
                    setUrlSpanForAddress("blockexplorer.com", address, builder);
                    setUrlSpanForAddress("blockchain.info", address, builder);
                    TextView messageView = new TextView(MainActivity.this);
                    messageView.setText(builder);
                    messageView.setMovementMethod(LinkMovementMethod.getInstance());
                    int padding = dp2px(16);
                    messageView.setPadding(padding, padding, padding, padding);
                    new AlertDialog.Builder(MainActivity.this)
                            .setView(messageView)
                            .setPositiveButton(android.R.string.ok, null)
                            .show();
                }
            };
            builder.setSpan(urlSpan, spanBegin, spanBegin + wutLink.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);

            spanBegin = builder.toString().indexOf(jsonLink);
            urlSpan = new URLSpan("http://blockchain.info/unspent?active=" + address);
            builder.setSpan(urlSpan, spanBegin, spanBegin + jsonLink.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);

            rawTxDescriptionView.setText(builder);
            rawTxDescriptionView.setMovementMethod(LinkMovementMethod.getInstance());
            onUnspentOutputsInfoChanged();
        }
        sendLayout.setVisibility(keyPair != null ? View.VISIBLE : View.GONE);
        enterPrivateKeyAck.setVisibility(keyPair == null ? View.VISIBLE : View.GONE);
    }

    private int dp2px(int dp) {
        return (int) (dp * (getResources().getDisplayMetrics().densityDpi / 160f));
    }

    private static void setUrlSpanForAddress(String domain, String address, SpannableStringBuilder builder) {
        int spanBegin = builder.toString().indexOf(domain);
        if (spanBegin >= 0) {
            URLSpan urlSpan = new URLSpan("http://" + domain + "/address/" + address);
            builder.setSpan(urlSpan, spanBegin, spanBegin + domain.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        cancelAllRunningTasks();
    }
}
