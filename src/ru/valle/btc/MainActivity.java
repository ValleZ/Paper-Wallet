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

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.graphics.Bitmap;
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
import android.text.style.URLSpan;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;
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
    private EditText addressView;
    private TextView privateKeyTypeView;
    private EditText privateKeyTextEdit;
    private View sendLayout;
    private TextView rawTxDescriptionView;
    private EditText rawTxToSpendEdit;
    private TextView recipientAddressView;
    private EditText amountEdit;
    private TextView spendTxDescriptionView;
    private TextView spendTxEdit;
    private View generateButton;

    private boolean insertingPrivateKeyProgrammatically, insertingAddressProgrammatically, changingTxProgrammatically;
    private AsyncTask<Void, Void, KeyPair> addressGenerateTask;
    private AsyncTask<Void, Void, GenerateTransactionResult> generateTransactionTask;
    private AsyncTask<Void, Void, KeyPair> switchingCompressionTypeTask;
    private AsyncTask<Void, Void, KeyPair> decodePrivateKeyTask;
    private AsyncTask<Void, Void, KeyPair> bip38Task;

    private KeyPair currentKeyPair;
    private View scanPrivateKeyButton, scanRecipientAddressButton;
    private View enterPrivateKeyAck;
    private View rawTxToSpendPasteButton;
    private ClipboardManager.OnPrimaryClipChangedListener clipboardListener;
    private View obtainUnspentOutputsButton;
    private View sendTxInBrowserButton;
    private TextView passwordButton;
    private EditText passwordEdit;
    private boolean lastBip38ActionWasDecryption;


    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        addressView = (EditText) findViewById(R.id.address_label);
        generateButton = findViewById(R.id.generate_button);
        privateKeyTypeView = (TextView) findViewById(R.id.private_key_type_label);
        privateKeyTypeView.setMovementMethod(LinkMovementMethod.getInstance());
        privateKeyTextEdit = (EditText) findViewById(R.id.private_key_label);
        passwordButton = (TextView) findViewById(R.id.password_button);
        passwordEdit = (EditText) findViewById(R.id.password_edit);

        sendLayout = findViewById(R.id.send_layout);
        obtainUnspentOutputsButton = findViewById(R.id.obtain_unspent_outputs_button);
        rawTxToSpendPasteButton = findViewById(R.id.paste_tx_button);
        rawTxToSpendEdit = (EditText) findViewById(R.id.raw_tx);
        recipientAddressView = (TextView) findViewById(R.id.recipient_address);
        amountEdit = (EditText) findViewById(R.id.amount);
        rawTxDescriptionView = (TextView) findViewById(R.id.raw_tx_description);
        spendTxDescriptionView = (TextView) findViewById(R.id.spend_tx_description);
        spendTxEdit = (TextView) findViewById(R.id.spend_tx);
        sendTxInBrowserButton = findViewById(R.id.send_tx_button);
        scanPrivateKeyButton = findViewById(R.id.scan_private_key_button);
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
                android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                clipboard.addPrimaryClipChangedListener(clipboardListener = new ClipboardManager.OnPrimaryClipChangedListener() {
                    @Override
                    public void onPrimaryClipChanged() {
                        rawTxToSpendPasteButton.setEnabled(!TextUtils.isEmpty(getTextInClipboard()));
                    }
                });
            }
            rawTxToSpendPasteButton.setEnabled(hasTextInClipboard);
        } else {
            rawTxToSpendPasteButton.setVisibility(hasTextInClipboard ? View.VISIBLE : View.GONE);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (Build.VERSION.SDK_INT >= 11 && clipboardListener != null) {
            android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.removePrimaryClipChangedListener(clipboardListener);
        }
    }


    @SuppressWarnings("deprecation")
    private String getTextInClipboard() {
        CharSequence textInClipboard = "";
        if (Build.VERSION.SDK_INT >= 11) {
            android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard.hasPrimaryClip() && clipboard.getPrimaryClipDescription().hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN) && clipboard.getPrimaryClip().getItemCount() > 0) {
                ClipData.Item item = clipboard.getPrimaryClip().getItemAt(0);
                textInClipboard = item.getText();
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
            android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText(label, text);
            clipboard.setPrimaryClip(clip);
        } else {
            android.text.ClipboardManager clipboard = (android.text.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setText(text);
        }
    }

    private void wireListeners() {
        addressView.addTextChangedListener(new TextWatcher() {
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
                } else {
                    showQRCode(s.toString());
                }
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
                    setTextWithoutJumping(addressView, getString(R.string.decoding));
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
        passwordButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final KeyPair inputKeyPair = currentKeyPair;
                final String password = passwordEdit.getText().toString();
                if (inputKeyPair != null && !TextUtils.isEmpty(password)) {
                    cancelAllRunningTasks();
                    final boolean decrypting = inputKeyPair.privateKey.type == BTCUtils.PrivateKeyInfo.TYPE_BIP38;
                    lastBip38ActionWasDecryption = decrypting;
                    passwordButton.setEnabled(false);
                    passwordButton.setText(decrypting ? R.string.decrypting : R.string.encrypting);
                    InputMethodManager inputMethodManager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                    inputMethodManager.hideSoftInputFromWindow(passwordEdit.getWindowToken(), 0);

                    bip38Task = new AsyncTask<Void, Void, KeyPair>() {
                        ProgressDialog dialog;
                        public int sendLayoutVisibility;

                        @Override
                        protected void onPreExecute() {
                            super.onPreExecute();
                            dialog = ProgressDialog.show(MainActivity.this, "", (decrypting ?
                                    getString(R.string.decrypting_progress_description) : getString(R.string.encrypting_progress_description)), true);
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
                        protected KeyPair doInBackground(Void... params) {
                            try {
                                if (decrypting) {
                                    return BTCUtils.bip38Decrypt(inputKeyPair.privateKey.privateKeyEncoded, password);
                                } else {
                                    String encryptedPrivateKey = BTCUtils.bip38Encrypt(inputKeyPair, password);
                                    return new KeyPair(new BTCUtils.PrivateKeyInfo(BTCUtils.PrivateKeyInfo.TYPE_BIP38, encryptedPrivateKey,
                                            inputKeyPair.privateKey.privateKeyDecoded, inputKeyPair.privateKey.isPublicKeyCompressed));
                                }
                            } catch (Exception e) {
                                return null;
                            }
                        }

                        @Override
                        protected void onPostExecute(KeyPair keyPair) {
                            super.onPostExecute(keyPair);
                            bip38Task = null;
                            dialog.dismiss();
                            if (keyPair != null) {
                                insertingPrivateKeyProgrammatically = true;
                                privateKeyTextEdit.setText(keyPair.privateKey.privateKeyEncoded);
                                insertingPrivateKeyProgrammatically = false;
                                onKeyPairModify(false, keyPair);
                                if (!decrypting) {
                                    sendLayout.setVisibility(sendLayoutVisibility);
                                }
                            } else if (decrypting) {
                                onKeyPairModify(false, inputKeyPair);
                                passwordEdit.setError(getString(R.string.incorrect_password));
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
        });
        TextWatcher generateTransactionOnInputChangeTextWatcher = new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (!changingTxProgrammatically) {
                    cancelAllRunningTasks();
                    generateSpendingTransaction(rawTxToSpendEdit.getText().toString(), recipientAddressView.getText().toString(), amountEdit.getText().toString(), currentKeyPair);
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        };
        obtainUnspentOutputsButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String address = addressView.getText().toString();
                Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://blockchain.info/unspent?active=" + address));
                startActivity(intent);
            }
        });
        rawTxToSpendPasteButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                rawTxToSpendEdit.setText(getTextInClipboard());
            }
        });
        rawTxToSpendEdit.addTextChangedListener(generateTransactionOnInputChangeTextWatcher);
        recipientAddressView.addTextChangedListener(generateTransactionOnInputChangeTextWatcher);
        amountEdit.addTextChangedListener(generateTransactionOnInputChangeTextWatcher);
        scanPrivateKeyButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivityForResult(new Intent(MainActivity.this, ScanActivity.class), REQUEST_SCAN_PRIVATE_KEY);
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
                copyTextToClipboard(getString(R.string.tx_description_for_clipboard, amountEdit.getText(), recipientAddressView.getText()), spendTxEdit.getText().toString());
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://blockchain.info/pushtx")));
            }
        });

        if (!getPackageManager().hasSystemFeature(PackageManager.FEATURE_CAMERA)) {
            scanPrivateKeyButton.setVisibility(View.GONE);
            scanRecipientAddressButton.setVisibility(View.GONE);
        }
    }

    private void showQRCode(final String data) {
        if (data.startsWith("1")) {
            new AsyncTask<Void, Void, Bitmap>() {

                @Override
                protected Bitmap doInBackground(Void... params) {
                    QRCode qr = new QRCode();
                    qr.setTypeNumber(3);
                    qr.setErrorCorrectLevel(ErrorCorrectLevel.M);
                    qr.addData(data);
                    qr.make();
                    return qr.createImage(dp2px(8), dp2px(10));
                }

                @Override
                protected void onPostExecute(final Bitmap bitmap) {
                    ImageView qrView = (ImageView) findViewById(R.id.qr_code);
                    qrView.setImageBitmap(bitmap);
                    qrView.setOnClickListener(new View.OnClickListener() {
                        @Override
                        public void onClick(View v) {
                            if (PrintHelper.systemSupportsPrint()) {
                                new PrintHelper(MainActivity.this).printBitmap("Address " + data, bitmap);
                            } else {
                                Toast.makeText(MainActivity.this, "not supported", Toast.LENGTH_LONG).show();
                            }
                        }
                    });
                }
            }.execute();

        }
    }

    private int dp2px(int dp) {
        return (int) (dp * (getResources().getDisplayMetrics().densityDpi / 160f));
    }

    private void onNewKeyPairGenerated(KeyPair keyPair) {
        insertingAddressProgrammatically = true;
        if (keyPair != null) {
            addressView.setText(keyPair.address);
            privateKeyTypeView.setVisibility(View.VISIBLE);
            privateKeyTypeView.setText(getPrivateKeyTypeLabel(keyPair));
            insertingPrivateKeyProgrammatically = true;
            privateKeyTextEdit.setText(keyPair.privateKey.privateKeyEncoded);
            insertingPrivateKeyProgrammatically = false;
        } else {
            privateKeyTypeView.setVisibility(View.GONE);
            addressView.setText(getString(R.string.generating_failed));
        }
        insertingAddressProgrammatically = false;
        updatePasswordView(keyPair);
        showSpendPanelForKeyPair(null);//generated address does not have funds to spend yet
    }

    private void onKeyPairModify(boolean noPrivateKeyEntered, KeyPair keyPair) {
        insertingAddressProgrammatically = true;
        if (keyPair != null) {
            if (!TextUtils.isEmpty(keyPair.address)) {
                addressView.setText(keyPair.address);
            } else {
                addressView.setText(getString(R.string.not_decrypted_yet));
            }
            privateKeyTypeView.setVisibility(View.VISIBLE);
            privateKeyTypeView.setText(getPrivateKeyTypeLabel(keyPair));
        } else {
            privateKeyTypeView.setVisibility(View.GONE);
            addressView.setText(noPrivateKeyEntered ? "" : getString(R.string.bad_private_key));
        }
        insertingAddressProgrammatically = false;
        updatePasswordView(keyPair);
        showSpendPanelForKeyPair(keyPair);
    }

    private void updatePasswordView(KeyPair keyPair) {
        currentKeyPair = keyPair;
        String encodedPrivateKey = keyPair == null ? null : keyPair.privateKey.privateKeyEncoded;
        passwordButton.setEnabled(!TextUtils.isEmpty(passwordEdit.getText()) && !TextUtils.isEmpty(encodedPrivateKey));
        passwordEdit.setEnabled(true);
        passwordEdit.setError(null);
        if (keyPair != null && keyPair.privateKey.type == BTCUtils.PrivateKeyInfo.TYPE_BIP38) {
            if (keyPair.privateKey.privateKeyDecoded == null) {
                passwordButton.setText(R.string.decrypt_private_key);
                passwordEdit.setImeActionLabel(getString(R.string.ime_decrypt), R.id.action_decrypt);
            } else {
                if (lastBip38ActionWasDecryption) {
                    passwordButton.setText(getString(R.string.decrypted));
                    passwordButton.setEnabled(false);
                } else {
                    passwordButton.setText(getString(R.string.encrypted_verify));
                    passwordButton.setEnabled(true);
                }
                passwordEdit.setEnabled(false);
            }
        } else {
            passwordButton.setText(R.string.encrypt_private_key);
            passwordEdit.setImeActionLabel(getString(R.string.ime_encrypt), R.id.action_encrypt);
        }
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
        private final long availableAmountToSend;
        final long fee;

        public GenerateTransactionResult(String errorMessage, int errorSource, long availableAmountToSend) {
            tx = null;
            this.errorMessage = errorMessage;
            this.errorSource = errorSource;
            this.availableAmountToSend = availableAmountToSend;
            fee = -1;
        }

        public GenerateTransactionResult(Transaction tx, long fee) {
            this.tx = tx;
            errorMessage = null;
            errorSource = ERROR_SOURCE_UNKNOWN;
            availableAmountToSend = -1;
            this.fee = fee;
        }
    }

    private void generateSpendingTransaction(final String unspentOutputsInfo, final String outputAddress, final String requestedAmountToSendStr, final KeyPair keyPair) {
        rawTxToSpendEdit.setError(null);
        recipientAddressView.setError(null);
        spendTxDescriptionView.setVisibility(View.GONE);
        spendTxEdit.setText("");
        spendTxEdit.setVisibility(View.GONE);
        sendTxInBrowserButton.setVisibility(View.GONE);
//        https://blockchain.info/pushtx

        cancelAllRunningTasks();
        if (!(TextUtils.isEmpty(unspentOutputsInfo) && TextUtils.isEmpty(outputAddress)) && keyPair != null && keyPair.privateKey != null) {

            generateTransactionTask = new AsyncTask<Void, Void, GenerateTransactionResult>() {

                @Override
                protected GenerateTransactionResult doInBackground(Void... voids) {
                    byte[] outputScriptWeAreAbleToSpend = Transaction.Script.buildOutput(keyPair.address).bytes;
                    ArrayList<UnspentOutputInfo> unspentOutputs = new ArrayList<UnspentOutputInfo>();
                    //1. decode tx or json
                    try {
                        byte[] rawTx = BTCUtils.fromHex(unspentOutputsInfo);
                        if (rawTx != null) {
                            Transaction baseTx = new Transaction(rawTx);//TODO parse multiple txs
                            byte[] rawTxReconstructed = baseTx.getBytes();
                            if (!Arrays.equals(rawTxReconstructed, rawTx)) {
                                throw new IllegalArgumentException("Unable to decode given transaction");
                            }
                            byte[] txHash = BTCUtils.reverse(BTCUtils.doubleSha256(rawTx));
                            for (int outputIndex = 0; outputIndex < baseTx.outputs.length; outputIndex++) {
                                Transaction.Output output = baseTx.outputs[outputIndex];
                                if (Arrays.equals(outputScriptWeAreAbleToSpend, output.script.bytes)) {
                                    unspentOutputs.add(new UnspentOutputInfo(txHash, output.script, output.value, outputIndex));
                                }
                            }
                        } else {
                            JSONObject jsonObject = new JSONObject(unspentOutputsInfo);
                            JSONArray unspentOutputsArray = jsonObject.getJSONArray("unspent_outputs");
                            for (int i = 0; i < unspentOutputsArray.length(); i++) {
                                JSONObject unspentOutput = unspentOutputsArray.getJSONObject(i);
                                byte[] txHash = BTCUtils.reverse(BTCUtils.fromHex(unspentOutput.getString("tx_hash")));
                                Transaction.Script script = new Transaction.Script(BTCUtils.fromHex(unspentOutput.getString("script")));
                                long value = unspentOutput.getLong("value");
                                int outputIndex = unspentOutput.getInt("tx_output_n");
                                if (Arrays.equals(outputScriptWeAreAbleToSpend, script.bytes)) {
                                    unspentOutputs.add(new UnspentOutputInfo(txHash, script, value, outputIndex));
                                }
                            }
                        }
                        if (unspentOutputs.isEmpty()) {
                            return new GenerateTransactionResult("No spendable standard outputs for " + keyPair.address + " have found", GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD, -1);
                        }
                    } catch (Exception e) {
                        return new GenerateTransactionResult(getString(R.string.error_unable_to_decode_transaction), GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD, -1);
                    }

                    //3. verify amount to send
                    long availableAmountToSend = 0;
                    for (UnspentOutputInfo unspentOutput : unspentOutputs) {
                        availableAmountToSend += unspentOutput.value;
                    }
                    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
                    long fee = (long) (Double.parseDouble(preferences.getString(PreferencesActivity.PREF_FEE, Double.toString(FeePreference.PREF_FEE_DEFAULT))) * 1e8);
                    availableAmountToSend -= fee;
                    long requestedAmountToSend;
                    if (TextUtils.isEmpty(requestedAmountToSendStr)) {
                        requestedAmountToSend = availableAmountToSend;
                    } else {
                        try {
                            requestedAmountToSend = (long) (Double.parseDouble(requestedAmountToSendStr) * 1e8);
                        } catch (Exception e) {
                            return new GenerateTransactionResult(getString(R.string.error_amount_parsing), GenerateTransactionResult.ERROR_SOURCE_AMOUNT_FIELD, availableAmountToSend);
                        }
                    }
                    if (requestedAmountToSend > availableAmountToSend) {
                        return new GenerateTransactionResult(getString(R.string.error_not_enough_funds), GenerateTransactionResult.ERROR_SOURCE_AMOUNT_FIELD, availableAmountToSend);
                    }
                    if (requestedAmountToSend <= fee) {
                        return new GenerateTransactionResult(getString(R.string.error_amount_to_send_less_than_fee), GenerateTransactionResult.ERROR_SOURCE_AMOUNT_FIELD, availableAmountToSend);
                    }
                    //4. verify address
                    if (TextUtils.isEmpty(outputAddress)) {
                        return new GenerateTransactionResult(getString(R.string.enter_address_to_spend), GenerateTransactionResult.HINT_FOR_ADDRESS_FIELD, availableAmountToSend);
                    }
                    if (!BTCUtils.verifyBitcoinAddress(outputAddress)) {
                        return new GenerateTransactionResult(getString(R.string.invalid_address), GenerateTransactionResult.ERROR_SOURCE_ADDRESS_FIELD, availableAmountToSend);
                    }
                    //5. generate spend tx
                    final Transaction spendTx;
                    try {
                        spendTx = BTCUtils.createTransaction(unspentOutputs,
                                outputAddress, keyPair.address, requestedAmountToSend, fee, keyPair.publicKey, keyPair.privateKey);

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
                    } catch (Exception e) {
                        return new GenerateTransactionResult(getString(R.string.error_failed_to_create_transaction), GenerateTransactionResult.ERROR_SOURCE_UNKNOWN, availableAmountToSend);
                    }
                    return new GenerateTransactionResult(spendTx, fee);
                }

                @Override
                protected void onPostExecute(GenerateTransactionResult result) {
                    super.onPostExecute(result);
                    generateTransactionTask = null;
                    if (result != null) {
                        if (result.tx != null) {
                            String amount = null;
                            Transaction.Script out = Transaction.Script.buildOutput(outputAddress);
                            if (result.tx.outputs[0].script.equals(out)) {
                                amount = BTCUtils.formatValue(result.tx.outputs[0].value);
                            }
                            if (amount == null) {
                                rawTxToSpendEdit.setError(getString(R.string.error_unknown));
                            } else {
                                changingTxProgrammatically = true;
                                amountEdit.setText(amount);
                                changingTxProgrammatically = false;
                                if (result.tx.outputs.length == 1) {
                                    spendTxDescriptionView.setText(getString(R.string.spend_tx_description,
                                            amount,
                                            keyPair.address,
                                            outputAddress,
                                            BTCUtils.formatValue(result.fee)
                                    ));
                                } else if (result.tx.outputs.length == 2) {
                                    spendTxDescriptionView.setText(getString(R.string.spend_tx_with_change_description,
                                            amount,
                                            keyPair.address,
                                            outputAddress,
                                            BTCUtils.formatValue(result.fee),
                                            BTCUtils.formatValue(result.tx.outputs[1].value)
                                    ));
                                } else {
                                    throw new RuntimeException();
                                }
                                spendTxDescriptionView.setVisibility(View.VISIBLE);
                                spendTxEdit.setText(BTCUtils.toHex(result.tx.getBytes()));
                                spendTxEdit.setVisibility(View.VISIBLE);
                                sendTxInBrowserButton.setVisibility(View.VISIBLE);
                            }
                        } else if (result.errorSource == GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD) {
                            rawTxToSpendEdit.setError(result.errorMessage);
                        } else if (result.errorSource == GenerateTransactionResult.ERROR_SOURCE_ADDRESS_FIELD ||
                                result.errorSource == GenerateTransactionResult.HINT_FOR_ADDRESS_FIELD) {
                            recipientAddressView.setError(result.errorMessage);
                        }

                        if (result.errorSource == GenerateTransactionResult.ERROR_SOURCE_AMOUNT_FIELD) {
                            amountEdit.setError(result.errorMessage);
                        } else {
                            amountEdit.setError(null);
                        }

                        if (result.availableAmountToSend > 0 && amountEdit.getText().length() == 0) {
                            changingTxProgrammatically = true;
                            amountEdit.setText(BTCUtils.formatValue(result.availableAmountToSend));
                            changingTxProgrammatically = false;
                        }
                    }
                }
            }.execute();
        }
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        addressView.setMinLines(1);
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
            if (scannedResult.startsWith(SCHEME_BITCOIN)) {
                scannedResult = scannedResult.substring(SCHEME_BITCOIN.length());
                privateKey = "";
                int queryStartIndex = scannedResult.indexOf('?');
                if (queryStartIndex == -1) {
                    address = scannedResult;
                } else {
                    address = scannedResult.substring(0, queryStartIndex);
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
            setTextWithoutJumping(addressView, getString(R.string.generating));
            insertingAddressProgrammatically = false;
            addressGenerateTask = new AsyncTask<Void, Void, KeyPair>() {
                @Override
                protected KeyPair doInBackground(Void... params) {
                    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
                    String privateKeyType = preferences.getString(PreferencesActivity.PREF_PRIVATE_KEY, PreferencesActivity.PREF_PRIVATE_KEY_MINI);
                    if (PreferencesActivity.PREF_PRIVATE_KEY_WIF_COMPRESSED.equals(privateKeyType)) {
                        return BTCUtils.generateWifKey(true);
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
        if (keyPair == null) {
            rawTxToSpendEdit.setText("");
        } else {
            currentKeyPair = keyPair;
            String descStr = getString(R.string.raw_tx_description, keyPair.address);
            final SpannableStringBuilder builder = new SpannableStringBuilder(descStr);
            int spanBegin = descStr.indexOf(keyPair.address);
            if (spanBegin >= 0) {
                ForegroundColorSpan addressColorSpan = new ForegroundColorSpan(getResources().getColor(R.color.dark_orange));
                builder.setSpan(addressColorSpan, spanBegin, spanBegin + keyPair.address.length(), SpannableStringBuilder.SPAN_INCLUSIVE_INCLUSIVE);
            }
            setUrlSpanForAddress("blockexplorer.com", keyPair.address, builder);
            setUrlSpanForAddress("blockchain.info", keyPair.address, builder);
            rawTxDescriptionView.setText(builder);
            rawTxDescriptionView.setMovementMethod(LinkMovementMethod.getInstance());
        }
        sendLayout.setVisibility(keyPair != null ? View.VISIBLE : View.GONE);
        enterPrivateKeyAck.setVisibility(keyPair == null ? View.VISIBLE : View.GONE);
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
