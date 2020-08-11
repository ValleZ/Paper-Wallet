/*
 * The MIT License (MIT)
 * <p/>
 * Copyright (c) 2013-2020 Valentin Konovalov
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

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import androidx.activity.ComponentActivity;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public final class MainActivity extends ComponentActivity {

    private static final int REQUEST_SCAN_PRIVATE_KEY = 0;
    private static final int REQUEST_SCAN_RECIPIENT_ADDRESS = 1;
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
    private TextView rawTxToSpendErr;

    private boolean insertingPrivateKeyProgrammatically, insertingAddressProgrammatically;

    private KeyPair currentKeyPair;
    private View scanPrivateKeyButton, scanRecipientAddressButton;
    private ImageButton showQRCodeAddressButton, showQRCodePrivateKeyButton;
    private View enterPrivateKeyAck;
    private View sendBtcTxInBrowserButton, sendBchTxInBrowserButton;
    private TextView passwordButton;
    private EditText passwordEdit;
    private boolean lastBip38ActionWasDecryption;
    private ClipboardHelper clipboardHelper;

    //collected information for tx generation:
    private String verifiedRecipientAddressForTx;
    private KeyPair verifiedKeyPairForTx;
    private List<UnspentOutputInfo> verifiedUnspentOutputsForTx;
    private long verifiedAmountToSendForTx;
    private ViewGroup mainLayout;
    private CompoundButton segwitAddressSwitch;
    private SharedPreferences mainThreadPreferences;
    private MainActivityTasksContext tasks;
    private ProgressDialog progressDialog;
    private TextView amountErrorView;
    private TextView passwordErrorView;
    private TextView recipientAddressErrorView;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }
        findViews();
        privateKeyTypeView.setMovementMethod(getLinkMovementMethod());
        if (!EclairHelper.canScan(this)) {
            scanPrivateKeyButton.setVisibility(View.GONE);
            scanRecipientAddressButton.setVisibility(View.GONE);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                Configuration.UI_MODE_NIGHT_YES == (Configuration.UI_MODE_NIGHT_MASK & getResources().getConfiguration().uiMode)) {
            showQRCodeAddressButton.setColorFilter(Color.WHITE);
            showQRCodePrivateKeyButton.setColorFilter(Color.WHITE);
        }

        tasks = new MainActivityTasksContext();
        mainThreadPreferences = PreferenceManager.getDefaultSharedPreferences(this);
        clipboardHelper = new ClipboardHelper(this);
        wireListeners();

        if (savedInstanceState == null) {
            segwitAddressSwitch.setChecked(mainThreadPreferences.getBoolean(PreferencesActivity.PREF_SEGWIT, false));
        }
        generateNewAddress();
    }

    private void findViews() {
        mainLayout = findViewById(R.id.main);
        segwitAddressSwitch = findViewById(R.id.segwit_address_switch);
        addressTextEdit = findViewById(R.id.address_label);
        generateButton = findViewById(R.id.generate_button);
        privateKeyTypeView = findViewById(R.id.private_key_type_label);
        privateKeyTextEdit = findViewById(R.id.private_key_label);
        passwordButton = findViewById(R.id.password_button);
        passwordEdit = findViewById(R.id.password_edit);
        sendLayout = findViewById(R.id.send_layout);
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
        rawTxToSpendErr = findViewById(R.id.err_raw_tx);
        amountErrorView = findViewById(R.id.err_amount);
        passwordErrorView = findViewById(R.id.err_password);
        recipientAddressErrorView = findViewById(R.id.err_recipient_address);
    }

    @Override
    protected void onResume() {
        super.onResume();
        tryToGenerateSpendingTransaction();
    }

    private void copyTextToClipboard(String label, String text) {
        clipboardHelper.copyTextToClipboard(label, text);
    }

    private void wireListeners() {
        wireListenersForKeyGeneration();
        wireTextChangedListeners();
        wireSpentPanelInfoGeneratedListeners();
        wireBip38EncryptionListener();
        wireQrCodeRenderedListeners();
        wireButtonClickListeners();
    }

    private void wireButtonClickListeners() {
        segwitAddressSwitch.setOnCheckedChangeListener((compoundButton, checked) -> {
            if (currentKeyPair != null) {
                mainThreadPreferences.edit().putBoolean(PreferencesActivity.PREF_SEGWIT, checked).apply();
                tasks.switchAddressType(getSelectedPublicKeyRepresentation(), currentKeyPair.privateKey);
            }
        });

        generateButton.setOnClickListener(v -> generateNewAddress());

        passwordEdit.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == R.id.action_encrypt || actionId == R.id.action_decrypt) {
                encryptOrDecryptPrivateKey();
                return true;
            }
            return false;
        });

        passwordButton.setOnClickListener(v -> encryptOrDecryptPrivateKey());

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
    }

    private void wireBip38EncryptionListener() {
        tasks.bip38Transformation.observe(this, result -> {
            if (result != null) {
                tasks.bip38Transformation.setValue(null);
                if (result.cancelled) {
                    progressDialog.dismiss();
                    onKeyPairModify(false, currentKeyPair, getSelectedPublicKeyRepresentation());
                } else {
                    progressDialog.dismiss();
                    if (result.keyPair != null) {
                        KeyPair keyPair = result.keyPair;
                        insertingPrivateKeyProgrammatically = true;
                        privateKeyTextEdit.setText(keyPair.privateKey.privateKeyEncoded);
                        insertingPrivateKeyProgrammatically = false;
                        onKeyPairModify(false, keyPair, result.addressType);
                        if (!result.decrypting) {
                            sendLayout.setVisibility(result.sendLayoutVisible ? View.VISIBLE : View.GONE);
                        }
                    } else {
                        onKeyPairModify(false, result.inputKeyPair, result.addressType);
                        String msg = null;
                        if (result.th instanceof OutOfMemoryError || nonNullStr(result.th == null ? "" : result.th.getMessage()).contains("OutOfMemory")) {
                            msg = getString(R.string.error_oom_bip38);
                        } else if (result.th instanceof BitcoinException && ((BitcoinException) result.th).errorCode == BitcoinException.ERR_INCORRECT_PASSWORD) {
                            passwordErrorView.setText(R.string.incorrect_password);
                        } else if (result.th instanceof BitcoinException && ((BitcoinException) result.th).errorCode == BitcoinException.ERR_WRONG_TYPE
                                && result.decrypting && result.addressType != Address.PUBLIC_KEY_TO_ADDRESS_LEGACY) {
                            insertingAddressProgrammatically = true;
                            addressTextEdit.setText(R.string.no_segwit_address_uncompressed_public_key);
                            insertingAddressProgrammatically = false;
                        } else {
                            msg = result.th == null ? null : result.th.getMessage();
                            if (msg == null) {
                                msg = result.toString();
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
            }
        });
    }

    private void wireSpentPanelInfoGeneratedListeners() {
        tasks.unspentOutputs.observe(this, unspentOutputs -> {
            if (unspentOutputs != null) {
                tasks.unspentOutputs.setValue(null);
                verifiedUnspentOutputsForTx = unspentOutputs.unspentOutputs;
                if (unspentOutputs.unspentOutputs == null) {
                    if (unspentOutputs.jsonInput && !TextUtils.isEmpty(unspentOutputs.jsonParseError)) {
                        rawTxToSpendErr.setText(getString(R.string.error_unable_to_decode_json_transaction, unspentOutputs.jsonParseError));
                    } else {
                        rawTxToSpendErr.setText(R.string.error_unable_to_decode_transaction);
                    }
                } else if (unspentOutputs.unspentOutputs.isEmpty()) {
                    rawTxToSpendErr.setText(getString(R.string.error_no_spendable_outputs_found, unspentOutputs.keyPair.address));
                } else {
                    rawTxToSpendErr.setText("");
                    long availableAmount = 0;
                    for (UnspentOutputInfo unspentOutputInfo : unspentOutputs.unspentOutputs) {
                        availableAmount += unspentOutputInfo.value;
                    }
                    amountEdit.setHint(BTCUtils.formatValue(availableAmount));
                    if (TextUtils.isEmpty(getString(amountEdit))) {
                        verifiedAmountToSendForTx = MainActivityTasks.SEND_MAX;
                    }
                    tryToGenerateSpendingTransaction();
                }
            }
        });
        tasks.generatedTransaction.observe(this, result -> {
            if (result != null) {
                tasks.generatedTransaction.setValue(null);
                if (result.btcTx != null) {
                    String amountStr = null;
                    Transaction.Script out = null;
                    try {
                        out = Transaction.Script.buildOutput(result.outputAddress);
                    } catch (BitcoinException ignore) {
                    }
                    if (result.btcTx.outputs[0].scriptPubKey.equals(out)) {
                        amountStr = BTCUtils.formatValue(result.btcTx.outputs[0].value);
                    }
                    if (amountStr == null) {
                        rawTxToSpendErr.setText(R.string.error_unknown);
                    } else {
                        String feeStr = BTCUtils.formatValue(result.fee);
                        SpannableStringBuilder descBuilderBtc = getTxDescription(amountStr, result.btcTx.outputs, feeStr,
                                false, result.keyPair, result.outputAddress);
                        SpannableStringBuilder descBuilderBch = result.bchTx == null ? null :
                                getTxDescription(amountStr, result.bchTx.outputs, feeStr,
                                        true, result.keyPair, result.outputAddress);
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
                } else if (result.errorSource == MainActivityTasks.GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD) {
                    rawTxToSpendErr.setText(result.errorMessage);
                } else if (result.errorSource == MainActivityTasks.GenerateTransactionResult.ERROR_SOURCE_ADDRESS_FIELD ||
                        result.errorSource == MainActivityTasks.GenerateTransactionResult.HINT_FOR_ADDRESS_FIELD) {
                    recipientAddressErrorView.setText(result.errorMessage);
                } else if (!TextUtils.isEmpty(result.errorMessage) && result.errorSource == MainActivityTasks.GenerateTransactionResult.ERROR_SOURCE_UNKNOWN) {
                    new AlertDialog.Builder(MainActivity.this)
                            .setMessage(result.errorMessage)
                            .setPositiveButton(android.R.string.ok, null)
                            .show();
                }

                amountErrorView.setText(
                        result.errorSource == MainActivityTasks.GenerateTransactionResult.ERROR_SOURCE_AMOUNT_FIELD ? result.errorMessage : "");
            }
        });
    }

    private void wireQrCodeRenderedListeners() {
        tasks.qrCodeForAddress.observe(this, result -> {
            if (result != null) {
                tasks.qrCodeForAddress.setValue(null);
                View view = getLayoutInflater().inflate(R.layout.address_qr, mainLayout, false);
                if (view != null) {
                    final ImageView qrView = view.findViewById(R.id.qr_code_image);
                    qrView.setImageBitmap(result.bitmap);

                    final TextView bitcoinProtocolLinkView = view.findViewById(R.id.link1);
                    SpannableStringBuilder labelUri = new SpannableStringBuilder(result.uriStr);
                    ClickableSpan urlSpan = new ClickableSpan() {
                        @Override
                        public void onClick(@NonNull View widget) {
                            Intent intent = new Intent(Intent.ACTION_VIEW);
                            intent.setData(Uri.parse(result.uriStr));
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
                    setUrlSpanForAddress("blockexplorer.com", result.address, blockexplorerLinkText);
                    blockexplorerLinkView.setText(blockexplorerLinkText);
                    blockexplorerLinkView.setMovementMethod(getLinkMovementMethod());

                    final TextView blockchainLinkView = view.findViewById(R.id.link3);
                    SpannableStringBuilder blockchainLinkText = new SpannableStringBuilder("blockchain.info");
                    setUrlSpanForAddress("blockchain.info", result.address, blockchainLinkText);
                    blockchainLinkView.setText(blockchainLinkText);
                    blockchainLinkView.setMovementMethod(getLinkMovementMethod());


                    AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                    builder.setTitle(result.address);
                    builder.setView(view);
                    if (systemSupportsPrint()) {
                        builder.setPositiveButton(R.string.print, (dialog, which) ->
                                Renderer.printQR(MainActivity.this, result.uriStr));
                        builder.setNegativeButton(android.R.string.cancel, null);
                    } else {
                        builder.setPositiveButton(android.R.string.ok, null);
                    }

                    builder.show();
                }
            }
        });
        tasks.qrCodeForPrivateKey.observe(this, result -> {
            if (result != null) {
                tasks.qrCodeForPrivateKey.setValue(null);
                if (result.bitmap != null) {
                    View view = getLayoutInflater().inflate(R.layout.private_key_qr, mainLayout, false);
                    if (view != null) {
                        final ToggleButton toggle1 = view.findViewById(R.id.toggle_1);
                        final ToggleButton toggle2 = view.findViewById(R.id.toggle_2);
                        final ToggleButton toggle3 = view.findViewById(R.id.toggle_3);
                        final ImageView qrView = view.findViewById(R.id.qr_code_image);
                        final TextView dataView = view.findViewById(R.id.qr_code_data);

                        if (result.data[0] == null) {
                            toggle1.setVisibility(View.GONE);
                        } else {
                            toggle1.setTextOff(result.dataTypes[0]);
                            toggle1.setTextOn(result.dataTypes[0]);
                            toggle1.setOnCheckedChangeListener((buttonView, isChecked) -> {
                                if (isChecked) {
                                    toggle2.setChecked(false);
                                    toggle3.setChecked(false);
                                    qrView.setImageBitmap(result.bitmap[0]);
                                    dataView.setText(result.data[0]);
                                } else if (!toggle2.isChecked() && !toggle3.isChecked()) {
                                    buttonView.setChecked(true);
                                }
                            });
                        }
                        if (result.data[1] == null) {
                            toggle2.setVisibility(View.GONE);
                        } else {
                            toggle2.setTextOff(result.dataTypes[1]);
                            toggle2.setTextOn(result.dataTypes[1]);
                            toggle2.setOnCheckedChangeListener((buttonView, isChecked) -> {
                                if (isChecked) {
                                    toggle1.setChecked(false);
                                    toggle3.setChecked(false);
                                    qrView.setImageBitmap(result.bitmap[1]);
                                    dataView.setText(result.data[1]);
                                } else if (!toggle1.isChecked() && !toggle3.isChecked()) {
                                    buttonView.setChecked(true);
                                }
                            });
                        }
                        if (result.data[2] == null) {
                            toggle3.setVisibility(View.GONE);
                        } else {
                            toggle3.setTextOff(result.dataTypes[2]);
                            toggle3.setTextOn(result.dataTypes[2]);
                            toggle3.setOnCheckedChangeListener((buttonView, isChecked) -> {
                                if (isChecked) {
                                    toggle1.setChecked(false);
                                    toggle2.setChecked(false);
                                    qrView.setImageBitmap(result.bitmap[2]);
                                    dataView.setText(result.data[2]);
                                } else if (!toggle1.isChecked() && !toggle2.isChecked()) {
                                    buttonView.setChecked(true);
                                }
                            });
                        }
                        if (result.data[2] != null) {
                            toggle3.setChecked(true);
                        } else if (result.data[0] != null) {
                            toggle1.setChecked(true);
                        } else {
                            toggle2.setChecked(true);
                        }

                        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                        builder.setTitle(result.label);
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
                            intent.putExtra(Intent.EXTRA_SUBJECT, result.label);
                            intent.putExtra(Intent.EXTRA_TEXT, result.data[selectedIndex]);
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
                                Renderer.printWallet(MainActivity.this, result.label,
                                        MainActivityTasks.SCHEME_BITCOIN + result.address, result.data[selectedIndex]);
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
        });
    }

    private void wireTextChangedListeners() {
        addressTextEdit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (!insertingAddressProgrammatically) {
                    tasks.cancelAllRunningTasks();
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
        privateKeyTextEdit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (!insertingPrivateKeyProgrammatically) {
                    insertingAddressProgrammatically = true;
                    setTextWithoutJumping(addressTextEdit, getString(R.string.decoding));
                    insertingAddressProgrammatically = false;
                    final String privateKeyToDecode = s.toString();
                    if (!TextUtils.isEmpty(privateKeyToDecode)) {
                        tasks.decodePrivateKey(getSelectedPublicKeyRepresentation(), privateKeyToDecode);
                    } else {
                        tasks.cancelAllRunningTasks();
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
    }

    private void wireListenersForKeyGeneration() {
        tasks.generatedKeyPair.observe(this, keyPair -> {
            if (keyPair != null) {
                tasks.generatedKeyPair.setValue(null);
                onNewKeyPairGenerated(keyPair);
            }
        });
        tasks.changedKeyPair.observe(this, generated -> {
            if (generated != null) {
                tasks.changedKeyPair.setValue(null);
                onKeyPairModify(false, generated.keyPair, generated.addressType);
            }
        });
        tasks.decodedKeyPair.observe(this, decoded -> {
            if (decoded != null) {
                tasks.decodedKeyPair.setValue(null);
                onKeyPairModify(false, decoded.keyPair, decoded.addressType);
            }
        });
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
        if (Address.verify(addressStr)) {
            if (verifiedKeyPairForTx != null && verifiedKeyPairForTx.address != null &&
                    addressStr.equals(verifiedKeyPairForTx.address.addressString)) {
                recipientAddressErrorView.setText(R.string.output_address_same_as_input);
            } else {
                recipientAddressErrorView.setText("");
            }
            verifiedRecipientAddressForTx = addressStr;
            tryToGenerateSpendingTransaction();
        } else {
            verifiedRecipientAddressForTx = null;
            recipientAddressErrorView.setText(TextUtils.isEmpty(addressStr) ? "" : getString(R.string.invalid_address));
        }
    }

    private void onUnspentOutputsInfoChanged() {
        final String unspentOutputsInfoStr = getString(rawTxToSpendEdit);
        final KeyPair keyPair = currentKeyPair;
        if (keyPair != null && keyPair.privateKey != null && keyPair.privateKey.privateKeyDecoded != null) {
            verifiedKeyPairForTx = keyPair;
            if (!TextUtils.isEmpty(verifiedRecipientAddressForTx) && verifiedKeyPairForTx.address != null &&
                    verifiedRecipientAddressForTx.equals(verifiedKeyPairForTx.address.addressString)) {
                recipientAddressErrorView.setText(R.string.output_address_same_as_input);
            }
            if (TextUtils.isEmpty(unspentOutputsInfoStr)) {
                rawTxToSpendErr.setText("");
                verifiedUnspentOutputsForTx = null;
            } else {
                tasks.decodeUnspentOutputsInfo(getResources(), keyPair, unspentOutputsInfoStr);
            }
        } else {
            verifiedKeyPairForTx = null;
        }
    }

    private void onSendAmountChanged(String amountStr) {
        if (TextUtils.isEmpty(amountStr)) {
            verifiedAmountToSendForTx = MainActivityTasks.SEND_MAX;
            amountErrorView.setText("");
            tryToGenerateSpendingTransaction();
        } else {
            try {
                double requestedAmountToSendDouble = Double.parseDouble(amountStr);
                long requestedAmountToSend = (long) (requestedAmountToSendDouble * 1e8);
                if (requestedAmountToSendDouble > 0 && requestedAmountToSendDouble < 21000000 && requestedAmountToSend > 0) {
                    verifiedAmountToSendForTx = requestedAmountToSend;
                    amountErrorView.setText("");
                    tryToGenerateSpendingTransaction();
                } else {
                    verifiedAmountToSendForTx = AMOUNT_ERR;
                    amountErrorView.setText(R.string.error_amount_parsing);
                }
            } catch (Exception e) {
                verifiedAmountToSendForTx = AMOUNT_ERR;
                amountErrorView.setText(R.string.error_amount_parsing);
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
            final boolean decrypting = inputKeyPair.privateKey.type == BTCUtils.Bip38PrivateKeyInfo.TYPE_BIP38 && inputKeyPair.privateKey.privateKeyDecoded == null;
            lastBip38ActionWasDecryption = decrypting;
            passwordButton.setEnabled(false);
            passwordButton.setText(decrypting ? R.string.decrypting : R.string.encrypting);
            InputMethodManager inputMethodManager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
            if (inputMethodManager != null) {
                inputMethodManager.hideSoftInputFromWindow(passwordEdit.getWindowToken(), 0);
            }
            progressDialog = ProgressDialog.show(MainActivity.this, "", (decrypting ?
                    getString(R.string.decrypting) : getString(R.string.encrypting)), true);
            progressDialog.setCancelable(true);
            progressDialog.setOnCancelListener(d -> tasks.cancelAllRunningTasks());
            tasks.bip38Transformation(getSelectedPublicKeyRepresentation(), sendLayout.isShown(), decrypting, inputKeyPair, password);
        }
    }

    @NonNull
    private static String nonNullStr(@Nullable String s) {
        return s == null ? "" : s;
    }

    private void showQRCodePopupForAddress(final String address) {
        DisplayMetrics dm = getResources().getDisplayMetrics();
        final int screenSize = Math.min(dm.widthPixels, dm.heightPixels);
        tasks.generateQrCodeImageForAddress(address, screenSize / 2);
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
        tasks.generateQrCodeImageForPrivateKey(label, address, dataTypes, data, screenSize / 2);
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
        passwordErrorView.setText("");
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

    private void tryToGenerateSpendingTransaction() {
        final List<UnspentOutputInfo> unspentOutputs = verifiedUnspentOutputsForTx;
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
                keyPair != null && keyPair.address != null && requestedAmountToSend >= MainActivityTasks.SEND_MAX && requestedAmountToSend != 0
                && !TextUtils.isEmpty(keyPair.address.addressString)) {
            SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
            tasks.generateTransaction(unspentOutputs, outputAddress, keyPair, requestedAmountToSend, preferences, getResources());
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
            startActivity(new Intent(this, PreferencesActivity.class));
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
            if (scannedResult != null && scannedResult.startsWith(MainActivityTasks.SCHEME_BITCOIN)) {
                scannedResult = scannedResult.substring(MainActivityTasks.SCHEME_BITCOIN.length());
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
        insertingPrivateKeyProgrammatically = true;
        setTextWithoutJumping(privateKeyTextEdit, "");
        insertingPrivateKeyProgrammatically = false;
        insertingAddressProgrammatically = true;
        setTextWithoutJumping(addressTextEdit, getString(R.string.generating));
        insertingAddressProgrammatically = false;
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
        String privateKeyType = preferences.getString(PreferencesActivity.PREF_PRIVATE_KEY, PreferencesActivity.PREF_PRIVATE_KEY_WIF_COMPRESSED);
        if (privateKeyType != null) {
            tasks.generateNewAddress(getSelectedPublicKeyRepresentation(), privateKeyType);
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
                        tasks.switchCompressionType(addressType, keyPair);
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
        tasks.cancelAllRunningTasks();
    }
}
