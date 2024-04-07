package ru.valle.btc;

import android.content.SharedPreferences;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.util.Log;

import com.d_project.qrcode.ErrorCorrectLevel;
import com.d_project.qrcode.QRCode;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class MainActivityTasks {
    static final String SCHEME_BITCOIN = "bitcoin:";
    static final long SEND_MAX = -1;

    static KeyPairWithAddressType decodePrivateKey(int addressType, String privateKeyToDecode) {
        MainActivityTasks.KeyPairWithAddressType result = null;
        try {
            boolean compressedPublicKeyForPaperWallets = addressType != Address.PUBLIC_KEY_TO_ADDRESS_LEGACY;
            BTCUtils.PrivateKeyInfo privateKeyInfo = BTCUtils.decodePrivateKey(privateKeyToDecode, compressedPublicKeyForPaperWallets);
            if (privateKeyInfo != null) {
                KeyPair keyPair = new KeyPair(privateKeyInfo, addressType);
                result = new KeyPairWithAddressType(keyPair, addressType);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return result;
    }

    static KeyPair generateKeyPair(BTCUtils.PrivateKeyInfo privateKeyInfo, @Address.PublicKeyRepresentation int addressType) {
        return new KeyPair(privateKeyInfo, addressType);
    }

    @NonNull
    static ParsedUnspentOutputs runDecodeUnspentOutputsInfo(Resources resources, KeyPair keyPair, String unspentOutputsInfoStr) {
        boolean jsonInput = false;
        String jsonParseError;
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
                    jsonParseError = resources.getString(R.string.json_err_no_unspent_outputs);
                    return new ParsedUnspentOutputs(true, jsonParseError, null, keyPair);
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
            return new ParsedUnspentOutputs(jsonInput, null, unspentOutputs, keyPair);
        } catch (Exception e) {
            jsonParseError = e.getMessage();
            return new ParsedUnspentOutputs(jsonInput, jsonParseError, null, keyPair);
        }
    }

    public static Bip38TransformationResult bip38Transformation(int addressType, boolean decrypting, KeyPair inputKeyPair, String password, boolean sendLayoutVisible) {
        try {
            KeyPair keyPair;
            if (decrypting) {
                keyPair = BTCUtils.bip38Decrypt(inputKeyPair.privateKey.privateKeyEncoded, password, addressType);
            } else {
                String encryptedPrivateKey = BTCUtils.bip38Encrypt(inputKeyPair, password);
                keyPair = new KeyPair(new BTCUtils.Bip38PrivateKeyInfo(encryptedPrivateKey,
                        inputKeyPair.privateKey.privateKeyDecoded, password, inputKeyPair.privateKey.isPublicKeyCompressed), addressType);
            }
            return new Bip38TransformationResult(keyPair, null, false, addressType, sendLayoutVisible, decrypting, inputKeyPair);
        } catch (Throwable th) {
            return new Bip38TransformationResult(null, th, false, addressType, sendLayoutVisible, decrypting, inputKeyPair);
        }
    }

    public static QrForAddress qrForAddress(String address, int size) {
        String uriStr = SCHEME_BITCOIN + address;
        Bitmap result = QRCode.getMinimumQRCode(uriStr, ErrorCorrectLevel.M).createImage(size);
        return new QrForAddress(address, uriStr, result);
    }


    public static QrForPrivateKey qrCodeImageForPrivateKey(String label, String address, String[] dataTypes, String[] data, int size) {
        Bitmap[] bitmaps;
        try {
            bitmaps = new Bitmap[data.length];
            for (int i = 0; i < data.length; i++) {
                if (data[i] != null) {
                    QRCode qr = QRCode.getMinimumQRCode(data[i], ErrorCorrectLevel.M);
                    bitmaps[i] = qr.createImage(size);
                }
            }
        } catch (Exception e) {
            Log.w("QRCODE", "error", e);
            bitmaps = null;
        }
        return new MainActivityTasks.QrForPrivateKey(bitmaps, label, address, dataTypes, data);
    }

    public static GenerateTransactionResult generateTransaction(
            List<UnspentOutputInfo> unspentOutputs, String outputAddress, KeyPair keyPair, long requestedAmountToSend,
            SharedPreferences preferences, Resources resources) {
        Transaction btcSpendTx = null;
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

            try {
                satoshisPerVirtualByte = preferences.getInt(PreferencesActivity.PREF_FEE_SAT_BYTE, FeePreference.PREF_FEE_SAT_BYTE_DEFAULT);
            } catch (ClassCastException e) {
                preferences.edit()
                        .remove(PreferencesActivity.PREF_FEE_SAT_BYTE)
                        .putInt(PreferencesActivity.PREF_FEE_SAT_BYTE, FeePreference.PREF_FEE_SAT_BYTE_DEFAULT).apply();
                satoshisPerVirtualByte = FeePreference.PREF_FEE_SAT_BYTE_DEFAULT;
            }
            Address outputAddressDecoded = Address.decode(outputAddress);
            if (outputAddressDecoded != null && !outputAddressDecoded.isBitcoinCash()
                    && keyPair.address != null) {
                //Always try to use segwit here even if it's disabled since the switch is only about generated address type
                //Do we need another switch to disable segwit in tx?
                btcSpendTx = BTCUtils.createTransaction(unspentOutputs,
                        outputAddress, keyPair.address.addressString, amount, satoshisPerVirtualByte, BTCUtils.TRANSACTION_TYPE_SEGWIT
                );
            }
            try {
                if (outputAddressDecoded != null && outputAddressDecoded.keyhashType != Address.TYPE_P2SH
                        && keyPair.address != null) { //this check prevents sending BCH to SegWit
                    bchSpendTx = BTCUtils.createTransaction(unspentOutputs,
                            outputAddress, keyPair.address.addressString, amount, satoshisPerVirtualByte, BTCUtils.TRANSACTION_TYPE_BITCOIN_CASH);
                }
            } catch (Exception ignored) {
            }

            //6. double check that generated transaction is valid
            if (btcSpendTx != null) {
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
                BTCUtils.checkTransaction(btcSpendTx);
            }
            if (bchSpendTx != null) {
                Transaction.Script[] relatedScripts = new Transaction.Script[bchSpendTx.inputs.length];
                long[] amounts = new long[bchSpendTx.inputs.length];
                BTCUtils.verify(relatedScripts, amounts, bchSpendTx, true);
                BTCUtils.checkTransaction(bchSpendTx);
            }
        } catch (BitcoinException e) {
            switch (e.errorCode) {
                case BitcoinException.ERR_INSUFFICIENT_FUNDS:
                    return new GenerateTransactionResult(resources.getString(R.string.error_not_enough_funds),
                            GenerateTransactionResult.ERROR_SOURCE_AMOUNT_FIELD, outputAddress, keyPair);
                case BitcoinException.ERR_FEE_IS_TOO_BIG:
                    return new GenerateTransactionResult(resources.getString(R.string.generated_tx_have_too_big_fee),
                            GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD, outputAddress, keyPair);
                case BitcoinException.ERR_AMOUNT_TO_SEND_IS_LESS_THEN_ZERO:
                    return new GenerateTransactionResult(resources.getString(R.string.fee_is_greater_than_available_balance),
                            GenerateTransactionResult.ERROR_SOURCE_INPUT_TX_FIELD, outputAddress, keyPair);
                case BitcoinException.ERR_MEANINGLESS_OPERATION://input, output and change addresses are same.
                    return new GenerateTransactionResult(resources.getString(R.string.output_address_same_as_input),
                            GenerateTransactionResult.ERROR_SOURCE_ADDRESS_FIELD, outputAddress, keyPair);
//                            case BitcoinException.ERR_INCORRECT_PASSWORD
//                            case BitcoinException.ERR_WRONG_TYPE:
//                            case BitcoinException.ERR_FEE_IS_LESS_THEN_ZERO
//                            case BitcoinException.ERR_CHANGE_IS_LESS_THEN_ZERO
//                            case BitcoinException.ERR_AMOUNT_TO_SEND_IS_LESS_THEN_ZERO
                default:
                    return new GenerateTransactionResult(resources.getString(R.string.error_failed_to_create_transaction) +
                            ": " + e.getMessage(), GenerateTransactionResult.ERROR_SOURCE_UNKNOWN, outputAddress, keyPair);
            }
        } catch (Exception e) {
            return new GenerateTransactionResult(resources.getString(R.string.error_failed_to_create_transaction) +
                    ": " + e, GenerateTransactionResult.ERROR_SOURCE_UNKNOWN, outputAddress, keyPair);
        }

        long inValue = 0;
        if(btcSpendTx!=null || bchSpendTx!=null) {
            for (Transaction.Input input : btcSpendTx != null ? btcSpendTx.inputs : bchSpendTx.inputs) {
                for (UnspentOutputInfo unspentOutput : unspentOutputs) {
                    if (Arrays.equals(unspentOutput.txHash, input.outPoint.hash) && unspentOutput.outputIndex == input.outPoint.index) {
                        inValue += unspentOutput.value;
                    }
                }
            }
        }
        long outValue = 0;
        if(btcSpendTx!=null || bchSpendTx!=null) {
            for (Transaction.Output output : btcSpendTx != null ? btcSpendTx.outputs : bchSpendTx.outputs) {
                outValue += output.value;
            }
        }
        long fee = inValue - outValue;
        return new GenerateTransactionResult(btcSpendTx, bchSpendTx, fee, outputAddress, keyPair);
    }

    @Nullable
    public static KeyPair generateNewAddress(@Address.PublicKeyRepresentation int addressType, String privateKeyType) {
        switch (privateKeyType) {
            case PreferencesActivity.PREF_PRIVATE_KEY_WIF_COMPRESSED:
                return BTCUtils.generateWifKey(false, addressType);
            case PreferencesActivity.PREF_PRIVATE_KEY_MINI:
                return BTCUtils.generateMiniKey(addressType);
            case PreferencesActivity.PREF_PRIVATE_KEY_WIF_TEST_NET:
                return BTCUtils.generateWifKey(true, addressType);
        }
        return null;
    }

    public static KeyPairWithAddressType switchCompressionType(int addressType, KeyPair keyPair) {
        return new KeyPairWithAddressType(new KeyPair(new BTCUtils.PrivateKeyInfo(keyPair.privateKey.testNet,
                keyPair.privateKey.type, keyPair.privateKey.privateKeyEncoded,
                keyPair.privateKey.privateKeyDecoded, !keyPair.privateKey.isPublicKeyCompressed),
                addressType), addressType);
    }

    static class KeyPairWithAddressType {
        final KeyPair keyPair;
        @Address.PublicKeyRepresentation
        final int addressType;

        public KeyPairWithAddressType(KeyPair keyPair, @Address.PublicKeyRepresentation int addressType) {
            this.keyPair = keyPair;
            this.addressType = addressType;
        }
    }

    static class ParsedUnspentOutputs {
        final boolean jsonInput;
        @Nullable
        final String jsonParseError;
        @Nullable
        final List<UnspentOutputInfo> unspentOutputs;
        final KeyPair keyPair;

        public ParsedUnspentOutputs(boolean jsonInput, @Nullable String jsonParseError, @Nullable List<UnspentOutputInfo> unspentOutputs, KeyPair keyPair) {
            this.jsonInput = jsonInput;
            this.jsonParseError = jsonParseError;
            this.unspentOutputs = unspentOutputs;
            this.keyPair = keyPair;
        }
    }


    static class Bip38TransformationResult {
        public static final Bip38TransformationResult CANCELLED = new Bip38TransformationResult(
                null, null, true, 0, false, false, null);
        @Nullable
        final KeyPair keyPair;
        @Nullable
        final Throwable th;
        final boolean cancelled;
        @Address.PublicKeyRepresentation
        final int addressType;
        final boolean sendLayoutVisible;
        final boolean decrypting;
        final KeyPair inputKeyPair;

        public Bip38TransformationResult(@Nullable KeyPair keyPair, @Nullable Throwable th,
                                         boolean cancelled, int addressType, boolean sendLayoutVisible,
                                         boolean decrypting, KeyPair inputKeyPair
        ) {
            this.keyPair = keyPair;
            this.th = th;
            this.cancelled = cancelled;
            this.addressType = addressType;
            this.sendLayoutVisible = sendLayoutVisible;
            this.decrypting = decrypting;
            this.inputKeyPair = inputKeyPair;
        }
    }

    static class QrForAddress {

        final String address;
        final String uriStr;
        final Bitmap bitmap;

        public QrForAddress(String address, String uriStr, Bitmap bitmap) {
            this.address = address;
            this.uriStr = uriStr;
            this.bitmap = bitmap;
        }
    }

    static class QrForPrivateKey {
        final Bitmap[] bitmap;
        final String label;
        final String address;
        final String[] dataTypes;
        final String[] data;

        public QrForPrivateKey(Bitmap[] bitmap, String label, String address, String[] dataTypes, String[] data) {
            this.bitmap = bitmap;
            this.label = label;
            this.address = address;
            this.dataTypes = dataTypes;
            this.data = data;
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

        final String outputAddress;
        final KeyPair keyPair;

        GenerateTransactionResult(String errorMessage, int errorSource, String outputAddress, KeyPair keyPair) {
            this.outputAddress = outputAddress;
            this.keyPair = keyPair;
            btcTx = null;
            bchTx = null;
            this.errorMessage = errorMessage;
            this.errorSource = errorSource;
            fee = -1;
        }

        GenerateTransactionResult(Transaction btcTx, @Nullable Transaction bchTx, long fee, String outputAddress, KeyPair keyPair) {
            this.btcTx = btcTx;
            this.bchTx = bchTx;
            this.outputAddress = outputAddress;
            this.keyPair = keyPair;
            errorMessage = null;
            errorSource = ERROR_SOURCE_UNKNOWN;
            this.fee = fee;
        }
    }
}
