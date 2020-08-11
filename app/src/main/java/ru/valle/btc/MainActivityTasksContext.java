package ru.valle.btc;

import android.content.SharedPreferences;
import android.content.res.Resources;
import android.os.Handler;
import android.os.Looper;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import androidx.annotation.AnyThread;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.lifecycle.MutableLiveData;

// it's not a view model yet
public class MainActivityTasksContext {
    private static final ExecutorService EXECUTOR = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    final MutableLiveData<KeyPair> generatedKeyPair = new MutableLiveData<>();
    final MutableLiveData<MainActivityTasks.KeyPairWithAddressType> changedKeyPair = new MutableLiveData<>();
    final MutableLiveData<MainActivityTasks.KeyPairWithAddressType> decodedKeyPair = new MutableLiveData<>();
    final MutableLiveData<MainActivityTasks.ParsedUnspentOutputs> unspentOutputs = new MutableLiveData<>();
    final MutableLiveData<MainActivityTasks.Bip38TransformationResult> bip38Transformation = new MutableLiveData<>();
    final MutableLiveData<MainActivityTasks.QrForAddress> qrCodeForAddress = new MutableLiveData<>();
    final MutableLiveData<MainActivityTasks.QrForPrivateKey> qrCodeForPrivateKey = new MutableLiveData<>();
    final MutableLiveData<MainActivityTasks.GenerateTransactionResult> generatedTransaction = new MutableLiveData<>();
    private int seqCounter;
    private Future<?> bip38Task;

    public void cancelAllRunningTasks() {
        newOrder();
    }

    public void switchAddressType(@Address.PublicKeyRepresentation int addressType, BTCUtils.PrivateKeyInfo privateKeyInfo) {
        int seq = newOrder();
        EXECUTOR.submit(() -> {
            KeyPair result = MainActivityTasks.generateKeyPair(privateKeyInfo, addressType);
            postResult(seq, new MainActivityTasks.KeyPairWithAddressType(result, addressType), changedKeyPair);
        });
    }

    public void switchCompressionType(@Address.PublicKeyRepresentation int addressType, KeyPair keyPair) {
        int seq = newOrder();
        EXECUTOR.submit(() -> {
            MainActivityTasks.KeyPairWithAddressType result = MainActivityTasks.switchCompressionType(addressType, keyPair);
            postResult(seq, result, changedKeyPair);
        });
    }

    public void decodePrivateKey(@Address.PublicKeyRepresentation int addressType, @NonNull String privateKeyToDecode) {
        int seq = newOrder();
        EXECUTOR.submit(() -> {
            MainActivityTasks.KeyPairWithAddressType result = MainActivityTasks.decodePrivateKey(addressType, privateKeyToDecode);
            if (result != null) {
                postResult(seq, result, decodedKeyPair);
            }
        });
    }

    public void decodeUnspentOutputsInfo(@NonNull Resources resources, @NonNull KeyPair keyPair, @NonNull String unspentOutputsInfoStr) {
        int seq = newOrder();
        EXECUTOR.submit(() -> {
            MainActivityTasks.ParsedUnspentOutputs result = MainActivityTasks.runDecodeUnspentOutputsInfo(
                    resources, keyPair, unspentOutputsInfoStr);
            postResult(seq, result, unspentOutputs);
        });
    }


    @MainThread
    private int newOrder() {
        if (bip38Task != null) {
            bip38Task.cancel(true);
            bip38Task = null;
            bip38Transformation.setValue(MainActivityTasks.Bip38TransformationResult.CANCELLED);
        }
        return ++seqCounter;
    }

    @AnyThread
    private <T> void postResult(int seq, T result, MutableLiveData<T> liveData) {
        handler.post(() -> {
            if (seq >= seqCounter) {
                liveData.setValue(result);
            }
            bip38Task = null;
        });
    }

    public void bip38Transformation(@Address.PublicKeyRepresentation int addressType,
                                    boolean sendLayoutVisible, boolean decrypting,
                                    KeyPair inputKeyPair, String password) {
        int seq = newOrder();
        bip38Task = EXECUTOR.submit(() -> {
            MainActivityTasks.Bip38TransformationResult result = MainActivityTasks.bip38Transformation(
                    addressType, decrypting, inputKeyPair, password, sendLayoutVisible);
            postResult(seq, result, bip38Transformation);
        });
    }

    public void generateQrCodeImageForAddress(String address, int size) {
        EXECUTOR.submit(() -> {
            MainActivityTasks.QrForAddress result = MainActivityTasks.qrForAddress(address, size);
            postResult(Integer.MAX_VALUE, result, qrCodeForAddress);
        });
    }

    public void generateQrCodeImageForPrivateKey(String label, String address, String[] dataTypes, String[] data, int size) {
        EXECUTOR.submit(() -> {
            MainActivityTasks.QrForPrivateKey result = MainActivityTasks.qrCodeImageForPrivateKey(label, address, dataTypes, data, size);
            postResult(Integer.MAX_VALUE, result, qrCodeForPrivateKey);
        });
    }

    public void generateTransaction(List<UnspentOutputInfo> unspentOutputs, String outputAddress, KeyPair keyPair,
                                    long requestedAmountToSend, SharedPreferences preferences, Resources resources) {
        int seq = newOrder();
        EXECUTOR.submit(() -> {
            MainActivityTasks.GenerateTransactionResult result = MainActivityTasks.generateTransaction(
                    unspentOutputs, outputAddress, keyPair, requestedAmountToSend, preferences, resources);
            postResult(seq, result, generatedTransaction);
        });
    }

    public void generateNewAddress(int selectedPublicKeyRepresentation, String privateKeyType) {
        int seq = newOrder();
        EXECUTOR.submit(() -> {
            KeyPair result = MainActivityTasks.generateNewAddress(selectedPublicKeyRepresentation, privateKeyType);
            if (result != null) {
                postResult(seq, result, generatedKeyPair);
            }
        });
    }
}
