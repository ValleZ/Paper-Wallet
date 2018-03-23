/*
 * Basic no frills app which integrates the ZBar barcode scanner with
 * the camera.
 * 
 * Created by lisah0 on 2012-02-24
 */
package ru.valle.btc;

import android.Manifest;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.hardware.Camera;
import android.hardware.Camera.AutoFocusCallback;
import android.hardware.Camera.PreviewCallback;
import android.hardware.Camera.Size;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.WorkerThread;
import android.text.TextUtils;
import android.util.Log;
import android.view.WindowManager;

import net.sourceforge.zbar.Config;
import net.sourceforge.zbar.Image;
import net.sourceforge.zbar.ImageScanner;
import net.sourceforge.zbar.Symbol;
import net.sourceforge.zbar.SymbolSet;

import java.security.MessageDigest;

@SuppressWarnings("deprecation")
public final class ScanActivity extends Activity {
    private static final String TAG = "CameraTestActivity";
    private static final int REQUEST_CAMERA_PERMISSION = 1;
    private static final String BITCOIN_SCHEMA = "bitcoin:";
    @Nullable
    private Camera camera;

    static {
        System.loadLibrary("iconv");
    }

    @Nullable
    private HandlerThread recognizerThread;
    @Nullable
    private RecognizerHandler recognizer;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }
        if (Build.VERSION.SDK_INT < 23 || hasCameraPermission()) {
            createCameraSource();
        } else {
            requestCameraPermission();
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void requestCameraPermission() {
        requestPermissions(new String[]{Manifest.permission.CAMERA}, REQUEST_CAMERA_PERMISSION);
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean hasCameraPermission() {
        return checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED;
    }

    private class RecognizerHandler extends Handler {
        static final int MSG_FRAME = 1;
        static final int MSG_DESTROY = 2;
        @Nullable
        private ImageScanner scanner;
        private boolean finished;

        RecognizerHandler(Looper looper) {
            super(looper);
        }

        @Override
        @WorkerThread
        public void handleMessage(Message msg) {
            if (!finished) {
                if (msg.what == MSG_FRAME) {
                    recognizeFrame(msg);
                } else if (msg.what == MSG_DESTROY) {
                    destroy();
                }
            }
        }

        @WorkerThread
        private void recognizeFrame(Message msg) {
            if (scanner == null) {
                scanner = new ImageScanner();
                scanner.setConfig(0, Config.X_DENSITY, 3);
                scanner.setConfig(0, Config.Y_DENSITY, 3);
            }
            Image barcode = (Image) msg.obj;
            int result = scanner.scanImage(barcode);
            if (result != 0) {
                SymbolSet syms = scanner.getResults();
                for (Symbol sym : syms) {
                    String scannedData = sym.getData();
                    if (!TextUtils.isEmpty(scannedData)) {
                        if (scannedData.startsWith(BITCOIN_SCHEMA)) {
                            scannedData = scannedData.substring(BITCOIN_SCHEMA.length());
                        }
                        boolean validInput = Address.verify(scannedData);
                        if (!validInput) {
                            //then maybe it's a private key?
                            byte[] decodedEntity = BTCUtils.decodeBase58(scannedData);
                            validInput = decodedEntity != null && BTCUtils.verifyDoubleSha256Checksum(decodedEntity);
                            if (!validInput && decodedEntity != null && scannedData.startsWith("S")) {
                                try {
                                    validInput = MessageDigest.getInstance("SHA-256").digest(
                                            (scannedData + '?').getBytes("UTF-8"))[0] == 0;
                                } catch (Exception ignored) {
                                }
                            }
                        }
                        if (validInput) {
                            destroy();
                            String finalScannedData = scannedData;
                            mainHandler.post(() -> {
                                recognizer = null;
                                if (camera != null) {
                                    camera.setPreviewCallback(null);
                                    camera.stopPreview();
                                    releaseCamera();
                                }
                                setResult(RESULT_OK, new Intent().putExtra("data", finalScannedData));
                                finish();
                            });
                        }
                    }
                }
            }
        }

        @WorkerThread
        private void destroy() {
            if (scanner != null) {
                scanner.destroy();
                scanner = null;
            }
            finished = true;
            Looper looper = getLooper();
            if (looper != null) {
                looper.quit();
            }
        }
    }

    private void createCameraSource() {
        if (camera == null) {
            try {
                camera = Camera.open();
                if (camera == null) {
                    throw new RuntimeException(getString(R.string.unable_open_camera));
                }
                recognizerThread = new HandlerThread("recognizer");
                recognizerThread.start();
                recognizer = new RecognizerHandler(recognizerThread.getLooper());
                setContentView(new CameraPreview(this, camera, previewCallback, autoFocusCallback));
            } catch (Exception e) {
                Log.e(TAG, getString(R.string.unable_open_camera), e);
                setResult(RESULT_CANCELED);
                finish();
            }
        }
    }

    @SuppressLint("Override")
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (grantResults.length != 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            createCameraSource();
        } else {
            new AlertDialog.Builder(this).setMessage(R.string.no_camera_permission_granted)
                    .setPositiveButton(R.string.ok, (dialogInterface, i) -> finish()).show();
        }
    }

    private final PreviewCallback previewCallback = new PreviewCallback() {
        @SuppressWarnings("deprecation")
        public void onPreviewFrame(byte[] data, Camera camera) {
            Size size = null;
            try {
                size = camera.getParameters().getPreviewSize();
            } catch (Exception e) {
                Log.e(TAG, "Failed to get camera preview parameters", e);
            }
            if (size != null && recognizer != null && !recognizer.hasMessages(RecognizerHandler.MSG_FRAME)) {
                Image barcode = new Image(size.width, size.height, "Y800");
                barcode.setData(data);
                recognizer.sendMessage(recognizer.obtainMessage(RecognizerHandler.MSG_FRAME, barcode));
            }
        }
    };

    @Override
    protected void onDestroy() {
        super.onDestroy();
        releaseCamera();
    }

    private void releaseCamera() {
        if (camera != null) {
            camera.setPreviewCallback(null);
            camera.release();
            camera = null;
        }
        if (recognizer != null) {
            recognizer.sendEmptyMessage(RecognizerHandler.MSG_DESTROY);
            recognizer = null;
            recognizerThread = null;
        }
    }

    private final Handler handler = new Handler();

    private final AutoFocusCallback autoFocusCallback = new AutoFocusCallback() {
        public void onAutoFocus(boolean success, Camera camera) {
            handler.postDelayed(doAutoFocus, 1000);
        }
    };

    private final Runnable doAutoFocus = new Runnable() {
        public void run() {
            if (camera != null) {
                try {
                    camera.autoFocus(autoFocusCallback);
                } catch (Exception e) {
                    Log.w(TAG, "autofocus", e);
                    handler.postDelayed(this, 1000);
                }
            }
        }
    };

}
