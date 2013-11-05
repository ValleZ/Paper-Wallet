/*
 * Basic no frills app which integrates the ZBar barcode scanner with
 * the camera.
 * 
 * Created by lisah0 on 2012-02-24
 */
package ru.valle.btc;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.hardware.Camera;
import android.hardware.Camera.AutoFocusCallback;
import android.hardware.Camera.PreviewCallback;
import android.hardware.Camera.Size;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import net.sourceforge.zbar.Config;
import net.sourceforge.zbar.Image;
import net.sourceforge.zbar.ImageScanner;
import net.sourceforge.zbar.Symbol;
import net.sourceforge.zbar.SymbolSet;

public final class ScanActivity extends Activity {
    private static final String TAG = "CameraTestActivity";

    Camera camera;
    private ImageScanner scanner;

    static {
        System.loadLibrary("iconv");
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
        if (camera == null) {
            try {
                camera = Camera.open();
                scanner = new ImageScanner();
                scanner.setConfig(0, Config.X_DENSITY, 3);
                scanner.setConfig(0, Config.Y_DENSITY, 3);
                setContentView(new CameraPreview(this, camera, previewCallback, autoFocusCallback));
            } catch (Exception e) {
                Log.e(TAG, "unable to open camera", e);
                setResult(RESULT_CANCELED);
                finish();
            }
        }
    }

    private final PreviewCallback previewCallback = new PreviewCallback() {
        public void onPreviewFrame(byte[] data, Camera camera) {
            Size size = camera.getParameters().getPreviewSize();
            Image barcode = new Image(size.width, size.height, "Y800");
            barcode.setData(data);
            int result = scanner.scanImage(barcode);
            if (result != 0) {
                SymbolSet syms = scanner.getResults();
                for (Symbol sym : syms) {
                    String scannedData = sym.getData();
                    byte[] decodedEntity = BTCUtils.decodeBase58(scannedData);
                    if (decodedEntity != null && BTCUtils.verifyChecksum(decodedEntity)) {
                        camera.setPreviewCallback(null);
                        camera.stopPreview();
                        releaseCamera();
                        setResult(RESULT_OK, new Intent().putExtra("data", scannedData));
                        finish();
                        return;
                    }
                }
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
            scanner.destroy();
            camera = null;
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
