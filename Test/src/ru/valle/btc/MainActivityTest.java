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
import android.test.ActivityInstrumentationTestCase2;
import android.test.UiThreadTest;
import android.text.TextUtils;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

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
        String address = waitForAddress(getActivity());
        assertNotNull(address);
        assertTrue("Addresses must starts with '1', but generated address is '" + address + "'", address.startsWith("1"));
        String privateKey = getText(getActivity(), R.id.private_key_label);
        assertTrue("Private keys must starts with 'S', but generated key is '" + privateKey + "'", privateKey.startsWith("S"));
        assertEquals("Private keys should have length 30 characters ", privateKey.length(), 30);
    }

    private String waitForAddress(Activity activity) {
        for (int i = 0; i < 10; i++) {
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
                return ((TextView) activity.findViewById(id)).getText().toString();
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

}
