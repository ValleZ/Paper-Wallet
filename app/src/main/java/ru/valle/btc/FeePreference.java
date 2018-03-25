/*
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

import android.content.Context;
import android.content.res.TypedArray;
import android.preference.EditTextPreference;
import android.support.annotation.NonNull;
import android.util.AttributeSet;

import java.text.NumberFormat;

public class FeePreference extends EditTextPreference {
    private static final int PREF_FEE_SAT_MAX = 1000;
    public static final int PREF_FEE_SAT_BYTE_DEFAULT = 50;

    public FeePreference(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
    }

    public FeePreference(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public FeePreference(Context context) {
        super(context);
    }

    @Override
    protected boolean callChangeListener(Object newValue) {
        return super.callChangeListener(newValue) && enteredFeeIsValid(newValue);
    }

    private static boolean enteredFeeIsValid(Object newValue) {
        if (newValue == null) {
            return false;
        }
        try {
            int newFee = newValue instanceof Number ?
                    ((Number) newValue).intValue() : Integer.parseInt(newValue.toString());
            return newFee >= 0 && newFee < PREF_FEE_SAT_MAX;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected Object onGetDefaultValue(@NonNull TypedArray a, int index) {
        return PREF_FEE_SAT_BYTE_DEFAULT;
    }

    @Override
    protected boolean persistString(String value) {
        try {
            return persistInt(NumberFormat.getInstance().parse(value).intValue());
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected String getPersistedString(String defaultReturnValue) {
        try {
            return NumberFormat.getInstance().format(getPersistedInt(PREF_FEE_SAT_BYTE_DEFAULT));
        } catch (ClassCastException e) {
            return super.getPersistedString(NumberFormat.getInstance().format(PREF_FEE_SAT_BYTE_DEFAULT));
        }
    }
}
