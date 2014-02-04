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

import android.content.Context;
import android.content.res.TypedArray;
import android.preference.EditTextPreference;
import android.util.AttributeSet;
import org.jetbrains.annotations.NotNull;

public class FeePreference extends EditTextPreference {
    public static final double PREF_FEE_MIN = 0;
    public static final long PREF_FEE_DEFAULT = BTCUtils.parseValue("0.0002");
    public static final long PREF_FEE_MAX = BTCUtils.parseValue("0.1");

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

    private boolean enteredFeeIsValid(Object newValue) {
        try {
            long newFee = BTCUtils.parseValue(newValue.toString());
            return newFee >= PREF_FEE_MIN && newFee < PREF_FEE_MAX;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected Object onGetDefaultValue(@NotNull TypedArray a, int index) {
        return BTCUtils.formatValue(PREF_FEE_DEFAULT);
    }

    @Override
    protected boolean persistString(String value) {
        try {
            return persistLong(BTCUtils.parseValue(value));
        } catch (NumberFormatException e) {
            return persistLong(BTCUtils.parseValue(value.replace(',', '.')));
        }
    }

    @Override
    protected String getPersistedString(String defaultReturnValue) {
        try {
            return BTCUtils.formatValue(super.getPersistedLong(PREF_FEE_DEFAULT));
        } catch (ClassCastException e) {
            return super.getPersistedString(BTCUtils.formatValue(PREF_FEE_DEFAULT));
        }
    }

    @Override
    protected long getPersistedLong(long defaultReturnValue) {
        try {
            return super.getPersistedLong(defaultReturnValue);
        } catch (ClassCastException e) {
            return BTCUtils.parseValue(getPersistedString(BTCUtils.formatValue(PREF_FEE_DEFAULT)));
        }
    }
}
