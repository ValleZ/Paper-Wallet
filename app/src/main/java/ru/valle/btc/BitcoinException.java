/*
 The MIT License (MIT)

 Copyright (c) 2013-2014 Valentin Konovalov

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

@SuppressWarnings("WeakerAccess")
public final class BitcoinException extends Exception {
    public static final int ERR_NO_SPENDABLE_OUTPUTS_FOR_THE_ADDRESS = 0;
    public static final int ERR_INSUFFICIENT_FUNDS = 1;
    public static final int ERR_WRONG_TYPE = 2;
    public static final int ERR_BAD_FORMAT = 3;
    public static final int ERR_INCORRECT_PASSWORD = 4;
    public static final int ERR_MEANINGLESS_OPERATION = 5;
    public static final int ERR_NO_INPUT = 6;
    public static final int ERR_FEE_IS_TOO_BIG = 7;
    public static final int ERR_FEE_IS_LESS_THEN_ZERO = 8;
    public static final int ERR_CHANGE_IS_LESS_THEN_ZERO = 9;
    public static final int ERR_AMOUNT_TO_SEND_IS_LESS_THEN_ZERO = 10;
    public static final int ERR_UNSUPPORTED = 11;

    public final int errorCode;
    @SuppressWarnings({"WeakerAccess", "unused"})
    public final Object extraInformation;

    public BitcoinException(int errorCode, String detailMessage, Object extraInformation) {
        super(detailMessage);
        this.errorCode = errorCode;
        this.extraInformation = extraInformation;
    }

    public BitcoinException(int errorCode, String detailMessage) {
        this(errorCode, detailMessage, null);
    }
}
