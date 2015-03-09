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

public class KeyPair {
    public final byte[] publicKey;
    public final String address;
    public final BTCUtils.PrivateKeyInfo privateKey;

    public KeyPair(BTCUtils.PrivateKeyInfo privateKeyInfo) {
        if (privateKeyInfo.privateKeyDecoded == null) {
            publicKey = null;
            address = null;
        } else {
            publicKey = BTCUtils.generatePublicKey(privateKeyInfo.privateKeyDecoded, privateKeyInfo.isPublicKeyCompressed);
            address = BTCUtils.publicKeyToAddress(publicKey);
        }
        privateKey = privateKeyInfo;
    }

    public KeyPair(String address, byte[] publicKey, BTCUtils.PrivateKeyInfo privateKey) {
        this.publicKey = publicKey;
        this.address = address;
        this.privateKey = privateKey;
    }
}
