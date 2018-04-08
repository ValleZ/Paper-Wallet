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

import android.support.annotation.NonNull;

@SuppressWarnings("WeakerAccess")
public class KeyPair {
    public final byte[] publicKey;
    public final Address address;
    public final BTCUtils.PrivateKeyInfo privateKey;

    public KeyPair(@NonNull BTCUtils.PrivateKeyInfo privateKeyInfo, @Address.PublicKeyRepresentation int publicKeyRepresentation) {
        if (privateKeyInfo.privateKeyDecoded == null) {
            publicKey = null;
            address = null;
        } else {
            publicKey = BTCUtils.generatePublicKey(privateKeyInfo.privateKeyDecoded, privateKeyInfo.isPublicKeyCompressed);
            String addressStr;
            switch (publicKeyRepresentation) {
                case Address.PUBLIC_KEY_TO_ADDRESS_LEGACY:
                    addressStr = Address.publicKeyToAddress(privateKeyInfo.testNet, publicKey);
                    break;
                case Address.PUBLIC_KEY_TO_ADDRESS_P2WKH:
                    addressStr = Address.publicKeyToP2wkhAddress(privateKeyInfo.testNet, publicKey);
                    break;
                case Address.PUBLIC_KEY_TO_ADDRESS_P2SH_P2WKH:
                    addressStr = Address.publicKeyToP2shP2wkhAddress(privateKeyInfo.testNet, publicKey);
                    break;
                default:
                    throw new RuntimeException("Unknown publicKeyRepresentation " + publicKeyRepresentation);
            }
            address = Address.decode(addressStr);
        }
        privateKey = privateKeyInfo;
    }

    public KeyPair(String address, byte[] publicKey, BTCUtils.PrivateKeyInfo privateKey) {
        this.publicKey = publicKey;
        this.address = Address.decode(address);
        this.privateKey = privateKey;
    }

    @SuppressWarnings("SimplifiableIfStatement")
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        KeyPair keyPair = (KeyPair) o;

        if (address != null ? !address.equals(keyPair.address) : keyPair.address != null) {
            return false;
        }
        return privateKey.equals(keyPair.privateKey);
    }

    @Override
    public int hashCode() {
        int result = address != null ? address.hashCode() : 0;
        result = 31 * result + privateKey.hashCode();
        return result;
    }
}
