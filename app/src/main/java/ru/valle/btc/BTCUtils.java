/*
 * The MIT License (MIT)
 * <p/>
 * Copyright (c) 2013-2018 Valentin Konovalov
 * <p/>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p/>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p/>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package ru.valle.btc;

import android.os.SystemClock;
import android.support.annotation.IntDef;
import android.support.annotation.NonNull;
import android.text.TextUtils;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DERSequenceGenerator;
import org.spongycastle.asn1.DLSequence;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Stack;

import ru.valle.spongycastle.crypto.generators.SCrypt;

import static ru.valle.btc.Transaction.Script.convertDataToScript;

@SuppressWarnings({"WeakerAccess", "TryWithIdenticalCatches", "unused"})
public final class BTCUtils {
    private static final ECDomainParameters EC_PARAMS;
    private static final char[] BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    public static final TrulySecureRandom SECURE_RANDOM = new TrulySecureRandom();
    static final BigInteger LARGEST_PRIVATE_KEY = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);//SECP256K1_N
    public static final long MIN_FEE_PER_KB = 10000;
    public static final long MAX_ALLOWED_FEE = BTCUtils.parseValue("0.1");
    public static final float EXPECTED_BLOCKS_PER_DAY = 144.0f;//(expected confirmations per day)
    private static final int MAX_SCRIPT_ELEMENT_SIZE = 520;
    public static final int TRANSACTION_TYPE_LEGACY = 0;
    public static final int TRANSACTION_TYPE_BITCOIN_CASH = 1;
    public static final int TRANSACTION_TYPE_SEGWIT = 2;
    public static final int TRANSACTION_TYPE_SEGWIT_P2SH = 3;

    static {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        EC_PARAMS = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    public static byte[] generatePublicKey(BigInteger privateKey, boolean compressed) {
        synchronized (EC_PARAMS) {
            ECPoint uncompressed = EC_PARAMS.getG().multiply(privateKey);
            return uncompressed.getEncoded(compressed);
        }
    }

    public static byte[] doubleSha256(byte[] bytes) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(sha256.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sha256(byte[] bytes) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String formatValue(double value) {
        if (value < 0) {
            throw new NumberFormatException("Negative value " + value);
        }
        String s = String.format(Locale.US, "%.8f", value);
        while (s.length() > 1 && (s.endsWith("0") || s.endsWith(""))) {
            s = (s.substring(0, s.length() - 1));
        }
        return s;
    }

    public static String formatValue(long value) throws NumberFormatException {
        if (value < 0) {
            throw new NumberFormatException("Negative value " + value);
        }
        StringBuilder sb = new StringBuilder(Long.toString(value));
        while (sb.length() <= 8) {
            sb.insert(0, '0');
        }
        sb.insert(sb.length() - 8, '.');
        while (sb.length() > 1 && (sb.charAt(sb.length() - 1) == '0' || sb.charAt(sb.length() - 1) == '.')) {
            sb.setLength(sb.length() - 1);
        }
        return sb.toString();
    }

    public static long parseValue(String valueStr) throws NumberFormatException {
        return new BigDecimal(valueStr).multiply(BigDecimal.valueOf(1_0000_0000)).setScale(0, BigDecimal.ROUND_HALF_DOWN).longValueExact();
    }

    public static long calcMinimumFee(int txLen) {
        return MIN_FEE_PER_KB * (1 + txLen / 1000);
    }

    public static int getMaximumTxSize(Collection<UnspentOutputInfo> unspentOutputInfos, int outputsCount, boolean compressedPublicKey) throws BitcoinException {
        if (unspentOutputInfos == null || unspentOutputInfos.isEmpty()) {
            throw new BitcoinException(BitcoinException.ERR_NO_INPUT, "No information about tx inputs provided");
        }
        int maxInputScriptLen = 73 + (compressedPublicKey ? 33 : 65);
        return 9 + unspentOutputInfos.size() * (41 + maxInputScriptLen) + outputsCount * 33;
    }

    public static class PrivateKeyInfo {
        public static final int TYPE_WIF = 0;
        public static final int TYPE_MINI = 1;
        public static final int TYPE_BRAIN_WALLET = 2;
        public final boolean testNet;
        public final int type;
        public final String privateKeyEncoded;
        public final BigInteger privateKeyDecoded;
        public final boolean isPublicKeyCompressed;

        public PrivateKeyInfo(boolean testNet, int type, String privateKeyEncoded, BigInteger privateKeyDecoded, boolean isPublicKeyCompressed) {
            this.testNet = testNet;
            this.type = type;
            this.privateKeyEncoded = privateKeyEncoded;
            this.privateKeyDecoded = privateKeyDecoded;
            this.isPublicKeyCompressed = isPublicKeyCompressed;
        }
    }

    public static class Bip38PrivateKeyInfo extends PrivateKeyInfo {
        public static final int TYPE_BIP38 = 4;

        public final String confirmationCode;
        public final String password;

        public Bip38PrivateKeyInfo(String privateKeyEncoded, String confirmationCode, boolean isPublicKeyCompressed) {
            super(false, TYPE_BIP38, privateKeyEncoded, null, isPublicKeyCompressed);
            this.confirmationCode = confirmationCode;
            this.password = null;
        }

        public Bip38PrivateKeyInfo(String privateKeyEncoded, BigInteger privateKeyDecoded, String password, boolean isPublicKeyCompressed) {
            super(false, TYPE_BIP38, privateKeyEncoded, privateKeyDecoded, isPublicKeyCompressed);
            this.confirmationCode = null;
            this.password = password;
        }
    }

    /**
     * Decodes given string as private key
     *
     * @param encodedPrivateKey a text what is likely a private key
     * @return decoded private key and its information
     */
    public static PrivateKeyInfo decodePrivateKey(String encodedPrivateKey) {
        if (encodedPrivateKey.length() > 0) {
            try {
                byte[] decoded = decodeBase58(encodedPrivateKey);
                if (decoded != null && (decoded.length == 37 || decoded.length == 38) && ((decoded[0] & 0xff) == 0x80 || (decoded[0] & 0xff) == 0xef)) {
                    if (verifyChecksum(decoded)) {
                        boolean testNet = (decoded[0] & 0xff) == 0xef;
                        byte[] secret = new byte[32];
                        System.arraycopy(decoded, 1, secret, 0, secret.length);
                        boolean isPublicKeyCompressed;
                        if (decoded.length == 38) {
                            if (decoded[decoded.length - 5] == 1) {
                                isPublicKeyCompressed = true;
                            } else {
                                return null;
                            }
                        } else {
                            isPublicKeyCompressed = false;
                        }
                        BigInteger privateKeyBigInteger = new BigInteger(1, secret);
                        if (privateKeyBigInteger.compareTo(BigInteger.ONE) > 0 && privateKeyBigInteger.compareTo(LARGEST_PRIVATE_KEY) < 0) {
                            return new PrivateKeyInfo(testNet, PrivateKeyInfo.TYPE_WIF, encodedPrivateKey, privateKeyBigInteger, isPublicKeyCompressed);
                        }
                    }
                } else if (decoded != null && decoded.length == 43 && (decoded[0] & 0xff) == 0x01 && ((decoded[1] & 0xff) == 0x43 || (decoded[1] & 0xff) == 0x42)) {
                    if (verifyChecksum(decoded)) {
                        return new PrivateKeyInfo(false, Bip38PrivateKeyInfo.TYPE_BIP38, encodedPrivateKey, null, false);
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return decodePrivateKeyAsSHA256(encodedPrivateKey, false);
    }

    /**
     * Decodes brainwallet and mini keys. Both are SHA256(input), but mini keys have basic checksum verification.
     *
     * @param encodedPrivateKey input
     * @return private key what is SHA256 of the input string
     */
    public static PrivateKeyInfo decodePrivateKeyAsSHA256(String encodedPrivateKey, boolean testNet) {
        if (encodedPrivateKey.length() > 0) {
            try {
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                BigInteger privateKeyBigInteger = new BigInteger(1, sha256.digest(encodedPrivateKey.getBytes()));
                if (privateKeyBigInteger.compareTo(BigInteger.ONE) > 0 && privateKeyBigInteger.compareTo(LARGEST_PRIVATE_KEY) < 0) {
                    int type;

                    if (sha256.digest((encodedPrivateKey + '?').getBytes("UTF-8"))[0] == 0) {
                        type = PrivateKeyInfo.TYPE_MINI;
                    } else {
                        type = PrivateKeyInfo.TYPE_BRAIN_WALLET;
                    }
                    final boolean isPublicKeyCompressed = false;
                    return new PrivateKeyInfo(testNet, type, encodedPrivateKey, privateKeyBigInteger, isPublicKeyCompressed);
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    public static boolean verifyBitcoinAddress(String address) {
        byte[] decodedAddress = decodeBase58(address);
        return !(decodedAddress == null || decodedAddress.length < 6 ||
                !(decodedAddress[0] == 0 || decodedAddress[0] == 111 || decodedAddress[0] == (byte) 196) ||
                !verifyChecksum(decodedAddress));
    }

    public static boolean verifyChecksum(byte[] bytesWithChecksumm) {
        try {
            if (bytesWithChecksumm == null || bytesWithChecksumm.length < 5) {
                return false;
            }
            MessageDigest digestSha = MessageDigest.getInstance("SHA-256");
            digestSha.update(bytesWithChecksumm, 0, bytesWithChecksumm.length - 4);
            byte[] first = digestSha.digest();
            byte[] calculatedDigest = digestSha.digest(first);
            boolean checksumValid = true;
            for (int i = 0; i < 4; i++) {
                if (calculatedDigest[i] != bytesWithChecksumm[bytesWithChecksumm.length - 4 + i]) {
                    checksumValid = false;
                }
            }
            return checksumValid;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sha256ripemd160(byte[] publicKey) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            //https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
            //1 - Take the corresponding public key generated with it (65 bytes, 1 byte 0x04, 32 bytes corresponding to X coordinate, 32 bytes corresponding to Y coordinate)
            //2 - Perform SHA-256 hashing on the public key
            byte[] sha256hash = sha256.digest(publicKey);
            //3 - Perform RIPEMD-160 hashing on the result of SHA-256
            RIPEMD160Digest ripemd160Digest = new RIPEMD160Digest();
            ripemd160Digest.update(sha256hash, 0, sha256hash.length);
            byte[] hashedPublicKey = new byte[20];
            ripemd160Digest.doFinal(hashedPublicKey, 0);
            return hashedPublicKey;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String publicKeyToAddress(byte[] publicKey) {
        return publicKeyToAddress(false, publicKey);
    }

    public static String publicKeyToAddress(boolean testNet, byte[] publicKey) {
        return ripemd160HashToAddress(testNet, sha256ripemd160(publicKey));
    }

    @Deprecated
    public static String publicKeyToPseudoP2wkhAddress(boolean testNet, byte[] publicKey) {
        if (publicKey.length > 33) {
            return null; //key should be compressed
        }
        return ripemd160HashToP2shAddress(testNet, sha256ripemd160(publicKey));
    }

    public static String publicKeyToP2shP2wkhAddress(boolean testNet, byte[] publicKey) {
        if (publicKey.length > 33) {
            return null; //key should be compressed
        }
        return ripemd160HashToP2shAddress(testNet, sha256ripemd160(new Transaction.Script.WitnessProgram(0, sha256ripemd160(publicKey)).getBytes()));
    }

    public static String ripemd160HashToAddress(boolean testNet, byte[] hashedPublicKey) {
        byte version = (byte) (testNet ? 111 : 0);
        return ripemd160HashToAddress(version, hashedPublicKey);
    }

    public static String ripemd160HashToP2shAddress(boolean testNet, byte[] hashedPublicKey) {
        byte version = (byte) (testNet ? 196 : 5);
        return ripemd160HashToAddress(version, hashedPublicKey);
    }

    private static String ripemd160HashToAddress(byte version, byte[] hashedPublicKey) {
        try {
            //4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
            byte[] addressBytes = new byte[1 + hashedPublicKey.length + 4];
            addressBytes[0] = version;
            System.arraycopy(hashedPublicKey, 0, addressBytes, 1, hashedPublicKey.length);
            //5 - Perform SHA-256 hash on the extended RIPEMD-160 result
            //6 - Perform SHA-256 hash on the result of the previous SHA-256 hash
            MessageDigest digestSha = MessageDigest.getInstance("SHA-256");
            digestSha.update(addressBytes, 0, addressBytes.length - 4);
            byte[] check = digestSha.digest(digestSha.digest());
            //7 - Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
            //8 - Add the 4 checksum bytes from point 7 at the end of extended RIPEMD-160 hash from point 4. This is the 25-byte binary Bitcoin Address.
            System.arraycopy(check, 0, addressBytes, hashedPublicKey.length + 1, 4);
            return encodeBase58(addressBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static final int BASE58_CHUNK_DIGITS = 10;//how many base 58 digits fits in long
    private static final BigInteger BASE58_CHUNK_MOD = BigInteger.valueOf(0x5fa8624c7fba400L); //58^BASE58_CHUNK_DIGITS
    private static final byte[] BASE58_VALUES = new byte[]{-1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -2, -2, -2, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1,
            -1, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
            22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
            -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

    public static byte[] decodeBase58(String input) {
        if (input == null) {
            return null;
        }
        input = input.trim();
        if (input.length() == 0) {
            return new byte[0];
        }
        BigInteger resultNum = BigInteger.ZERO;
        int nLeadingZeros = 0;
        while (nLeadingZeros < input.length() && input.charAt(nLeadingZeros) == BASE58[0]) {
            nLeadingZeros++;
        }
        long acc = 0;
        int nDigits = 0;
        int p = nLeadingZeros;
        while (p < input.length()) {
            int v = BASE58_VALUES[input.charAt(p) & 0xff];
            if (v >= 0) {
                acc *= 58;
                acc += v;
                nDigits++;
                if (nDigits == BASE58_CHUNK_DIGITS) {
                    resultNum = resultNum.multiply(BASE58_CHUNK_MOD).add(BigInteger.valueOf(acc));
                    acc = 0;
                    nDigits = 0;
                }
                p++;
            } else {
                break;
            }
        }
        if (nDigits > 0) {
            long mul = 58;
            while (--nDigits > 0) {
                mul *= 58;
            }
            resultNum = resultNum.multiply(BigInteger.valueOf(mul)).add(BigInteger.valueOf(acc));
        }
        final int BASE58_SPACE = -2;
        while (p < input.length() && BASE58_VALUES[input.charAt(p) & 0xff] == BASE58_SPACE) {
            p++;
        }
        if (p < input.length()) {
            return null;
        }
        byte[] plainNumber = resultNum.toByteArray();
        int plainNumbersOffs = plainNumber[0] == 0 ? 1 : 0;
        byte[] result = new byte[nLeadingZeros + plainNumber.length - plainNumbersOffs];
        System.arraycopy(plainNumber, plainNumbersOffs, result, nLeadingZeros, plainNumber.length - plainNumbersOffs);
        return result;
    }

    public static String encodeBase58(byte[] input) {
        if (input == null) {
            return null;
        }
        StringBuilder str = new StringBuilder((input.length * 350) / 256 + 1);
        BigInteger bn = new BigInteger(1, input);
        long rem;
        while (true) {
            BigInteger[] divideAndRemainder = bn.divideAndRemainder(BASE58_CHUNK_MOD);
            bn = divideAndRemainder[0];
            rem = divideAndRemainder[1].longValue();
            if (bn.compareTo(BigInteger.ZERO) == 0) {
                break;
            }
            for (int i = 0; i < BASE58_CHUNK_DIGITS; i++) {
                str.append(BASE58[(int) (rem % 58)]);
                rem /= 58;
            }
        }
        while (rem != 0) {
            str.append(BASE58[(int) (rem % 58)]);
            rem /= 58;
        }
        str.reverse();
        int nLeadingZeros = 0;
        while (nLeadingZeros < input.length && input[nLeadingZeros] == 0) {
            str.insert(0, BASE58[0]);
            nLeadingZeros++;
        }
        return str.toString();
    }

    public static KeyPair generateMiniKey() {
        KeyPair key = null;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            StringBuilder sb = new StringBuilder(31);
            SECURE_RANDOM.addSeedMaterial(SystemClock.elapsedRealtime());
            while (true) {
                sb.append('S');
                for (int i = 0; i < 29; i++) {
                    sb.append(BASE58[1 + SECURE_RANDOM.nextInt(BASE58.length - 1)]);
                }
                if (sha256.digest((sb.toString() + '?').getBytes("UTF-8"))[0] == 0) {
                    key = new KeyPair(decodePrivateKeyAsSHA256(sb.toString(), false));
                    break;
                }
                sb.setLength(0);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
    }

    public static KeyPair generateWifKey() {
        return generateWifKey(false);
    }

    @SuppressWarnings("ConstantConditions")
    public static KeyPair generateWifKey(boolean testNet) {
        SECURE_RANDOM.addSeedMaterial(SystemClock.elapsedRealtime());
        try {
            MessageDigest digestSha = MessageDigest.getInstance("SHA-256");
            byte[] rawPrivateKey = new byte[38];
            rawPrivateKey[0] = (byte) (testNet ? 0xef : 0x80);
            rawPrivateKey[rawPrivateKey.length - 5] = 1;
            byte[] secret;
            BigInteger privateKeyBigInteger;
            do {
                secret = new byte[32];
                SECURE_RANDOM.nextBytes(secret);
                privateKeyBigInteger = new BigInteger(1, secret);
                System.arraycopy(secret, 0, rawPrivateKey, 1, secret.length);
                digestSha.update(rawPrivateKey, 0, rawPrivateKey.length - 4);
                byte[] check = digestSha.digest(digestSha.digest());
                System.arraycopy(check, 0, rawPrivateKey, rawPrivateKey.length - 4, 4);
            }
            while (privateKeyBigInteger.compareTo(BigInteger.ONE) < 0 || privateKeyBigInteger.compareTo(LARGEST_PRIVATE_KEY) > 0 || !verifyChecksum(rawPrivateKey));
            return new KeyPair(new PrivateKeyInfo(testNet, PrivateKeyInfo.TYPE_WIF, encodeBase58(rawPrivateKey), privateKeyBigInteger, true));
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static String encodeWifKey(boolean isPublicKeyCompressed, byte[] secret) {
        try {
            MessageDigest digestSha = MessageDigest.getInstance("SHA-256");
            byte[] rawPrivateKey = new byte[isPublicKeyCompressed ? 38 : 37];
            rawPrivateKey[0] = (byte) 0x80;
            if (isPublicKeyCompressed) {
                rawPrivateKey[rawPrivateKey.length - 5] = 1;
            }
            System.arraycopy(secret, 0, rawPrivateKey, 1, secret.length);
            digestSha.update(rawPrivateKey, 0, rawPrivateKey.length - 4);
            byte[] check = digestSha.digest(digestSha.digest());
            System.arraycopy(check, 0, rawPrivateKey, rawPrivateKey.length - 4, 4);
            return encodeBase58(rawPrivateKey);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static String toHex(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] fromHex(String s) {
        if (s != null) {
            try {
                StringBuilder sb = new StringBuilder(s.length());
                for (int i = 0; i < s.length(); i++) {
                    char ch = s.charAt(i);
                    if (!Character.isWhitespace(ch)) {
                        sb.append(ch);
                    }
                }
                s = sb.toString();
                int len = s.length();
                byte[] data = new byte[len / 2];
                for (int i = 0; i < len; i += 2) {
                    int hi = (Character.digit(s.charAt(i), 16) << 4);
                    int low = Character.digit(s.charAt(i + 1), 16);
                    if (hi >= 256 || low < 0 || low >= 16) {
                        return null;
                    }
                    data[i / 2] = (byte) (hi | low);
                }
                return data;
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    public static byte[] sign(BigInteger privateKey, byte[] input) {
        synchronized (EC_PARAMS) {
            ECDSASigner signer = new ECDSASigner();
            ECPrivateKeyParameters privateKeyParam = new ECPrivateKeyParameters(privateKey, EC_PARAMS);
            signer.init(true, new ParametersWithRandom(privateKeyParam, SECURE_RANDOM));
            BigInteger[] sign = signer.generateSignature(input);
            BigInteger r = sign[0];
            BigInteger s = sign[1];
            BigInteger largestAllowedS = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16);//SECP256K1_N_DIV_2
            if (s.compareTo(largestAllowedS) > 0) {
                //https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures
                s = LARGEST_PRIVATE_KEY.subtract(s);
            }
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream(72);
                DERSequenceGenerator derGen = new DERSequenceGenerator(baos);
                derGen.addObject(new ASN1Integer(r));
                derGen.addObject(new ASN1Integer(s));
                derGen.close();
                return baos.toByteArray();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static boolean verify(byte[] publicKey, byte[] signature, byte[] msg) {
        synchronized (EC_PARAMS) {
            boolean valid;
            ECDSASigner signerVer = new ECDSASigner();
            if (publicKey.length == 0) {
                return false;
            }
            if (signature.length == 0) {
                return true; //likely it's incorrect. Revise after full script implementation.
            }
            ECPublicKeyParameters pubKey = new ECPublicKeyParameters(EC_PARAMS.getCurve().decodePoint(publicKey), EC_PARAMS);
            signerVer.init(false, pubKey);
            BigInteger r, s;
            try {
                ASN1InputStream derSigStream = new ASN1InputStream(signature);
                DLSequence seq = (DLSequence) derSigStream.readObject();
                r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
                s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
                derSigStream.close();
            } catch (Exception e) {
//                throw new RuntimeException("BIP66 requires correct DER encoding", e);
                //ok, manual ASN1 decode to conform old bitcoin core:
                try {
                    int i = 0;
                    if (signature[i++] != 0x30) {
                        throw new RuntimeException("No ASN1 sequence in signature");
                    }
                    int len = signature[i++] & 0xff;
                    if (i + len != signature.length) {
                        throw new RuntimeException("Invalid signature ASN1 length");
                    }
                    byte type = signature[i++];
                    if (type != 2) {
                        throw new RuntimeException("R value has invalid type in signature: " + type);
                    }
                    len = signature[i++] & 0xff;
                    byte[] rBytes = new byte[len];
                    System.arraycopy(signature, i, rBytes, 0, len);
                    r = new BigInteger(1, rBytes);
                    i += len;

                    type = signature[i++];
                    if (type != 2) {
                        throw new RuntimeException("S value has invalid type in signature: " + type);
                    }
                    len = signature[i++] & 0xff;
                    byte[] sBytes = new byte[len];
                    System.arraycopy(signature, i, rBytes, 0, len);
                    s = new BigInteger(1, rBytes);
                } catch (Exception err2) {
                    throw new RuntimeException("Invalid ASN/DER encoding of signature", err2);
                }
            }
            valid = signerVer.verifySignature(msg, r, s);
            return valid;
        }
    }

    public static byte[] reverse(byte[] bytes) {
        byte[] result = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            result[i] = bytes[bytes.length - i - 1];
        }
        return result;
    }

    public static byte[] reverseInPlace(byte[] bytes) {
        int len = bytes.length / 2;
        for (int i = 0; i < len; i++) {
            byte t = bytes[i];
            bytes[i] = bytes[bytes.length - i - 1];
            bytes[bytes.length - i - 1] = t;
        }
        return bytes;
    }

    @SuppressWarnings("SameParameterValue")
    public static int findSpendableOutput(Transaction tx, String forAddress, long minAmount) throws BitcoinException {
        byte[] outputScriptWeAreAbleToSpend = Transaction.Script.buildOutput(forAddress).bytes;
        int indexOfOutputToSpend = -1;
        for (int indexOfOutput = 0; indexOfOutput < tx.outputs.length; indexOfOutput++) {
            Transaction.Output output = tx.outputs[indexOfOutput];
            if (Arrays.equals(outputScriptWeAreAbleToSpend, output.scriptPubKey.bytes)) {
                indexOfOutputToSpend = indexOfOutput;
                break;//only one input is supported for now
            }
        }
        if (indexOfOutputToSpend == -1) {
            throw new BitcoinException(BitcoinException.ERR_NO_SPENDABLE_OUTPUTS_FOR_THE_ADDRESS, "No spendable standard outputs for " + forAddress + " have found", forAddress);
        }
        final long spendableOutputValue = tx.outputs[indexOfOutputToSpend].value;
        if (spendableOutputValue < minAmount) {
            throw new BitcoinException(BitcoinException.ERR_INSUFFICIENT_FUNDS, "Unspent amount is too small: " + spendableOutputValue, spendableOutputValue);
        }
        return indexOfOutputToSpend;
    }

    public static void verify(Transaction.Script[] scriptPubKeys, long[] amounts, Transaction spendTx, boolean bitcoinCash) throws Transaction.Script.ScriptInvalidException {
        int flags = Transaction.Script.SCRIPT_ALL_SUPPORTED;
        if (bitcoinCash) {
            flags |= Transaction.Script.SCRIPT_ENABLE_SIGHASH_FORKID;
        }
        verify(scriptPubKeys, amounts, spendTx, flags);
    }

    public static void verify(Transaction.Script[] scriptPubKeys, long[] amounts, Transaction tx, int flags) throws Transaction.Script.ScriptInvalidException {
        if (tx.isCoinBase()) {
            throw new NotImplementedException("Coinbase verification");
        }
        for (int i = 0; i < tx.outputs.length; i++) {
            if (tx.outputs[i].value < 0) {
                throw new Transaction.Script.ScriptInvalidException("Negative output");
            }
        }
        HashSet<Transaction.OutPoint> inputsPointsSet = new HashSet<>(tx.inputs.length);
        for (int i = 0; i < tx.inputs.length; i++) {
            if (!inputsPointsSet.add(tx.inputs[i].outPoint)) {
                throw new Transaction.Script.ScriptInvalidException("Duplicate inputs");
            }
        }
        for (int i = 0; i < scriptPubKeys.length; i++) {
            if (scriptPubKeys[i] == null || amounts[i] < 0) {
                //verify only given inputs
                continue;
            }
            Transaction.Checker checker = new Transaction.Checker(i, i >= amounts.length ? -1 : amounts[i], tx);
            Stack<byte[]> stack = new Stack<>();
            Stack<byte[]> stackCopy = null;
            Transaction.Script scriptSig = tx.inputs[i].scriptSig;
            if ((flags & Transaction.Script.SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.isPushOnly()) {
                throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_SIG_PUSHONLY");
            }
            if (scriptSig.isNull() && tx.inputs.length > 1 && !tx.isCoinBase() && (flags & Transaction.Script.SCRIPT_VERIFY_WITNESS) == 0) {
                throw new Transaction.Script.ScriptInvalidException("Null txin, but without being a coinbase (because there are two inputs)");
            }
            if (!scriptSig.run(checker, stack, flags, Transaction.Script.SIGVERSION_BASE)) { //usually loads signature+public key
                throw new Transaction.Script.ScriptInvalidException();
            }
            if ((flags & Transaction.Script.SCRIPT_VERIFY_P2SH) != 0) {
                stackCopy = new Stack<>();
                stackCopy.addAll(stack);
            }
            Transaction.Script scriptPubKey = scriptPubKeys[i];
            if (!scriptPubKey.run(checker, stack, flags, Transaction.Script.SIGVERSION_BASE)) { //verify that this transaction able to spend that output
                throw new Transaction.Script.ScriptInvalidException();
            }
            if (stack.isEmpty() || !castToBool(stack.peek())) {
                throw new Transaction.Script.ScriptInvalidException();
            }
            // Bare witness programs
            boolean hadWitness = false;
            if ((flags & Transaction.Script.SCRIPT_VERIFY_WITNESS) != 0) {
                Transaction.Script.WitnessProgram wp = scriptPubKey.getWitnessProgram();
                if (wp != null) {
                    hadWitness = true;
                    if (scriptSig.bytes.length != 0) {
                        // The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
                        throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_WITNESS_MALLEATED");
                    }
                    byte[][] witness = i < tx.scriptWitnesses.length ? tx.scriptWitnesses[i] : new byte[0][];
                    if (!verifyWitnessProgram(checker, witness, wp, flags)) {
                        throw new Transaction.Script.ScriptInvalidException("Bad signature in witness");
                    }
                    // Bypass the cleanstack check at the end. The actual stack is _obviously_ not clean
                    // for witness programs.
                    stack.clear();
                    stack.add(null);
                }
            }
            if ((flags & Transaction.Script.SCRIPT_VERIFY_P2SH) != 0 && scriptPubKey.isPayToScriptHash()) {
                if (!scriptSig.isPushOnly()) {
                    throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_SIG_PUSHONLY");
                }
                stack.clear();
                stack.addAll(stackCopy);
                byte[] pubKeySerialized = stack.pop();
                Transaction.Script pubKey2;
                try {
                    pubKey2 = new Transaction.Script(pubKeySerialized);
                    if (!pubKey2.run(checker, stack, flags, Transaction.Script.SIGVERSION_BASE)) {
                        throw new Transaction.Script.ScriptInvalidException();
                    }
                    if (stack.isEmpty() || !castToBool(stack.pop())) {
                        throw new Transaction.Script.ScriptInvalidException();
                    }

                    if ((flags & Transaction.Script.SCRIPT_VERIFY_WITNESS) != 0) {
                        Transaction.Script.WitnessProgram wp = pubKey2.getWitnessProgram();
                        if (wp != null) {
                            hadWitness = true;
                            if (!Arrays.equals(scriptSig.bytes, convertDataToScript(pubKey2.bytes))) {
                                // The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
                                throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_WITNESS_MALLEATED");
                            }
                            if (!verifyWitnessProgram(checker, tx.scriptWitnesses[i], wp, flags)) {
                                throw new Transaction.Script.ScriptInvalidException("Bad witness");
                            }
                            // Bypass the cleanstack check at the end. The actual stack is _obviously_ not clean
                            // for witness programs.
                            stack.clear();
                            stack.add(null);
                        }
                    }
                } catch (NotImplementedException e) {
                    throw e;
                } catch (Transaction.Script.ScriptInvalidException e) {
                    throw e;
                } catch (Exception e) {
                    throw new Transaction.Script.ScriptInvalidException(e.toString());
                }
            }

            // The CLEANSTACK check is only performed after potential P2SH evaluation,
            // as the non-P2SH evaluation of a P2SH script will obviously not result in
            // a clean stack (the P2SH inputs remain). The same holds for witness evaluation.
            if ((flags & Transaction.Script.SCRIPT_VERIFY_CLEANSTACK) != 0) {
                // Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
                // would be possible, which is not a softfork (and P2SH should be one).
//                assert((flags & Transaction.Script.SCRIPT_VERIFY_P2SH) != 0);
//                assert((flags & Transaction.Script.SCRIPT_VERIFY_WITNESS) != 0);
                if (stack.size() != 1) {
                    throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_CLEANSTACK");
                }
            }

            if ((flags & Transaction.Script.SCRIPT_VERIFY_WITNESS) != 0) {
                // We can't check for correct unexpected witness data if P2SH was off, so require
                // that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
                // possible, which is not a softfork.
//                assert((flags & Transaction.Script.SCRIPT_VERIFY_P2SH) != 0);
                if (!hadWitness && tx.scriptWitnesses.length > 0 && tx.scriptWitnesses[i].length > 0) {
                    throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_WITNESS_UNEXPECTED");
                }
            } else if (tx.scriptWitnesses.length > 0) {
                throw new NotImplementedException("SegWit is not supported yet");
            }
        }
    }

    private static boolean verifyWitnessProgram(Transaction.Checker checker, byte[][] scriptWitnesses, Transaction.Script.WitnessProgram wp, int flags)
            throws Transaction.Script.ScriptInvalidException {
        Stack<byte[]> stack = new Stack<>();
        Transaction.Script scriptPubKey;
        if (wp.version == 0) {
            if (wp.program.length == 32) {
                // Version 0 segregated witness program: SHA256(CScript) inside the program, CScript + inputs in witness
                if (scriptWitnesses.length == 0) {
                    throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY");
                }
                scriptPubKey = new Transaction.Script(scriptWitnesses[scriptWitnesses.length - 1]);
                byte[] hashScriptPubKey = BTCUtils.sha256(scriptPubKey.bytes);
                if (!Arrays.equals(hashScriptPubKey, wp.program)) {
                    throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH");
                }
                for (int i = 0; i < scriptWitnesses.length - 1; i++) {
                    stack.add(scriptWitnesses[i]);
                }
            } else if (wp.program.length == 20) {
                // Special case for pay-to-pubkeyhash; signature + pubkey in witness
                if (scriptWitnesses.length != 2) {
                    throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH"); // 2 items in witness
                }
                try {
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    os.write(Transaction.Script.OP_DUP);
                    os.write(Transaction.Script.OP_HASH160);
                    os.write(convertDataToScript(wp.program));
                    os.write(Transaction.Script.OP_EQUALVERIFY);
                    os.write(Transaction.Script.OP_CHECKSIG);
                    os.close();
                    scriptPubKey = new Transaction.Script(os.toByteArray());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                stack.addAll(Arrays.asList(scriptWitnesses));
            } else {
                throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH");
            }
        } else if ((flags & Transaction.Script.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) != 0) {
            throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM");
        } else {
            // Higher version witness scripts return true for future softfork compatibility
            return true;
        }

        // Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
        for (int i = 0; i < stack.size(); i++) {
            if (stack.get(i).length > MAX_SCRIPT_ELEMENT_SIZE) {
                throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_PUSH_SIZE");
            }
        }

        if (!scriptPubKey.run(checker, stack, flags, Transaction.Script.SIGVERSION_WITNESS_V0)) {
            return false;
        }

        // Scripts inside witness implicitly require cleanstack behaviour
        if (stack.size() != 1 || !castToBool(stack.peek())) {
            throw new Transaction.Script.ScriptInvalidException("SCRIPT_ERR_EVAL_FALSE");
        }
        return true;
    }

    private static boolean castToBool(byte[] vch) {
        for (int i = 0; i < vch.length; i++) {
            if (vch[i] != 0) {
                return !(i == vch.length - 1 && vch[i] == 0x80);
            }
        }
        return false;
    }

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({TRANSACTION_TYPE_LEGACY, TRANSACTION_TYPE_BITCOIN_CASH, TRANSACTION_TYPE_SEGWIT, TRANSACTION_TYPE_SEGWIT_P2SH})
    public @interface TransactionType {
    }

    @SuppressWarnings("SameParameterValue")
    public static Transaction createTransaction(Transaction baseTransaction, int indexOfOutputToSpend, long confirmations, String outputAddress, String changeAddress,
                                                long amountToSend, long extraFee, KeyPair keys, @TransactionType int transactionType) throws BitcoinException {
        byte[] hashOfPrevTransaction = baseTransaction.hash();
        return createTransaction(hashOfPrevTransaction, baseTransaction.outputs[indexOfOutputToSpend].value, baseTransaction.outputs[indexOfOutputToSpend].scriptPubKey,
                indexOfOutputToSpend, confirmations, outputAddress, changeAddress, amountToSend, extraFee, keys, transactionType);
    }

    public static Transaction createTransaction(byte[] hashOfPrevTransaction, long valueOfUnspentOutput, Transaction.Script scriptOfUnspentOutput,
                                                int indexOfOutputToSpend, long confirmations, String outputAddress, String changeAddress, long amountToSend,
                                                long extraFee, KeyPair keys, @TransactionType int transactionType) throws BitcoinException {
        if (hashOfPrevTransaction == null) {
            throw new BitcoinException(BitcoinException.ERR_NO_INPUT, "hashOfPrevTransaction is null");
        }
        ArrayList<UnspentOutputInfo> unspentOutputs = new ArrayList<>(1);
        unspentOutputs.add(new UnspentOutputInfo(keys, hashOfPrevTransaction, scriptOfUnspentOutput, valueOfUnspentOutput, indexOfOutputToSpend));
        return createTransaction(unspentOutputs, outputAddress, changeAddress, amountToSend, extraFee, transactionType);
    }

    public static Transaction createTransaction(List<UnspentOutputInfo> unspentOutputs,
                                                String outputAddress, String changeAddress, final long amountToSend, final long extraFee,
                                                @TransactionType int transactionType) throws BitcoinException {

        if (!verifyBitcoinAddress(outputAddress)) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Output address is invalid", outputAddress);
        }

        FeeChangeAndSelectedOutputs processedTxData = calcFeeChangeAndSelectOutputsToSpend(unspentOutputs, amountToSend, extraFee);

        Transaction.Output[] outputs;
        if (processedTxData.change == 0) {
            outputs = new Transaction.Output[]{
                    new Transaction.Output(processedTxData.amountForRecipient, Transaction.Script.buildOutput(outputAddress, transactionType)),
            };
        } else {
            if (outputAddress.equals(changeAddress)) {
                throw new BitcoinException(BitcoinException.ERR_MEANINGLESS_OPERATION, "Change address equals to recipient's address, it is likely an error.");
            }
            if (!verifyBitcoinAddress(changeAddress)) {
                throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Change address is invalid", changeAddress);
            }
            outputs = new Transaction.Output[]{
                    new Transaction.Output(processedTxData.amountForRecipient, Transaction.Script.buildOutput(outputAddress, transactionType)),
                    new Transaction.Output(processedTxData.change, Transaction.Script.buildOutput(changeAddress, transactionType)),
            };
        }
        ArrayList<UnspentOutputInfo> outputsToSpend = processedTxData.outputsToSpend;
        Transaction.Input[] unsignedInputs = new Transaction.Input[outputsToSpend.size()];
        Transaction unsignedTx = new Transaction(unsignedInputs, outputs, 0);
        for (int j = 0; j < unsignedTx.inputs.length; j++) {
            UnspentOutputInfo outputToSpend = outputsToSpend.get(j);
            Transaction.OutPoint outPoint = new Transaction.OutPoint(outputToSpend.txHash, outputToSpend.outputIndex);
            unsignedTx.inputs[j] = new Transaction.Input(outPoint, null, 0xffffffff);
        }
        boolean bitcoinCash = transactionType == TRANSACTION_TYPE_BITCOIN_CASH;
        int sigVersion = transactionType == TRANSACTION_TYPE_SEGWIT || transactionType == TRANSACTION_TYPE_SEGWIT_P2SH ? Transaction.Script.SIGVERSION_WITNESS_V0 : Transaction.Script.SIGVERSION_BASE;
        return sign(outputsToSpend, unsignedTx, bitcoinCash, sigVersion);
    }

    @NonNull
    public static Transaction sign(List<UnspentOutputInfo> outputsToSpend, Transaction unsignedTx, boolean bitcoinCash, int sigVersion) throws BitcoinException {
        Transaction.Input[] signedInputs = new Transaction.Input[unsignedTx.inputs.length];
        byte hashType = Transaction.Script.SIGHASH_ALL;
        if (bitcoinCash) {
            hashType |= Transaction.Script.SIGHASH_FORKID;
            sigVersion = Transaction.Script.SIGVERSION_BASE;
        }
        byte[][][] witnesses;
        if (sigVersion == Transaction.Script.SIGVERSION_BASE) {
            witnesses = new byte[0][][];
        } else {
            witnesses = new byte[signedInputs.length][][];
            for (int i = 0; i < witnesses.length; i++) {
                witnesses[i] = new byte[0][];
            }
        }
        for (int i = 0; i < signedInputs.length; i++) {
            UnspentOutputInfo outputToSpend = outputsToSpend.get(i);
            long inputValue = outputToSpend.value;
            BigInteger privateKey = outputToSpend.keys.privateKey.privateKeyDecoded;
            byte[] subScript = outputToSpend.scriptPubKey.bytes; //unsignedTx.inputs[i].scriptSig.bytes;

            Transaction.Script scriptSig;
            if (outputToSpend.scriptPubKey.isPay2PublicKeyHash()) {
                byte[] signatureAndHashType = getSignatureAndHashType(unsignedTx, i, inputValue, privateKey, subScript, Transaction.Script.SIGVERSION_BASE, hashType);
                scriptSig = new Transaction.Script(signatureAndHashType, outputToSpend.keys.publicKey);
            } else if (outputToSpend.scriptPubKey.isPubkey()) {
                byte[] signatureAndHashType = getSignatureAndHashType(unsignedTx, i, inputValue, privateKey, subScript, Transaction.Script.SIGVERSION_BASE, hashType);
                scriptSig = new Transaction.Script(convertDataToScript(signatureAndHashType));
            } else if (sigVersion != Transaction.Script.SIGVERSION_BASE) {
                Transaction.Script.WitnessProgram wp;
                if (outputToSpend.scriptPubKey.isPayToScriptHash()) {
                    if (outputToSpend.keys.publicKey != null && outputToSpend.keys.publicKey.length > 33) {
                        throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Writing uncompressed public key into witness");
                    }
                    wp = new Transaction.Script.WitnessProgram(0, BTCUtils.sha256ripemd160(outputToSpend.keys.publicKey));
                    scriptSig = new Transaction.Script(convertDataToScript(wp.getBytes()));
                } else {
                    wp = outputToSpend.scriptPubKey.getWitnessProgram();
                    scriptSig = new Transaction.Script(new byte[0]);
                }
                byte[] actualSubScriptForWitness;
                if (wp != null) {
                    try {
                        ByteArrayOutputStream os = new ByteArrayOutputStream();
                        if (wp.program.length == 20) {
                            os.write(Transaction.Script.OP_DUP);
                            os.write(Transaction.Script.OP_HASH160);
                            os.write(convertDataToScript(wp.program));
                            os.write(Transaction.Script.OP_EQUALVERIFY);
                            os.write(Transaction.Script.OP_CHECKSIG);
                        } else {
                            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Unsupported scriptPubKey type: " + outputToSpend.scriptPubKey);
                        }
                        os.close();
                        actualSubScriptForWitness = os.toByteArray();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Unsupported scriptPubKey type: " + outputToSpend.scriptPubKey);
                }
                byte[] signatureAndHashType = getSignatureAndHashType(unsignedTx, i, inputValue, privateKey, actualSubScriptForWitness, sigVersion, hashType);
                if (outputToSpend.keys.publicKey == null) {
                    throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Writing null public key into witness");
                }
                if (outputToSpend.keys.publicKey.length > 33) {
                    throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Writing uncompressed public key into witness");
                }
                witnesses[i] = new byte[][]{signatureAndHashType, outputToSpend.keys.publicKey};
            } else {
                //is it legacy P2SH?
                throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Unsupported scriptPubKey type: " + outputToSpend.scriptPubKey + " for base sig version");
            }
            signedInputs[i] = new Transaction.Input(unsignedTx.inputs[i].outPoint, scriptSig, unsignedTx.inputs[i].sequence);
        }
        return new Transaction(1, signedInputs, unsignedTx.outputs, unsignedTx.lockTime, witnesses);
    }

    private static byte[] getSignatureAndHashType(Transaction unsignedTx, int i, long inputValue, BigInteger privateKey, byte[] subScript, int sigVersion, byte hashType) {
        byte[] hash = Transaction.Script.hashTransaction(i, subScript, unsignedTx, hashType, inputValue, sigVersion);
        byte[] signature = sign(privateKey, hash);
        byte[] signatureAndHashType = new byte[signature.length + 1];
        System.arraycopy(signature, 0, signatureAndHashType, 0, signature.length);
        signatureAndHashType[signatureAndHashType.length - 1] = hashType;
        return signatureAndHashType;
    }

    private static class FeeChangeAndSelectedOutputs {
        public final long amountForRecipient, change, fee;
        public final ArrayList<UnspentOutputInfo> outputsToSpend;

        public FeeChangeAndSelectedOutputs(long fee, long change, long amountForRecipient, ArrayList<UnspentOutputInfo> outputsToSpend) {
            this.fee = fee;
            this.change = change;
            this.amountForRecipient = amountForRecipient;
            this.outputsToSpend = outputsToSpend;
        }
    }

    private static FeeChangeAndSelectedOutputs calcFeeChangeAndSelectOutputsToSpend(List<UnspentOutputInfo> unspentOutputs,
                                                                                    long amountToSend, long extraFee) throws BitcoinException {
        final boolean isPublicKeyCompressed = true;
        long fee = 0;//calculated below
        long change = 0;
        long valueOfUnspentOutputs;
        ArrayList<UnspentOutputInfo> outputsToSpend = new ArrayList<>();
        if (amountToSend <= 0) {
            //transfer all funds from these addresses to outputAddress
            change = 0;
            valueOfUnspentOutputs = 0;
            for (UnspentOutputInfo outputInfo : unspentOutputs) {
                outputsToSpend.add(outputInfo);
                valueOfUnspentOutputs += outputInfo.value;
            }
            final int txLen = BTCUtils.getMaximumTxSize(unspentOutputs, 1, isPublicKeyCompressed);
            fee = BTCUtils.calcMinimumFee(txLen);
            amountToSend = valueOfUnspentOutputs - fee - extraFee;
        } else {
            valueOfUnspentOutputs = 0;
            for (UnspentOutputInfo outputInfo : unspentOutputs) {
                outputsToSpend.add(outputInfo);
                valueOfUnspentOutputs += outputInfo.value;
                long updatedFee = MIN_FEE_PER_KB;
                for (int i = 0; i < 3; i++) {
                    fee = updatedFee;
                    change = valueOfUnspentOutputs - fee - extraFee - amountToSend;
                    int txLen = BTCUtils.getMaximumTxSize(unspentOutputs, change > 0 ? 2 : 1, isPublicKeyCompressed);
                    updatedFee = BTCUtils.calcMinimumFee(txLen);
                    if (updatedFee == fee) {
                        break;
                    }
                }
                fee = updatedFee;
                if (valueOfUnspentOutputs >= amountToSend + fee + extraFee) {
                    break;
                }
            }

        }
        if (amountToSend > valueOfUnspentOutputs - fee) {
            throw new BitcoinException(BitcoinException.ERR_INSUFFICIENT_FUNDS, "Not enough funds", valueOfUnspentOutputs - fee);
        }
        if (outputsToSpend.isEmpty()) {
            throw new BitcoinException(BitcoinException.ERR_NO_INPUT, "No outputs to spend");
        }
        if (fee + extraFee > MAX_ALLOWED_FEE) {
            throw new BitcoinException(BitcoinException.ERR_FEE_IS_TOO_BIG, "Fee is too big", fee);
        }
        if (fee < 0 || extraFee < 0) {
            throw new BitcoinException(BitcoinException.ERR_FEE_IS_LESS_THEN_ZERO, "Incorrect fee", fee);
        }
        if (change < 0) {
            throw new BitcoinException(BitcoinException.ERR_CHANGE_IS_LESS_THEN_ZERO, "Incorrect change", change);
        }
        if (amountToSend < 0) {
            throw new BitcoinException(BitcoinException.ERR_AMOUNT_TO_SEND_IS_LESS_THEN_ZERO, "Incorrect amount to send", amountToSend);
        }
        return new FeeChangeAndSelectedOutputs(fee + extraFee, change, amountToSend, outputsToSpend);

    }

    @SuppressWarnings("SameParameterValue")
    public static String bip38GetIntermediateCode(String password) throws InterruptedException {
        try {
            byte[] ownerSalt = new byte[8];
            SECURE_RANDOM.nextBytes(ownerSalt);
            byte[] passFactor = SCrypt.generate(password.getBytes("UTF-8"), ownerSalt, 16384, 8, 8, 32);
            ECPoint uncompressed = EC_PARAMS.getG().multiply(new BigInteger(1, passFactor));
            byte[] passPoint = uncompressed.getEncoded(true);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(fromHex("2CE9B3E1FF39E253"));
            baos.write(ownerSalt);
            baos.write(passPoint);
            baos.write(doubleSha256(baos.toByteArray()), 0, 4);
            return encodeBase58(baos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair bip38GenerateKeyPair(String intermediateCode) throws InterruptedException, BitcoinException {
        byte[] intermediateBytes = decodeBase58(intermediateCode);
        if (!verifyChecksum(intermediateBytes) || intermediateBytes.length != 53) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Bad intermediate code");
        }
        byte[] magic = fromHex("2CE9B3E1FF39E2");
        for (int i = 0; i < magic.length; i++) {
            if (magic[i] != intermediateBytes[i]) {
                throw new BitcoinException(BitcoinException.ERR_WRONG_TYPE, "It isn't an intermediate code");
            }
        }
        try {
            byte[] ownerEntropy = new byte[8];
            System.arraycopy(intermediateBytes, 8, ownerEntropy, 0, 8);
            byte[] passPoint = new byte[33];
            System.arraycopy(intermediateBytes, 16, passPoint, 0, 33);
            byte flag = (byte) 0x20; //compressed public key
            byte[] seedB = new byte[24];
            SECURE_RANDOM.nextBytes(seedB);
            byte[] factorB = doubleSha256(seedB);
            BigInteger factorBInteger = new BigInteger(1, factorB);
            ECPoint uncompressedPublicKeyPoint = EC_PARAMS.getCurve().decodePoint(passPoint).multiply(factorBInteger);
            byte[] publicKey = uncompressedPublicKeyPoint.getEncoded(true);
            String address = publicKeyToAddress(publicKey);
            byte[] addressHashAndOwnerSalt = new byte[12];

            byte[] addressHash = new byte[4];
            System.arraycopy(doubleSha256(address.getBytes("UTF-8")), 0, addressHash, 0, 4);
            System.arraycopy(addressHash, 0, addressHashAndOwnerSalt, 0, 4);
            System.arraycopy(ownerEntropy, 0, addressHashAndOwnerSalt, 4, 8);
            byte[] derived = SCrypt.generate(passPoint, addressHashAndOwnerSalt, 1024, 1, 1, 64);
            byte[] key = new byte[32];
            System.arraycopy(derived, 32, key, 0, 32);
            for (int i = 0; i < 16; i++) {
                seedB[i] ^= derived[i];
            }
            AESEngine cipher = new AESEngine();
            cipher.init(true, new KeyParameter(key));
            byte[] encryptedHalf1 = new byte[16];
            byte[] encryptedHalf2 = new byte[16];
            cipher.processBlock(seedB, 0, encryptedHalf1, 0);
            byte[] secondBlock = new byte[16];
            System.arraycopy(encryptedHalf1, 8, secondBlock, 0, 8);
            System.arraycopy(seedB, 16, secondBlock, 8, 8);
            for (int i = 0; i < 16; i++) {
                secondBlock[i] ^= derived[i + 16];
            }
            cipher.processBlock(secondBlock, 0, encryptedHalf2, 0);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(0x01);
            baos.write(0x43);
            baos.write(flag);
            baos.write(addressHashAndOwnerSalt);
            baos.write(encryptedHalf1, 0, 8);
            baos.write(encryptedHalf2);
            baos.write(doubleSha256(baos.toByteArray()), 0, 4);
            String encryptedPrivateKey = encodeBase58(baos.toByteArray());

            byte[] pointB = generatePublicKey(factorBInteger, true);
            byte pointBPrefix = (byte) (pointB[0] ^ (derived[63] & 0x01));
            byte[] encryptedPointB = new byte[33];
            encryptedPointB[0] = pointBPrefix;
            for (int i = 0; i < 32; i++) {
                pointB[i + 1] ^= derived[i];
            }
            cipher.processBlock(pointB, 1, encryptedPointB, 1);
            cipher.processBlock(pointB, 17, encryptedPointB, 17);
            baos.reset();
            baos.write(0x64);
            baos.write(0x3B);
            baos.write(0xF6);
            baos.write(0xA8);
            baos.write(0x9A);
            baos.write(flag);
            baos.write(addressHashAndOwnerSalt);
            baos.write(encryptedPointB);
            baos.write(doubleSha256(baos.toByteArray()), 0, 4);
            String confirmationCode = encodeBase58(baos.toByteArray());

            Bip38PrivateKeyInfo privateKeyInfo = new Bip38PrivateKeyInfo(encryptedPrivateKey, confirmationCode, true);
            return new KeyPair(address, publicKey, privateKeyInfo);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String bip38DecryptConfirmation(String confirmationCode, String password) throws BitcoinException, InterruptedException {
        byte[] confirmationBytes = decodeBase58(confirmationCode);
        if (!verifyChecksum(confirmationBytes) || confirmationBytes.length != 55) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Bad confirmation code");
        }
        byte[] magic = fromHex("643BF6A89A");
        for (int i = 0; i < magic.length; i++) {
            if (magic[i] != confirmationBytes[i]) {
                throw new BitcoinException(BitcoinException.ERR_WRONG_TYPE, "It isn't a confirmation code");
            }
        }
        try {
            byte flag = confirmationBytes[5];
            boolean compressed = (flag & 0x20) == 0x20;
            boolean lotSequencePresent = (flag & 0x04) == 0x04;
            byte[] addressHash = new byte[4];
            System.arraycopy(confirmationBytes, 6, addressHash, 0, 4);
            byte[] ownerEntropy = new byte[8];
            System.arraycopy(confirmationBytes, 10, ownerEntropy, 0, 8);
            byte[] salt = new byte[lotSequencePresent ? 4 : 8];
            System.arraycopy(ownerEntropy, 0, salt, 0, salt.length);
            byte[] encryptedPointB = new byte[33];
            System.arraycopy(confirmationBytes, 18, encryptedPointB, 0, 33);
            byte[] passFactor = SCrypt.generate(password.getBytes("UTF-8"), salt, 16384, 8, 8, 32);
            ECPoint uncompressed = EC_PARAMS.getG().multiply(new BigInteger(1, passFactor));
            byte[] passPoint = uncompressed.getEncoded(true);

            byte[] addressHashAndOwnerSalt = new byte[12];
            System.arraycopy(addressHash, 0, addressHashAndOwnerSalt, 0, 4);
            System.arraycopy(ownerEntropy, 0, addressHashAndOwnerSalt, 4, 8);
            byte[] derived = SCrypt.generate(passPoint, addressHashAndOwnerSalt, 1024, 1, 1, 64);
            byte[] key = new byte[32];
            System.arraycopy(derived, 32, key, 0, 32);
            AESEngine cipher = new AESEngine();
            cipher.init(false, new KeyParameter(key));

            byte[] pointB = new byte[33];
            pointB[0] = (byte) (encryptedPointB[0] ^ (derived[63] & 0x01));
            cipher.processBlock(encryptedPointB, 1, pointB, 1);
            cipher.processBlock(encryptedPointB, 17, pointB, 17);

            for (int i = 0; i < 32; i++) {
                pointB[i + 1] ^= derived[i];
            }
            ECPoint uncompressedPublicKey;
            try {
                uncompressedPublicKey = EC_PARAMS.getCurve().decodePoint(pointB).multiply(new BigInteger(1, passFactor));
            } catch (RuntimeException e) {
                //point b doesn't belong the curve - bad password
                return null;
            }
            String address = BTCUtils.publicKeyToAddress(uncompressedPublicKey.getEncoded(compressed));
            byte[] decodedAddressHash = doubleSha256(address.getBytes("UTF-8"));
            for (int i = 0; i < 4; i++) {
                if (addressHash[i] != decodedAddressHash[i]) {
                    return null;
                }
            }
            return address;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String bip38Encrypt(KeyPair keyPair, String password) throws InterruptedException {
        try {
            byte[] addressHash = new byte[4];
            if (TextUtils.isEmpty(keyPair.address)) {
                throw new RuntimeException("Unknown address");
            }
            System.arraycopy(doubleSha256(keyPair.address.getBytes("UTF-8")), 0, addressHash, 0, 4);
            byte[] passwordDerived = SCrypt.generate(password.getBytes("UTF-8"), addressHash, 16384, 8, 8, 64);
            byte[] xor = new byte[32];
            System.arraycopy(passwordDerived, 0, xor, 0, 32);
            byte[] key = new byte[32];
            System.arraycopy(passwordDerived, 32, key, 0, 32);
            byte[] privateKeyBytes = getPrivateKeyBytes(keyPair.privateKey.privateKeyDecoded);
            for (int i = 0; i < 32; i++) {
                xor[i] ^= privateKeyBytes[i];
            }
            AESEngine cipher = new AESEngine();
            cipher.init(true, new KeyParameter(key));
            byte[] encryptedHalf1 = new byte[16];
            byte[] encryptedHalf2 = new byte[16];
            cipher.processBlock(xor, 0, encryptedHalf1, 0);
            cipher.processBlock(xor, 16, encryptedHalf2, 0);
            byte[] result = new byte[43];
            result[0] = 1;
            result[1] = 0x42;
            result[2] = (byte) (keyPair.privateKey.isPublicKeyCompressed ? 0xe0 : 0xc0);
            System.arraycopy(addressHash, 0, result, 3, 4);
            System.arraycopy(encryptedHalf1, 0, result, 7, 16);
            System.arraycopy(encryptedHalf2, 0, result, 23, 16);
            MessageDigest digestSha = MessageDigest.getInstance("SHA-256");
            digestSha.update(result, 0, result.length - 4);
            System.arraycopy(digestSha.digest(digestSha.digest()), 0, result, 39, 4);
            return encodeBase58(result);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getPrivateKeyBytes(BigInteger privateKey) {
        byte[] privateKeyPlainNumber = privateKey.toByteArray();
        int plainNumbersOffs = privateKeyPlainNumber[0] == 0 ? 1 : 0;
        byte[] privateKeyBytes = new byte[32];
        System.arraycopy(privateKeyPlainNumber, plainNumbersOffs, privateKeyBytes, privateKeyBytes.length - (privateKeyPlainNumber.length - plainNumbersOffs), privateKeyPlainNumber.length - plainNumbersOffs);
        return privateKeyBytes;
    }

    public static KeyPair bip38Decrypt(String encryptedPrivateKey, String password) throws InterruptedException, BitcoinException {
        byte[] encryptedPrivateKeyBytes = decodeBase58(encryptedPrivateKey);
        if (encryptedPrivateKeyBytes != null && encryptedPrivateKey.startsWith("6P") && verifyChecksum(encryptedPrivateKeyBytes) && encryptedPrivateKeyBytes[0] == 1) {
            try {
                byte[] addressHash = new byte[4];
                System.arraycopy(encryptedPrivateKeyBytes, 3, addressHash, 0, 4);
                boolean compressed = (encryptedPrivateKeyBytes[2] & 0x20) == 0x20;
                AESEngine cipher = new AESEngine();
                if (encryptedPrivateKeyBytes[1] == 0x42) {
                    byte[] encryptedSecret = new byte[32];
                    System.arraycopy(encryptedPrivateKeyBytes, 7, encryptedSecret, 0, 32);
                    byte[] passwordDerived = SCrypt.generate(password.getBytes("UTF-8"), addressHash, 16384, 8, 8, 64);
                    byte[] key = new byte[32];
                    System.arraycopy(passwordDerived, 32, key, 0, 32);
                    cipher.init(false, new KeyParameter(key));
                    byte[] secret = new byte[32];
                    cipher.processBlock(encryptedSecret, 0, secret, 0);
                    cipher.processBlock(encryptedSecret, 16, secret, 16);
                    for (int i = 0; i < 32; i++) {
                        secret[i] ^= passwordDerived[i];
                    }
                    KeyPair keyPair = new KeyPair(new Bip38PrivateKeyInfo(encryptedPrivateKey, new BigInteger(1, secret), password, compressed));
                    byte[] addressHashCalculated = new byte[4];
                    if (TextUtils.isEmpty(keyPair.address)) {
                        throw new RuntimeException("Unknown address");
                    }
                    System.arraycopy(doubleSha256(keyPair.address.getBytes("UTF-8")), 0, addressHashCalculated, 0, 4);
                    if (!org.spongycastle.util.Arrays.areEqual(addressHashCalculated, addressHash)) {
                        throw new BitcoinException(BitcoinException.ERR_INCORRECT_PASSWORD, "Bad password");
                    }
                    return keyPair;
                } else if (encryptedPrivateKeyBytes[1] == 0x43) {
                    byte[] ownerSalt = new byte[8];
                    System.arraycopy(encryptedPrivateKeyBytes, 7, ownerSalt, 0, 8);
                    byte[] passFactor = SCrypt.generate(password.getBytes("UTF-8"), ownerSalt, 16384, 8, 8, 32);
                    ECPoint uncompressed = EC_PARAMS.getG().multiply(new BigInteger(1, passFactor));
                    byte[] passPoint = uncompressed.getEncoded(true);
                    byte[] addressHashAndOwnerSalt = new byte[12];
                    System.arraycopy(encryptedPrivateKeyBytes, 3, addressHashAndOwnerSalt, 0, 12);
                    byte[] derived = SCrypt.generate(passPoint, addressHashAndOwnerSalt, 1024, 1, 1, 64);
                    byte[] key = new byte[32];
                    System.arraycopy(derived, 32, key, 0, 32);
                    cipher.init(false, new KeyParameter(key));
                    byte[] decryptedHalf2 = new byte[16];
                    cipher.processBlock(encryptedPrivateKeyBytes, 23, decryptedHalf2, 0);
                    for (int i = 0; i < 16; i++) {
                        decryptedHalf2[i] ^= derived[i + 16];
                    }
                    byte[] encryptedHalf1 = new byte[16];
                    System.arraycopy(encryptedPrivateKeyBytes, 15, encryptedHalf1, 0, 8);
                    System.arraycopy(decryptedHalf2, 0, encryptedHalf1, 8, 8);
                    byte[] decryptedHalf1 = new byte[16];
                    cipher.processBlock(encryptedHalf1, 0, decryptedHalf1, 0);
                    for (int i = 0; i < 16; i++) {
                        decryptedHalf1[i] ^= derived[i];
                    }
                    byte[] seedB = new byte[24];
                    System.arraycopy(decryptedHalf1, 0, seedB, 0, 16);
                    System.arraycopy(decryptedHalf2, 8, seedB, 16, 8);
                    byte[] factorB = doubleSha256(seedB);
                    BigInteger privateKey = new BigInteger(1, passFactor).multiply(new BigInteger(1, factorB)).remainder(EC_PARAMS.getN());
                    KeyPair keyPair = new KeyPair(new Bip38PrivateKeyInfo(encryptedPrivateKey, privateKey, password, compressed));
                    if (TextUtils.isEmpty(keyPair.address)) {
                        throw new RuntimeException("Unknown address");
                    }
                    byte[] resultedAddressHash = doubleSha256(keyPair.address.getBytes("UTF-8"));
                    for (int i = 0; i < 4; i++) {
                        if (addressHashAndOwnerSalt[i] != resultedAddressHash[i]) {
                            throw new BitcoinException(BitcoinException.ERR_INCORRECT_PASSWORD, "Bad password");
                        }
                    }
                    return keyPair;
                } else {
                    throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Bad encrypted private key");
                }
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
        } else {
            throw new BitcoinException(BitcoinException.ERR_WRONG_TYPE, "It is not an encrypted private key");
        }
    }


}
