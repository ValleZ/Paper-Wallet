/*
 The MIT License (MIT)

 Copyright (c) 2018 Valentin Konovalov

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

import java.io.ByteArrayOutputStream;
import java.util.Locale;

final class Bech32 {
    private static final String charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] generator = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

    static String encodeSegwitAddress(String hrp, int version, byte[] program) throws BitcoinException {
        if (version < 0 || version > 16) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid witness version: " + version);
        }
        if (program.length < 2 || program.length > 40) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid program length: " + program.length);
        }
        if (version == 0 && program.length != 20 && program.length != 32) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid program length for witness version 0 (per BIP141): " + program.length);
        }
        byte[] data = convertBits(program, 8, 5, true);
        byte[] versionPlusData = new byte[1 + data.length];
        versionPlusData[0] = (byte) version;
        System.arraycopy(data, 0, versionPlusData, 1, data.length);
        return encode(hrp, versionPlusData);
    }

    @NonNull
    static Transaction.Script.WitnessProgram decodeSegwitAddress(String hrp, String address) throws BitcoinException {
        DecodeResult decoded = decode(address);
        String dechrp = decoded.dechrp;
        byte[] data = decoded.data;
        if (!dechrp.equals(hrp)) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid human-readable part: " + hrp + " != " + dechrp);
        }
        if (data.length == 0) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid decode data length: " + data.length);
        }
        if ((data[0] & 0xff) > 16) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid witness version: " + (data[0] & 0xff));
        }
        byte[] dataWithNoVersion = new byte[data.length - 1];
        System.arraycopy(data, 1, dataWithNoVersion, 0, dataWithNoVersion.length);
        byte[] res = convertBits(dataWithNoVersion, 5, 8, false);
        if (res.length < 2 || res.length > 40) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid convertbits length: " + res.length);
        }
        if (data[0] == 0 && res.length != 20 && res.length != 32) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid program length for witness version 0 (per BIP141): " + res.length);
        }
        return new Transaction.Script.WitnessProgram(data[0], res);
    }

    static class DecodeResult {
        final String dechrp;
        final byte[] data;

        DecodeResult(String dechrp, byte[] data) {
            this.dechrp = dechrp;
            this.data = data;
        }
    }

    static DecodeResult decode(String bechString) throws BitcoinException {
        if (bechString.length() > 90) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "too long: len=" + bechString.length());
        }
        String lowercased = bechString.toLowerCase(Locale.ENGLISH);
        String uppercased = bechString.toUpperCase(Locale.ENGLISH);
        if (lowercased.equals(bechString) && uppercased.equals(bechString)) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "mixed case");
        }
        bechString = lowercased;
        int pos = bechString.lastIndexOf('1');
        if (pos < 1 || pos + 7 > bechString.length()) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "separator '1' at invalid position: pos=" + pos + ", len=" + bechString.length());
        }
        String hrp = bechString.substring(0, pos);
        for (int i = 0; i < hrp.length(); i++) {
            char c = hrp.charAt(i);
            if (c < 33 || c > 126) {
                throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid character human-readable part: bechString[" + i + "]=" + c);
            }
        }
        byte[] data = new byte[bechString.length() - pos - 1];
        for (int p = pos + 1, i = 0; p < bechString.length(); p++, i++) {
            int d = charset.indexOf(bechString.charAt(p));
            if (d == -1) {
                throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid character data part : bechString[" + p + "]=" + bechString.charAt(p));
            }
            data[i] = (byte) d;
        }
        if (!verifyChecksum(hrp, data)) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid checksum");
        }
        byte[] outData = new byte[data.length - 6];
        System.arraycopy(data, 0, outData, 0, outData.length);
        return new DecodeResult(hrp, outData);
    }

    private static boolean verifyChecksum(String hrp, byte[] data) {
        byte[] ehrp = hrpExpand(hrp);
        byte[] values = new byte[ehrp.length + data.length];
        System.arraycopy(ehrp, 0, values, 0, ehrp.length);
        System.arraycopy(data, 0, values, ehrp.length, data.length);
        return polymod(values) == 1;
    }

    static String encode(String hrp, byte[] data) throws BitcoinException {
        if ((hrp.length() + data.length + 7) > 90) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "too long: hrp length=" + hrp.length() + ", data length=" + data.length);
        }
        if (hrp.length() == 0) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "no hrp");
        }
        for (int i = 0; i < hrp.length(); i++) {
            char c = hrp.charAt(i);
            if (c < 33 || c > 126) {
                throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid character human-readable part: hrp[" + i + "]=" + c);
            }
        }
        String uppercased = hrp.toUpperCase(Locale.ENGLISH);
        String lowercased = hrp.toLowerCase(Locale.ENGLISH);
        if (!uppercased.equals(hrp) && !lowercased.equals(hrp)) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "mixed case: hrp=" + hrp);
        }
        boolean lower = lowercased.equals(hrp);
        hrp = lowercased;
        byte[] checksum = createChecksum(hrp, data);
        byte[] combined = new byte[data.length + checksum.length];
        System.arraycopy(data, 0, combined, 0, data.length);
        System.arraycopy(checksum, 0, combined, data.length, checksum.length);
        StringBuilder ret = new StringBuilder();
        ret.append(hrp);
        ret.append("1");
        for (int i = 0; i < combined.length; i++) {
            int p = combined[i] & 0xff;
            if (p >= charset.length()) {
                throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid data: data[" + i + "]=" + p);
            }
            ret.append(charset.charAt(p));
        }
        if (lower) {
            return ret.toString();
        }
        return ret.toString().toUpperCase(Locale.ENGLISH);
    }

    private static byte[] createChecksum(String hrp, byte[] data) {
        byte[] ehrp = hrpExpand(hrp);
        byte[] values = new byte[ehrp.length + data.length + 6];
        System.arraycopy(ehrp, 0, values, 0, ehrp.length);
        System.arraycopy(data, 0, values, ehrp.length, data.length);
        int mod = polymod(values) ^ 1;
        byte[] ret = new byte[6];
        for (int p = 0; p < ret.length; p++) {
            ret[p] = (byte) ((mod >>> (5 * (5 - p))) & 31);
        }
        return ret;
    }

    private static int polymod(byte[] values) {
        int chk = 1;
        for (byte value : values) {
            int v = value & 0xff;
            int top = chk >>> 25;
            chk = (chk & 0x1ffffff) << 5 ^ v;
            for (int j = 0; j < 5; j++) {
                if (((top >> j) & 1) == 1) {
                    chk ^= generator[j];
                }
            }
        }
        return chk;
    }

    private static byte[] hrpExpand(String hrp) {
        byte[] ret = new byte[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            char c = hrp.charAt(i);
            ret[i] = (byte) (c >> 5);
        }
        for (int i = 0; i < hrp.length(); i++) {
            char c = hrp.charAt(i);
            ret[i + hrp.length() + 1] = (byte) (c & 31);
        }
        return ret;
    }

    private static byte[] convertBits(byte[] data, int frombits, int tobits, boolean pad) throws BitcoinException {
        int acc = 0;
        int bits = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int maxv = (1 << tobits) - 1;
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xff;
            if ((value >>> frombits) != 0) {
                throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "invalid data range: data[" + i + "]=" + value + " (frombits=" + frombits + ")");
            }
            acc = (acc << frombits) | value;
            bits += frombits;
            while (bits >= tobits) {
                bits -= tobits;
                baos.write((acc >>> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) {
                baos.write((acc << (tobits - bits)) & maxv);
            }
        } else if (bits >= frombits) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "illegal zero padding");
        } else if (((acc << (tobits - bits)) & maxv) != 0) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "non-zero padding");
        }
        return baos.toByteArray();
    }
}
