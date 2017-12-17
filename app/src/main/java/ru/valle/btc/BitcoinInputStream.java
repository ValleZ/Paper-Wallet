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

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;

@SuppressWarnings("WeakerAccess")
public class BitcoinInputStream extends ByteArrayInputStream {
    public BitcoinInputStream(byte[] buf) {
        super(buf);
    }

    @SuppressWarnings("unused")
    public BitcoinInputStream(byte[] buf, int offset, int length) {
        super(buf, offset, length);
    }

    public int readInt16() throws EOFException {
        return (readByte() & 0xff) | ((readByte() & 0xff) << 8);
    }

    public int readInt32() throws EOFException {
        return (readByte() & 0xff) | ((readByte() & 0xff) << 8) | ((readByte() & 0xff) << 16) | ((readByte() & 0xff) << 24);
    }

    public long readInt64() throws EOFException {
        return (readInt32() & 0xFFFFFFFFL) | ((readInt32() & 0xFFFFFFFFL) << 32);
    }

    public int readByte() throws EOFException {
        int readedByte = super.read();
        if (readedByte == -1) {
            throw new EOFException();
        }
        return readedByte;
    }

    public long readVarInt() throws EOFException {
        int readedByte = readByte();
        if (readedByte < 0xfd) {
            return readedByte;
        } else if (readedByte == 0xfd) {
            return readInt16();
        } else if (readedByte == 0xfe) {
            return readInt32();
        } else {
            return readInt64();
        }
    }

    public byte[] readChars(final int count) throws IOException {
        byte[] buf = new byte[count];
        int off = 0;
        while (off != count) {
            int bytesReadCurr = read(buf, off, count - off);
            if (bytesReadCurr == -1) {
                throw new EOFException();
            } else {
                off += bytesReadCurr;
            }
        }
        return buf;
    }

}
