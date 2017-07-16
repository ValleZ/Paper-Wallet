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

import junit.framework.TestCase;

import java.io.EOFException;
import java.util.Arrays;

public class BitcoinInputStreamTest extends TestCase {
    private static final byte[] CONTENT = new byte[]{(byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, 0x76, 0x54, 0x32, 0x10};
    private BitcoinInputStream is;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        is = new BitcoinInputStream(CONTENT);
    }

    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        is.close();
    }

    public void testReadByte() throws Exception {
        assertEquals(is.readByte() & 0xff, 0xfe);
        assertEquals(is.readByte() & 0xff, 0xdc);
        assertEquals(is.readByte() & 0xff, 0xba);
        assertEquals(is.readByte() & 0xff, 0x98);

        assertEquals(is.readByte() & 0xff, 0x76);
        assertEquals(is.readByte() & 0xff, 0x54);
        assertEquals(is.readByte() & 0xff, 0x32);
        assertEquals(is.readByte() & 0xff, 0x10);
        try {
            is.readByte();
            assertFalse("readByte() must throw EOFException", true);
        } catch (EOFException ignored) {
        }
    }

    public void testReadInt16() throws Exception {
        assertEquals(is.readInt16() & 0xffff, 0xdcfe);
        assertEquals(is.readInt16() & 0xffff, 0x98ba);
        assertEquals(is.readInt16() & 0xffff, 0x5476);
        assertEquals(is.readInt16() & 0xffff, 0x1032);
        try {
            is.readInt16();
            assertFalse("readInt16() must throw EOFException", true);
        } catch (EOFException ignored) {
        }
    }

    public void testReadInt32() throws Exception {
        assertEquals(is.readInt32(), 0x98badcfe);
        assertEquals(is.readInt32(), 0x10325476);
        try {
            is.readInt32();
            assertFalse("readInt32() must throw EOFException", true);
        } catch (EOFException ignored) {
        }
    }

    public void testReadInt64() throws Exception {
        assertEquals(is.readInt64(), 0x1032547698badcfeL);
        try {
            is.readInt64();
            assertFalse("readInt64() must throw EOFException", true);
        } catch (EOFException ignored) {
        }
    }

    public void testReadVarInt() throws Exception {
        assertEquals(is.readVarInt(), 0x7698badc);//fe
        assertEquals(is.readVarInt(), 0x54);//<fd
        tearDown();
        is = new BitcoinInputStream(new byte[]{(byte) 0xfd, 1, (byte) 0xff, (byte) 0xff, (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, 0x76, 0x54, 0x32, 0x10});
        assertEquals(is.readVarInt(), 0xff01);//fd
        assertEquals(is.readVarInt(), 0x1032547698badcfeL);//ff
    }

    public void testReadChars() throws Exception {
        assertTrue(Arrays.equals(is.readChars(8), CONTENT));
    }
}
