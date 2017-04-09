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

public class BitcoinOutputStreamTest extends TestCase {
    private BitcoinOutputStream os;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        os = new BitcoinOutputStream();
    }

    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        os.close();
    }

    public void testOutputStream() throws Exception {
        int a = 0x012345678;
        int b = (int) (0xfedcba987L);
        long c = 0xfedcba9876543210L;
        int d = 0xabcd;
        os.writeInt32(a);
        os.writeInt32(b);
        os.writeInt64(c);
        os.writeInt16(d);
        os.writeVarInt(0);
        os.writeVarInt(0xfd);
        os.writeVarInt(0xfe);
        os.writeVarInt(0xff);
        os.writeVarInt(0xff0);
        os.writeVarInt(0xff11223344L);
        os.close();
        byte[] result = os.toByteArray();
        BitcoinInputStream is = new BitcoinInputStream(result);
        assertEquals(is.readInt32(), a);
        assertEquals(is.readInt32(), b);
        assertEquals(is.readInt64(), c);
        assertEquals(is.readInt16(), d);
        assertEquals(is.readVarInt(), 0);
        assertEquals(is.readVarInt(), 0xfd);
        assertEquals(is.readVarInt(), 0xfe);
        assertEquals(is.readVarInt(), 0xff);
        assertEquals(is.readVarInt(), 0xff0);
        assertEquals(is.readVarInt(), 0xff11223344L);
    }
}
