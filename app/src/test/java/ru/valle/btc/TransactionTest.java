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

import java.util.Arrays;
import java.util.Stack;

public final class TransactionTest extends TestCase {
    //    public static final String TX_HASH = "ba3d64e55402f04ce03822f5bcf5a99e3cae675b7dc4ac743e6474bc72b46b48";
    private static final String TX_BYTES = "01000000018c60fb1230de41b2edbad2de83e34ee56ee6fe117891d5a2fdc749e96bae165d" +
            "010000006c49304602210092812e3867c0fb8790746b2b73fe66136f28dc089a8d6c9e47949eb041539a63022100ad4dc298192f627d772ffb9932f9bda4c84cc" +
            "23fb2fe5f59ca7ff00f0e372d4d0121031c6efa01036e2a9a40dc945de6086422d926ed57c823be1f93e7f7fc447020b9ffffffff" +
            "0210935d2c000000001976a91401f42191c6593d31d555cf66fa3c813ccebbf1d288ac139a1e720c0000001976a9141a7bb01bf7b41675bad93b2bcd55db3ce8d3fc7f88ac00000000";

    public void testTransactionSerialization() throws Exception {
        Transaction tx = null;
        try {
            tx = new Transaction(BTCUtils.fromHex(TX_BYTES));
        } catch (Exception e) {
            assertTrue(e.getMessage(), false);
        }
        assertNotNull(tx);
        assertNotNull(tx.inputs);
        assertNotNull(tx.outputs);
        assertEquals(0, tx.lockTime);

        assertEquals(1, tx.inputs.length);
        assertNotNull(tx.inputs[0]);
        assertNotNull(tx.inputs[0].script);
        assertTrue(Arrays.equals(
                BTCUtils.fromHex("49304602210092812e3867c0fb8790746b2b73fe66136f28dc089a8d6c9e47949eb041539a63022100ad4dc298192f627d772ffb9932f9bda4c84cc23fb2fe5f59ca7ff00f0e372d4d0121031c6efa01036e2a9a40dc945de6086422d926ed57c823be1f93e7f7fc447020b9"),
                tx.inputs[0].script.bytes
        ));
        assertEquals(4294967295L, tx.inputs[0].sequence & 0xffffffffL);
        assertNotNull(tx.inputs[0].outPoint);
        assertEquals(1, tx.inputs[0].outPoint.index);
        assertTrue(Arrays.equals(
                BTCUtils.fromHex("5d16ae6be949c7fda2d5917811fee66ee54ee383ded2baedb241de3012fb608c"),
                tx.inputs[0].outPoint.hash
        ));

        assertEquals(2, tx.outputs.length);
        assertNotNull(tx.outputs[0]);
        assertNotNull(tx.outputs[0].script);
        assertNotNull(tx.outputs[0].script.bytes);
        assertEquals(744330000L, tx.outputs[0].value);
        assertTrue(Arrays.equals(BTCUtils.fromHex("76a91401f42191c6593d31d555cf66fa3c813ccebbf1d288ac"), tx.outputs[0].script.bytes));
        assertNotNull(tx.outputs[1]);
        assertNotNull(tx.outputs[1].script);
        assertNotNull(tx.outputs[1].script.bytes);
        assertEquals(53454215699L, tx.outputs[1].value);
        assertTrue(Arrays.equals(BTCUtils.fromHex("76a9141a7bb01bf7b41675bad93b2bcd55db3ce8d3fc7f88ac"), tx.outputs[1].script.bytes));

        assertTrue(Arrays.equals(BTCUtils.fromHex(TX_BYTES), tx.getBytes()));

    }

    public void testScript() throws Exception {
        Stack<byte[]> stack = new Stack<>();
        try {
            new Transaction.Script(BTCUtils.fromHex("483045022100e22ad498e72e38624718c52bcf4648ecf0ddb449e3fbc4c66fa175d59fe1b37102203e87cf1126053e23a47a7df2a0a3d3a3b4d1e705521a540e923f0bc24590449d012103063f535fc8a92e6006dc9948f184650f49966dd36a4251fdaeafd86499e798cc")).run(stack);
            new Transaction.Script(BTCUtils.fromHex("76a9146440b26e52d7834016317165042f2dda7308575588757504DEADBEFF75")).run(stack);//OP_DUP OP_HASH160 6440b26e52d7834016317165042f2dda73085755 OP_EQUALVERIFY OP_DROP OP_DROP DEADBEFF OP_DROP
            assertTrue(stack.empty());
        } catch (Exception e) {
            assertTrue("script should run w/o exceptions " + e, false);
        }
    }

    public void testScriptDecodingEncoding() {
        byte[] bytes = BTCUtils.fromHex("76a9146440b26e52d7834016317165042f2dda7308575588757504DEADBEFF75");
        String txStr = Transaction.Script.convertBytesToReadableString(bytes);
        assertEquals("OP_DUP OP_HASH160 6440b26e52d7834016317165042f2dda73085755 OP_EQUALVERIFY OP_DROP OP_DROP deadbeff OP_DROP", txStr);
        byte[] bytesOut = Transaction.Script.convertReadableStringToBytes(txStr);
        assertTrue(Arrays.equals(bytes, bytesOut));

        bytes = BTCUtils.fromHex("76a914ba507bae8f1643d2556000ca26b9301b9069dc6b88ac");
        txStr = Transaction.Script.convertBytesToReadableString(bytes);
        assertEquals("OP_DUP OP_HASH160 ba507bae8f1643d2556000ca26b9301b9069dc6b OP_EQUALVERIFY OP_CHECKSIG", txStr);
        bytesOut = Transaction.Script.convertReadableStringToBytes(txStr);
        assertTrue(Arrays.equals(bytes, bytesOut));
    }
}
