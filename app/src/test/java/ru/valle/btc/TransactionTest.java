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

import org.json.JSONArray;
import org.json.JSONException;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DLSequence;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;
import java.util.Stack;

public final class TransactionTest extends TestCase {
    //    public static final String TX_HASH = "ba3d64e55402f04ce03822f5bcf5a99e3cae675b7dc4ac743e6474bc72b46b48";
    private static final String TX_BYTES = "01000000018c60fb1230de41b2edbad2de83e34ee56ee6fe117891d5a2fdc749e96bae165d" +
            "010000006c49304602210092812e3867c0fb8790746b2b73fe66136f28dc089a8d6c9e47949eb041539a63022100ad4dc298192f627d772ffb9932f9bda4c84cc" +
            "23fb2fe5f59ca7ff00f0e372d4d0121031c6efa01036e2a9a40dc945de6086422d926ed57c823be1f93e7f7fc447020b9ffffffff" +
            "0210935d2c000000001976a91401f42191c6593d31d555cf66fa3c813ccebbf1d288ac139a1e720c0000001976a9141a7bb01bf7b41675bad93b2bcd55db3ce8d3fc7f88ac00000000";

    public void testTransactionSerialization() {
        Transaction tx = null;
        try {
            tx = Transaction.decodeTransaction(BTCUtils.fromHex(TX_BYTES));
        } catch (Exception e) {
            assertTrue(e.getMessage(), false);
        }
        assertNotNull(tx);
        assertNotNull(tx.inputs);
        assertNotNull(tx.outputs);
        assertEquals(0, tx.lockTime);

        assertEquals(1, tx.inputs.length);
        assertNotNull(tx.inputs[0]);
        assertNotNull(tx.inputs[0].scriptSig);
        assertTrue(Arrays.equals(
                BTCUtils.fromHex("49304602210092812e3867c0fb8790746b2b73fe66136f28dc089a8d6c9e47949eb041539a63022100ad4dc298192f627d772ffb9932f9bda4c84cc23fb2fe5f59ca7ff00f0e372d4d0121031c6efa01036e2a9a40dc945de6086422d926ed57c823be1f93e7f7fc447020b9"),
                tx.inputs[0].scriptSig.bytes
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
        assertNotNull(tx.outputs[0].scriptPubKey);
        assertNotNull(tx.outputs[0].scriptPubKey.bytes);
        assertEquals(744330000L, tx.outputs[0].value);
        assertTrue(Arrays.equals(BTCUtils.fromHex("76a91401f42191c6593d31d555cf66fa3c813ccebbf1d288ac"), tx.outputs[0].scriptPubKey.bytes));
        assertNotNull(tx.outputs[1]);
        assertNotNull(tx.outputs[1].scriptPubKey);
        assertNotNull(tx.outputs[1].scriptPubKey.bytes);
        assertEquals(53454215699L, tx.outputs[1].value);
        assertTrue(Arrays.equals(BTCUtils.fromHex("76a9141a7bb01bf7b41675bad93b2bcd55db3ce8d3fc7f88ac"), tx.outputs[1].scriptPubKey.bytes));

        assertTrue(Arrays.equals(BTCUtils.fromHex(TX_BYTES), tx.getBytes()));

    }

    public void testScript() {
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

    @SuppressWarnings("ConstantConditions")
    public void testCreateTxFromWebsiteData() throws Exception {
        String privateKey = "cTWi7zbRcbSKj1S6sokToNmCvLUsTAW9Mn5hxHnLUt3NAPUPnNKK";

        String hashOfPrevTransaction = "93abfe1eba39a1356fd41653f99b16a503f8454277eb0676f33a3f047f582f00";
        String amountStr = "1.8";
        String scriptStr = "OP_DUP OP_HASH160 109c70e69cb267df2f907a0c4955a83d0287bbe2 OP_EQUALVERIFY OP_CHECKSIG";
        int indexOfOutputToSpend = 0;
        int confirmations = 150;//confirmations count is to calculate fee
        String outputAddress = "msVcNhmpHEMiNCmw3NNeN7JD3vTDsrMUnY";
        String changeAddress = null;
        float feeSatByte = 50;

        BTCUtils.PrivateKeyInfo privateKeyInfo = BTCUtils.decodePrivateKey(privateKey);
        KeyPair keyPair = new KeyPair(privateKeyInfo, Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);

        Transaction.Script scriptOfUnspentOutput = new Transaction.Script(Transaction.Script.convertReadableStringToBytes(scriptStr));
        long amount = BTCUtils.parseValue(amountStr);
        Transaction tx = BTCUtils.createTransaction(
                BTCUtils.fromHex(hashOfPrevTransaction),
                amount,
                scriptOfUnspentOutput,
                indexOfOutputToSpend,
                confirmations,
                outputAddress,
                changeAddress,
                -1,//send all with some fee
                feeSatByte,
                keyPair,
                BTCUtils.TRANSACTION_TYPE_LEGACY);
        assertNotNull(tx);
        BTCUtils.verify(new Transaction.Script[]{scriptOfUnspentOutput}, new long[]{amount}, tx, false);

        Stack<byte[]> stack = new Stack<>();
        tx.inputs[0].scriptSig.run(stack);
        stack.pop();//public key
        byte[] signatureAndHashType = stack.pop();
        byte[] signature = new byte[signatureAndHashType.length - 1];
        System.arraycopy(signatureAndHashType, 0, signature, 0, signature.length);
        assertTrue(signature.length <= 72);
        ASN1InputStream derSigStream = new ASN1InputStream(signature);
        DLSequence seq = (DLSequence) derSigStream.readObject();
//        BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
        derSigStream.close();
        BigInteger largestAllowedS = BTCUtils.LARGEST_PRIVATE_KEY.divide(BigInteger.valueOf(2));
        assertFalse("S is too high", s.compareTo(largestAllowedS) > 0);
//        System.out.println(BTCUtils.toHex(tx.getBytes()));
    }

    public void testHighSInCreatedTx() throws Exception {
        for (int i = 0; i < 10; i++) {
            testCreateTxFromWebsiteData();
        }
    }

    @SuppressWarnings("ConstantConditions")
    public void testCreateTxFromWebsiteData2() throws Exception {
        String privateKey = "cTWi7zbRcbSKj1S6sokToNmCvLUsTAW9Mn5hxHnLUt3NAPUPnNKK";
        BTCUtils.PrivateKeyInfo privateKeyInfo = BTCUtils.decodePrivateKey(privateKey);
        KeyPair keyPair = new KeyPair(privateKeyInfo, Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);

        String hashOfPrevTransaction = "6520d998704f2bce33c2f1325364d110bc12061970a76b294751be03212a48ba";
        String amountStr = "1.8";
        String scriptStr = Transaction.Script.buildOutput(keyPair.address.addressString).toString();// "OP_DUP OP_HASH160 e74de5ee50745652ee03c3c499622f79134ad5b8 OP_EQUALVERIFY OP_CHECKSIG";
        int indexOfOutputToSpend = 0;
        int confirmations = 0;
        String outputAddress = "msVcNhmpHEMiNCmw3NNeN7JD3vTDsrMUnY";
        String changeAddress = null;
        float feeSatByte = 50;

        Transaction.Script scriptOfUnspentOutput = new Transaction.Script(Transaction.Script.convertReadableStringToBytes(scriptStr));
        long amount = BTCUtils.parseValue(amountStr);
        Transaction tx = BTCUtils.createTransaction(
                BTCUtils.fromHex(hashOfPrevTransaction),
                amount,
                scriptOfUnspentOutput,
                indexOfOutputToSpend,
                confirmations,
                outputAddress,
                changeAddress,
                -1,//send all with some fee
                feeSatByte,
                keyPair,
                BTCUtils.TRANSACTION_TYPE_LEGACY);
        assertNotNull(tx);
        BTCUtils.verify(new Transaction.Script[]{scriptOfUnspentOutput}, new long[]{amount}, tx, false);
//        System.out.println(BTCUtils.toHex(tx.getBytes()));
    }

    @SuppressWarnings("ConstantConditions")
    public void testCreateTxFromWebsiteData3() throws Exception {
        String privateKey = "cRRtyQNav5susPoFZPzFY4d5hUiZeM9dkzeckrfi98KJkB2ULw1h";
        BTCUtils.PrivateKeyInfo privateKeyInfo = BTCUtils.decodePrivateKey(privateKey);
        KeyPair keyPair = new KeyPair(privateKeyInfo, Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);

        String hashOfPrevTransaction = "d060aa367d9961591723ef3dfcc0a5c292bfb41a2abff021693f79cbf6d12ce0";
        String amountStr = "1.799";
        String scriptStr = Transaction.Script.buildOutput(keyPair.address.addressString).toString();// "OP_DUP OP_HASH160 e74de5ee50745652ee03c3c499622f79134ad5b8 OP_EQUALVERIFY OP_CHECKSIG";
        int indexOfOutputToSpend = 0;
        int confirmations = 2;
        String outputAddress = "mk6DbNSrs8Hf5Zq3RrXMTbgrco9duzLF2w";
        String changeAddress = null;
        float feeSatByte = 50;

        Transaction.Script scriptOfUnspentOutput = new Transaction.Script(Transaction.Script.convertReadableStringToBytes(scriptStr));
        long amount = BTCUtils.parseValue(amountStr);
        Transaction tx = BTCUtils.createTransaction(
                BTCUtils.fromHex(hashOfPrevTransaction),
                amount,
                scriptOfUnspentOutput,
                indexOfOutputToSpend,
                confirmations,
                outputAddress,
                changeAddress,
                -1,//send all with some fee
                feeSatByte,
                keyPair,
                BTCUtils.TRANSACTION_TYPE_LEGACY);
        assertNotNull(tx);
        BTCUtils.verify(new Transaction.Script[]{scriptOfUnspentOutput}, new long[]{amount}, tx, false);
//        System.out.println(BTCUtils.toHex(tx.getBytes()));
    }

    public void testBitcoinCoreValidTransactions() throws FileNotFoundException, JSONException {
        File file = new File(getClass().getClassLoader().getResource("tx_valid.json").getPath());
        assertTrue(file.exists());
        JSONArray all = new JSONArray(isToString(new FileInputStream(file)));
        String desc = "";
        for (int i = 0; i < all.length(); i++) {
            JSONArray line = all.getJSONArray(i);
            if (line.length() == 1) {
                desc = line.getString(0);
//                System.out.println(desc);
            } else if (line.length() == 3) {
                JSONArray inputsJson = line.getJSONArray(0);
                Transaction.Script[] unspentOutputsScripts = new Transaction.Script[inputsJson.length()];
                long[] amounts = new long[inputsJson.length()];
                for (int j = 0; j < inputsJson.length(); j++) {
                    JSONArray inputJson = inputsJson.getJSONArray(j);
                    String scriptStr = inputJson.getString(2);
                    if (inputJson.length() > 3) {
                        amounts[j] = inputJson.getLong(3);
                    }
                    unspentOutputsScripts[j] = new Transaction.Script(Transaction.Script.convertReadableStringToBytesCoreStyle(scriptStr));
                }
                String txStr = line.getString(1);
                Transaction tx = null;
                try {
                    tx = Transaction.decodeTransaction(BTCUtils.fromHex(txStr));
                } catch (Exception e) {
                    fail("decoding '" + desc + "' gives " + e);
                }
                int flags = parseScriptFlags(line.getString(2));
                try {
//                    for (int j = 0; j < tx.inputs.length; j++) {
//                        if (j < unspentOutputsScripts.length) {
//                            System.out.println("scriptPubKey: " + unspentOutputsScripts[j].toString());
//                        }
//                        System.out.println("scriptSig: " + tx.inputs[j].script.toString());
//                    }
                    BTCUtils.verify(unspentOutputsScripts, amounts, tx, flags);
                } catch (NotImplementedException ignored) {
                    System.out.println(ignored.toString());
                } catch (Transaction.Script.ScriptInvalidException e) {
                    e.printStackTrace();
                    fail(e.toString());
                }
            }
        }
    }

    public void testBitcoinCoreInvalidTransactions() throws FileNotFoundException, JSONException {
        File file = new File(getClass().getClassLoader().getResource("tx_invalid.json").getPath());
        assertTrue(file.exists());
        JSONArray all = new JSONArray(isToString(new FileInputStream(file)));
        String desc = "";
        for (int i = 0; i < all.length(); i++) {
            JSONArray line = all.getJSONArray(i);
            if (line.length() == 1) {
                desc = line.getString(0);
//                System.out.println(desc);
            } else if (line.length() == 3) {
                JSONArray inputsJson = line.getJSONArray(0);
                Transaction.Script[] unspentOutputsScripts = new Transaction.Script[inputsJson.length()];
                long[] amounts = new long[inputsJson.length()];
                for (int j = 0; j < inputsJson.length(); j++) {
                    JSONArray inputJson = inputsJson.getJSONArray(j);
                    String scriptStr = inputJson.getString(2);
                    if (inputJson.length() > 3) {
                        amounts[j] = inputJson.getLong(3);
                    }
                    unspentOutputsScripts[j] = new Transaction.Script(Transaction.Script.convertReadableStringToBytesCoreStyle(scriptStr));
                }
                String txStr = line.getString(1);
                Transaction tx = null;
                try {
                    tx = Transaction.decodeTransaction(BTCUtils.fromHex(txStr));
                } catch (Exception e) {
                    fail("decoding '" + desc + "' gives " + e);
                }
                try {
//                    for (int j = 0; j < tx.inputs.length; j++) {
//                        if (j < unspentOutputsScripts.length) {
//                            System.out.println("scriptPubKey: " + unspentOutputsScripts[j].toString());
//                        }
//                        System.out.println("scriptSig: " + tx.inputs[j].script.toString());
//                    }
                    int flags = parseScriptFlags(line.getString(2));
                    BTCUtils.verify(unspentOutputsScripts, amounts, tx, flags);
                    fail(desc);
                } catch (NotImplementedException ignored) {
                    System.out.println(ignored.toString());
                } catch (Transaction.Script.ScriptInvalidException ignored) {
                    //all TX in this test are expected to fail
                }
//                System.out.println();
            }
        }
    }

    public void testSighashes() throws FileNotFoundException, JSONException, BitcoinException {
        File file = new File(getClass().getClassLoader().getResource("sighash.json").getPath());
        assertTrue(file.exists());
        JSONArray all = new JSONArray(isToString(new FileInputStream(file)));
        for (int i = 0; i < all.length(); i++) {
            JSONArray line = all.getJSONArray(i);
            if (line.length() == 5) {
                Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex(line.getString(0)));
                byte[] scriptBytes = BTCUtils.fromHex(line.getString(1));
                Transaction.Script script = new Transaction.Script(scriptBytes);
                assertTrue(Arrays.equals(scriptBytes, script.bytes));
                int inputIndex = line.getInt(2);
                int hashType = line.getInt(3);
                if ((hashType & Transaction.Script.SIGHASH_FORKID) != Transaction.Script.SIGHASH_FORKID) {
                    byte[] expectedSigHash = BTCUtils.fromHex(line.getString(4));
                    byte[] actualSigHash = BTCUtils.reverse(Transaction.Script.hashTransaction(inputIndex, script.bytes, tx, hashType, -1, Transaction.Script.SIGVERSION_BASE));
                    assertTrue(Arrays.equals(expectedSigHash, actualSigHash));
                }
            }
        }
    }

    private int parseScriptFlags(String flagsStr) {
        String[] flagsStrArray = flagsStr.split(",");
        int flags = 0;
        for (String flagStr : flagsStrArray) {
            switch (flagStr) {
                case "NONE":
                    break;
                case "P2SH":
                    flags |= Transaction.Script.SCRIPT_VERIFY_P2SH;
                    break;
                case "STRICTENC":
                    flags |= Transaction.Script.SCRIPT_VERIFY_STRICTENC;
                    break;
                case "DERSIG":
                    flags |= Transaction.Script.SCRIPT_VERIFY_DERSIG;
                    break;
                case "LOW_S":
                    flags |= Transaction.Script.SCRIPT_VERIFY_LOW_S;
                    break;
                case "SIGPUSHONLY":
                    flags |= Transaction.Script.SCRIPT_VERIFY_SIGPUSHONLY;
                    break;
                case "WITNESS":
                    flags |= Transaction.Script.SCRIPT_VERIFY_WITNESS;
                    break;
                case "NULLDUMMY":
                case "CHECKLOCKTIMEVERIFY":
                case "CHECKSEQUENCEVERIFY":
                    break;
                case "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
                    flags |= Transaction.Script.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
                    break;
                case "NULLFAIL":
                    flags |= Transaction.Script.SCRIPT_VERIFY_NULLFAIL;
                    break;
                case "ENABLE_SIGHASH_FORKID":
                    flags |= Transaction.Script.SCRIPT_ENABLE_SIGHASH_FORKID;
                    break;
                default:
                    System.out.println("ignoring " + flagStr);
                    break;
            }
        }
        if ((flags & Transaction.Script.SCRIPT_VERIFY_CLEANSTACK) != 0) {
            flags |= Transaction.Script.SCRIPT_VERIFY_P2SH;
            flags |= Transaction.Script.SCRIPT_VERIFY_WITNESS;
        }
        return flags;
    }

    static String isToString(InputStream is) {
        Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }
}
