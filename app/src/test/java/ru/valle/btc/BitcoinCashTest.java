package ru.valle.btc;

import junit.framework.TestCase;

import java.util.Arrays;

public final class BitcoinCashTest extends TestCase {
    /**
     * this is first example from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
     */
    public void testBip143Hash1() throws BitcoinException {
        Transaction unsignedTx = new Transaction(BTCUtils.fromHex("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef" +
                "51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d59" +
                "88ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"));
        Transaction.Script spendScript = new Transaction.Script(BTCUtils.fromHex("1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"));
        byte[] sigHash = Transaction.Script.bip143Hash(1, unsignedTx, Transaction.Script.SIGHASH_ALL, spendScript.bytes,
                BTCUtils.parseValue("6"));
        assertTrue(Arrays.equals(BTCUtils.fromHex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"), sigHash));
    }

    public void testBip143Hash2() throws BitcoinException {
        Transaction unsignedTx = new Transaction(BTCUtils.fromHex("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb" +
                "0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"));
        Transaction.Script spendScript = new Transaction.Script(BTCUtils.fromHex("1976a91479091972186c449eb1ded22b78e40d009bdf008988ac"));
        byte[] sigHash = Transaction.Script.bip143Hash(0, unsignedTx, Transaction.Script.SIGHASH_ALL, spendScript.bytes,
                BTCUtils.parseValue("10"));
        assertTrue(Arrays.equals(BTCUtils.fromHex("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"), sigHash));
    }

    public void testBip143Hash3() throws BitcoinException {
        Transaction unsignedTx = new Transaction(BTCUtils.fromHex("0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf" +
                "020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000"));
        Transaction.Script spendScriptFirst = new Transaction.Script(BTCUtils.fromHex("4721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"));
        byte[] sigHash2 = Transaction.Script.bip143Hash(1, unsignedTx, Transaction.Script.SIGHASH_SINGLE, spendScriptFirst.bytes,
                BTCUtils.parseValue("49"));
        assertTrue(Arrays.equals(BTCUtils.fromHex("82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"), sigHash2));

        Transaction.Script spendScriptSecond = new Transaction.Script(BTCUtils.fromHex("23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"));
        byte[] sigHash1 = Transaction.Script.bip143Hash(1, unsignedTx, Transaction.Script.SIGHASH_SINGLE, spendScriptSecond.bytes,
                BTCUtils.parseValue("49"));
        assertTrue(Arrays.equals(BTCUtils.fromHex("fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"), sigHash1));
    }
}
