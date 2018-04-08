package ru.valle.btc;

import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.Arrays;

public final class BitcoinCashTest extends TestCase {
    /**
     * this is first example from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
     */
    public void testBip143Hash1() throws BitcoinException {
        Transaction unsignedTx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef" +
                "51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d59" +
                "88ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"));
        Transaction.Script spendScript = new Transaction.Script(BTCUtils.fromHex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"));
        byte[] sigHash = Transaction.Script.bip143Hash(1, unsignedTx, Transaction.Script.SIGHASH_ALL, spendScript.bytes,
                BTCUtils.parseValue("6"));
        assertTrue(Arrays.equals(BTCUtils.fromHex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"), sigHash));
    }

    public void testBip143Hash2() throws BitcoinException {
        Transaction unsignedTx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb" +
                "0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"));
        Transaction.Script spendScript = new Transaction.Script(BTCUtils.fromHex("76a91479091972186c449eb1ded22b78e40d009bdf008988ac"));
        byte[] sigHash = Transaction.Script.bip143Hash(0, unsignedTx, Transaction.Script.SIGHASH_ALL, spendScript.bytes,
                BTCUtils.parseValue("10"));
        assertTrue(Arrays.equals(BTCUtils.fromHex("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"), sigHash));
    }

    public void testBip143Hash3() throws BitcoinException {
        Transaction unsignedTx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf" +
                "020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000"));
        Transaction.Script spendScriptFirst = new Transaction.Script(BTCUtils.fromHex("21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"));
        byte[] sigHash2 = Transaction.Script.bip143Hash(1, unsignedTx, Transaction.Script.SIGHASH_SINGLE, spendScriptFirst.bytes,
                BTCUtils.parseValue("49"));
        assertTrue(Arrays.equals(BTCUtils.fromHex("82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"), sigHash2));

        Transaction.Script spendScriptSecond = new Transaction.Script(BTCUtils.fromHex("210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"));
        byte[] sigHash1 = Transaction.Script.bip143Hash(1, unsignedTx, Transaction.Script.SIGHASH_SINGLE, spendScriptSecond.bytes,
                BTCUtils.parseValue("49"));
        assertTrue(Arrays.equals(BTCUtils.fromHex("fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"), sigHash1));
    }

    public void testVerifyInitialTxGeneratedOnWebsite() throws BitcoinException, Transaction.Script.ScriptInvalidException {
        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("01000000012e43b5053e9d910148fde10afddb2e7ffa59b03325a94f5ed8e5f9ce21308a2f010000006b483045022100f2552628d46688abe440a2a85fd34e840c583ce4ab1c5247ce2545bd47867a5" +
                "90220077e24a37d0075c1423074edeb322435bb5eaf02c09eb40e90e0df116aacbe884121034d3b162e9bf2770e1bfa23f7c3442107c08f8a73cb1f76aec75dda9a901b9465ffffffff0200d2496b000000001976a91496a8ddbbaa7466a7d6a649538b3048cc" +
                "a39be78688ac8c80a9e7140000001976a9147670313b938c872172c3539c271fe80c88c4713d88ac00000000"));
        long amount = BTCUtils.parseValue("915.86091308");
        Transaction.Script scriptOfUnspentOutput = Transaction.Script.buildOutput("n3sRo1vqL9i6iAwMZg6HqvSVBZYB3ziKkK");
        BTCUtils.verify(new Transaction.Script[]{scriptOfUnspentOutput}, new long[]{amount}, tx, true);
    }

    public void testTransferFromATestNetToTestNetInitial() throws BitcoinException, Transaction.Script.ScriptInvalidException {
        KeyPair fromKeyPair = new KeyPair(BTCUtils.decodePrivateKey("93HEBZpKKh8e9LjgbNB1firTk66Z8H3Ub4XD16CbEQq3CZp21xB"), Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
//        https://www.blocktrail.com/tBCC/address/muFZwrVAx95bdx7hLSWE2p6kMJBnu5z9yY/transactions
        String hashOfPrevTransaction = "3a1ff428215a0972eeec78537cb161a18323120f52427dd823b2c1b58da9732a";
        String amountStr = "18.0";
        int indexOfOutputToSpend = 0;
        String outputAddress = "mymHGRN9LhQHqPLobnR1fkeHMzLbmN9rZV";
        String changeAddress = null;
        float satoshisPerVirtualByte = 10;

        long amount = BTCUtils.parseValue(amountStr);
        assertNotNull(fromKeyPair.address);
        Transaction.Script scriptOfUnspentOutput = Transaction.Script.buildOutput(fromKeyPair.address.addressString);
        ArrayList<UnspentOutputInfo> unspentOutputs = new ArrayList<>();
        unspentOutputs.add(new UnspentOutputInfo(fromKeyPair, BTCUtils.fromHex(hashOfPrevTransaction), scriptOfUnspentOutput, amount, indexOfOutputToSpend));
        @SuppressWarnings("ConstantConditions")
        Transaction tx = BTCUtils.createTransaction(unspentOutputs, outputAddress, changeAddress,
                (long) -1, satoshisPerVirtualByte, BTCUtils.TRANSACTION_TYPE_BITCOIN_CASH);
        assertNotNull(tx);
//        System.out.println(BTCUtils.toHex(tx.getBytes()));
        BTCUtils.verify(new Transaction.Script[]{scriptOfUnspentOutput}, new long[]{amount}, tx, true);
        //produced https://www.blocktrail.com/tBCC/tx/c2f5a38413d874ef6a64cd29357a2ec71d456b96c9d1b2191eb981ebe07e8dac
    }

    public void testPartialTransferByUsingRawTxFromBitcoinAbc() throws BitcoinException, Transaction.Script.ScriptInvalidException {
        KeyPair fromKeyPair = new KeyPair(BTCUtils.decodePrivateKey("93JNfPEf5srzF4S3KRvyJh4s5uV7GY2kPA2CwKzQRoAHPZHsFTQ"), Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
//        https://www.blocktrail.com/tBCC/address/mymHGRN9LhQHqPLobnR1fkeHMzLbmN9rZV/transactions
        long amountToTransfer = BTCUtils.parseValue("10");
        String outputAddress = "n1jtJPB5uVv4RE2PyWNRhECFWghRwRhzxh";
        String changeAddress = "mymHGRN9LhQHqPLobnR1fkeHMzLbmN9rZV";
        float satoshisPerVirtualByte = 10;
        //getrawtransaction "c2f5a38413d874ef6a64cd29357a2ec71d456b96c9d1b2191eb981ebe07e8dac"
        byte[] txWithUnspentOutputBytes = BTCUtils.fromHex("01000000012a73a98db5c1b223d87d42520f122383a161b17c5378ecee72095a2128f41f3a000000008b4830450221" +
                "00e0c97dc544fe4db5167e30097cb8ad9348fe0e596543689f40659580462a694f02205802237621047efa8c83390b242b1091e97cc2d610b2937dbd378645eaa94ce5414104da" +
                "1231a801647130b43275c6d3081a9872087a8c6fae6b42beebc9094590d95faed9b111b0e00a9fb76b0cf12363e9e61eebdd2bf0e113e08db4738b9ce0b104ffffffff01604b486b" +
                "000000001976a914c827ecaa0cc660e6180e750a8a5174dc1b23f6a288ac00000000");
        Transaction txWithUnspentOutput = Transaction.decodeTransaction(txWithUnspentOutputBytes);
        byte[] hashOfTxWithUnspentOutput = txWithUnspentOutput.hash();
        assertTrue(Arrays.equals(BTCUtils.fromHex("c2f5a38413d874ef6a64cd29357a2ec71d456b96c9d1b2191eb981ebe07e8dac"), hashOfTxWithUnspentOutput));
        int indexOfUnspentOutput = 0;
        Transaction.Script scriptOfUnspentOutput = txWithUnspentOutput.outputs[indexOfUnspentOutput].scriptPubKey;
        long amountInUnspentInput = txWithUnspentOutput.outputs[indexOfUnspentOutput].value;
        ArrayList<UnspentOutputInfo> unspentOutputs = new ArrayList<>();
        unspentOutputs.add(new UnspentOutputInfo(fromKeyPair, hashOfTxWithUnspentOutput, scriptOfUnspentOutput,
                amountInUnspentInput, indexOfUnspentOutput));
        Transaction tx = BTCUtils.createTransaction(unspentOutputs, outputAddress, changeAddress,
                amountToTransfer, satoshisPerVirtualByte, BTCUtils.TRANSACTION_TYPE_BITCOIN_CASH);
        assertNotNull(tx);
//        System.out.println(BTCUtils.toHex(tx.getBytes()));
        BTCUtils.verify(new Transaction.Script[]{scriptOfUnspentOutput}, new long[]{amountInUnspentInput}, tx, true);
        //produced https://www.blocktrail.com/tBCC/tx/d17655514c00067476deba9996c1e96fbdd320a2f64c3de12a9535091f5ae985

        //now send everything back to testnet faucet
        outputAddress = "mgRoeWs2CeCEuqQmNfhJjnpX8YvtPACmCX";
        //getrawtransaction "d17655514c00067476deba9996c1e96fbdd320a2f64c3de12a9535091f5ae985"
        txWithUnspentOutputBytes = BTCUtils.fromHex("0100000001ac8d7ee0eb81b91e19b2d1c9966b451dc72e7a3529cd646aef74d81384a3f5c2000000008a4730440" +
                "2200da8d7b354c89c0c05d789eb37ae92c9d6e416f6703bbdf73600368718465b5c0220239479c53fd7f0b8db48062bd81cfc8166359cb6eb387284b13d214e48465c1d41410494" +
                "da0dbfa5a36b413d81b24cceea4e8893736e7f4563d8ad7c498d4508ddc49742adc7eb9b9b5ed7963d3ab4e14df47983fe6063503b04a6b49f754c4d1ac5d6ffffffff0200ca9a3b" +
                "000000001976a914ddd496c1128a5db1dfb5d293178a19f03062385288acc0faab2f000000001976a914c827ecaa0cc660e6180e750a8a5174dc1b23f6a288ac00000000");
        txWithUnspentOutput = Transaction.decodeTransaction(txWithUnspentOutputBytes);
        //both outputs in this tx are unspent.
        //Index 0 belongs to n1jtJPB5uVv4RE2PyWNRhECFWghRwRhzxh (10)
        //Index 1 belongs to mymHGRN9LhQHqPLobnR1fkeHMzLbmN9rZV (7.998)
        hashOfTxWithUnspentOutput = txWithUnspentOutput.hash();
        unspentOutputs.clear();
        unspentOutputs.add(new UnspentOutputInfo(
                new KeyPair(BTCUtils.decodePrivateKey("cRXrvmftedJrnCo577rwAFcxf5kd5JENc8Sitn7bMXCfGi1EiQHT"), Address.PUBLIC_KEY_TO_ADDRESS_LEGACY),
                hashOfTxWithUnspentOutput,
                txWithUnspentOutput.outputs[0].scriptPubKey,
                txWithUnspentOutput.outputs[0].value, 0));
        unspentOutputs.add(new UnspentOutputInfo(
                new KeyPair(BTCUtils.decodePrivateKey("93JNfPEf5srzF4S3KRvyJh4s5uV7GY2kPA2CwKzQRoAHPZHsFTQ"), Address.PUBLIC_KEY_TO_ADDRESS_LEGACY),
                hashOfTxWithUnspentOutput,
                txWithUnspentOutput.outputs[1].scriptPubKey,
                txWithUnspentOutput.outputs[1].value, 1));
        //since there are 2 input addresses we need to use 2 key sets
        tx = BTCUtils.createTransaction(unspentOutputs, outputAddress, null,
                -1, satoshisPerVirtualByte, BTCUtils.TRANSACTION_TYPE_BITCOIN_CASH);
//        System.out.println(BTCUtils.toHex(tx.getBytes()));
//        https://www.blocktrail.com/tBCC/tx/93d44ec42e8a0b2476e12ac44c86991fe4df99621289ae2be74cec8cd272b853
        BTCUtils.verify(new Transaction.Script[]{unspentOutputs.get(0).scriptPubKey, unspentOutputs.get(1).scriptPubKey},
                new long[]{unspentOutputs.get(0).value, unspentOutputs.get(1).value},
                tx, true);
    }
}
