package ru.valle.btc;

import junit.framework.TestCase;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

import static ru.valle.btc.Transaction.Script.OP_CHECKSIG;

public class BitcoinTest extends TestCase {
    public void testSimpleWitnessTxParsing() throws BitcoinException {
        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000003362c10b042d48378b428d60c5c98d8b8aca7a03e1a2ca1048bfd469934bbda95010000008b483045022046c8bc9fb0e063e2" +
                "fc8c6b1084afe6370461c16cbf67987d97df87827917d42d022100c807fa0ab95945a6e74c59838cc5f9e850714d8850cec4db1e7f3bcf71d5f5ef0141044450af01b4cc0d45207bddfb47911744d01f768d23686e" +
                "9ac784162a5b3a15bc01e6653310bdd695d8c35d22e9bb457563f8de116ecafea27a0ec831e4a3e9feffffffffc19529a54ae15c67526cc5e20e535973c2d56ef35ff51bace5444388331c4813000000008b483045" +
                "02201738185959373f04cc73dbbb1d061623d51dc40aac0220df56dabb9b80b72f49022100a7f76bde06369917c214ee2179e583fefb63c95bf876eb54d05dfdf0721ed772014104e6aa2cf108e1c650e12d8dd7ec0" +
                "a36e478dad5a5d180585d25c30eb7c88c3df0c6f5fd41b3e70b019b777abd02d319bf724de184001b3d014cb740cb83ed21a6ffffffffbaae89b5d2e3ca78fd3f13cf0058784e7c089fb56e1e596d70adcfa486603967" +
                "010000008b483045022055efbaddb4c67c1f1a46464c8f770aab03d6b513779ad48735d16d4c5b9907c2022100f469d50a5e5556fc2c932645f6927ac416aa65bc83d58b888b82c3220e1f0b73014104194b3f8aa08b9" +
                "6cae19b14bd6c32a92364bea3051cb9f018b03e3f09a57208ff058f4b41ebf96b9911066aef3be22391ac59175257af0984d1432acb8f2aefcaffffffff0340420f00000000001976a914c0fbb13eb10b57daa78b47660" +
                "a4ffb79c29e2e6b88ac204e0000000000001976a9142cae94ffdc05f8214ccb2b697861c9c07e3948ee88ac1c2e0100000000001976a9146e03561cd4d6033456cc9036d409d2bf82721e9888ac00000000"));
        assertEquals(3, tx.outputs.length);
        assertEquals(3, tx.inputs.length);
        assertFalse(tx.scriptWitnesses.length > 0);
    }

    public void testBip143WitnessHash() throws BitcoinException {
        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000000010213206299feb17742091c3cb2ab45faa3aa87922d3c030cafb3f798850a2722bf0000000000feffffffa12f2424b9599898a1d30f0" +
                "6e1ce55eba7fabfeee82ae9356f07375806632ff3010000006b483045022100fcc8cf3014248e1a0d6dcddf03e80f7e591605ad0dbace27d2c0d87274f8cd66022053fcfff64f35f22a14deb657ac57f110084fb07bb917c3b" +
                "42e7d033c54c7717b012102b9e4dcc33c9cc9cb5f42b96dddb3b475b067f3e21125f79e10c853e5ca8fba31feffffff02206f9800000000001976a9144841b9874d913c430048c78a7b18baebdbea440588ac80969800000000" +
                "00160014e4873ef43eac347471dd94bc899c51b395a509a502483045022100dd8250f8b5c2035d8feefae530b10862a63030590a851183cb61b3672eb4f26e022057fe7bc8593f05416c185d829b574290fb8706423451ebd0a" +
                "0ae50c276b87b43012102179862f40b85fa43487500f1d6b13c864b5eb0a83999738db0f7a6b91b2ec64f00db080000"));
        byte[] hash = Transaction.Script.bip143Hash(0, tx, Transaction.Script.SIGHASH_ALL, BTCUtils.fromHex("76a914e4873ef43eac347471dd94bc899c51b395a509a588ac"), 10000000);
        assertTrue(Arrays.equals(BTCUtils.fromHex("36c6483c901d82f55a6557b5060653036f3ba96cd8c55ddb0f204c9e1fbd5b15"), BTCUtils.reverseInPlace(hash)));
    }

    public void testVerifySegWitBip143ByCheckingSignedTxFromSampleNativeP2wpkh() throws BitcoinException, Transaction.Script.ScriptInvalidException, IOException {
        //The following is an unsigned transaction:
        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa8" +
                "9e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"));
        assertEquals(1, tx.version);
        assertEquals(2, tx.inputs.length);
        assertTrue(Arrays.equals(BTCUtils.fromHex("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"), BTCUtils.reverse(tx.inputs[0].outPoint.hash)));
        assertEquals(0, tx.inputs[0].scriptSig.bytes.length);
        assertEquals(0xffffffee, tx.inputs[0].sequence);
        assertTrue(Arrays.equals(BTCUtils.fromHex("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"), BTCUtils.reverse(tx.inputs[1].outPoint.hash)));
        assertEquals(0, tx.inputs[1].scriptSig.bytes.length);
        assertEquals(0xffffffff, tx.inputs[1].sequence);
        assertEquals(0x11, tx.lockTime);

        //The first input comes from an ordinary P2PK: (VK: it is not an ordinary P2PK, it's simplified version of P2PK, named just "Pubkey")
        byte[] privateKey = BTCUtils.fromHex("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
        KeyPair firstKeyPair = new KeyPair(new BTCUtils.PrivateKeyInfo(false, BTCUtils.PrivateKeyInfo.TYPE_WIF, null,
                new BigInteger(1, privateKey), true));
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        Transaction.Script.writeBytes(firstKeyPair.publicKey, os);
        os.write(OP_CHECKSIG);
        os.close();
        byte[] scriptPubKeyFirst = os.toByteArray();
//        byte[] scriptPubKeyFirst = Transaction.Script.buildOutput(firstKeyPair.address).bytes; //this would be an ordinary P2PK
        assertTrue(Arrays.equals(BTCUtils.fromHex("2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"), scriptPubKeyFirst));

        //The second input comes from a P2WPKH witness program:
        privateKey = BTCUtils.fromHex("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
        KeyPair secondKeyPair = new KeyPair(new BTCUtils.PrivateKeyInfo(false, BTCUtils.PrivateKeyInfo.TYPE_WIF, null,
                new BigInteger(1, privateKey), true));
        os = new ByteArrayOutputStream();
        os.write(0); //witness version
        Transaction.Script.writeBytes(BTCUtils.sha256ripemd160(secondKeyPair.publicKey), os);
        os.close();
        byte[] scriptPubKeySecond = os.toByteArray();
        assertTrue(Arrays.equals(BTCUtils.fromHex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"), scriptPubKeySecond));

        //sigHash
        byte[] sigHash = Transaction.Script.bip143Hash(1, tx, Transaction.Script.SIGHASH_ALL,
                Transaction.Script.buildOutput(secondKeyPair.address).bytes, BTCUtils.parseValue("6"));
        assertTrue(Arrays.equals(BTCUtils.fromHex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"), sigHash));

        Transaction myTx = BTCUtils.sign(Arrays.asList(
                new UnspentOutputInfo(firstKeyPair, tx.inputs[0].outPoint.hash, new Transaction.Script(scriptPubKeyFirst), BTCUtils.parseValue("6.25"), 0, 100),
                new UnspentOutputInfo(secondKeyPair, tx.inputs[1].outPoint.hash, new Transaction.Script(scriptPubKeySecond), BTCUtils.parseValue("6"), 1, 100)),
                tx, false, Transaction.Script.SIGVERSION_WITNESS_V0);

        //The serialized signed transaction is:
        Transaction signedTx = Transaction.decodeTransaction(BTCUtils.fromHex("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02" +
                "742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000" +
                "ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b454" +
                "2f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"));
        BTCUtils.verify(
                new Transaction.Script[]{new Transaction.Script(scriptPubKeyFirst), new Transaction.Script(scriptPubKeySecond)},
                new long[]{BTCUtils.parseValue("6.25"), BTCUtils.parseValue("6")},
                signedTx,
                false);

        BTCUtils.verify(
                new Transaction.Script[]{new Transaction.Script(scriptPubKeyFirst), new Transaction.Script(scriptPubKeySecond)},
                new long[]{BTCUtils.parseValue("6.25"), BTCUtils.parseValue("6")},
                myTx,
                false);
    }

    public void testVerifySegWitBip143ByCheckingSignedTxFromSampleP2shP2wpkh() throws BitcoinException, Transaction.Script.ScriptInvalidException, IOException {
        //The following is an unsigned transaction:
        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b" +
                "000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"));
        assertEquals(1, tx.version);
        assertEquals(1, tx.inputs.length);
        assertTrue(Arrays.equals(BTCUtils.fromHex("db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477"), BTCUtils.reverse(tx.inputs[0].outPoint.hash)));
        assertEquals(0, tx.inputs[0].scriptSig.bytes.length);
        assertEquals(0xfffffffe, tx.inputs[0].sequence);
        assertEquals(0x0492, tx.lockTime);
        assertEquals(2, tx.outputs.length);

        //The input comes from a P2SH-P2WPKH witness program:
        byte[] privateKey = BTCUtils.fromHex("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf");
        KeyPair keyPair = new KeyPair(new BTCUtils.PrivateKeyInfo(false, BTCUtils.PrivateKeyInfo.TYPE_WIF, null,
                new BigInteger(1, privateKey), true));
        assertTrue(Arrays.equals(BTCUtils.fromHex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"), keyPair.publicKey));
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(0); //witness version
        Transaction.Script.writeBytes(BTCUtils.sha256ripemd160(keyPair.publicKey), os);
        os.close();
        byte[] redeemScript = os.toByteArray();
        assertTrue(Arrays.equals(BTCUtils.fromHex("001479091972186c449eb1ded22b78e40d009bdf0089"), redeemScript));
        os = new ByteArrayOutputStream();
        os.write(Transaction.Script.OP_HASH160);
        os.write(Transaction.Script.convertDataToScript(BTCUtils.sha256ripemd160(redeemScript)));
        os.write(Transaction.Script.OP_EQUAL);
        os.close();
        byte[] scriptPubKey = os.toByteArray();
        assertTrue(Arrays.equals(BTCUtils.fromHex("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"), scriptPubKey));
        long value = BTCUtils.parseValue("10");

        //sigHash
        byte[] sigHash = Transaction.Script.bip143Hash(0, tx, Transaction.Script.SIGHASH_ALL, Transaction.Script.buildOutput(keyPair.address).bytes, value);
        assertTrue(Arrays.equals(BTCUtils.fromHex("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"), sigHash));

        Transaction myTx = BTCUtils.sign(Collections.singletonList(
                new UnspentOutputInfo(keyPair, tx.inputs[0].outPoint.hash, new Transaction.Script(scriptPubKey), value, 0, 100)),
                tx, false, Transaction.Script.SIGVERSION_WITNESS_V0);


        //The serialized signed transaction is:
        Transaction signedTx = Transaction.decodeTransaction(BTCUtils.fromHex("01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a547701000000" +
                "1716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd2" +
                "70b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f646" +
                "77e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"));
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{value}, signedTx, false);

        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{value}, myTx, false);
    }

    public void testVerifyInitialTxGeneratedOnWebsite() throws BitcoinException, Transaction.Script.ScriptInvalidException {
        //https://live.blockcypher.com/btc-testnet/tx/08f6a425a7305bf7ee32fa76ae93488573714c1aedc47a1aa3da4f170dc0dda8/
//        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000000010186ddb9ffc155afd1dc4226e62e241bf6488cef2041adfa8226bc3893d788ffec0100000017160014b6bfc02" +
//                "a1ae7918160dc9481d4a196ef0e4d16ebffffffff020095ba0a000000001976a91496a8ddbbaa7466a7d6a649538b3048cca39be78688ac93964f4a2c00000017a914a749afd2ef5ba36b5" +
//                "89be4e8656acaa0dea305d9870247304402202d8322986663745b7f6bcf2c000f3e97996fed206acaca21d42ec0d4e5e8fcad0220624577a2b047d92b22834fe6e38d8f444112ee6d36" +
//                "e0f960f728f57df73e03f9012103a025e5bb73fcc6d3cdc5d7126c87423945f2af4768e13a1cd212f1ee7f20938100000000"));
//        long amount = BTCUtils.parseValue("1904.05290899");
    }
//
//    public void testTransferFromATestNetToTestNetInitial() throws BitcoinException, Transaction.Script.ScriptInvalidException {
//        KeyPair fromKeyPair = new KeyPair(BTCUtils.decodePrivateKey("93HEBZpKKh8e9LjgbNB1firTk66Z8H3Ub4XD16CbEQq3CZp21xB"));
////        https://www.blocktrail.com/tBCC/address/muFZwrVAx95bdx7hLSWE2p6kMJBnu5z9yY/transactions
//        String hashOfPrevTransaction = "3a1ff428215a0972eeec78537cb161a18323120f52427dd823b2c1b58da9732a";
//        String amountStr = "18.0";
//        int indexOfOutputToSpend = 0;
//        int confirmations = 300;
//        String outputAddress = "mymHGRN9LhQHqPLobnR1fkeHMzLbmN9rZV";
//        String changeAddress = null;
//        String extraFee = "0.0010";
//
//        long amount = BTCUtils.parseValue(amountStr);
//        Transaction.Script scriptOfUnspentOutput = Transaction.Script.buildOutput(fromKeyPair.address); //assume it's standard script
//        ArrayList<UnspentOutputInfo> unspentOutputs = new ArrayList<>();
//        unspentOutputs.add(new UnspentOutputInfo(fromKeyPair, BTCUtils.fromHex(hashOfPrevTransaction), scriptOfUnspentOutput, amount, indexOfOutputToSpend, (long) confirmations));
//        @SuppressWarnings("ConstantConditions")
//        Transaction tx = BTCUtils.createTransaction(unspentOutputs, outputAddress, changeAddress,
//                (long) -1, BTCUtils.parseValue(extraFee), true);
//        assertNotNull(tx);
////        System.out.println(BTCUtils.toHex(tx.getBytes()));
//        BTCUtils.verify(new Transaction.Script[]{scriptOfUnspentOutput}, new long[]{amount}, tx, true);
//        //produced https://www.blocktrail.com/tBCC/tx/c2f5a38413d874ef6a64cd29357a2ec71d456b96c9d1b2191eb981ebe07e8dac
//    }
//
//    public void testPartialTransferByUsingRawTxFromBitcoinAbc() throws BitcoinException, Transaction.Script.ScriptInvalidException {
//        KeyPair fromKeyPair = new KeyPair(BTCUtils.decodePrivateKey("93JNfPEf5srzF4S3KRvyJh4s5uV7GY2kPA2CwKzQRoAHPZHsFTQ"));
////        https://www.blocktrail.com/tBCC/address/mymHGRN9LhQHqPLobnR1fkeHMzLbmN9rZV/transactions
//        long amountToTransfer = BTCUtils.parseValue("10");
//        int confirmations = 300;
//        String outputAddress = "n1jtJPB5uVv4RE2PyWNRhECFWghRwRhzxh";
//        String changeAddress = "mymHGRN9LhQHqPLobnR1fkeHMzLbmN9rZV";
//        String extraFee = "0.0010";
//        //getrawtransaction "c2f5a38413d874ef6a64cd29357a2ec71d456b96c9d1b2191eb981ebe07e8dac"
//        byte[] txWithUnspentOutputBytes = BTCUtils.fromHex("01000000012a73a98db5c1b223d87d42520f122383a161b17c5378ecee72095a2128f41f3a000000008b4830450221" +
//                "00e0c97dc544fe4db5167e30097cb8ad9348fe0e596543689f40659580462a694f02205802237621047efa8c83390b242b1091e97cc2d610b2937dbd378645eaa94ce5414104da" +
//                "1231a801647130b43275c6d3081a9872087a8c6fae6b42beebc9094590d95faed9b111b0e00a9fb76b0cf12363e9e61eebdd2bf0e113e08db4738b9ce0b104ffffffff01604b486b" +
//                "000000001976a914c827ecaa0cc660e6180e750a8a5174dc1b23f6a288ac00000000");
//        Transaction txWithUnspentOutput = Transaction.decodeTransaction(txWithUnspentOutputBytes);
//        byte[] hashOfTxWithUnspentOutput = BTCUtils.reverseInPlace(BTCUtils.doubleSha256(txWithUnspentOutput.getBytes()));
//        assertTrue(Arrays.equals(BTCUtils.fromHex("c2f5a38413d874ef6a64cd29357a2ec71d456b96c9d1b2191eb981ebe07e8dac"), hashOfTxWithUnspentOutput));
//        int indexOfUnspentOutput = 0;
//        Transaction.Script scriptOfUnspentOutput = txWithUnspentOutput.outputs[indexOfUnspentOutput].script;
//        long amountInUnspentInput = txWithUnspentOutput.outputs[indexOfUnspentOutput].value;
//        ArrayList<UnspentOutputInfo> unspentOutputs = new ArrayList<>();
//        unspentOutputs.add(new UnspentOutputInfo(fromKeyPair, hashOfTxWithUnspentOutput, scriptOfUnspentOutput,
//                amountInUnspentInput, indexOfUnspentOutput, (long) confirmations));
//        Transaction tx = BTCUtils.createTransaction(unspentOutputs, outputAddress, changeAddress,
//                amountToTransfer, BTCUtils.parseValue(extraFee), true);
//        assertNotNull(tx);
////        System.out.println(BTCUtils.toHex(tx.getBytes()));
//        BTCUtils.verify(new Transaction.Script[]{scriptOfUnspentOutput}, new long[]{amountInUnspentInput}, tx, true);
//        //produced https://www.blocktrail.com/tBCC/tx/d17655514c00067476deba9996c1e96fbdd320a2f64c3de12a9535091f5ae985
//
//        //now send everything back to testnet faucet
//        outputAddress = "mgRoeWs2CeCEuqQmNfhJjnpX8YvtPACmCX";
//        //getrawtransaction "d17655514c00067476deba9996c1e96fbdd320a2f64c3de12a9535091f5ae985"
//        txWithUnspentOutputBytes = BTCUtils.fromHex("0100000001ac8d7ee0eb81b91e19b2d1c9966b451dc72e7a3529cd646aef74d81384a3f5c2000000008a4730440" +
//                "2200da8d7b354c89c0c05d789eb37ae92c9d6e416f6703bbdf73600368718465b5c0220239479c53fd7f0b8db48062bd81cfc8166359cb6eb387284b13d214e48465c1d41410494" +
//                "da0dbfa5a36b413d81b24cceea4e8893736e7f4563d8ad7c498d4508ddc49742adc7eb9b9b5ed7963d3ab4e14df47983fe6063503b04a6b49f754c4d1ac5d6ffffffff0200ca9a3b" +
//                "000000001976a914ddd496c1128a5db1dfb5d293178a19f03062385288acc0faab2f000000001976a914c827ecaa0cc660e6180e750a8a5174dc1b23f6a288ac00000000");
//        txWithUnspentOutput = Transaction.decodeTransaction(txWithUnspentOutputBytes);
//        //both outputs in this tx are unspent.
//        //Index 0 belongs to n1jtJPB5uVv4RE2PyWNRhECFWghRwRhzxh (10)
//        //Index 1 belongs to mymHGRN9LhQHqPLobnR1fkeHMzLbmN9rZV (7.998)
//        hashOfTxWithUnspentOutput = BTCUtils.reverseInPlace(BTCUtils.doubleSha256(txWithUnspentOutput.getBytes()));
//        unspentOutputs.clear();
//        unspentOutputs.add(new UnspentOutputInfo(
//                new KeyPair(BTCUtils.decodePrivateKey("cRXrvmftedJrnCo577rwAFcxf5kd5JENc8Sitn7bMXCfGi1EiQHT")),
//                hashOfTxWithUnspentOutput,
//                txWithUnspentOutput.outputs[0].script,
//                txWithUnspentOutput.outputs[0].value, 0, 6));
//        unspentOutputs.add(new UnspentOutputInfo(
//                new KeyPair(BTCUtils.decodePrivateKey("93JNfPEf5srzF4S3KRvyJh4s5uV7GY2kPA2CwKzQRoAHPZHsFTQ")),
//                hashOfTxWithUnspentOutput,
//                txWithUnspentOutput.outputs[1].script,
//                txWithUnspentOutput.outputs[1].value, 1, 6));
//        //since there are 2 input addresses we need to use 2 key sets
//        tx = BTCUtils.createTransaction(unspentOutputs, outputAddress, null,-1, BTCUtils.parseValue(extraFee), true);
////        System.out.println(BTCUtils.toHex(tx.getBytes()));
////        https://www.blocktrail.com/tBCC/tx/93d44ec42e8a0b2476e12ac44c86991fe4df99621289ae2be74cec8cd272b853
//        BTCUtils.verify(new Transaction.Script[]{unspentOutputs.get(0).script, unspentOutputs.get(1).script},
//                new long[]{unspentOutputs.get(0).value, unspentOutputs.get(1).value},
//                tx, true);
//    }

}
