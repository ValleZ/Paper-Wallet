package ru.valle.btc;

import junit.framework.TestCase;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

public class SegWitTest extends TestCase {
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
                new BigInteger(1, privateKey), true), Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        assertNotNull(firstKeyPair.publicKey);
        Transaction.Script.writeBytes(firstKeyPair.publicKey, os);
        os.write(Transaction.Script.OP_CHECKSIG);
        os.close();
        byte[] scriptPubKeyFirst = os.toByteArray();
//        byte[] scriptPubKeyFirst = Transaction.Script.buildOutput(firstKeyPair.address).bytes; //this would be an ordinary P2PK
        assertTrue(Arrays.equals(BTCUtils.fromHex("2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"), scriptPubKeyFirst));

        //The second input comes from a P2WPKH witness program:
        privateKey = BTCUtils.fromHex("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
        KeyPair secondKeyPair = new KeyPair(new BTCUtils.PrivateKeyInfo(false, BTCUtils.PrivateKeyInfo.TYPE_WIF, null,
                new BigInteger(1, privateKey), true), Address.PUBLIC_KEY_TO_ADDRESS_P2WKH);
        assertNotNull(secondKeyPair.publicKey);
        byte[] scriptPubKeySecond = buildSegWitRedeemScriptFromPublicKey(secondKeyPair.publicKey);
        assertTrue(Arrays.equals(BTCUtils.fromHex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"), scriptPubKeySecond));

        //sigHash
        assertNotNull(secondKeyPair.address);
        byte[] sigHash = Transaction.Script.bip143Hash(1, tx, Transaction.Script.SIGHASH_ALL,
                Transaction.Script.buildOutput(Address.publicKeyToAddress(false, secondKeyPair.publicKey)).bytes, BTCUtils.parseValue("6"));
        assertTrue(Arrays.equals(BTCUtils.fromHex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"), sigHash));

        Transaction myTx = BTCUtils.sign(Arrays.asList(
                new UnspentOutputInfo(firstKeyPair, tx.inputs[0].outPoint.hash, new Transaction.Script(scriptPubKeyFirst), BTCUtils.parseValue("6.25"), 0),
                new UnspentOutputInfo(secondKeyPair, tx.inputs[1].outPoint.hash, new Transaction.Script(scriptPubKeySecond), BTCUtils.parseValue("6"), 1)),
                tx, BTCUtils.TRANSACTION_TYPE_SEGWIT);

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
                new BigInteger(1, privateKey), true), Address.PUBLIC_KEY_TO_ADDRESS_P2SH_P2WKH);
        assertTrue(Arrays.equals(BTCUtils.fromHex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"), keyPair.publicKey));
        assertNotNull(keyPair.publicKey);
        byte[] redeemScript = buildSegWitRedeemScriptFromPublicKey(keyPair.publicKey);
        assertTrue(Arrays.equals(BTCUtils.fromHex("001479091972186c449eb1ded22b78e40d009bdf0089"), redeemScript));
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(Transaction.Script.OP_HASH160);
        os.write(Transaction.Script.convertDataToScript(BTCUtils.sha256ripemd160(redeemScript)));
        os.write(Transaction.Script.OP_EQUAL);
        os.close();
        byte[] scriptPubKey = os.toByteArray();
        assertTrue(Arrays.equals(BTCUtils.fromHex("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"), scriptPubKey));
        long value = BTCUtils.parseValue("10");

        //sigHash
        assertNotNull(keyPair.address);
        byte[] sigHash = Transaction.Script.bip143Hash(0, tx, Transaction.Script.SIGHASH_ALL,
                Transaction.Script.buildOutput(Address.publicKeyToAddress(false, keyPair.publicKey)).bytes, value);
        assertTrue(Arrays.equals(BTCUtils.fromHex("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"), sigHash));

        Transaction myTx = BTCUtils.sign(Collections.singletonList(
                new UnspentOutputInfo(keyPair, tx.inputs[0].outPoint.hash, new Transaction.Script(scriptPubKey), value, 0)),
                tx, BTCUtils.TRANSACTION_TYPE_SEGWIT);

        //The serialized signed transaction is:
        Transaction signedTx = Transaction.decodeTransaction(BTCUtils.fromHex("01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a547701000000" +
                "1716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd2" +
                "70b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f646" +
                "77e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"));
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{value}, signedTx, false);

        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{value}, myTx, false);
    }

    private static byte[] buildSegWitRedeemScriptFromPublicKey(byte[] publicKey) {
        if (publicKey.length > 33) {
            throw new RuntimeException("Non compressed public key");
        }
        return new Transaction.Script.WitnessProgram(0, BTCUtils.sha256ripemd160(publicKey)).getBytes();
    }

    public void testVerifyInitialTxGeneratedOnWebsite() throws BitcoinException, Transaction.Script.ScriptInvalidException {
//        https://live.blockcypher.com/btc-testnet/tx/08f6a425a7305bf7ee32fa76ae93488573714c1aedc47a1aa3da4f170dc0dda8/
        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000000010186ddb9ffc155afd1dc4226e62e241bf6488cef2041adfa8226bc3893d788ffec0100000017160014b6bfc02" +
                "a1ae7918160dc9481d4a196ef0e4d16ebffffffff020095ba0a000000001976a91496a8ddbbaa7466a7d6a649538b3048cca39be78688ac93964f4a2c00000017a914a749afd2ef5ba36b5" +
                "89be4e8656acaa0dea305d9870247304402202d8322986663745b7f6bcf2c000f3e97996fed206acaca21d42ec0d4e5e8fcad0220624577a2b047d92b22834fe6e38d8f444112ee6d36" +
                "e0f960f728f57df73e03f9012103a025e5bb73fcc6d3cdc5d7126c87423945f2af4768e13a1cd212f1ee7f20938100000000"));

        KeyPair keyPair = new KeyPair(BTCUtils.decodePrivateKey("93HEBZpKKh8e9LjgbNB1firTk66Z8H3Ub4XD16CbEQq3CZp21xB"),
                Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
        assertNotNull(keyPair.address);
        byte[] scriptPubKey = Transaction.Script.buildOutput(keyPair.address.addressString).bytes;
        float feeSatByte = 10.5f;
        Transaction spendTx = BTCUtils.createTransaction(tx, 0, 300, "mymHGRN9LhQHqPLobnR1fkeHMzLbmN9rZV",
                null, -1, feeSatByte, keyPair, BTCUtils.TRANSACTION_TYPE_LEGACY);
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{tx.outputs[0].value}, spendTx, false);
//        System.out.println("Legacy tx " + BTCUtils.toHex(spendTx.getBytes())); https://live.blockcypher.com/btc-testnet/tx/9355e8eae1db4354e6fb677917547d7881080195e378b6126dc5a2afdad11e9e/

        Transaction spendTxSegWit = BTCUtils.createTransaction(tx, 0, 300, "mymHGRN9LhQHqPLobnR1fkeHMzLbmN9rZV",
                null, -1, feeSatByte, keyPair, BTCUtils.TRANSACTION_TYPE_SEGWIT);
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{tx.outputs[0].value}, spendTxSegWit, false);
    }

    public void testWitnessEncoding() throws BitcoinException {
//        https://live.blockcypher.com/btc-testnet/tx/08f6a425a7305bf7ee32fa76ae93488573714c1aedc47a1aa3da4f170dc0dda8/
        byte[] txActualBytes = BTCUtils.fromHex("0100000000010186ddb9ffc155afd1dc4226e62e241bf6488cef2041adfa8226bc3893d788ffec0100000017160014b6bfc02" +
                "a1ae7918160dc9481d4a196ef0e4d16ebffffffff020095ba0a000000001976a91496a8ddbbaa7466a7d6a649538b3048cca39be78688ac93964f4a2c00000017a914a749afd2ef5ba36b5" +
                "89be4e8656acaa0dea305d9870247304402202d8322986663745b7f6bcf2c000f3e97996fed206acaca21d42ec0d4e5e8fcad0220624577a2b047d92b22834fe6e38d8f444112ee6d36" +
                "e0f960f728f57df73e03f9012103a025e5bb73fcc6d3cdc5d7126c87423945f2af4768e13a1cd212f1ee7f20938100000000");
        Transaction tx = Transaction.decodeTransaction(txActualBytes);
        assertTrue(tx.scriptWitnesses.length > 0);
        assertTrue(Arrays.equals(txActualBytes, tx.getBytes()));
        assertFalse(Arrays.equals(txActualBytes, tx.getBytes(false)));
        assertTrue(Arrays.equals(BTCUtils.fromHex("08f6a425a7305bf7ee32fa76ae93488573714c1aedc47a1aa3da4f170dc0dda8"), tx.hash()));
    }

    public void testSendLegacyTxOnSegwitEngine() throws BitcoinException, Transaction.Script.ScriptInvalidException {
//        https://live.blockcypher.com/btc-testnet/tx/9355e8eae1db4354e6fb677917547d7881080195e378b6126dc5a2afdad11e9e/
        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000001a8ddc00d174fdaa31a7ac4ed1a4c7173854893ae76fa32eef75b30a725a4f60800000000" +
                "8a473044022048143298a9222b67caa932dab6cfff24f1c050cd5fd5c6ad3bc8ad21bea83b52022056383303db0724c61b51748310a32152f790dd728e46d7155d0b9a6ff1ab0329" +
                "014104da1231a801647130b43275c6d3081a9872087a8c6fae6b42beebc9094590d95faed9b111b0e00a9fb76b0cf12363e9e61eebdd2bf0e113e08db4738b9ce0b104ffffffff" +
                "01600eb90a000000001976a914c827ecaa0cc660e6180e750a8a5174dc1b23f6a288ac00000000"));

        KeyPair keyPair = new KeyPair(BTCUtils.decodePrivateKey("93JNfPEf5srzF4S3KRvyJh4s5uV7GY2kPA2CwKzQRoAHPZHsFTQ"),
                Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
        assertNotNull(keyPair.address);
        byte[] scriptPubKey = Transaction.Script.buildOutput(keyPair.address.addressString).bytes;
        float feeSatByte = 10;
        Transaction spendTxFromSegWit = BTCUtils.createTransaction(tx, 0, 1, "mvu7MENQXFHefNiE53DqpknFTs27EJ86hV",
                null, -1, feeSatByte, keyPair, BTCUtils.TRANSACTION_TYPE_LEGACY);
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{tx.outputs[0].value}, spendTxFromSegWit, false);
        //System.out.println("tx " + BTCUtils.toHex(spendTxSegWit.getBytes())); // https://live.blockcypher.com/btc-testnet/tx/91474762517c0766effdee122e8df77c11a6b28eb002898fb67af82e5a65d450
        //this one spent from segwit successfully but by using plain tx without witness as TRANSACTION_TYPE_SEGWIT says, same in test below
    }

    public void testSendToUncompressedPublicKeyAndSpendFromIt() throws BitcoinException, Transaction.Script.ScriptInvalidException {
//        https://live.blockcypher.com/btc-testnet/tx/91474762517c0766effdee122e8df77c11a6b28eb002898fb67af82e5a65d450/
        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("01000000019e1ed1daafa2c56d12b678e395010881787d54177967fbe65443dbe1eae8559300000000" +
                "8a47304402201122b3ed325a5fbfce50a517cd4dcb5dc0f59043cf9fbe41b18a94a2e3d0abc502206b48a905c495105cbc28043071645802b913966021533cd231dd8c603aff4" +
                "fb201410494da0dbfa5a36b413d81b24cceea4e8893736e7f4563d8ad7c498d4508ddc49742adc7eb9b9b5ed7963d3ab4e14df47983fe6063503b04a6b49f754c4d1ac5d6ffffffff" +
                "01b060b70a000000001976a914a8ba98b20803a8192728503e52b0c0f612d8ef3988ac00000000"));

        KeyPair keyPair = new KeyPair(BTCUtils.decodePrivateKey("cTybpRUiJkErJvFfiRTgK4yUnbLUhxnHqSsUveMF2HjGnPtzkJLZ"),
                Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
        assertNotNull(keyPair.address);
        byte[] scriptPubKey = Transaction.Script.buildOutput(keyPair.address.addressString).bytes;

        KeyPair firstUncompressedKeyPair = new KeyPair(BTCUtils.decodePrivateKeyAsSHA256("Not a secret private key", true),
                Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
        assertFalse(firstUncompressedKeyPair.privateKey.isPublicKeyCompressed);

        assertNotNull(firstUncompressedKeyPair.address);
        float feeSatByte = 10;
        Transaction spendTxSegWit = BTCUtils.createTransaction(tx, 0, 10, firstUncompressedKeyPair.address.addressString,
                null, -1, feeSatByte, keyPair, BTCUtils.TRANSACTION_TYPE_LEGACY);
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{tx.outputs[0].value}, spendTxSegWit, false);
//        System.out.println("SegWit tx " + BTCUtils.toHex(spendTxSegWit.getBytes())); // https://live.blockcypher.com/btc-testnet/tx/407fdb062fdfa9bee55c35fdc110ed6860b4f288e33dd676540f2c985385572a/

//        tx = spendTxSegWit;
        tx = Transaction.decodeTransaction(BTCUtils.fromHex("010000000150d4655a2ef87ab68f8902b08eb2a6117cf78d2e12eefdef66077c516247479100000000" +
                "6a47304402204d6d78a7de9ed38be6b91bf612b23bbad7f1f4f40add66d9f3d421fb3d7bbfd90220613647be5d20a07b624ea89a37ebe4f2e849b1d62295110700" +
                "80971eaf8a5d35012102c5d7b7f76179edf020806ec2d34f34575bfc05b103715691d2c519c264601cbaffffffff0100b3b50a000000001976a914d7f904bf1c64" +
                "60216761113b3e6ca9352002a58988ac00000000"));
        keyPair = firstUncompressedKeyPair;
        assertNotNull(keyPair.address);
        scriptPubKey = Transaction.Script.buildOutput(keyPair.address.addressString).bytes;
        KeyPair kp2 = new KeyPair(BTCUtils.decodePrivateKeyAsSHA256("Another one not a secret private key", true),
                Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
        assertNotNull(kp2.address);
        Transaction spendTxSegWit2 = BTCUtils.createTransaction(tx, 0, 1, kp2.address.addressString,
                null, -1, feeSatByte, keyPair, BTCUtils.TRANSACTION_TYPE_LEGACY);
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{tx.outputs[0].value}, spendTxSegWit2, false);
//        System.out.println("SegWit tx " + BTCUtils.toHex(spendTxSegWit2.getBytes())); //https://live.blockcypher.com/btc-testnet/tx/de54679cee8e511837048d28cd7231d04e1298f95801e9ed84cbce9e0081d957/
    }

    public void testLegacy2WitnessHashAndWitnessHash2WitnessHash() throws BitcoinException, Transaction.Script.ScriptInvalidException {
        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("01000000012a578553982c0f5476d63de388f2b46068ed10c1fd355ce5bea9df2f06db7f4000000000" +
                "8b483045022100fd9f73d3ea16191ad1b4df10155a2f9c0226e9ffe7c0e5e5958d4313afbe9ed502207ef66c2afe8b58662e3eb45e624b56e7f006cc3e89c8e3f9fe0c9f2d08fe" +
                "0cde0141047e2d56c335560438cb28987910a45993be0c3a24e9f4525757438363aca2dfedf4c45fa5ac53e554d789ba16561ea2c92e5c41b754d9b9b03106085dbf142c07" +
                "ffffffff015005b40a000000001976a9146301c758e3aa651353a7de63a27ba51e13fe086388ac00000000"));
        KeyPair keyPair = new KeyPair(BTCUtils.decodePrivateKeyAsSHA256("Another one not a secret private key", true),
                Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);

        KeyPair destKp = new KeyPair(BTCUtils.decodePrivateKey("cPy8rxTF6kHYPinYkNfZRbBqXpDmorJy3gNoHQ9bLg7KTRarHQWQ"),
                Address.PUBLIC_KEY_TO_ADDRESS_P2WKH);
        assertTrue(destKp.privateKey.isPublicKeyCompressed);
        assertNotNull(destKp.address);
        float feeSatByte = 10;
        Transaction spendTx = BTCUtils.createTransaction(tx, 0, 6, destKp.address.addressString,
                null, -1, feeSatByte, keyPair, BTCUtils.TRANSACTION_TYPE_SEGWIT);
        assertNotNull(spendTx.outputs[0].scriptPubKey.getWitnessProgram());

        byte[] scriptPubKey = tx.outputs[0].scriptPubKey.bytes;
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{tx.outputs[0].value}, spendTx, false);
//        System.out.println(BTCUtils.toHex(spendTx.getBytes(true)));

//https://live.blockcypher.com/btc-testnet/tx/af44ef1a76d6be977db26b6f486c71d1bd9def4df1419997be0c321e45492ed4/
//https://testnet.smartbit.com.au/tx/af44ef1a76d6be977db26b6f486c71d1bd9def4df1419997be0c321e45492ed4
//https://chain.so/tx/BTCTEST/af44ef1a76d6be977db26b6f486c71d1bd9def4df1419997be0c321e45492ed4
        //no explorer able to show receiving address. it should be https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
        //but 2Mvyu7Q8cQUvwGgHCA3RwiFBh3M7nKpVTjC is acceptable as well

        assertNotNull(destKp.publicKey);
        scriptPubKey = buildSegWitRedeemScriptFromPublicKey(destKp.publicKey);
        keyPair = destKp;
        tx = Transaction.decodeTransaction(BTCUtils.fromHex("010000000157d981009ececb84ede90158f998124ed03172cd288d043718518eee9c6754de00000000" +
                "8a47304402200846d6ada47cd8c129d0d2fb16f30c2f5e0b8b1e68cf07f380f039a019e190300220095485460632926ad5d23a799957a24ae31ee30bfb4f63d55ddf7a230fb" +
                "96dbf0141041c82851399bbe53ca321d5c729e055c1c9c57f0ad25801efadfa868b6e192d792a252dcd6ef2a63b183f81863aec0792a8c9a54685c44fc3a5ea8115905d25e8" +
                "ffffffff01a057b20a0000000016001428fa8176c5126a7c60be4ebe89dd08ef847262bb00000000"));
        destKp = new KeyPair(BTCUtils.decodePrivateKey("cUExLdTNa6n4DsN6wUwg22CcESf5CSf1tzYAtjj8eQHjpK7GboqR"),
                Address.PUBLIC_KEY_TO_ADDRESS_P2WKH);
        assertNotNull(destKp.address);
        spendTx = BTCUtils.createTransaction(tx, 0, 6, destKp.address.addressString,
                null, -1, feeSatByte, keyPair, BTCUtils.TRANSACTION_TYPE_SEGWIT);
        assertNotNull(spendTx.outputs[0].scriptPubKey.getWitnessProgram());
        assertTrue(spendTx.inputs[0].scriptSig.isNull());
        assertTrue(Arrays.equals(tx.outputs[0].scriptPubKey.bytes, scriptPubKey));
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{tx.outputs[0].value}, spendTx, false);
//        System.out.println(spendTx.toHexEncodedString()); //https://testnet.smartbit.com.au/tx/e69b41e3366e2b122ae8bcf1dc6e11864372641e2a930a2f30a9282938fa827a
    }
//
//    public void testFromWitnessHash2Legacy() throws BitcoinException {
//        Transaction tx = Transaction.decodeTransaction(BTCUtils.fromHex("01000000000101d42e49451e320cbe979941f14def9dbdd1716c486f6bb27d97bed6761aef44af0000000000ffffffff" +
//                "01f0a9b00a00000000160014b55ac734d2061d88d3474180c4751a3238254c0702483045022100a282eab722f15de8135803b01d6cbc48a10d0d7cea6237fff097acb244360eb9022001cdf319f" +
//                "aecccf57eb622926b45bf5add1e9532de77a4f3550c5830a04cfb50012102d9d3df7f13babab3d47ef2bdba675b6b29ec9bdc27f5ab442de534c372fad53200000000"));
//        KeyPair keyPair = new KeyPair(BTCUtils.decodePrivateKey("cUExLdTNa6n4DsN6wUwg22CcESf5CSf1tzYAtjj8eQHjpK7GboqR"), Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
//        KeyPair destKp = new KeyPair(BTCUtils.decodePrivateKey("cQgi28ToiCcp4ehbWfZhAToog6783fZWy5bTnSUDFm9ePWC48RPH"), Address.PUBLIC_KEY_TO_ADDRESS_LEGACY);
//
//        assertNotNull(destKp.address);
////        Transaction spendTx = BTCUtils.createTransaction(tx, 0, 6, destKp.address.addressString,
////                null, -1, BTCUtils.parseValue("0.001"), keyPair, BTCUtils.TRANSACTION_TYPE_SEGWIT);
////        System.out.println(spendTx.toHexEncodedString()); //https://testnet.smartbit.com.au/tx/1a5d938c5c610d2be40e850915993853a4c71abce7473bf92608522d38f43b80
//    }

    public void testGenerateSegWitP2shAddress() {
        byte[] decodedAddress = BTCUtils.decodeBase58("1Ek9S3QNnutPV7GhtzR8Lr8yKPhxnUP8iw");
        byte[] addressHash = new byte[20];
        System.arraycopy(decodedAddress, 1, addressHash, 0, addressHash.length);
        byte[] pubKeyScript = new Transaction.Script.WitnessProgram(0, addressHash).getBytes();
        String segwitAddress = Address.ripemd160HashToP2shAddress(false, BTCUtils.sha256ripemd160(pubKeyScript));
        assertEquals("36ghjA1KSAB1jDYD2RdiexEcY7r6XjmDQk", segwitAddress);
    }

    public void testSendToAndFromP2sh() throws BitcoinException, Transaction.Script.ScriptInvalidException {
        KeyPair keyPair, destKp;
        Transaction tx, spendTx;
        byte[] scriptPubKey;

        destKp = new KeyPair(BTCUtils.decodePrivateKey("cTbkZ1hyxJZPEn8gb7kMbXkYwFksnG7K896N7mGhcCB5J1McQJiM"), Address.PUBLIC_KEY_TO_ADDRESS_P2SH_P2WKH);
        keyPair = new KeyPair(BTCUtils.decodePrivateKey("cQgi28ToiCcp4ehbWfZhAToog6783fZWy5bTnSUDFm9ePWC48RPH"), Address.PUBLIC_KEY_TO_ADDRESS_P2SH_P2WKH);
        tx = Transaction.decodeTransaction(BTCUtils.fromHex("0100000000010144045bb1612f7619020cbca7356ea6ea04fd9300e5584a821104f377738c680b0100000017160014ad3f3cf0875d21bcad0a4f2a54b39f62076af84bffffffff" +
                "020095ba0a000000001976a914f29381fcca48a35c271e636c7ce5a54bbae947ab88ac3f0bca1f1100000017a914e70d68b3d283cc122664ab23f0698558fc7c219b8702483045022100a9041ac02608153c0e215dfdb8d2939d91e7d00d3e" +
                "5c7c4ec318773170b4e10f02207fa86ffbaeb734bafb5e26404de0288dd74d850fd4d713fa0205e75dd42ac7c90121027d2463df7bc0cbb9462428a12d7d8f95f674207a05bb0a109486a996b57daea600000000"));
        assertNotNull(destKp);
        assertNotNull(destKp.publicKey);
        String outputAddress = Address.publicKeyToP2shP2wkhAddress(destKp.privateKey.testNet, destKp.publicKey);
        assertNotNull(destKp.address);
        assertEquals(outputAddress, destKp.address.addressString);
        spendTx = BTCUtils.createTransaction(tx, 0, 6, outputAddress,
                null, -1, 0, keyPair, BTCUtils.TRANSACTION_TYPE_SEGWIT);
        scriptPubKey = tx.outputs[0].scriptPubKey.bytes;
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{tx.outputs[0].value}, spendTx, false);
//        System.out.println(spendTx.toHexEncodedString());
        assertEquals(outputAddress, spendTx.outputs[0].getP2shAddress(true));

        keyPair = destKp;

        tx = spendTx;
        destKp = new KeyPair(BTCUtils.decodePrivateKey("cMdg8k9nX8bhxP2r6cBojzbi3KtpszP1QZkcYcMeDFqpK54NNkuy"), Address.PUBLIC_KEY_TO_ADDRESS_P2SH_P2WKH);
        assertNotNull(destKp.publicKey);
        outputAddress = Address.publicKeyToP2shP2wkhAddress(destKp.privateKey.testNet, destKp.publicKey);
        assertNotNull(destKp.address);
        assertEquals(outputAddress, destKp.address.addressString);
        assertEquals("2MxhmrTPgPG4b4Yx8URH95E1RGmjihnTTYV", outputAddress);
        spendTx = BTCUtils.createTransaction(tx, 0, 6, outputAddress,
                null, -1, 0, keyPair, BTCUtils.TRANSACTION_TYPE_SEGWIT);
        scriptPubKey = tx.outputs[0].scriptPubKey.bytes;
        BTCUtils.verify(new Transaction.Script[]{new Transaction.Script(scriptPubKey)}, new long[]{tx.outputs[0].value}, spendTx, false);
//        System.out.println(spendTx.toHexEncodedString());
        assertEquals(outputAddress, spendTx.outputs[0].getP2shAddress(true));
        //807d661dd32b3d8557c798b72c6e50eee0f410f62d219c0a9f3099d2aed72052
        //683afbfadc7f5fdc5fcca447c0f418758dd7b3117ff442961673fad56b727bdb
    }
}
