/*
 The MIT License (MIT)

 Copyright (c) 2013-2018 Valentin Konovalov

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
import android.support.annotation.Nullable;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;
import java.util.Stack;

@SuppressWarnings("WeakerAccess")
public final class Transaction {
    public final int version;
    public final Input[] inputs;
    public final Output[] outputs;
    public final byte[][][] scriptWitnesses;
    public final int lockTime;

    public static Transaction decodeTransaction(byte[] rawBytes) throws BitcoinException {
        try {
            return new Transaction(rawBytes, true);
        } catch (BitcoinException e) {
            if (e.errorCode == BitcoinException.ERR_WRONG_TYPE) {
                return new Transaction(rawBytes, false);
            }
            throw e;
        }
    }

    /**
     * Decodes transaction w/o BIP144 witness data
     */
    public Transaction(byte[] rawBytes) throws BitcoinException {
        this(rawBytes, false);
    }

    public Transaction(byte[] rawBytes, boolean withWitness) throws BitcoinException {
        if (rawBytes == null) {
            throw new BitcoinException(BitcoinException.ERR_NO_INPUT, "empty input");
        }
        BitcoinInputStream bais = null;
        try {
            bais = new BitcoinInputStream(rawBytes);
            version = bais.readInt32();
            if (withWitness) {
                if (bais.readByte() != 0) {
                    throw new BitcoinException(BitcoinException.ERR_WRONG_TYPE, "", version);
                }
                if (bais.readByte() == 0) {
                    throw new BitcoinException(BitcoinException.ERR_WRONG_TYPE, "", version);
                }
            }
            int inputsCount = (int) bais.readVarInt();
            inputs = new Input[inputsCount];
            for (int i = 0; i < inputsCount; i++) {
                OutPoint outPoint = new OutPoint(BTCUtils.reverse(bais.readChars(32)), bais.readInt32());
                byte[] script = bais.readChars((int) bais.readVarInt());
                int sequence = bais.readInt32();
                inputs[i] = new Input(outPoint, new Script(script), sequence);
            }
            int outputsCount = (int) bais.readVarInt();
            outputs = new Output[outputsCount];
            for (int i = 0; i < outputsCount; i++) {
                long value = bais.readInt64();
                long scriptSize = bais.readVarInt();
                if (scriptSize < 0 || scriptSize > 10_000_000) {
                    throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Script size for output " + i +
                            " is strange (" + scriptSize + " bytes).");
                }
                byte[] script = bais.readChars((int) scriptSize);
                outputs[i] = new Output(value, new Script(script));
            }
            scriptWitnesses = new byte[withWitness ? inputsCount : 0][][];
            for (int i = 0; i < scriptWitnesses.length; i++) {
                long stackItemsCount = bais.readVarInt();
                if (stackItemsCount < 0 || stackItemsCount > 10_000_000) {
                    throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Stack count size " + i +
                            " is strange (" + stackItemsCount + ").");
                }
                scriptWitnesses[i] = new byte[(int) stackItemsCount][];
                for (int j = 0; j < stackItemsCount; j++) {
                    long itemLength = bais.readVarInt();
                    if (itemLength < 0 || itemLength > 10_000_000) {
                        throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Item length " + i + ' ' + j +
                                " is strange (" + itemLength + " bytes).");
                    }
                    scriptWitnesses[i][j] = bais.readChars((int) itemLength);
                }
            }
            lockTime = bais.readInt32();
        } catch (EOFException e) {
            throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "TX incomplete");
        } catch (IOException e) {
            throw new IllegalArgumentException("Unable to read TX");
        } catch (Error e) {
            throw new IllegalArgumentException("Unable to read TX: " + e);
        } finally {
            if (bais != null) {
                try {
                    bais.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @SuppressWarnings("SameParameterValue")
    public Transaction(Input[] inputs, Output[] outputs, int lockTime) {
        this(1, inputs, outputs, lockTime, new byte[0][][]);
    }

    public Transaction(int version, Input[] inputs, Output[] outputs, int lockTime) {
        this(version, inputs, outputs, lockTime, new byte[0][][]);
    }

    public Transaction(int version, Input[] inputs, Output[] outputs, int lockTime, byte[][][] scriptWitnesses) {
        this.version = version;
        this.inputs = inputs;
        this.outputs = outputs;
        this.lockTime = lockTime;
        this.scriptWitnesses = scriptWitnesses;
    }

    boolean isCoinBase() {
        return inputs.length == 1 && inputs[0].outPoint.isNull();
    }

    public byte[] hash() {
        return BTCUtils.reverseInPlace(BTCUtils.doubleSha256(getBytes(false)));
    }

    public byte[] getBytes() {
        return getBytes(true);
    }

    @SuppressWarnings("unused")
    public String toHexEncodedString() {
        return BTCUtils.toHex(getBytes(true));
    }

    public byte[] getBytes(boolean withWitness) {
        if (withWitness && scriptWitnesses.length == 0) {
            withWitness = false;
        }
        BitcoinOutputStream baos = new BitcoinOutputStream();
        try {
            baos.writeInt32(version);
            if (withWitness) {
                baos.write(0);
                baos.write(1);
            }
            baos.writeVarInt(inputs.length);
            for (Input input : inputs) {
                baos.write(BTCUtils.reverse(input.outPoint.hash));
                baos.writeInt32(input.outPoint.index);
                int scriptLen = input.scriptSig == null ? 0 : input.scriptSig.bytes.length;
                baos.writeVarInt(scriptLen);
                if (scriptLen > 0) {
                    baos.write(input.scriptSig.bytes);
                }
                baos.writeInt32(input.sequence);
            }
            baos.writeVarInt(outputs.length);
            for (Output output : outputs) {
                baos.writeInt64(output.value);
                int scriptLen = output.scriptPubKey == null ? 0 : output.scriptPubKey.bytes.length;
                baos.writeVarInt(scriptLen);
                if (scriptLen > 0) {
                    baos.write(output.scriptPubKey.bytes);
                }
            }
            if (withWitness) {
                for (byte[][] witness : scriptWitnesses) {
                    baos.writeVarInt(witness.length);
                    for (byte[] stackEntry : witness) {
                        baos.writeVarInt(stackEntry.length);
                        baos.write(stackEntry);
                    }
                }
            }
            baos.writeInt32(lockTime);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                baos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return baos.toByteArray();

    }

    @Override
    public String toString() {
        return "{" +
                "\n\"inputs\":\n" + printAsJsonArray(inputs) +
                ",\n\"outputs\":\n" + printAsJsonArray(outputs) +
                (scriptWitnesses.length == 0 ? "" : (",\n\"witnesses\":\n" + printWitnesses(scriptWitnesses))) +
                ",\n\"lockTime\":\"" + lockTime + "\"}\n";
    }

    private String printWitnesses(byte[][][] scriptWitnesses) {
        StringBuilder sb = new StringBuilder();
        sb.append('[');
        for (int i = 0; i < scriptWitnesses.length; i++) {
            sb.append('[');
            if (scriptWitnesses[i] == null) {
                sb.append("[]");
            } else {
                for (int j = 0; j < scriptWitnesses[i].length; j++) {
                    sb.append('[');
                    sb.append(BTCUtils.toHex(scriptWitnesses[i][j]));
                    sb.append(']');
                    if (j != scriptWitnesses[i].length - 1) {
                        sb.append(',');
                    }
                }
            }
            sb.append(']');
            if (i != scriptWitnesses.length - 1) {
                sb.append(",\n");
            }
        }
        sb.append(']');
        return sb.toString();
    }

    private String printAsJsonArray(Object[] a) {
        if (a == null) {
            return "null";
        }
        if (a.length == 0) {
            return "[]";
        }
        int iMax = a.length - 1;
        StringBuilder sb = new StringBuilder();
        sb.append('[');
        for (int i = 0; ; i++) {
            sb.append(String.valueOf(a[i]));
            if (i == iMax)
                return sb.append(']').toString();
            sb.append(",\n");
        }
    }

    public int getWeightUnits() {
        int legacySize = getBytes(false).length;
        int witnessSize = getBytes(true).length - legacySize;
        return legacySize * 4 + witnessSize;
    }

    public int getVBytesSize() {
        return (int) Math.ceil(getWeightUnits() / 4f);
    }

    public static class Input {
        public final OutPoint outPoint;
        public final Script scriptSig;
        public final int sequence;

        public Input(OutPoint outPoint, Script scriptSig, int sequence) {
            this.outPoint = outPoint;
            this.scriptSig = scriptSig;
            this.sequence = sequence;
        }

        @Override
        public String toString() {
            return "{\n\"outPoint\":" + outPoint + ",\n\"script\":\"" + scriptSig + "\",\n\"sequence\":\"" + Integer.toHexString(sequence) + "\"\n}\n";
        }
    }

    public static class OutPoint {
        public final byte[] hash;//32-byte hash of the transaction from which we want to redeem an output
        public final int index;//Four-byte field denoting the output index we want to redeem from the transaction with the above hash (output number 2 = output index 1)

        public OutPoint(byte[] hash, int index) {
            this.hash = hash;
            this.index = index;
        }

        @Override
        public String toString() {
            return "{" + "\"hash\":\"" + BTCUtils.toHex(hash) + "\", \"index\":\"" + index + "\"}";
        }

        public boolean isNull() {
            return index == -1 && allZeroes(hash);
        }

        private static boolean allZeroes(byte[] hash) {
            for (byte b : hash) {
                if (b != 0) {
                    return false;
                }
            }
            return true;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            OutPoint outPoint = (OutPoint) o;
            return index == outPoint.index && Arrays.equals(hash, outPoint.hash);
        }

        @Override
        public int hashCode() {
            int result = Arrays.hashCode(hash);
            result = 31 * result + index;
            return result;
        }
    }

    public static class Output {
        public final long value;
        public final Script scriptPubKey;

        public Output(long value, @NonNull Script scriptPubKey) {
            this.value = value;
            this.scriptPubKey = scriptPubKey;
        }

        @Override
        public String toString() {
            return "{\n\"value\":\"" + BTCUtils.formatValue(value) +
                    "\",\"script\":\"" + scriptPubKey +
                    "\",\"address\":" + getQuotedAddressInfo() + "\n}";
        }

        private String getQuotedAddressInfo() {
            if (scriptPubKey.isPay2PublicKeyHash()) {
                return "\"p2pkh prod " + getP2pkhAddress(false) + " or testnet " + getP2pkhAddress(true) + "\"";
            }
            if (scriptPubKey.isPayToScriptHash()) {
                return "\"p2sh prod " + getP2shAddress(false) + " or testnet " + getP2shAddress(true) + "\"";
            }
            Script.WitnessProgram wp = scriptPubKey.getWitnessProgram();
            if (wp != null && wp.version == 0 && wp.program.length == 20) {
                try {
                    return "\"p2wkh prod " + new Address(false, wp) + " or testnet " +
                            new Address(true, wp) + "\"";
                } catch (BitcoinException ignored) {
                }
            }
            return "\"unknown\"";
        }

        @Nullable
        public String getP2pkhAddress(boolean testNet) {
            if (scriptPubKey.isPay2PublicKeyHash()) {
                byte[] hash = new byte[20];
                System.arraycopy(scriptPubKey.bytes, 2, hash, 0, hash.length);
                return Address.ripemd160HashToAddress(testNet, hash);
            } else {
                return null;
            }
        }

        @Nullable
        public String getP2shAddress(boolean testNet) {
            if (scriptPubKey.isPayToScriptHash()) {
                byte[] hash = new byte[20];
                System.arraycopy(scriptPubKey.bytes, 2, hash, 0, hash.length);
                return Address.ripemd160HashToP2shAddress(testNet, hash);
            } else {
                return null;
            }
        }
    }

    public static class Checker {
        final int inputIndex;
        final long amount;
        final Transaction spendTx;

        public Checker(int inputIndex, long amount, Transaction spendTx) {
            this.inputIndex = inputIndex;
            this.amount = amount;
            this.spendTx = spendTx;
        }

        @Override
        public String toString() {
            return "Checker{" +
                    "inputIndex=" + inputIndex +
                    ", amount=" + amount +
                    ", spendTx=" + spendTx +
                    '}';
        }
    }

    public static final class Script {

        private static final int LOCKTIME_THRESHOLD = 500000000;
        public static final int SCRIPT_VERIFY_P2SH = 1;
        public static final int SCRIPT_VERIFY_STRICTENC = 1 << 1;
        public static final int SCRIPT_VERIFY_DERSIG = 1 << 2;
        public static final int SCRIPT_VERIFY_LOW_S = 1 << 3;
        public static final int SCRIPT_VERIFY_SIGPUSHONLY = 1 << 5;
        public static final int SCRIPT_VERIFY_WITNESS = 1 << 11;
        public static final int SCRIPT_VERIFY_CLEANSTACK = 1 << 8;
        public static final int SCRIPT_VERIFY_NULLFAIL = 1 << 14;
        public static final int SCRIPT_ENABLE_SIGHASH_FORKID = 1 << 16;
        public static final int SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12;
        public static final int SCRIPT_ALL_SUPPORTED = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S |
                SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK;

        public static final int SIGVERSION_BASE = 0;
        public static final int SIGVERSION_WITNESS_V0 = 1;

        public static class ScriptInvalidException extends Exception {
            public ScriptInvalidException() {
            }

            @SuppressWarnings("unused")
            public ScriptInvalidException(String s) {
                super(s);
            }
        }

        public static final byte OP_FALSE = 0;
        public static final byte OP_TRUE = 0x51;
        public static final byte OP_PUSHDATA1 = 0x4c;
        public static final byte OP_PUSHDATA2 = 0x4d;
        public static final byte OP_PUSHDATA4 = 0x4e;
        public static final byte OP_DUP = 0x76;//Duplicates the top stack item.
        public static final byte OP_DROP = 0x75;
        public static final byte OP_HASH160 = (byte) 0xA9;//The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
        public static final byte OP_VERIFY = 0x69;//Marks transaction as invalid if top stack value is not true. True is removed, but false is not.
        public static final byte OP_EQUAL = (byte) 0x87;//Returns 1 if the inputs are exactly equal, 0 otherwise.
        public static final byte OP_EQUALVERIFY = (byte) 0x88;//Same as OP_EQUAL, but runs OP_VERIFY afterward.
        public static final byte OP_CHECKSIG = (byte) 0xAC;//The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this hash and public key. If it is, 1 is returned, 0 otherwise.
        public static final byte OP_CHECKSIGVERIFY = (byte) 0xAD;
        public static final byte OP_NOP = 0x61;
        public static final byte OP_2 = 0x52;
        public static final byte OP_3 = 0x53;
        public static final byte OP_4 = 0x54;
        public static final byte OP_5 = 0x55;
        public static final byte OP_6 = 0x56;
        public static final byte OP_7 = 0x57;
        public static final byte OP_8 = 0x58;
        public static final byte OP_16 = 0x60;
        public static final byte OP_CHECKMULTISIG = (byte) 0xae;
        public static final byte OP_CHECKMULTISIGVERIFY = (byte) 0xaf;
        public static final byte OP_1NEGATE = 0x4f;
        public static final byte OP_SWAP = 0x7c;
        public static final byte OP_PICK = 0x79;
        public static final byte OP_SHA256 = (byte) 0xa8;
        public static final byte OP_BOOLAND = (byte) 0x9a;
        public static final byte OP_SIZE = (byte) 0x82;
        public static final byte OP_NIP = 0x77;
        public static final byte OP_WITHIN = (byte) 0xa5;
        public static final byte OP_IF = 0x63;
        public static final byte OP_ELSE = 0x67;
        public static final byte OP_ENDIF = 0x68;
        public static final byte OP_NOT = (byte) 0x91;
        public static final byte OP_CODESEPARATOR = (byte) 0xab;
        public static final byte OP_CHECKLOCKTIMEVERIFY = (byte) 0xb1;
        public static final byte OP_1ADD = (byte) 0x8b;
        public static final byte OP_ADD = (byte) 0x93;
        public static final byte OP_CHECKSEQUENCEVERIFY = (byte) 0xb2;
        public static final byte OP_1SUB = (byte) 0x8c;
        public static final byte OP_FROMALTSTACK = 0x6c;
        public static final byte OP_SUB = (byte) 0x94;
        public static final byte OP_VERIF = 0x65;
        public static final byte OP_RETURN = 0x6a;

        public static final byte SIGHASH_ALL = 1;
        public static final byte SIGHASH_NONE = 2;
        public static final byte SIGHASH_SINGLE = 3;
        public static final byte SIGHASH_FORKID = 0x40;
        public static final int SIGHASH_ANYONECANPAY = 0x80;
        private static final int SIGHASH_MASK = 0x1f;


        public final byte[] bytes;

        public Script(byte[] rawBytes) {
            bytes = rawBytes;
        }

        public Script(byte[] data1, byte[] data2) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(data1.length + data2.length + 2);
            try {
                writeBytes(data1, baos);
                writeBytes(data2, baos);
                baos.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            bytes = baos.toByteArray();
        }

        public static void writeBytes(byte[] data, ByteArrayOutputStream baos) throws IOException {
            if (data.length < OP_PUSHDATA1) {
                baos.write(data.length);
            } else if (data.length < 0xff) {
                baos.write(OP_PUSHDATA1);
                baos.write(data.length);
            } else if (data.length < 0xffff) {
                baos.write(OP_PUSHDATA2);
                baos.write(data.length & 0xff);
                baos.write((data.length >> 8) & 0xff);
            } else {
                baos.write(OP_PUSHDATA4);
                baos.write(data.length & 0xff);
                baos.write((data.length >> 8) & 0xff);
                baos.write((data.length >> 16) & 0xff);
                baos.write((data.length >>> 24) & 0xff);
            }
            baos.write(data);
        }

        @SuppressWarnings({"ConstantConditions", "UnusedReturnValue"})
        public boolean run(Stack<byte[]> stack) throws ScriptInvalidException {
            return run(new Checker(0, -1, null), stack, SCRIPT_ALL_SUPPORTED, SIGVERSION_BASE);
        }

        @SuppressWarnings("ConstantConditions")
        public boolean run(Checker checker, Stack<byte[]> stack, int flags, int sigVersion) throws ScriptInvalidException {
            boolean withinIf = false;
            boolean skip = false;
            int pbegincodehash = 0;
            for (int pos = 0; pos < bytes.length; pos++) {
                if (withinIf) {
                    if (bytes[pos] == OP_ELSE) {
                        skip = !skip;
                        continue;
                    }
                    if (bytes[pos] == OP_ENDIF) {
                        withinIf = false;
                        continue;
                    }
                    if (skip) {
                        continue;
                    }
                }
                switch (bytes[pos]) {
                    case OP_NOP:
                        break;
                    case OP_DROP:
                        if (stack.isEmpty()) {
                            throw new IllegalArgumentException("stack empty on OP_DROP");
                        }
                        stack.pop();
                        break;
                    case OP_DUP:
                        if (stack.isEmpty()) {
                            throw new IllegalArgumentException("stack empty on OP_DUP");
                        }
                        stack.push(stack.peek());
                        break;
                    case OP_HASH160:
                        if (stack.isEmpty()) {
                            throw new IllegalArgumentException("stack empty on OP_HASH160");
                        }
                        stack.push(BTCUtils.sha256ripemd160(stack.pop()));
                        break;
                    case OP_EQUAL:
                    case OP_EQUALVERIFY:
                        if (stack.size() < 2) {
                            throw new IllegalArgumentException("not enough elements to perform OP_EQUAL");
                        }
                        stack.push(new byte[]{(byte) (Arrays.equals(stack.pop(), stack.pop()) ? 1 : 0)});
                        if (bytes[pos] == OP_EQUALVERIFY) {
                            if (verifyFails(stack)) {
                                return false;
                            }
                        }
                        break;
                    case OP_VERIFY:
                        if (verifyFails(stack)) {
                            throw new ScriptInvalidException();
                        }
                        break;
                    case OP_CHECKSIG:
                    case OP_CHECKSIGVERIFY:
                        if (stack.size() < 2) {
                            return false;
                        }
                        byte[] publicKey = stack.pop();
                        byte[] signatureAndHashType = stack.pop();
                        boolean valid = false;
                        if (signatureAndHashType.length != 0) {
                            if (!checkSignatureEncoding(signatureAndHashType, flags)) {// || !checkPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
                                return false;
                            }
                            byte[] signature = new byte[signatureAndHashType.length - 1];
                            System.arraycopy(signatureAndHashType, 0, signature, 0, signature.length);
                            byte[] subScript;
                            if (pbegincodehash == 0) {
                                subScript = bytes;
                            } else {
                                subScript = new byte[bytes.length - pbegincodehash];
                                System.arraycopy(bytes, pbegincodehash, subScript, 0, subScript.length);
                            }
                            int hashType = signatureAndHashType[signatureAndHashType.length - 1] & 0xff;
                            if ((hashType & Script.SIGHASH_FORKID) == 0) {
                                if (sigVersion == SIGVERSION_BASE) {
                                    subScript = findAndDelete(subScript, convertDataToScript(signatureAndHashType));
                                }
                            } else if ((flags & SCRIPT_ENABLE_SIGHASH_FORKID) == 0) {
                                return false; //set_error(serror, SCRIPT_ERR_ILLEGAL_FORKID);
                            }
                            byte[] hash = hashTransaction(checker.inputIndex, subScript, checker.spendTx, hashType, checker.amount, sigVersion);
                            valid = BTCUtils.verify(publicKey, signature, hash);
                        }
                        if (!valid && (flags & SCRIPT_VERIFY_NULLFAIL) != 0 && signatureAndHashType.length > 0) {
                            return false;
                        }
                        stack.push(new byte[]{(byte) (valid ? 1 : 0)});
                        if (bytes[pos] == OP_CHECKSIGVERIFY) {
                            if (verifyFails(stack)) {
                                return false;
                            }
                        }
                        break;
                    case OP_FALSE:
                        stack.push(new byte[]{});
                        break;
                    case OP_TRUE:
                        stack.push(new byte[]{1});
                        break;
                    case OP_2:
                        stack.push(new byte[]{2});
                        break;
                    case OP_3:
                        stack.push(new byte[]{3});
                        break;
                    case OP_4:
                        stack.push(new byte[]{4});
                        break;
                    case OP_5:
                        stack.push(new byte[]{5});
                        break;
                    case OP_6:
                        stack.push(new byte[]{6});
                        break;
                    case OP_7:
                        stack.push(new byte[]{7});
                        break;
                    case OP_8:
                        stack.push(new byte[]{8});
                        break;
                    case OP_16:
                        stack.push(new byte[]{16});
                        break;
                    case OP_1NEGATE:
                        stack.push(new byte[]{-1});
                        break;
                    case OP_CHECKMULTISIG:
                        throw new NotImplementedException("OP_CHECKMULTISIG not implemented");
                    case OP_CHECKMULTISIGVERIFY:
                        throw new NotImplementedException("OP_CHECKMULTISIGVERIFY not implemented");
                    case OP_SWAP:
                        byte[] a = stack.pop();
                        byte[] b = stack.pop();
                        stack.push(b);
                        stack.push(a);
                        break;
                    case OP_PICK:
                        int n = stack.pop()[0] & 0xff;
                        byte[] d = stack.get(stack.size() - 1 - n);
                        stack.push(d);
                        break;
                    case OP_SHA256:
                        stack.push(BTCUtils.sha256(stack.pop()));
                        break;
                    case OP_BOOLAND:
                        byte av = stack.pop()[0];
                        byte bv = stack.pop()[0];
                        stack.push(new byte[]{(byte) (av != 0 && bv != 0 ? 1 : 0)});
                        break;
                    case OP_SIZE:
                        stack.push(new byte[]{(byte) (stack.peek().length)});
                        break;
                    case OP_NIP:
                        a = stack.pop();
                        stack.pop();
                        stack.push(a);
                        break;
                    case OP_WITHIN:
                        long x = new BigInteger(stack.pop()).longValue();
                        long min = new BigInteger(stack.pop()).longValue();
                        long max = new BigInteger(stack.pop()).longValue();
                        stack.push(new byte[]{(byte) (x >= min && x < max ? 1 : 0)});
                        break;
                    case OP_IF:
                        withinIf = true;
                        a = stack.pop();
                        skip = a.length == 0 || a[0] == 0;
                        break;
                    case OP_NOT:
                        av = stack.pop()[0];
                        stack.push(new byte[]{(byte) (av == 0 ? 1 : 0)});
                        break;
                    case OP_1ADD:
                        a = stack.pop();
                        BigInteger ab = a.length == 0 ? BigInteger.ZERO : new BigInteger(a);
                        stack.push(ab.add(BigInteger.ONE).toByteArray());
                        break;
                    case OP_1SUB:
                        a = stack.pop();
                        ab = a.length == 0 ? BigInteger.ZERO : new BigInteger(a);
                        stack.push(ab.subtract(BigInteger.ONE).toByteArray());
                        break;
                    case OP_ADD:
                        a = stack.pop();
                        b = stack.pop();
                        ab = a.length == 0 ? BigInteger.ZERO : new BigInteger(a);
                        BigInteger bb = b.length == 0 ? BigInteger.ZERO : new BigInteger(b);
                        stack.push(ab.add(bb).toByteArray());
                        break;
                    case OP_SUB:
                        a = stack.pop();
                        b = stack.pop();
                        ab = a.length == 0 ? BigInteger.ZERO : new BigInteger(a);
                        bb = b.length == 0 ? BigInteger.ZERO : new BigInteger(b);
                        stack.push(bb.subtract(ab).toByteArray());
                        break;
                    case OP_CODESEPARATOR:
                        pbegincodehash = pos + 1;
                        break;
                    case OP_CHECKLOCKTIMEVERIFY:
                        if (stack.isEmpty()) {
                            return false;
                        }
                        a = stack.peek();
                        if (a.length > 5) {
                            return false;
                        }
                        long nLockTime = a.length == 0 ? 0 : new BigInteger(a).longValue();
                        if (nLockTime < 0) {
                            return false;
                        }
                        long txLockTime = checker.spendTx.lockTime & 0xFFFFFFFFL;
                        if (!((txLockTime < LOCKTIME_THRESHOLD && nLockTime < LOCKTIME_THRESHOLD) ||
                                (txLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD))) {
                            return false;
                        }
                        if (nLockTime > txLockTime) {
                            return false;
                        }
                        if (0xFFFFFFFF == checker.spendTx.inputs[checker.inputIndex].sequence) {
                            return false;
                        }
                        break;
                    case OP_CHECKSEQUENCEVERIFY:
                        throw new NotImplementedException("OP_CHECKSEQUENCEVERIFY (BIP68) not implemented");
                    default:
                        int op = bytes[pos] & 0xff;
                        int len;
                        if (op < OP_PUSHDATA1) {
                            len = op;
                            byte[] data = new byte[len];
                            System.arraycopy(bytes, pos + 1, data, 0, len);
                            stack.push(data);
                            pos += data.length;
                        } else if (op == OP_PUSHDATA1) {
                            len = bytes[pos + 1] & 0xff;
                            byte[] data = new byte[len];
                            System.arraycopy(bytes, pos + 2, data, 0, len);
                            stack.push(data);
                            pos += 1 + data.length;
                        } else {
                            throw new IllegalArgumentException("I cannot execute this data or operation: 0x" +
                                    Integer.toHexString(bytes[pos] & 0xff).toUpperCase(Locale.ENGLISH));
                        }
                        break;
                }
            }
            return true;
        }

        @SuppressWarnings("RedundantIfStatement")
        private static boolean checkSignatureEncoding(byte[] vchSig, int flags) {
            // Empty signature. Not strictly DER encoded, but allowed to provide a
            // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
            if (vchSig.length == 0) {
                return true;
            }
            if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !isValidSignatureEncoding(vchSig)) {
                return false;
//            }else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !IsLowDERSignature(vchSig, serror)) {
//                return false;
            } else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !isDefinedHashtypeSignature(vchSig, (flags & SCRIPT_ENABLE_SIGHASH_FORKID) != 0)) {
                return false;
            }
            return true;
        }

        private static boolean isDefinedHashtypeSignature(byte[] vchSig, boolean bitcoinCash) {
            if (vchSig.length == 0) {
                return false;
            }
            byte sighHashTypeFlags = vchSig[vchSig.length - 1];
            if (bitcoinCash != ((sighHashTypeFlags & SIGHASH_FORKID) == SIGHASH_FORKID)) {
                return false;
            }
            int nHashType = sighHashTypeFlags & (~(SIGHASH_ANYONECANPAY | SIGHASH_FORKID));
            return !(nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE);
        }

        private static boolean isValidSignatureEncoding(byte[] sig) {
            // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
            // * total-length: 1-byte length descriptor of everything that follows,
            //   excluding the sighash byte.
            // * R-length: 1-byte length descriptor of the R value that follows.
            // * R: arbitrary-length big-endian encoded R value. It must use the shortest
            //   possible encoding for a positive integers (which means no null bytes at
            //   the start, except a single one when the next byte has its highest bit set).
            // * S-length: 1-byte length descriptor of the S value that follows.
            // * S: arbitrary-length big-endian encoded S value. The same rules apply.
            // * sighash: 1-byte value indicating what data is hashed (not part of the DER
            //   signature)

            // Minimum and maximum size constraints.
            if (sig.length < 9) {
                return false;
            }
            if (sig.length > 73) {
                return false;
            }

            // A signature is of type 0x30 (compound).
            if (sig[0] != 0x30) {
                return false;
            }

            // Make sure the length covers the entire signature.
            if (sig[1] != sig.length - 3) {
                return false;
            }

            // Extract the length of the R element.
            int lenR = sig[3] & 0xff;

            // Make sure the length of the S element is still inside the signature.
            if (5 + lenR >= sig.length) {
                return false;
            }

            // Extract the length of the S element.
            int lenS = sig[5 + lenR] & 0xff;

            // Verify that the length of the signature matches the sum of the length
            // of the elements.
            if (lenR + lenS + 7 != sig.length) {
                return false;
            }

            // Check whether the R element is an integer.
            if (sig[2] != 0x02) {
                return false;
            }

            // Zero-length integers are not allowed for R.
            if (lenR == 0) {
                return false;
            }

            // Negative numbers are not allowed for R.
            if ((sig[4] & 0x80) != 0) {
                return false;
            }

            // Null bytes at the start of R are not allowed, unless R would
            // otherwise be interpreted as a negative number.
            if (lenR > 1 && (sig[4] == 0x00) && (sig[5] & 0x80) == 0) {
                return false;
            }

            // Check whether the S element is an integer.
            if (sig[lenR + 4] != 0x02) {
                return false;
            }

            // Zero-length integers are not allowed for S.
            if (lenS == 0) {
                return false;
            }

            // Negative numbers are not allowed for S.
            if ((sig[lenR + 6] & 0x80) != 0) {
                return false;
            }

            // Null bytes at the start of S are not allowed, unless S would otherwise be
            // interpreted as a negative number.
            return !(lenS > 1 && (sig[lenR + 6] == 0x00) && (sig[lenR + 7] & 0x80) == 0);
        }

        static byte[] convertDataToScript(byte[] bytes) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length + 1);
            try {
                writeBytes(bytes, baos);
                baos.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return baos.toByteArray();
        }

        private static byte[] findAndDelete(byte[] script, byte[] scriptTokenToDelete) {
            for (int i = 0; i < script.length; ) {
                int tokenLength = getScriptTokenLengthAt(script, i);
                if (tokenLength == scriptTokenToDelete.length) {
                    boolean equals = true;
                    for (int j = 0; j < tokenLength; j++) {
                        if (script[i + j] != scriptTokenToDelete[j]) {
                            equals = false;
                            break;
                        }
                    }
                    if (equals) {
                        byte[] updatedScript = new byte[script.length - tokenLength];
                        System.arraycopy(script, 0, updatedScript, 0, i);
                        System.arraycopy(script, i + tokenLength, updatedScript, i, updatedScript.length - i);
                        script = updatedScript;
                        i -= tokenLength;
                    }
                }
                i += tokenLength;
            }
            return script;
        }

        public static int getScriptTokenLengthAt(byte[] script, int pos) {
            int op = script[pos] & 0xff;
            if (op > OP_PUSHDATA4) {
                return 1;
            }
            if (op < OP_PUSHDATA1) {
                return 1 + op;
            }
            if (op == OP_PUSHDATA1) {
                return 2 + (script[pos + 1] & 0xff);
            }
            throw new NotImplementedException("No large data load implemented");
        }

        public WitnessProgram getWitnessProgram() {
            if (bytes.length < 4 || bytes.length > 42) {
                return null;
            }
            int versionByte = bytes[0] & 0xFF;
            if (versionByte != 0 && (versionByte < Script.OP_TRUE || versionByte > Transaction.Script.OP_16)) {
                return null;
            }
            int witnessProgramLen = bytes[1] & 0xff;
            if (witnessProgramLen == bytes.length - 2) {
                byte[] witnessProgram = new byte[witnessProgramLen];
                System.arraycopy(bytes, 2, witnessProgram, 0, witnessProgram.length);
                return new WitnessProgram(decodeOpN(versionByte), witnessProgram);
            }
            return null;
        }

        private static int decodeOpN(int opcode) {
            if (opcode == OP_FALSE)
                return 0;
            if (opcode < OP_TRUE || opcode > OP_16) {
                throw new IllegalArgumentException("decodeOpN " + opcode);
            }
            return opcode - (OP_TRUE - 1);
        }

        static class WitnessProgram {
            final int version;
            final byte[] program;

            public WitnessProgram(int version, byte[] witnessProgram) {
                this.version = version;
                this.program = witnessProgram;
            }

            @Override
            public String toString() {
                return "WitnessProgram{" +
                        "version=" + version +
                        ", program=" + BTCUtils.toHex(program) +
                        '}';
            }

            public byte[] getBytes() {
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                os.write(version == 0 ? 0 : (version + 0x50));
                try {
                    Script.writeBytes(program, os);
                    os.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                return os.toByteArray();
            }

            public boolean isWitnessKeyHashType() {
                return program.length == 20;
            }

            public boolean isWitnessSha256Type() {
                return program.length == 32;
            }
        }

        //https://bitcoin.org/en/developer-guide#standard-transactions
        public boolean isPay2PublicKeyHash() {
            return bytes.length == 25 &&
                    bytes[0] == Script.OP_DUP &&
                    bytes[1] == Script.OP_HASH160 &&
                    bytes[2] == 20;
        }

        public boolean isPayToScriptHash() {
            return bytes.length == 23 &&
                    bytes[0] == OP_HASH160 &&
                    bytes[1] == 0x14 &&
                    bytes[22] == OP_EQUAL;
        }


        public boolean isPubkey() {
            return bytes.length > 2 &&
                    getScriptTokenLengthAt(bytes, 0) == bytes.length - 1 &&
                    bytes[bytes.length - 1] == Script.OP_CHECKSIG;
        }

        public boolean isNull() {
            return bytes.length == 0;
        }

        @SuppressWarnings("BooleanMethodIsAlwaysInverted")
        public boolean isPushOnly() {
            for (int i = 0; i < bytes.length; ) {
                int tokenLength = getScriptTokenLengthAt(bytes, i);
                if ((bytes[i] & 0xff) > OP_16) {
                    return false;
                }
                i += tokenLength;
            }
            return true;
        }

        public static byte[] hashTransaction(int inputIndex, byte[] subScript, Transaction tx, int hashType, long amount, int sigVersion) {
            boolean bitcoinCash = (hashType & Script.SIGHASH_FORKID) == Script.SIGHASH_FORKID;
            if (tx != null && (hashType & Transaction.Script.SIGHASH_MASK) == Transaction.Script.SIGHASH_SINGLE && inputIndex >= tx.outputs.length && sigVersion == SIGVERSION_BASE) {
                byte[] hash = new byte[32];
                hash[0] = 1;
                return hash;
            }
            if (!bitcoinCash && sigVersion == SIGVERSION_BASE) {
                subScript = findAndDelete(subScript, new byte[]{OP_CODESEPARATOR});
            }
            int inputsCount = tx == null ? 0 : tx.inputs.length;
            Input[] unsignedInputs = new Input[inputsCount];
            for (int i = 0; i < inputsCount; i++) {
                Input txInput = tx.inputs[i];
                if (i == inputIndex) {
                    unsignedInputs[i] = new Input(txInput.outPoint, new Script(subScript), txInput.sequence);
                } else {
                    unsignedInputs[i] = new Input(txInput.outPoint, new Script(new byte[0]), txInput.sequence);
                }
            }
            Output[] outputs;
            if (sigVersion == SIGVERSION_BASE) {
                switch (hashType & Transaction.Script.SIGHASH_MASK) {
                    case Script.SIGHASH_NONE:
                        outputs = new Output[0];
                        for (int i = 0; i < inputsCount; i++) {
                            if (i != inputIndex) {
                                unsignedInputs[i] = new Input(unsignedInputs[i].outPoint, unsignedInputs[i].scriptSig, 0);
                            }
                        }
                        break;
                    case Script.SIGHASH_SINGLE:
                        outputs = new Output[inputIndex + 1];
                        for (int i = 0; i < inputIndex; i++) {
                            outputs[i] = new Output(-1, new Script(new byte[0]));
                        }
                        if (tx == null) {
                            throw new RuntimeException("Null TX in hashTransaction/SIGHASH_SINGLE");
                        }
                        outputs[inputIndex] = tx.outputs[inputIndex];
                        for (int i = 0; i < inputsCount; i++) {
                            if (i != inputIndex) {
                                unsignedInputs[i] = new Input(unsignedInputs[i].outPoint, unsignedInputs[i].scriptSig, 0);
                            }
                        }
                        break;
                    default:
                        outputs = tx == null ? new Output[0] : tx.outputs;
                        break;
                }

                if ((hashType & Transaction.Script.SIGHASH_ANYONECANPAY) != 0) {
                    unsignedInputs = new Input[]{unsignedInputs[inputIndex]};
                }
            } else {
                outputs = tx == null ? new Output[0] : tx.outputs;
            }
            Transaction unsignedTransaction = new Transaction(tx == null ? 1 : tx.version, unsignedInputs, outputs, tx == null ? 0 : tx.lockTime);
            if (bitcoinCash || sigVersion == SIGVERSION_WITNESS_V0) {
                if (tx == null) {
                    throw new RuntimeException("null tx");
                }
                return bip143Hash(inputIndex, unsignedTransaction, hashType, subScript, amount);
            } else {
                byte[] txUnsignedBytes = unsignedTransaction.getBytes(false);
                BitcoinOutputStream baos = new BitcoinOutputStream();
                try {
                    baos.write(txUnsignedBytes);
                    baos.writeInt32(hashType);
                    baos.close();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                return BTCUtils.doubleSha256(baos.toByteArray());
            }
        }

        public static byte[] bip143Hash(int inputIndex, Transaction tx, int hashType, byte[] script, long amount) {
            boolean single = (hashType & Transaction.Script.SIGHASH_MASK) == Transaction.Script.SIGHASH_SINGLE;
            boolean none = (hashType & Transaction.Script.SIGHASH_MASK) == Script.SIGHASH_NONE;
            BitcoinOutputStream baos = new BitcoinOutputStream();
            try {
//                    1. nVersion of the transaction (4-byte little endian)
                baos.writeInt32(tx.version);
//                    2. hashPrevouts (32-byte hash)
                if ((hashType & Script.SIGHASH_ANYONECANPAY) == 0) {
                    BitcoinOutputStream prevOuts = new BitcoinOutputStream();
                    for (Input input : tx.inputs) {
                        prevOuts.write(BTCUtils.reverse(input.outPoint.hash));
                        prevOuts.writeInt32(input.outPoint.index);
                    }
                    prevOuts.close();
                    baos.write(BTCUtils.doubleSha256(prevOuts.toByteArray()));
                } else {
                    baos.write(new byte[32]);
                }
//                    3. hashSequence (32-byte hash)
                if ((hashType & Script.SIGHASH_ANYONECANPAY) == 0 && !single && !none) {
                    BitcoinOutputStream sequences = new BitcoinOutputStream();
                    for (Input input : tx.inputs) {
                        sequences.writeInt32(input.sequence);
                    }
                    sequences.close();
                    baos.write(BTCUtils.doubleSha256(sequences.toByteArray()));
                } else {
                    baos.write(new byte[32]);
                }
//                    4. outpoint (32-byte hash + 4-byte little endian)
                baos.write(BTCUtils.reverse(tx.inputs[inputIndex].outPoint.hash));
                baos.writeInt32(tx.inputs[inputIndex].outPoint.index);
//                    5. scriptCode of the input (serialized as scripts inside CTxOuts)
                baos.write(convertDataToScript(script));
//                    6. value of the output spent by this input (8-byte little endian)
                baos.writeInt64(amount);
//                    7. nSequence of the input (4-byte little endian)
                baos.writeInt32(tx.inputs[inputIndex].sequence);
//                    8. hashOutputs (32-byte hash)
                BitcoinOutputStream outputStream = new BitcoinOutputStream();
                if (!single && !none) {
                    for (Output output : tx.outputs) {
                        outputStream.writeInt64(output.value);
                        outputStream.write(convertDataToScript(output.scriptPubKey == null ?
                                new byte[0] : output.scriptPubKey.bytes));
                    }
                    outputStream.close();
                    baos.write(BTCUtils.doubleSha256(outputStream.toByteArray()));
                } else if (single && inputIndex < tx.outputs.length) {
                    outputStream.writeInt64(tx.outputs[inputIndex].value);
                    outputStream.write(convertDataToScript(tx.outputs[inputIndex].scriptPubKey == null ?
                            new byte[0] : tx.outputs[inputIndex].scriptPubKey.bytes));
                    outputStream.close();
                    baos.write(BTCUtils.doubleSha256(outputStream.toByteArray()));
                } else {
                    baos.write(new byte[32]);
                }
//                    9. nLocktime of the transaction (4-byte little endian)
                baos.writeInt32(tx.lockTime);
//                    10. sighash type of the signature (4-byte little endian)
                baos.writeInt32(hashType);
                return BTCUtils.doubleSha256(baos.toByteArray());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static boolean verifyFails(Stack<byte[]> stack) {
            byte[] input;
            boolean valid;
            if (stack.isEmpty()) {
                valid = true;
            } else {
                input = stack.pop();
                valid = !(input.length == 0 || (input.length == 1 && input[0] == OP_FALSE));
            }
            return !valid;
        }

        @Override
        public String toString() {
            return convertBytesToReadableString(bytes);
        }

        //converts something like "DUP HASH160 0x14 0xdc44b1164188067c3a32d4780f5996fa14a4f2d9 EQUALVERIFY CHECKSIG" into bytes
        public static byte[] convertReadableStringToBytesCoreStyle(String readableString) {
            String[] tokens = readableString.trim().split("\\s+");
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            for (String token : tokens) {
                switch (token) {
                    case "NOP":
                        os.write(OP_NOP);
                        break;
                    case "DROP":
                        os.write(OP_DROP);
                        break;
                    case "DUP":
                        os.write(OP_DUP);
                        break;
                    case "HASH160":
                        os.write(OP_HASH160);
                        break;
                    case "EQUAL":
                        os.write(OP_EQUAL);
                        break;
                    case "EQUALVERIFY":
                        os.write(OP_EQUALVERIFY);
                        break;
                    case "VERIFY":
                        os.write(OP_VERIFY);
                        break;
                    case "CHECKSIG":
                        os.write(OP_CHECKSIG);
                        break;
                    case "CHECKSIGVERIFY":
                        os.write(OP_CHECKSIGVERIFY);
                        break;
                    case "0":
                        //fallthrough
                    case "FALSE":
                        os.write(OP_FALSE);
                        break;
                    case "TRUE":
                        os.write(OP_TRUE);
                        break;
                    case "1":
                        os.write(OP_TRUE);
                        break;
                    case "2":
                        os.write(OP_2);
                        break;
                    case "3":
                        os.write(OP_3);
                        break;
                    case "NOT":
                        os.write(OP_NOT);
                        break;
                    case "IF":
                        os.write(OP_IF);
                        break;
                    case "ENDIF":
                        os.write(OP_ENDIF);
                        break;
                    case "CODESEPARATOR":
                        os.write(OP_CODESEPARATOR);
                        break;
                    case "CHECKLOCKTIMEVERIFY":
                        os.write(OP_CHECKLOCKTIMEVERIFY);
                        break;
                    case "1ADD":
                        os.write(OP_1ADD);
                        break;
                    case "ADD":
                        os.write(OP_ADD);
                        break;
                    case "1SUB":
                        os.write(OP_1SUB);
                        break;
                    case "CHECKSEQUENCEVERIFY":
                        os.write(OP_CHECKSEQUENCEVERIFY);
                        break;
                    case "CHECKMULTISIG":
                    case "OP_CHECKMULTISIG":
                        os.write(OP_CHECKMULTISIG);
                        break;
                    case "OP_CHECKMULTISIGVERIFY":
                        os.write(OP_CHECKMULTISIGVERIFY);
                        break;
                    default:
                        if (token.startsWith("0x")) {
                            byte[] data = BTCUtils.fromHex(token.substring(2));
                            if (data == null) {
                                throw new IllegalArgumentException("convertReadableStringToBytesCoreStyle - I don't know what does this token mean '" + token + "' in '" + readableString + "'");
                            }
                            try {
                                os.write(data);
                            } catch (IOException e) {
                                throw new RuntimeException("ByteArrayOutputStream behaves weird: " + e);
                            }
                        } else {
                            try {
                                byte[] value = BigInteger.valueOf(Long.parseLong(token)).toByteArray();
                                os.write(value.length);
                                os.write(value);
                            } catch (Exception e) {
                                throw new IllegalArgumentException("convertReadableStringToBytesCoreStyle - I don't know what does this token mean '" + token + "' in '" + readableString + "'");
                            }
                        }
                        break;
                }
            }
            try {
                os.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return os.toByteArray();
        }

        //converts something like "OP_DUP OP_HASH160 ba507bae8f1643d2556000ca26b9301b9069dc6b OP_EQUALVERIFY OP_CHECKSIG" into bytes
        public static byte[] convertReadableStringToBytes(String readableString) {
            String[] tokens = readableString.trim().split("\\s+");
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            for (String token : tokens) {
                switch (token) {
                    case "OP_NOP":
                        os.write(OP_NOP);
                        break;
                    case "OP_DROP":
                        os.write(OP_DROP);
                        break;
                    case "OP_DUP":
                        os.write(OP_DUP);
                        break;
                    case "OP_HASH160":
                        os.write(OP_HASH160);
                        break;
                    case "OP_EQUAL":
                        os.write(OP_EQUAL);
                        break;
                    case "OP_EQUALVERIFY":
                        os.write(OP_EQUALVERIFY);
                        break;
                    case "OP_VERIFY":
                        os.write(OP_VERIFY);
                        break;
                    case "OP_CHECKSIG":
                        os.write(OP_CHECKSIG);
                        break;
                    case "OP_CHECKSIGVERIFY":
                        os.write(OP_CHECKSIGVERIFY);
                        break;
                    case "OP_FALSE":
                        os.write(OP_FALSE);
                        break;
                    case "OP_1":
                        //fallthrough
                    case "OP_TRUE":
                        os.write(OP_TRUE);
                        break;
                    case "OP_2":
                        os.write(OP_2);
                        break;
                    case "OP_CHECKMULTISIG":
                        os.write(OP_CHECKMULTISIG);
                        break;
                    default:
                        if (token.startsWith("OP_")) {
                            throw new IllegalArgumentException("I don't know this operation: " + token);
                        }
                        byte[] data = BTCUtils.fromHex(token);
                        if (data == null) {
                            throw new IllegalArgumentException("convertReadableStringToBytes - I don't know what does this token mean '" + token + "' in '" + readableString + "'");
                        }
                        if (data.length < OP_PUSHDATA1) {
                            os.write(data.length);
                            try {
                                os.write(data);
                            } catch (IOException e) {
                                throw new RuntimeException("ByteArrayOutputStream behaves weird: " + e);
                            }
                        } else if (data.length <= 255) {
                            os.write(OP_PUSHDATA1);
                            os.write(data.length);
                            try {
                                os.write(data);
                            } catch (IOException e) {
                                throw new RuntimeException("ByteArrayOutputStream behaves weird: " + e);
                            }
                        } else {
                            throw new IllegalArgumentException("OP_PUSHDATA2 & OP_PUSHDATA4 are not supported");
                        }
                        break;
                }
            }
            try {
                os.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return os.toByteArray();
        }

        public static String convertBytesToReadableString(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (int pos = 0; pos < bytes.length; pos++) {
                if (sb.length() > 0) {
                    sb.append(' ');
                }
                switch (bytes[pos]) {
                    case OP_NOP:
                        sb.append("OP_NOP");
                        break;
                    case OP_DROP:
                        sb.append("OP_DROP");
                        break;
                    case OP_DUP:
                        sb.append("OP_DUP");
                        break;
                    case OP_HASH160:
                        sb.append("OP_HASH160");
                        break;
                    case OP_EQUAL:
                        sb.append("OP_EQUAL");
                        break;
                    case OP_EQUALVERIFY:
                        sb.append("OP_EQUALVERIFY");
                        break;
                    case OP_VERIFY:
                        sb.append("OP_VERIFY");
                        break;
                    case OP_CHECKSIG:
                        sb.append("OP_CHECKSIG");
                        break;
                    case OP_CHECKSIGVERIFY:
                        sb.append("OP_CHECKSIGVERIFY");
                        break;
                    case OP_FALSE:
                        sb.append("OP_FALSE");
                        break;
                    case OP_TRUE:
                        sb.append("OP_TRUE");
                        break;
                    case OP_2:
                        sb.append("OP_2");
                        break;
                    case OP_3:
                        sb.append("OP_3");
                        break;
                    case OP_4:
                        sb.append("OP_4");
                        break;
                    case OP_5:
                        sb.append("OP_5");
                        break;
                    case OP_6:
                        sb.append("OP_6");
                        break;
                    case OP_7:
                        sb.append("OP_7");
                        break;
                    case OP_8:
                        sb.append("OP_8");
                        break;
                    case OP_16:
                        sb.append("OP_16");
                        break;
                    case OP_CHECKMULTISIG:
                        sb.append("OP_CHECKMULTISIG");
                        break;
                    case OP_CHECKMULTISIGVERIFY:
                        sb.append("OP_CHECKMULTISIGVERIFY");
                        break;
                    case OP_SWAP:
                        sb.append("OP_SWAP");
                        break;
                    case OP_PICK:
                        sb.append("OP_PICK");
                        break;
                    case OP_SHA256:
                        sb.append("OP_SHA256");
                        break;
                    case OP_BOOLAND:
                        sb.append("OP_BOOLAND");
                        break;
                    case OP_SIZE:
                        sb.append("OP_SIZE");
                        break;
                    case OP_NIP:
                        sb.append("OP_NIP");
                        break;
                    case OP_WITHIN:
                        sb.append("OP_WITHIN");
                        break;
                    case OP_IF:
                        sb.append("OP_IF");
                        break;
                    case OP_ELSE:
                        sb.append("OP_ELSE");
                        break;
                    case OP_ENDIF:
                        sb.append("OP_ENDIF");
                        break;
                    case OP_NOT:
                        sb.append("OP_NOT");
                        break;
                    case OP_1ADD:
                        sb.append("OP_1ADD");
                        break;
                    case OP_ADD:
                        sb.append("OP_ADD");
                        break;
                    case OP_CODESEPARATOR:
                        sb.append("OP_CODESEPARATOR");
                        break;
                    case OP_CHECKLOCKTIMEVERIFY:
                        sb.append("OP_CHECKLOCKTIMEVERIFY");
                        break;
                    case OP_CHECKSEQUENCEVERIFY:
                        sb.append("OP_CHECKSEQUENCEVERIFY");
                        break;
                    case OP_1SUB:
                        sb.append("OP_1SUB");
                        break;
                    case OP_FROMALTSTACK:
                        sb.append("OP_FROMALTSTACK");
                        break;
                    case OP_1NEGATE:
                        sb.append("OP_1NEGATE");
                        break;
                    case OP_SUB:
                        sb.append("OP_SUB");
                        break;
                    case OP_VERIF:
                        sb.append("OP_VERIF");
                        break;
                    case OP_RETURN:
                        sb.append("OP_RETURN");
                        break;
                    default:
                        int op = bytes[pos] & 0xff;
                        int len;
                        if (op < OP_PUSHDATA1) {
                            len = op;
                            byte[] data = new byte[len];
                            System.arraycopy(bytes, pos + 1, data, 0, len);
                            sb.append(BTCUtils.toHex(data));
                            pos += data.length;
                        } else if (op == OP_PUSHDATA1) {
                            len = bytes[pos + 1] & 0xff;
                            byte[] data = new byte[len];
                            System.arraycopy(bytes, pos + 2, data, 0, len);
                            sb.append(BTCUtils.toHex(data));
                            pos += 1 + data.length;
                        } else {
                            throw new IllegalArgumentException("I cannot read this data or operation: 0x" + Integer.toHexString(bytes[pos] & 0xff).toUpperCase(Locale.ENGLISH) +
                                    " at " + pos + " in " + BTCUtils.toHex(bytes) + ", decoded so far '" + sb.toString() + "'");
                        }
                        break;
                }
            }
            return sb.toString();
        }

        @Override
        public boolean equals(Object o) {
            return this == o || !(o == null || getClass() != o.getClass()) && Arrays.equals(bytes, ((Script) o).bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }

        public static Script buildOutput(String addressStr) throws BitcoinException {
            try {
                Address address = new Address(addressStr);
                if (address.keyhashType == Address.TYPE_MAINNET || address.keyhashType == Address.TYPE_TESTNET) {
                    //P2PKH
                    ByteArrayOutputStream buf = new ByteArrayOutputStream(25);
                    buf.write(OP_DUP);
                    buf.write(OP_HASH160);
                    writeBytes(address.hash160, buf);
                    buf.write(OP_EQUALVERIFY);
                    buf.write(OP_CHECKSIG);
                    return new Script(buf.toByteArray());
                } else if (address.keyhashType == Address.TYPE_NONE && address.witnessProgram != null && address.witnessProgram.version == 0) {
                    //P2WSH & P2WKH
                    return new Script(address.witnessProgram.getBytes());
                } else if (address.keyhashType == Address.TYPE_P2SH || address.keyhashType == Address.TYPE_P2SH_TESTNET) {
                    //P2SH
                    ByteArrayOutputStream buf = new ByteArrayOutputStream(25);
                    buf.write(OP_HASH160);
                    writeBytes(address.hash160, buf);
                    buf.write(OP_EQUAL);
                    return new Script(buf.toByteArray());
                } else {
                    throw new BitcoinException(BitcoinException.ERR_UNSUPPORTED, "Unsupported address " + address);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
