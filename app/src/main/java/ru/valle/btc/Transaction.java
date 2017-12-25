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

import android.support.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

    public Transaction(Input[] inputs, Output[] outputs, int lockTime) {
        this.version = 1;
        this.inputs = inputs;
        this.outputs = outputs;
        this.lockTime = lockTime;
        this.scriptWitnesses = new byte[0][][];
    }

    public Transaction(int version, Input[] inputs, Output[] outputs, int lockTime) {
        this.version = version;
        this.inputs = inputs;
        this.outputs = outputs;
        this.lockTime = lockTime;
        this.scriptWitnesses = new byte[0][][];
    }

    boolean isCoinBase() {
        return inputs.length == 1 && inputs[0].outPoint.isNull();
    }

    public byte[] getBytes() {
        BitcoinOutputStream baos = new BitcoinOutputStream();
        try {
            baos.writeInt32(version);
            baos.writeVarInt(inputs.length);
            for (Input input : inputs) {
                baos.write(BTCUtils.reverse(input.outPoint.hash));
                baos.writeInt32(input.outPoint.index);
                int scriptLen = input.script == null ? 0 : input.script.bytes.length;
                baos.writeVarInt(scriptLen);
                if (scriptLen > 0) {
                    baos.write(input.script.bytes);
                }
                baos.writeInt32(input.sequence);
            }
            baos.writeVarInt(outputs.length);
            for (Output output : outputs) {
                baos.writeInt64(output.value);
                int scriptLen = output.script == null ? 0 : output.script.bytes.length;
                baos.writeVarInt(scriptLen);
                if (scriptLen > 0) {
                    baos.write(output.script.bytes);
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
                ",\n\"lockTime\":\"" + lockTime + "\"}\n";
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

    public static class Input {
        public final OutPoint outPoint;
        public final Script script;
        public final int sequence;

        public Input(OutPoint outPoint, Script script, int sequence) {
            this.outPoint = outPoint;
            this.script = script;
            this.sequence = sequence;
        }

        @Override
        public String toString() {
            return "{\n\"outPoint\":" + outPoint + ",\n\"script\":\"" + script + "\",\n\"sequence\":\"" + Integer.toHexString(sequence) + "\"\n}\n";
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
    }

    public static class Output {
        public final long value;
        public final Script script;

        public Output(long value, @NonNull Script script) {
            this.value = value;
            this.script = script;
        }

        @Override
        public String toString() {
            return "{\n\"value\":\"" + value * 1e-8 + "\",\"script\":\"" + script + "\"\n}";
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
        public static final int SCRIPT_ALL_SUPPORTED = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_SIGPUSHONLY;

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
        public static final byte OP_16 = 0x60;
        public static final byte OP_CHECKMULTISIG = (byte) 0xae;
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
        public static final int SIGHASH_ANYONE_CAN_PAY = 0x80;
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

        private static void writeBytes(byte[] data, ByteArrayOutputStream baos) throws IOException {
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
            return run(0, null, stack, SCRIPT_ALL_SUPPORTED);
        }

        public boolean run(int inputIndex, @SuppressWarnings("NullableProblems") @NonNull Transaction tx,
                           Stack<byte[]> stack, int flags) throws ScriptInvalidException {
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
                            if (signatureAndHashType[signatureAndHashType.length - 1] == SIGHASH_ALL) {
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
                                //if (sigversion == SIGVERSION_BASE)
                                subScript = findAndDelete(subScript, convertDataToScript(signatureAndHashType));
                                byte[] hash = hashTransaction(inputIndex, subScript, tx, Transaction.Script.SIGHASH_ALL);
                                valid = BTCUtils.verify(publicKey, signature, hash);
                            } else {
                                throw new NotImplementedException("Unsupported hash type " + signatureAndHashType[signatureAndHashType.length - 1]);
                            }
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
                    case OP_16:
                        stack.push(new byte[]{16});
                        break;
                    case OP_1NEGATE:
                        stack.push(new byte[]{-1});
                        break;
                    case OP_CHECKMULTISIG:
                        throw new NotImplementedException("OP_CHECKMULTISIG not implemented");
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
                        int x = stack.pop()[0];
                        int min = stack.pop()[0];
                        int max = stack.pop()[0];
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
                        long txLockTime = tx.lockTime & 0xFFFFFFFFL;
                        if (!((txLockTime < LOCKTIME_THRESHOLD && nLockTime < LOCKTIME_THRESHOLD) ||
                                (txLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD))) {
                            return false;
                        }
                        if (nLockTime > txLockTime) {
                            return false;
                        }
                        if (0xFFFFFFFF == tx.inputs[inputIndex].sequence) {
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

        private static boolean checkSignatureEncoding(byte[] vchSig, int flags) {
            // Empty signature. Not strictly DER encoded, but allowed to provide a
            // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
            if (vchSig.length == 0) {
                return true;
            }
            if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !isValidSignatureEncoding(vchSig)) {
                return false;
            }
//            else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !IsLowDERSignature(vchSig, serror)) {
//                 serror is set
//                return false;
//            } else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsDefinedHashtypeSignature(vchSig)) {
//                return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
//            }
            return true;
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
            if (bytes.length < OP_PUSHDATA1) {
                byte[] script = new byte[bytes.length + 1];
                script[0] = (byte) bytes.length;
                System.arraycopy(bytes, 0, script, 1, bytes.length);
                return script;
            } else {
                throw new NotImplementedException("Data is too big: " + bytes.length);
            }
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

        private static int getScriptTokenLengthAt(byte[] script, int pos) {
            int op = script[pos] & 0xff;
            if (op > OP_PUSHDATA4) {
                return 1;
            }
            if (op < OP_PUSHDATA1) {
                return 1 + op;
            }
            if (op == OP_PUSHDATA1) {
                return 1 + (script[pos + 1] & 0xff);
            }
            throw new NotImplementedException("No large data load implemented");
        }

        public boolean isPayToScriptHash() {
            return bytes.length == 23 &&
                    bytes[0] == OP_HASH160 &&
                    bytes[1] == 0x14 &&
                    bytes[22] == OP_EQUAL;
        }

        @SuppressWarnings("unused")
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

        public boolean isNull() {
            return bytes.length == 0;
        }

        public static byte[] hashTransaction(int inputIndex, byte[] subScript, Transaction tx, int hashType) {
            if (tx != null && (hashType & Transaction.Script.SIGHASH_MASK) == Transaction.Script.SIGHASH_SINGLE && inputIndex >= tx.outputs.length) {
                return new byte[]{1};
            }
            subScript = findAndDelete(subScript, new byte[]{OP_CODESEPARATOR});
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
            switch (hashType & Transaction.Script.SIGHASH_MASK) {
                case Script.SIGHASH_NONE:
                    outputs = new Output[0];
                    for (int i = 0; i < inputsCount; i++) {
                        if (i != inputIndex) {
                            unsignedInputs[i] = new Input(unsignedInputs[i].outPoint, unsignedInputs[i].script, 0);
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
                            unsignedInputs[i] = new Input(unsignedInputs[i].outPoint, unsignedInputs[i].script, 0);
                        }
                    }
                    break;
                default:
                    outputs = tx == null ? new Output[0] : tx.outputs;
                    break;
            }

            if ((hashType & Transaction.Script.SIGHASH_ANYONE_CAN_PAY) != 0) {
                unsignedInputs = new Input[]{unsignedInputs[inputIndex]};
            }

            Transaction unsignedTransaction = new Transaction(tx == null ? 1 : tx.version, unsignedInputs, outputs, tx == null ? 0 : tx.lockTime);
            return hashTransactionForSigning(unsignedTransaction, hashType);
        }

        public static byte[] hashTransactionForSigning(Transaction unsignedTransaction) {
            return hashTransactionForSigning(unsignedTransaction, Transaction.Script.SIGHASH_ALL);
        }

        public static byte[] hashTransactionForSigning(Transaction unsignedTransaction, int hashType) {
            byte[] txUnsignedBytes = unsignedTransaction.getBytes();
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
                    case OP_16:
                        sb.append("OP_16");
                        break;
                    case OP_CHECKMULTISIG:
                        sb.append("OP_CHECKMULTISIG");
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
                                    " at " + pos + " in " + BTCUtils.toHex(bytes));
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

        public static Script buildOutput(String address) throws BitcoinException {
            //noinspection TryWithIdenticalCatches
            try {
                byte[] addressWithCheckSumAndNetworkCode = BTCUtils.decodeBase58(address);
                if (addressWithCheckSumAndNetworkCode[0] != 0 && addressWithCheckSumAndNetworkCode[0] != 111) {
                    throw new BitcoinException(BitcoinException.ERR_UNSUPPORTED, "Unknown address type", address);
                }
                byte[] bareAddress = new byte[20];
                System.arraycopy(addressWithCheckSumAndNetworkCode, 1, bareAddress, 0, bareAddress.length);
                MessageDigest digestSha = MessageDigest.getInstance("SHA-256");
                digestSha.update(addressWithCheckSumAndNetworkCode, 0, addressWithCheckSumAndNetworkCode.length - 4);
                byte[] calculatedDigest = digestSha.digest(digestSha.digest());
                for (int i = 0; i < 4; i++) {
                    if (calculatedDigest[i] != addressWithCheckSumAndNetworkCode[addressWithCheckSumAndNetworkCode.length - 4 + i]) {
                        throw new BitcoinException(BitcoinException.ERR_BAD_FORMAT, "Bad address", address);
                    }
                }

                ByteArrayOutputStream buf = new ByteArrayOutputStream(25);
                buf.write(OP_DUP);
                buf.write(OP_HASH160);
                writeBytes(bareAddress, buf);
                buf.write(OP_EQUALVERIFY);
                buf.write(OP_CHECKSIG);
                return new Script(buf.toByteArray());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
