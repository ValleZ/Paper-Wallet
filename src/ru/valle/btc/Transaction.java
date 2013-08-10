/**
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

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Stack;

public final class Transaction {
    public final Input[] inputs;
    public final Output[] outputs;
    public final int lockTime;

    public Transaction(byte[] rawBytes) {
        if (rawBytes == null) {
            throw new IllegalArgumentException("empty input");
        }
        BitcoinInputStream bais = null;
        try {
            bais = new BitcoinInputStream(rawBytes);
            int version = bais.readInt32();
            if (version != 1) {
                throw new IllegalArgumentException("unsupported tx version: " + version);
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
                byte[] script = bais.readChars((int) bais.readVarInt());
                outputs[i] = new Output(value, new Script(script));
            }
            lockTime = bais.readInt32();
        } catch (EOFException e) {
            throw new IllegalArgumentException("tx incomplete");
        } catch (IOException e) {
            throw new IllegalArgumentException("unable to read tx");
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
        this.inputs = inputs;
        this.outputs = outputs;
        this.lockTime = lockTime;
    }

    public byte[] getBytes() {
        BitcoinOutputStream baos = new BitcoinOutputStream();
        try {
            baos.writeInt32(1);
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
    }

    public static class Output {
        public final long value;
        public final Script script;

        public Output(long value, Script script) {
            this.value = value;
            this.script = script;
        }

        @Override
        public String toString() {
            return "{\n\"value\":\"" + value * 1e-8 + "\",\"script\":\"" + script + "\"\n}";
        }
    }

    public static final class Script {

        public static class ScriptInvalidException extends Exception {
            public ScriptInvalidException() {
            }

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

        public static final byte SIGHASH_ALL = 1;

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
                throw new RuntimeException();
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

        public void run(Stack<byte[]> stack) throws ScriptInvalidException {
            run(0, null, stack);
        }

        public void run(int inputIndex, Transaction tx, Stack<byte[]> stack) throws ScriptInvalidException {
            for (int pos = 0; pos < bytes.length; pos++) {
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
                            if (!verify(stack)) {
                                throw new ScriptInvalidException("wrong address");
                            }
                        }
                        break;
                    case OP_VERIFY:
                        if (!verify(stack)) {
                            throw new ScriptInvalidException();
                        }
                        break;
                    case OP_CHECKSIG:
                    case OP_CHECKSIGVERIFY:
                        byte[] publicKey = stack.pop();
                        byte[] signatureAndHashType = stack.pop();
                        if (signatureAndHashType[signatureAndHashType.length - 1] != SIGHASH_ALL) {
                            throw new IllegalArgumentException("I cannot check this sig type: " + signatureAndHashType[signatureAndHashType.length - 1]);
                        }
                        byte[] signature = new byte[signatureAndHashType.length - 1];
                        System.arraycopy(signatureAndHashType, 0, signature, 0, signature.length);
                        byte[] hash = hashTransaction(inputIndex, bytes, tx);
                        boolean valid = BTCUtils.verify(publicKey, signature, hash);
                        if (bytes[pos] == OP_CHECKSIG) {
                            stack.push(new byte[]{(byte) (valid ? 1 : 0)});
                        } else {
                            if (!verify(stack)) {
                                throw new ScriptInvalidException("bad signature");
                            }
                        }
                        break;
                    case OP_FALSE:
                        stack.push(new byte[]{0});
                        break;
                    case OP_TRUE:
                        stack.push(new byte[]{1});
                        break;
                    default:
                        if (bytes[pos] < OP_PUSHDATA1) {
                            byte[] data = new byte[bytes[pos]];
                            System.arraycopy(bytes, pos + 1, data, 0, bytes[pos]);
                            stack.push(data);
                            pos += data.length;
                        } else if (bytes[pos] == OP_PUSHDATA1) {
                            int len = bytes[pos + 1] & 0xff;
                            byte[] data = new byte[len];
                            System.arraycopy(bytes, pos + 1, data, 0, len);
                            stack.push(data);
                            pos += 1 + data.length;
                        } else {
                            throw new IllegalArgumentException("I cannot read this data: " + Integer.toHexString(bytes[pos]));
                        }
                        break;
                }
            }
        }

        public static byte[] hashTransaction(int inputIndex, byte[] subscript, Transaction tx) {
            Input[] unsignedInputs = new Input[tx.inputs.length];
            for (int i = 0; i < tx.inputs.length; i++) {
                Input txInput = tx.inputs[i];
                if (i == inputIndex) {
                    unsignedInputs[i] = new Input(txInput.outPoint, new Script(subscript), txInput.sequence);
                } else {
                    unsignedInputs[i] = new Input(txInput.outPoint, new Script(new byte[0]), txInput.sequence);
                }
            }
            Transaction unsignedTransaction = new Transaction(unsignedInputs, tx.outputs, tx.lockTime);
            return hashTransactionForSigning(unsignedTransaction);
        }

        public static byte[] hashTransactionForSigning(Transaction unsignedTransaction) {
            byte[] txUnsignedBytes = unsignedTransaction.getBytes();
            BitcoinOutputStream baos = new BitcoinOutputStream();
            try {
                baos.write(txUnsignedBytes);
                baos.writeInt32(Transaction.Script.SIGHASH_ALL);
                baos.close();
            } catch (Exception e) {
                throw new RuntimeException();
            }
            return BTCUtils.doubleSha256(baos.toByteArray());
        }

        public static boolean verify(Stack<byte[]> stack) {
            byte[] input;
            boolean valid;
            input = stack.pop();
            if (input.length == 0 || (input.length == 1 && input[0] == OP_FALSE)) {
                //false
                stack.push(new byte[]{OP_FALSE});
                valid = false;
            } else {
                //true
                valid = true;
            }
            return valid;
        }

        @Override
        public String toString() {
            return BTCUtils.toHex(bytes);
        }

        @Override
        public boolean equals(Object o) {
            return this == o || !(o == null || getClass() != o.getClass()) && Arrays.equals(bytes, ((Script) o).bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }

        public static Script buildOutput(String address) {
            try {
                byte[] addressWithCheckSumAndNetworkCode = BTCUtils.decodeBase58(address);
                if (addressWithCheckSumAndNetworkCode[0] != 0) {
                    throw new RuntimeException("unknown address type");
                }
                byte[] bareAddress = new byte[20];
                System.arraycopy(addressWithCheckSumAndNetworkCode, 1, bareAddress, 0, bareAddress.length);
                MessageDigest digestSha = MessageDigest.getInstance("SHA-256");
                digestSha.update(addressWithCheckSumAndNetworkCode, 0, addressWithCheckSumAndNetworkCode.length - 4);
                byte[] calculatedDigest = digestSha.digest(digestSha.digest());
                for (int i = 0; i < 4; i++) {
                    if (calculatedDigest[i] != addressWithCheckSumAndNetworkCode[addressWithCheckSumAndNetworkCode.length - 4 + i]) {
                        throw new RuntimeException("bad address");
                    }
                }

                ByteArrayOutputStream buf = new ByteArrayOutputStream(25);
                buf.write(OP_DUP);
                buf.write(OP_HASH160);
                writeBytes(bareAddress, buf);
                buf.write(OP_EQUALVERIFY);
                buf.write(OP_CHECKSIG);
                return new Script(buf.toByteArray());
            } catch (Exception e) {
                throw new RuntimeException();
            }
        }
    }
}
