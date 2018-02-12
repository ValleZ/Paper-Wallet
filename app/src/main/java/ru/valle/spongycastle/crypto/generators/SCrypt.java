package ru.valle.spongycastle.crypto.generators;

/*
 * Nov/2013 Modified by Valentin Konovalov - threading & interruption handling was added. Jun/2015 1.7 sources semantics, rename methods
 *
 Spongy Castle uses the same adaptation of the MIT X11 License as Bouncy Castle.

 Copyright (c) 2000 - 2013 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.engines.Salsa20Engine;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.Pack;

import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class SCrypt {
    private static final int CPU_COUNT = Runtime.getRuntime().availableProcessors();
    private static final ExecutorService THREAD_POOL_EXECUTOR = new ThreadPoolExecutor(
            CPU_COUNT, CPU_COUNT * 2, 1, TimeUnit.SECONDS, new LinkedBlockingQueue<>(128));

    // TODO Validate arguments
    public static byte[] generate(byte[] P, byte[] S, int N, int r, int p, int dkLen) throws InterruptedException {
        try {
            return mfcrypt(P, S, N, r, p, dkLen);
        } catch (ExecutionException e) {
            throw new InterruptedException(e.getMessage());
        }
    }

    private static byte[] mfcrypt(byte[] P, byte[] S, final int N, final int r, int p, int dkLen) throws InterruptedException, ExecutionException {
        int MFLenBytes = r * 128;
        byte[] bytes = singleIterationPBKDF2(P, S, p * MFLenBytes);

        int[] B = null;

        try {
            int BLen = bytes.length >>> 2;
            B = new int[BLen];

            Pack.littleEndianToInt(bytes, 0, B);

            int MFLenWords = MFLenBytes >>> 2;
            ArrayList<Future<int[]>> futures = new ArrayList<>();
            final int BCount = r * 32;
            for (int BOff = 0; BOff < BLen; BOff += MFLenWords) {
                final int[] X = new int[BCount];
                System.arraycopy(B, BOff, X, 0, BCount);
                futures.add(THREAD_POOL_EXECUTOR.submit(() -> {
                    sMix(X, N, r);
                    return X;
                }));
            }
            for (int BOff = 0, i = 0; BOff < BLen; BOff += MFLenWords, i++) {
                System.arraycopy(futures.get(i).get(), 0, B, BOff, BCount);
            }

            Pack.intToLittleEndian(B, bytes, 0);

            return singleIterationPBKDF2(P, bytes, dkLen);
        } finally {
            clear(bytes);
            clear(B);
        }
    }

    private static byte[] singleIterationPBKDF2(byte[] P, byte[] S, int dkLen) {
        PBEParametersGenerator pGen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        pGen.init(P, S, 1);
        KeyParameter key = (KeyParameter) pGen.generateDerivedMacParameters(dkLen * 8);
        return key.getKey();
    }

    private static void sMix(int[] X, int N, int r) throws InterruptedException {
        int BCount = r * 32;

        int[] blockX1 = new int[16];
        int[] blockX2 = new int[16];
        int[] blockY = new int[BCount];

        int[][] V = new int[N][];

        try {
            for (int i = 0; i < N; ++i) {
                V[i] = Arrays.clone(X);
                blockMix(X, blockX1, blockX2, blockY, r);
            }
            if (Thread.interrupted()) {
                throw new InterruptedException();
            }
            int mask = N - 1;
            for (int i = 0; i < N; ++i) {
                int j = X[BCount - 16] & mask;
                xor(X, V[j], 0, X);
                blockMix(X, blockX1, blockX2, blockY, r);
            }
        } finally {
            clearAll(V);
            clearAll(new int[][]{blockX1, blockX2, blockY});
        }
    }

    private static void blockMix(int[] B, int[] X1, int[] X2, int[] Y, int r) {
        System.arraycopy(B, B.length - 16, X1, 0, 16);

        int BOff = 0, YOff = 0, halfLen = B.length >>> 1;

        for (int i = 2 * r; i > 0; --i) {
            xor(X1, B, BOff, X2);

            Salsa20Engine.salsaCore(8, X2, X1);
            System.arraycopy(X1, 0, Y, YOff, 16);

            YOff = halfLen + BOff - YOff;
            BOff += 16;
        }

        System.arraycopy(Y, 0, B, 0, Y.length);
    }

    private static void xor(int[] a, int[] b, int bOff, int[] output) {
        for (int i = output.length - 1; i >= 0; --i) {
            output[i] = a[i] ^ b[bOff + i];
        }
    }

    private static void clear(byte[] array) {
        if (array != null) {
            Arrays.fill(array, (byte) 0);
        }
    }

    private static void clear(int[] array) {
        if (array != null) {
            Arrays.fill(array, 0);
        }
    }

    private static void clearAll(int[][] arrays) {
        for (int[] array : arrays) {
            clear(array);
        }
    }
}
