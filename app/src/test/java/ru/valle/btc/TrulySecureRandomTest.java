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

public class TrulySecureRandomTest extends TestCase {
    private TrulySecureRandom secureRandom;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        secureRandom = new TrulySecureRandom();
    }

    public void testNextInt() {
        int[] baskets = new int[100];
        for (int i = 0; i < 10000; i++) {
            baskets[secureRandom.nextInt(100)]++;
        }
        for (int b : baskets) {
            assertFalse(b == 0);//quite lame
        }
    }

    public void testSeedIsDifferent() {
        TrulySecureRandom secureRandom1 = new TrulySecureRandom();
        TrulySecureRandom secureRandom2 = new TrulySecureRandom();
        assertNotSame(secureRandom1.nextInt(), secureRandom2.nextInt());
    }

    public void testMeanAndDeviation() {
        TrulySecureRandom sr = new TrulySecureRandom();
        long sum = 0;
        double sumDev = 0;
        int count = 100000;
        int max = 1_000_000;
        int expectedMean = max / 2;
        for (int i = 0; i < count; i++) {
            int n = sr.nextInt(max);
            sum += n;
            double err = n - expectedMean;
            sumDev += err * err;
        }
        long meanError = Math.abs(expectedMean - sum / count);
        assertTrue("Mean error is less than 1%: actual error is " +
                (100. * meanError) / max + "%", meanError < max * 0.01);
        double expectedDeviation = Math.sqrt(((double) max) * max / 12);
        double deviation = Math.sqrt(sumDev / count);
        double deviationError = Math.abs(expectedDeviation - deviation);
        assertTrue("Deviation error is less than 1%: actual error is " +
                (100. * deviationError) / expectedDeviation + "%", deviationError < expectedDeviation * 0.01);
    }
}
