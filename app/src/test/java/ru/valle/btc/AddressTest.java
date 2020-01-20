package ru.valle.btc;

import org.junit.Test;

import static org.junit.Assert.*;

public class AddressTest {

    @Test
    public void ripemd160HashToAddress() {
        assertEquals("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs", Address.ripemd160HashToAddress(false,
                BTCUtils.fromValidHex("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31")));
        assertEquals("1111111111111111111114oLvT2", Address.ripemd160HashToAddress(false,
                new byte[20]));
        assertEquals("111111111111111111117K4nzc", Address.ripemd160HashToAddress(false,
                new byte[19]));
        assertEquals("1Wh4bh", Address.ripemd160HashToAddress(false,
                new byte[0]));
    }

    @Test
    public void publicKeyToAddress() {
        assertEquals("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs", Address.publicKeyToAddress(
                BTCUtils.fromValidHex("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")));
    }

    @Test
    public void verify() {
        assertTrue(Address.verify("1111111111111111111114oLvT2", false));
        assertTrue(Address.verify("1111111111111111111114oLvT2", true));
        assertFalse(Address.verify("111111111111111111117K4nzc", false));
        assertFalse(Address.verify("111111111111111111117K4nzc", true));
        assertFalse(Address.verify("1Wh4bh", false));
        assertFalse(Address.verify("1Wh4bh", true));
    }
}