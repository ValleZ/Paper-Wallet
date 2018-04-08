package ru.valle.btc;

import junit.framework.TestCase;

import java.util.Arrays;
import java.util.Locale;

public class Bech32Test extends TestCase {
    public void testValidChecksum() throws Exception {
        String[] validChecksums = {
                "A12UEL5L",
                "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
                "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
                "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
                "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        };
        for (String s : validChecksums) {
            Bech32.decode(s);
        }
    }

    public void testInvalidChecksums() {
        String[] invalidChecksums = {
                " 1nwldj5",
                "\u007F1axkwrx",
                "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
                "pzry9x0s0muk",
                "1pzry9x0s0muk",
                "x1b4n0q5v",
                "li1dgmt3",
                "de1lg7wt\u00FF",
        };
        for (String s : invalidChecksums) {
            try {
                Bech32.decode(s);
                fail();
            } catch (BitcoinException ignored) {
            }
        }
    }

    public void testInvalidAddresses() {
        String[] invalidAddresses = {
                "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
                "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
                "bc1rw5uspcuh",
                "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
                "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
                "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
                "bc1gmk9yu"};
        for (String s : invalidAddresses) {
            try {
                Bech32.decodeSegwitAddress("bc", s);
                Bech32.decodeSegwitAddress("tb", s);
                fail();
            } catch (BitcoinException ignored) {
            }
        }
    }

    private static class Item {
        private final String address;
        private final byte[] scriptpubkey;

        Item(String s, byte[] data) {
            this.address = s;
            this.scriptpubkey = data;
        }
    }

    public void testValidAddresses() throws BitcoinException {
        Item[] validAddress = new Item[]{
                new Item("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                        new byte[]{
                                0x00, 0x14, 0x75, 0x1e, 0x76, (byte) 0xe8, 0x19, (byte) 0x91, (byte) 0x96, (byte) 0xd4, 0x54,
                                (byte) 0x94, 0x1c, 0x45, (byte) 0xd1, (byte) 0xb3, (byte) 0xa3, 0x23, (byte) (byte) 0xf1, 0x43, 0x3b, (byte) 0xd6,
                        }),
                new Item("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                        new byte[]{
                                0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, (byte) 0xc5, 0x16, 0x68, 0x04,
                                (byte) 0xbd, 0x19, 0x20, 0x33, 0x56, (byte) 0xda, 0x13, 0x6c, (byte) 0x98, 0x56, 0x78,
                                (byte) 0xcd, 0x4d, 0x27, (byte) 0xa1, (byte) 0xb8, (byte) 0xc6, 0x32, (byte) 0x96, 0x04, (byte) 0x90, 0x32,
                                0x62,
                        }),

                new Item("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
                        new byte[]{
                                0x51, 0x28, 0x75, 0x1e, 0x76, (byte) 0xe8, 0x19, (byte) 0x91, (byte) 0x96, (byte) 0xd4, 0x54,
                                (byte) 0x94, 0x1c, 0x45, (byte) 0xd1, (byte) 0xb3, (byte) 0xa3, 0x23, (byte) 0xf1, 0x43, 0x3b, (byte) 0xd6,
                                0x75, 0x1e, 0x76, (byte) 0xe8, 0x19, (byte) 0x91, (byte) 0x96, (byte) 0xd4, 0x54, (byte) 0x94, 0x1c,
                                0x45, (byte) 0xd1, (byte) 0xb3, (byte) 0xa3, 0x23, (byte) 0xf1, 0x43, 0x3b, (byte) 0xd6,
                        }),
                new Item("BC1SW50QA3JX3S",
                        new byte[]{
                                0x60, 0x02, 0x75, 0x1e,
                        }),
                new Item("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
                        new byte[]{
                                0x52, 0x10, 0x75, 0x1e, 0x76, (byte) 0xe8, 0x19, (byte) 0x91, (byte) 0x96, (byte) 0xd4, 0x54,
                                (byte) 0x94, 0x1c, 0x45, (byte) 0xd1, (byte) 0xb3, (byte) 0xa3, 0x23,
                        }),
                new Item("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
                        new byte[]{
                                0x00, 0x20, 0x00, 0x00, 0x00, (byte) 0xc4, (byte) 0xa5, (byte) 0xca, (byte) 0xd4, 0x62, 0x21,
                                (byte) 0xb2, (byte) 0xa1, (byte) 0x87, (byte) 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, (byte) 0x99, (byte) 0xd5,
                                (byte) 0xe9, 0x1c, 0x6c, (byte) 0xe2, 0x4d, 0x16, 0x5d, (byte) 0xab, (byte) 0x93, (byte) 0xe8, 0x64,
                                0x33,
                        }),
        };
        for (Item test : validAddress) {
            String hrp = "bc";
            Transaction.Script.WitnessProgram wp;
            try {
                wp = Bech32.decodeSegwitAddress(hrp, test.address);
            } catch (BitcoinException e) {
                hrp = "tb";
                wp = Bech32.decodeSegwitAddress(hrp, test.address);
            }
            byte[] output = wp.getBytes();
            assertTrue(test.address, Arrays.equals(output, test.scriptpubkey));
            String recreated = Bech32.encodeSegwitAddress(hrp, wp.version, wp.program);
            assertEquals(test.address.toLowerCase(Locale.ENGLISH), recreated);
        }
    }

    public void testEncode() throws BitcoinException {
        assertEquals("bc1pqqqsq9txsp", Bech32.encodeSegwitAddress("bc", 1, new byte[]{0, 1}));
    }

    public void testDecode() throws BitcoinException {
        assertTrue(Arrays.equals(new byte[]{0, 1}, Bech32.decodeSegwitAddress("bc", "bc1pqqqsq9txsp").program));
    }

    public void testErrorCases() throws BitcoinException {
        byte[] data = new byte[]{1};
        try {
            Bech32.encodeSegwitAddress("bc", 1, data);
            fail();
        } catch (Exception ignored) {
        }
        data = new byte[41];
        try {
            Bech32.encodeSegwitAddress("bc", 1, data);
            fail();
        } catch (Exception ignored) {
        }
        data = new byte[26];
        try {
            Bech32.encodeSegwitAddress("bc", 0, data);
            fail();
        } catch (Exception ignored) {
        }
        data = new byte[20];
        try {
            Bech32.encodeSegwitAddress("Bc", 0, data);
            fail();
        } catch (Exception ignored) {
        }

        try {
            Bech32.encodeSegwitAddress("bc", -1, data);
            fail();
        } catch (Exception ignored) {
        }
        try {
            Bech32.encodeSegwitAddress("bc", 17, data);
            fail();
        } catch (Exception ignored) {
        }

        try {
            Bech32.decodeSegwitAddress("a", "A12UEL5L");
            fail();
        } catch (Exception ignored) {
        }

        // Decode
        try {
            Bech32.decode("a1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq");
            fail();
        } catch (Exception ignored) {
        }
        try {
            Bech32.decode("1");
            fail();
        } catch (Exception ignored) {
        }
        try {
            Bech32.decode("a1qqqqq");
            fail();
        } catch (Exception ignored) {
        }
        try {
            Bech32.decode("a\u00201qqqqqq");
            fail();
        } catch (Exception ignored) {
        }
        try {
            Bech32.decode("a\u007f1qqqqqq");
            fail();
        } catch (Exception ignored) {
        }
        try {
            Bech32.decode("a1qqqqqb");
            fail();
        } catch (Exception ignored) {
        }
        // Encode
        String hrp = "bc";
        data = new byte[0];
        String bech32String = Bech32.encode(hrp, data);
        assertEquals(bech32String, bech32String.toLowerCase(Locale.ENGLISH));
        hrp = "BC";
        bech32String = Bech32.encode(hrp, data);
        assertEquals(bech32String, bech32String.toUpperCase(Locale.ENGLISH));
        hrp = "bc";
        data = new byte[90 - 7 - hrp.length() + 1];
        try {
            Bech32.encode(hrp, data);
            fail();
        } catch (Exception ignored) {
        }
        hrp = "";
        data = new byte[90 - 7 - hrp.length()];
        try {
            Bech32.encode(hrp, data);
            fail();
        } catch (Exception ignored) {
        }
        hrp = "Bc";
        data = new byte[90 - 7 - hrp.length()];
        try {
            Bech32.encode(hrp, data);
            fail();
        } catch (Exception ignored) {
        }
        hrp = "\u0021\u007e";
        data = new byte[90 - 7 - hrp.length()];
        Bech32.encode(hrp, data);
        hrp = "\u0020c";
        data = new byte[90 - 7 - hrp.length()];
        try {
            Bech32.encode(hrp, data);
            fail();
        } catch (Exception ignored) {
        }
        hrp = "b\u007f";
        data = new byte[90 - 7 - hrp.length()];
        try {
            Bech32.encode(hrp, data);
            fail();
        } catch (Exception ignored) {
        }
        hrp = "bc";
        data = new byte[]{0, 31};
        Bech32.encode(hrp, data);
        hrp = "bc";
        data = new byte[]{32};
        try {
            Bech32.encode(hrp, data);
            fail();
        } catch (Exception ignored) {
        }
    }
}