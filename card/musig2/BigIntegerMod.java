package nuri.musig2;

/**
 * BigInteger modular arithmetic for secp256k1
 * JavaCard implementation for 256-bit operations mod n
 */
public class BigIntegerMod {

    // secp256k1 order n
    public static final byte[] SECP256K1_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6, (byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C, (byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };

    /**
     * Add two 256-bit numbers modulo n
     * result = (a + b) mod n
     * Input-safe: handles aliasing when result == a or result == b
     */
    public static void addMod(byte[] a, short aOff, byte[] b, short bOff,
                              byte[] result, short rOff) {
        short carry = 0;

        // Add a + b
        for (short i = 31; i >= 0; i--) {
            short sum = (short)((a[(short)(aOff + i)] & 0xFF) +
                               (b[(short)(bOff + i)] & 0xFF) + carry);
            result[(short)(rOff + i)] = (byte)sum;
            carry = (short)(sum >> 8);
        }

        // If result >= n, subtract n
        if (carry != 0 || compare(result, rOff, SECP256K1_N, (short)0) >= 0) {
            // Subtract n in-place to handle aliasing
            short borrow = 0;
            for (short i = 31; i >= 0; i--) {
                short diff = (short)((result[(short)(rOff + i)] & 0xFF) -
                                    (SECP256K1_N[i] & 0xFF) - borrow);
                if (diff < 0) {
                    diff += 256;
                    borrow = 1;
                } else {
                    borrow = 0;
                }
                result[(short)(rOff + i)] = (byte)diff;
            }
        }
    }

    /**
     * Subtract two 256-bit numbers modulo n
     * result = (a - b) mod n
     * Input-safe: handles aliasing when result == a or result == b
     */
    public static void subMod(byte[] a, short aOff, byte[] b, short bOff,
                              byte[] result, short rOff) {
        short borrow = 0;

        // Subtract a - b
        for (short i = 31; i >= 0; i--) {
            short diff = (short)((a[(short)(aOff + i)] & 0xFF) -
                                (b[(short)(bOff + i)] & 0xFF) - borrow);
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[(short)(rOff + i)] = (byte)diff;
        }

        // If result is negative, add n
        if (borrow != 0) {
            // Add n in-place to handle aliasing
            short carry = 0;
            for (short i = 31; i >= 0; i--) {
                short sum = (short)((result[(short)(rOff + i)] & 0xFF) +
                                   (SECP256K1_N[i] & 0xFF) + carry);
                result[(short)(rOff + i)] = (byte)sum;
                carry = (short)(sum >> 8);
            }
        }
    }

    /**
     * Multiply two 256-bit numbers modulo n
     * result = (a * b) mod n
     *
     * Input-safe: does not modify a or b
     * temp buffer must be at least 32 bytes
     * result must NOT alias a or b
     */
    public static void mulMod(byte[] a, short aOff, byte[] b, short bOff,
                              byte[] result, short rOff, byte[] temp) {
        // Clear result
        for (short i = 0; i < 32; i++) {
            result[(short)(rOff + i)] = 0;
        }

        // Copy a to temp (read-only copy of multiplicand)
        copyBytes(a, aOff, temp, (short)0, (short)32);

        boolean started = false;

        // Process b from MSB to LSB, bit by bit
        for (short i = 0; i < 32; i++) {
            short byt = (short)(b[(short)(bOff + i)] & 0xFF);  // unsigned
            for (short bit = 7; bit >= 0; bit--) {
                // Check bit value
                boolean bitSet = ((byt >> bit) & 1) != 0;

                if (!started) {
                    // First 1 bit found - initialize result with a
                    if (bitSet) {
                        copyBytes(temp, (short)0, result, rOff, (short)32);
                        started = true;
                    }
                } else {
                    // Not first bit - double then add if bit is set
                    doubleInPlace(result, rOff);
                    if (bitSet) {
                        addMod(result, rOff, temp, (short)0, result, rOff);
                    }
                }
            }
        }
    }

    /**
     * Double a number in place modulo n
     * x = (2 * x) mod n
     */
    private static void doubleInPlace(byte[] x, short xOff) {
        short carry = 0;

        // Shift left by 1 (multiply by 2), processing from LSB to MSB
        for (short i = 31; i >= 0; i--) {
            short val = (short)((x[(short)(xOff + i)] & 0xFF) << 1);
            val |= carry;
            x[(short)(xOff + i)] = (byte)val;
            carry = (short)(val >> 8);
        }

        // If result >= n, subtract n
        if (carry != 0 || compare(x, xOff, SECP256K1_N, (short)0) >= 0) {
            subMod(x, xOff, SECP256K1_N, (short)0, x, xOff);
        }
    }

    /**
     * Negate a number modulo n
     * result = n - a
     */
    public static void negateMod(byte[] a, short aOff, byte[] result, short rOff) {
        subMod(SECP256K1_N, (short)0, a, aOff, result, rOff);
    }

    /**
     * Compare two 256-bit numbers
     * Returns: 1 if a > b, 0 if a == b, -1 if a < b
     */
    private static byte compare(byte[] a, short aOff, byte[] b, short bOff) {
        for (short i = 0; i < 32; i++) {
            short aVal = (short)(a[(short)(aOff + i)] & 0xFF);
            short bVal = (short)(b[(short)(bOff + i)] & 0xFF);
            if (aVal > bVal) return 1;
            if (aVal < bVal) return -1;
        }
        return 0;
    }

    /**
     * Copy bytes from source to destination
     */
    private static void copyBytes(byte[] src, short srcOff,
                                  byte[] dst, short dstOff, short len) {
        for (short i = 0; i < len; i++) {
            dst[(short)(dstOff + i)] = src[(short)(srcOff + i)];
        }
    }

    /**
     * Reduce a 256-bit number modulo n
     * Ensures 0 <= result < n
     */
    public static void reduce(byte[] a, short aOff, byte[] result, short rOff) {
        copyBytes(a, aOff, result, rOff, (short)32);

        while (compare(result, rOff, SECP256K1_N, (short)0) >= 0) {
            subMod(result, rOff, SECP256K1_N, (short)0, result, rOff);
        }
    }
}