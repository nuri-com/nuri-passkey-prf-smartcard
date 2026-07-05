package com.nuri.eth;

import javacard.framework.Util;

/**
 * Wrapper for Satochip's Biginteger to provide MuSig2 operations
 */
public class BigIntegerWrapper {
    
    // secp256k1 order n
    public static final byte[] SECP256K1_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6, (byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C, (byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };
    
    /**
     * Initialize Satochip Biginteger
     */
    public static void init() {
        Biginteger.init();
    }
    
    /**
     * Add modulo n
     * result = (a + b) mod n
     * Aliasing-safe: result may overlap with a and/or b.
     *
     * The previous version did `Util.arrayCopy(a, result)` first, which
     * clobbered b when result==b — so addMod(z, rd, rd) computed 2*z instead of
     * z+rd, producing wrong ECDSA s on every signature. We now copy a into
     * result via a byte-wise loop that reads a[i] and b[i] together per index,
     * so neither operand is destroyed before it is read.
     */
    public static void addMod(byte[] a, short a_offset,
                             byte[] b, short b_offset,
                             byte[] result, short result_offset,
                             short size) {
        // Add a + b into result, index by index, so aliasing of result with a
        // or b is safe (each byte of a and b is read before the corresponding
        // byte of result is written).
        short carry = 0;
        for (short i = (short)(size - 1); i >= 0; i--) {
            short sum = (short)((a[(short)(a_offset + i)] & 0xFF)
                             + (b[(short)(b_offset + i)] & 0xFF)
                             + carry);
            result[(short)(result_offset + i)] = (byte)sum;
            carry = (short)(sum >> 8);
        }

        // If carry or result >= n, subtract n
        if (carry != 0 || !Biginteger.lessThan(result, result_offset, SECP256K1_N, (short)0, size)) {
            Biginteger.subtract(result, result_offset, SECP256K1_N, (short)0, size);
        }
    }
    
    /**
     * Subtract modulo n
     * result = (a - b) mod n
     * Aliasing-safe: result may overlap with a and/or b (same rationale as
     * addMod — the previous `Util.arrayCopy(a, result)` clobbered b when
     * result==b).
     */
    public static void subMod(byte[] a, short a_offset,
                             byte[] b, short b_offset,
                             byte[] result, short result_offset,
                             short size) {
        // Subtract b from a into result, index by index (aliasing-safe).
        short borrow = 0;
        for (short i = (short)(size - 1); i >= 0; i--) {
            short diff = (short)((a[(short)(a_offset + i)] & 0xFF)
                              - (b[(short)(b_offset + i)] & 0xFF)
                              - borrow);
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[(short)(result_offset + i)] = (byte)diff;
        }

        // If borrow (result negative), add n
        if (borrow != 0) {
            Biginteger.add_carry(result, result_offset, SECP256K1_N, (short)0, size);
        }
    }
    
    /**
     * Multiply modulo n
     * result = (a * b) mod n
     * IMPORTANT: result must NOT overlap with a or b!
     * temp must be at least 96 bytes (Satochip's BUFFER_SIZE)
     */
    public static void mulMod(byte[] a, short a_offset,
                             byte[] b, short b_offset,
                             byte[] result, short result_offset,
                             byte[] temp, short temp_offset,
                             short size) {
        // Clear the full 96-byte workspace first
        Util.arrayFillNonAtomic(temp, temp_offset, (short)96, (byte)0);
        
        // Use Satochip's multiplication with RSA trick
        // This puts the full product (64 bytes) into temp
        if (Biginteger.FLAG_FAST_MULT_VIA_RSA) {
            Biginteger.mult_rsa_trick(a, a_offset, b, b_offset, size, temp, temp_offset);
        } else {
            // Fallback to standard multiplication
            // Standard multiplication
            for (short i = (short)(size - 1); i >= 0; i--) {
                short bByte = (short)(b[(short)(b_offset + i)] & 0xFF);
                if (bByte != 0) {
                    short carry = 0;
                    for (short j = (short)(size - 1); j >= 0; j--) {
                        short prod = (short)((short)(a[(short)(a_offset + j)] & 0xFF) * bByte + carry);
                        short resIndex = (short)(temp_offset + i + j + 1);
                        prod += (short)(temp[resIndex] & 0xFF);
                        temp[resIndex] = (byte)prod;
                        carry = (short)(prod >> 8);
                    }
                    temp[(short)(temp_offset + i)] = (byte)carry;
                }
            }
        }
        
        // Now reduce the product modulo n using the full 96-byte buffer
        // This matches Satochip's approach exactly
        Biginteger.mod(temp, temp_offset, (short)96, SECP256K1_N, (short)0, size);
        
        // After mod on a 96-byte buffer, the reduced 32-byte result is at offset 64
        // Copy from temp_offset + 64
        Util.arrayCopy(temp, (short)(temp_offset + 64), result, result_offset, size);
    }
    
    /**
     * Negate modulo n
     * result = n - a
     */
    public static void negateMod(byte[] a, short a_offset,
                                byte[] result, short result_offset,
                                short size) {
        // result = n - a
        Util.arrayCopy(SECP256K1_N, (short)0, result, result_offset, size);
        Biginteger.subtract(result, result_offset, a, a_offset, size);
    }
}