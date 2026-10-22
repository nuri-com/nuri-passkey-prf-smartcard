// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Emin Grande and contributors
package nuri.musig2;

import javacard.framework.JCSystem;

/**
 * Independent fixed-width scalar arithmetic for the BIP327/BIP340 order n.
 * Clean-room implementation from the protocol mathematics and W14 section 5.2
 * call contract; no inherited bignum, Satochip or Keycard implementation used.
 * See docs/scalar256.md for provenance, invariants and verification boundaries.
 *
 * Inputs and outputs are unsigned, big-endian, exactly 32 bytes at each offset.
 * Every input is normalized modulo n. Output may overlap either/both inputs,
 * including partial overlap. Methods stage inputs before writing output.
 * Scratch is private, transient CLEAR_ON_DESELECT, and wiped after operations.
 * This object is non-reentrant. No operation allocates memory after construction.
 * Fixed loop bounds and mask selection are source-level properties, not a claim
 * of chip/JVM timing or power-analysis resistance.
 */
public final class Scalar256 {
    private static final short SIZE = (short)32;
    private static final short A = (short)0;
    private static final short B = (short)32;
    private static final short R = (short)64;
    private static final short T = (short)96;
    private static final short D = (short)128;
    private static final byte[] ORDER = {
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xfe,
        (byte)0xba,(byte)0xae,(byte)0xdc,(byte)0xe6,
        (byte)0xaf,(byte)0x48,(byte)0xa0,(byte)0x3b,
        (byte)0xbf,(byte)0xd2,(byte)0x5e,(byte)0x8c,
        (byte)0xd0,(byte)0x36,(byte)0x41,(byte)0x41
    };
    private static final byte[] FIELD_PRIME = {
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
        (byte)0xff,(byte)0xff,(byte)0xff,(byte)0xfe,(byte)0xff,(byte)0xff,(byte)0xfc,(byte)0x2f
    };
    // Public operation mode only; never selected from a secret. Non-reentrant.
    private boolean fieldArithmetic;
    private final byte[] scratch;
    private final RsaMultiply fast = new RsaMultiply();

    public Scalar256() {
        scratch = JCSystem.makeTransientByteArray((short)160, JCSystem.CLEAR_ON_DESELECT);
    }

    /** Unsigned comparison, -1/0/1; scans all 32 bytes in either case. */
    public static short compare(byte[] a, short ao, byte[] b, short bo) {
        short borrow = 0;
        short different = 0;
        for (short i = (short)31; i >= 0; i--) {
            short av = (short)(a[(short)(ao + i)] & 0xff);
            short bv = (short)(b[(short)(bo + i)] & 0xff);
            short delta = (short)(av - bv - borrow);
            borrow = (short)((delta >> 15) & 1);
            different |= (short)(av ^ bv);
        }
        // different is in [0,255], so (different+255)>>8 is its nonzero bit.
        short nonzero = (short)(different + 255);
        return (short)((nonzero >> 8) - (borrow << 1));
    }

    public static boolean isZero(byte[] a, short ao) {
        short bits = 0;
        for (short i = 0; i < SIZE; i++) {
            bits |= (short)(a[(short)(ao + i)] & 0xff);
        }
        return bits == 0;
    }

    public void reduce(byte[] in, short io, byte[] out, short oo) {
        load(in, io, A);
        copy(scratch, A, out, oo);
        clear();
    }

    public void negate(byte[] in, short io, byte[] out, short oo) {
        load(in, io, A);
        short borrow = 0;
        short bits = 0;
        for (short i = (short)31; i >= 0; i--) {
            short av = (short)(scratch[(short)(A + i)] & 0xff);
            short delta = (short)((ORDER[i] & 0xff) - av - borrow);
            scratch[(short)(R + i)] = (byte)delta;
            borrow = (short)((delta >> 15) & 1);
            bits |= av;
        }
        short nonzero = (short)(bits + 255);
        short mask = (short)(-(nonzero >> 8));
        for (short i = 0; i < SIZE; i++) {
            out[(short)(oo + i)] = (byte)(scratch[(short)(R + i)] & mask);
        }
        clear();
    }

    public void addMod(byte[] a, short ao, byte[] b, short bo, byte[] out, short oo) {
        load(a, ao, A);
        load(b, bo, B);
        addCanonical(A, B, R);
        copy(scratch, R, out, oo);
        clear();
    }

    public void mulMod(byte[] a, short ao, byte[] b, short bo, byte[] out, short oo) {
        load(a, ao, A);
        load(b, bo, B);
        fast.multiply(scratch, A, scratch, B, out, oo, fieldArithmetic);
        clear();
    }

    /** Public-point field arithmetic modulo p, sharing the fixed-width engine.
     * Both n and p exceed 2^255, so the same one-subtract and carry rules apply.
     */
    public void fieldMultiply(byte[] a, short ao, byte[] b, short bo, byte[] out, short oo) {
        fieldArithmetic = true;
        try { mulMod(a, ao, b, bo, out, oo); }
        finally { clear(); }
    }

    public void fieldAdd(byte[] a, short ao, byte[] b, short bo, byte[] out, short oo) {
        fieldArithmetic = true;
        try { addMod(a, ao, b, bo, out, oo); }
        finally { clear(); }
    }

    /** Any 256-bit value is below 2*n; one conditional subtraction suffices. */
    private void load(byte[] in, short io, short slot) {
        copy(in, io, scratch, slot);
        subtractSelect(slot, (short)0);
    }

    /** Canonical x,y imply x+y < 2*n, even if the 256-bit sum carries. */
    private void addCanonical(short x, short y, short result) {
        short carry = 0;
        for (short i = (short)31; i >= 0; i--) {
            short sum = (short)((scratch[(short)(x + i)] & 0xff)
                + (scratch[(short)(y + i)] & 0xff) + carry);
            scratch[(short)(result + i)] = (byte)sum;
            carry = (short)(sum >> 8);
        }
        subtractSelect(result, carry);
    }

    /**
     * Reduce the 257-bit value high*2^256 + slot, known to be below 2*n.
     * If high==1 the low subtraction must borrow (because n>2^255).
     * Select subtraction exactly when high==1 OR low>=n, without a branch.
     */
    private void subtractSelect(short slot, short high) {
        byte[] modulus = fieldArithmetic ? FIELD_PRIME : ORDER;
        short borrow = 0;
        for (short i = (short)31; i >= 0; i--) {
            short delta = (short)((scratch[(short)(slot + i)] & 0xff)
                - (modulus[i] & 0xff) - borrow);
            scratch[(short)(D + i)] = (byte)delta;
            borrow = (short)((delta >> 15) & 1);
        }
        short mask = (short)(-(high | (borrow ^ 1)));
        for (short i = 0; i < SIZE; i++) {
            short at = (short)(slot + i);
            scratch[at] = (byte)((scratch[at] & ~mask)
                | (scratch[(short)(D + i)] & mask));
        }
    }

    private static void copy(byte[] in, short io, byte[] out, short oo) {
        for (short i = 0; i < SIZE; i++) {
            out[(short)(oo + i)] = in[(short)(io + i)];
        }
    }

    /** Explicit exceptional-exit cleanup for the applet boundary. */
    public void clear() {
        fieldArithmetic = false;
        for (short i = 0; i < (short)160; i++) {
            scratch[i] = 0;
        }
    }
}
