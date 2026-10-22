// SPDX-License-Identifier: MIT
package nuri.musig2;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.JCSystem;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/** Host-only BigInteger oracle for the real RSA provider path; no card/reader use. */
public final class RsaMultiplyTest {
    private static final BigInteger N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger P = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger MAX = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
    private static final long SEED = 0x5253414D554C3235L;
    private static final int RANDOM_PAIRS = 5000;
    private static final String AID = "4E55524952534101";
    private static final List<byte[]> SCRATCH = new ArrayList<byte[]>();
    private static RsaMultiply rsa;
    private static long assertions, orderCases, fieldCases, randomOrderPairs, randomFieldPairs;

    public static final class Harness extends Applet {
        private Harness() { rsa = new RsaMultiply(); register(); }
        public static void install(byte[] data, short offset, byte length) { new Harness(); }
        public void process(APDU apdu) { }
    }

    public static void main(String[] args) throws Exception {
        Simulator sim = new Simulator();
        sim.installApplet(AIDUtil.create(AID), Harness.class);
        check(sim.selectApplet(AIDUtil.create(AID)), "RSA harness select");
        for (Field field : RsaMultiply.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) || field.getType() != byte[].class) continue;
            field.setAccessible(true);
            byte[] value = (byte[]) field.get(rsa);
            check(JCSystem.isTransient(value) != JCSystem.NOT_A_TRANSIENT_OBJECT,
                "transient RSA scratch: " + field.getName());
            SCRATCH.add(value);
        }
        check(!SCRATCH.isEmpty(), "RSA scratch discovered");
        scratchCleared();

        // Cartesian boundary products force equality to either modulus, both
        // noncanonical ranges, subtraction/borrow and 257-bit a+b carry paths.
        BigInteger[] edges = {
            BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2),
            N.subtract(BigInteger.ONE), N, N.add(BigInteger.ONE),
            P.subtract(BigInteger.ONE), P, P.add(BigInteger.ONE),
            MAX.subtract(BigInteger.ONE), MAX,
            BigInteger.ONE.shiftLeft(127).subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(128), BigInteger.ONE.shiftLeft(255),
            new BigInteger("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 16),
            new BigInteger("5555555555555555555555555555555555555555555555555555555555555555", 16)
        };
        for (boolean field : new boolean[] {false, true}) {
            for (BigInteger a : edges) {
                for (BigInteger b : edges) multiply(bytes(a), bytes(b), field, 0, 0);
            }
            for (int bit = 0; bit < 256; bit++) {
                BigInteger power = BigInteger.ONE.shiftLeft(bit);
                multiply(bytes(power), bytes(MAX.xor(power)), field, 0, 0);
                multiply(bytes(power.subtract(BigInteger.ONE)), bytes(MAX), field, 0, 0);
            }
            // Every exact/partial output alias, including out==second input.
            for (int shift = -31; shift <= 31; shift++) {
                for (int layout = 1; layout <= 2; layout++) {
                    multiply(bytes(MAX), bytes(MAX), field, layout, shift);
                    multiply(bytes(N), bytes(P), field, layout, shift);
                }
                multiply(bytes(MAX), bytes(MAX), field, 4, shift);
                multiply(bytes(N), bytes(P), field, 5, shift);
            }
        }

        // Count genuinely uniform full-width random pairs separately from edges
        // and alias reruns: at least 5000 distinct draws for EACH modulus.
        Random random = new Random(SEED);
        for (int i = 0; i < RANDOM_PAIRS; i++) {
            byte[] a = new byte[32], b = new byte[32];
            random.nextBytes(a);
            random.nextBytes(b);
            multiply(a, b, false, 0, 0);
            randomOrderPairs++;
            multiply(a, b, true, 0, 0);
            randomFieldPairs++;
            if (i < 128) {
                for (boolean field : new boolean[] {false, true}) {
                    multiply(a, b, field, 1, (i % 63) - 31);
                    multiply(a, b, field, 2, (i % 63) - 31);
                    multiply(a, b, field, 3, 0);
                    multiply(a, b, field, 5, (i % 63) - 31);
                }
            }
        }
        check(randomOrderPairs >= 5000 && randomFieldPairs >= 5000, "random-pair coverage floor");
        sim.reset();
        check(sim.selectApplet(AIDUtil.create(AID)), "RSA harness reselect after reset");
        scratchCleared();
        multiply(bytes(MAX), bytes(MAX), false, 0, 0);
        multiply(bytes(MAX), bytes(MAX), true, 0, 0);
        System.out.println("RSA_MULTIPLY_OK assertions=" + assertions
            + " order=" + orderCases + " field=" + fieldCases
            + " randomPairsN=" + randomOrderPairs + " randomPairsP=" + randomFieldPairs
            + " scratchArrays=" + SCRATCH.size() + " seed=" + Long.toHexString(SEED));
    }

    private static void multiply(byte[] av, byte[] bv, boolean field, int layout, int shift) {
        byte[] a = filled(), b = filled(), out = filled();
        int ao = 64, bo = 192, oo = 129;
        if (layout == 1) { out = a; oo = ao + shift; }
        if (layout == 2) { out = b; oo = bo + shift; }
        if (layout == 3) { b = a; out = a; bo = ao + 32; oo = ao + 16; }
        if (layout == 4) { b = a; out = a; bo = ao; oo = ao + shift; }
        if (layout == 5) { b = a; out = a; bo = ao + 11; oo = ao + shift; }
        System.arraycopy(av, 0, a, ao, 32);
        System.arraycopy(bv, 0, b, bo, 32);
        // Snapshot AFTER laying out overlapping inputs, before any caller writes.
        BigInteger x = integer(a, ao), y = integer(b, bo), modulus = field ? P : N;
        BigInteger expected = x.multiply(y).mod(modulus);
        byte[] beforeA = a.clone(), beforeB = b.clone(), beforeOut = out.clone();
        rsa.multiply(a, (short) ao, b, (short) bo, out, (short) oo, field);
        BigInteger actual = integer(out, oo);
        String label = "mod=" + (field ? "p" : "n") + " layout=" + layout + " shift=" + shift;
        check(actual.compareTo(modulus) < 0, label + " canonical output");
        check(expected.equals(actual), label + " a=" + x.toString(16) + " b=" + y.toString(16)
            + " expected=" + expected.toString(16) + " actual=" + actual.toString(16));
        for (int i = 0; i < out.length; i++) {
            if (i < oo || i >= oo + 32) check(out[i] == beforeOut[i], label + " output guard " + i);
        }
        if (a != out) check(Arrays.equals(a, beforeA), label + " first input preserved");
        if (b != out) check(Arrays.equals(b, beforeB), label + " second input preserved");
        scratchCleared();
        if (field) fieldCases++; else orderCases++;
    }

    private static void scratchCleared() {
        for (byte[] value : SCRATCH) {
            for (int i = 0; i < value.length; i++) check(value[i] == 0, "RSA scratch erased at " + i);
        }
    }
    private static byte[] filled() {
        byte[] value = new byte[320];
        for (int i = 0; i < value.length; i++) value[i] = (byte) (0xa5 ^ (i * 73));
        return value;
    }
    private static BigInteger integer(byte[] value, int offset) {
        return new BigInteger(1, Arrays.copyOfRange(value, offset, offset + 32));
    }
    private static byte[] bytes(BigInteger value) {
        if (value.signum() < 0 || value.bitLength() > 256) throw new IllegalArgumentException("not uint256");
        byte[] encoded = value.toByteArray(), out = new byte[32];
        int length = Math.min(encoded.length, out.length);
        System.arraycopy(encoded, encoded.length - length, out, out.length - length, length);
        return out;
    }
    private static void check(boolean condition, String label) {
        assertions++;
        if (!condition) throw new AssertionError(label);
    }
}
