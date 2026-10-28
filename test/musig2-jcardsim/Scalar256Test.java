// SPDX-License-Identifier: MIT
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.math.ec.ECPoint;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.JCSystem;
import nuri.musig2.Scalar256;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Clean-room, host-only scalar oracle and jCardSim allocation harness. No JUnit.
 * BigInteger is used only in this test, never as an applet implementation.
 * No inherited card arithmetic or third-party arithmetic source was consulted.
 *
 * Protocol mathematics and public fixtures:
 * https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 * https://github.com/bitcoin/bips/blob/master/bip-0327/vectors/sign_verify_vectors.json
 * Only point operations use jCardSim's already-present shaded BC dependency.
 * This is not a constant-time, fault-resistance, or hardware-performance test.
 */
public final class Scalar256Test {
    private static final BigInteger N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger MAX = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
    private static final long SEED = 0x5343414C41523256L;
    private static final int RANDOM_CASES = 1024;
    private static final String AID = "4E5552495343414C01";
    private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256k1");
    private static Scalar256 scalar;
    private static final List<Object> scratch = new ArrayList<Object>();
    private static long assertions, compareCases, zeroCases, reduceCases, negateCases;
    private static long addCases, mulCases, chains, bipCases, scratchChecks;

    /** Allocates transient arrays inside a real simulator applet install context. */
    public static final class Harness extends Applet {
        private Harness() {
            scalar = new Scalar256();
            register();
        }
        public static void install(byte[] data, short offset, byte length) {
            new Harness();
        }
        public void process(APDU apdu) { }
    }

    public static void main(String[] args) throws Exception {
        Simulator sim = new Simulator();
        sim.installApplet(AIDUtil.create(AID), Harness.class);
        check(sim.selectApplet(AIDUtil.create(AID)), "scalar harness select");
        discoverScratch();
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
        Random fieldRandom = new Random(SEED);
        BigInteger[] edge = {BigInteger.ZERO, BigInteger.ONE, N.subtract(BigInteger.ONE), p.subtract(BigInteger.ONE), MAX};
        for (int i=0;i<1050;i++) {
            BigInteger a=i<25?edge[i/5]:new BigInteger(256,fieldRandom);
            BigInteger b=i<25?edge[i%5]:new BigInteger(256,fieldRandom);
            byte[] result=new byte[32];
            scalar.fieldMultiply(bytes(a),(short)0,bytes(b),(short)0,result,(short)0);
            check(new BigInteger(1,result).equals(a.multiply(b).mod(p)),"field multiply oracle " + i);
        }
        BigInteger[] boundaries = {
            BigInteger.ZERO, BigInteger.ONE, N.subtract(BigInteger.ONE),
            N, N.add(BigInteger.ONE), MAX
        };
        for (BigInteger a : boundaries) {
            unarySweep(bytes(a), true);
            for (BigInteger b : boundaries) pairSweep(bytes(a), bytes(b), true);
        }
        // Each bit position, plus leading-zero and signed-byte transitions.
        for (int bit = 0; bit < 256; bit++) {
            byte[] a = bytes(BigInteger.ONE.shiftLeft(bit));
            byte[] b = bytes(MAX.xor(BigInteger.ONE.shiftLeft(bit)));
            unarySweep(a, false);
            pairSweep(a, b, false);
            // Identical leading bytes: compare must inspect every byte, unsigned.
            compare(bytes(BigInteger.ZERO), a, false);
            compare(a, bytes(BigInteger.ZERO), true);
        }
        Random random = new Random(SEED);
        for (int i = 0; i < RANDOM_CASES; i++) {
            byte[] a = new byte[32], b = new byte[32];
            random.nextBytes(a);
            random.nextBytes(b);
            // Uniform random inputs almost never hit [n,2^256); force those too.
            if ((i & 3) == 0) a = bytes(N.add(BigInteger.valueOf(i)));
            if ((i & 3) == 1) Arrays.fill(a, 0, 16, (byte) 0);
            unarySweep(a, false);
            pairSweep(a, b, false);
            byte[] e = new byte[32], k1 = new byte[32], k2 = new byte[32], sk = new byte[32];
            random.nextBytes(e);
            random.nextBytes(k1);
            random.nextBytes(k2);
            random.nextBytes(sk);
            chain(a, b, e, k1, k2, sk, (i & 1) != 0, (i & 2) != 0);
        }
        // Explicit all-zero, modulus, carry/borrow and noncanonical chain cases.
        for (BigInteger a : boundaries) {
            chain(bytes(a), bytes(MAX), bytes(N.add(BigInteger.ONE)), bytes(a),
                bytes(MAX), bytes(N), false, true);
        }
        bip327();
        sim.reset();
        check(sim.selectApplet(AIDUtil.create(AID)), "scalar harness reselect after reset");
        checkScratch();
        pairSweep(bytes(MAX), bytes(MAX), false);
        System.out.println("SCALAR256_OK assertions=" + assertions
            + " compare=" + compareCases + " isZero=" + zeroCases
            + " reduce=" + reduceCases + " negate=" + negateCases
            + " add=" + addCases + " multiply=" + mulCases
            + " chains=" + chains + " bip327=" + bipCases
            + " scratchArrays=" + scratch.size() + " scratchChecks=" + scratchChecks
            + " seed=" + Long.toHexString(SEED));
    }

    private static void unarySweep(byte[] value, boolean exhaustive) throws Exception {
        byte[] in = filled(80);
        System.arraycopy(value, 0, in, 13, 32);
        byte[] before = in.clone();
        check(Scalar256.isZero(in, (short) 13) == (integer(value).signum() == 0), "isZero");
        zeroCases++;
        check(Arrays.equals(in, before), "isZero preserves input");
        // Both ends of a window and every byte position must affect zero testing.
        if (exhaustive) {
            for (int i = 0; i < 32; i++) {
                byte[] one = filled(80);
                Arrays.fill(one, 13, 45, (byte) 0);
                one[13 + i] = (byte) 0x80;
                check(!Scalar256.isZero(one, (short) 13), "isZero byte " + i);
                zeroCases++;
            }
        }
        for (boolean negate : new boolean[] {false, true}) {
            unary(value, negate, false, 0);
            int[] shifts = exhaustive ? range(-31, 31) : new int[] {-31, -1, 0, 1, 31};
            for (int shift : shifts) unary(value, negate, true, shift);
        }
    }

    private static void unary(byte[] value, boolean negate, boolean alias, int shift)
            throws Exception {
        byte[] in = filled(150), out = alias ? in : filled(150);
        int io = 48, oo = alias ? io + shift : 113;
        System.arraycopy(value, 0, in, io, 32);
        byte[] oldIn = in.clone(), oldOut = out.clone();
        BigInteger expected = integer(value).mod(N);
        if (negate) expected = expected.negate().mod(N);
        if (negate) {
            scalar.negate(in, (short) io, out, (short) oo);
            negateCases++;
        } else {
            scalar.reduce(in, (short) io, out, (short) oo);
            reduceCases++;
        }
        result(out, oo, expected, negate ? "negate" : "reduce");
        unchangedExcept(out, oldOut, oo, "unary output guards");
        if (!alias) check(Arrays.equals(in, oldIn), "unary input unchanged");
        checkScratch();
    }

    private static void pairSweep(byte[] a, byte[] b, boolean exhaustive) throws Exception {
        compare(a, b, false);
        compare(a, b, true);
        for (boolean multiply : new boolean[] {false, true}) {
            binary(a, b, multiply, 0, 0); // separate arrays, nonzero offsets
            binary(a, b, multiply, 5, 0); // shared inputs, disjoint output
            binary(a, b, multiply, 3, 0); // output overlaps both adjacent inputs
            int[] shifts = exhaustive ? range(-31, 31) : new int[] {-31, -1, 0, 1, 31};
            for (int shift : shifts) {
                binary(a, b, multiply, 1, shift); // out == a
                binary(a, b, multiply, 2, shift); // out == b
            }
            // All three references identical; equal and partially overlapping inputs.
            for (int shift : new int[] {-31, 0, 31}) {
                binary(a, a, multiply, 4, shift);
                binary(a, b, multiply, 6, shift);
            }
        }
    }

    private static void compare(byte[] av, byte[] bv, boolean shared) {
        byte[] a = filled(320), b = shared ? a : filled(320);
        int ao = 129, bo = 211;
        System.arraycopy(av, 0, a, ao, 32);
        System.arraycopy(bv, 0, b, bo, 32);
        byte[] oldA = a.clone(), oldB = b.clone();
        int expected = Integer.signum(integer(av).compareTo(integer(bv)));
        check(Scalar256.compare(a, (short) ao, b, (short) bo) == expected,
            "unsigned compare expected=" + expected);
        compareCases++;
        check(Scalar256.compare(b, (short) bo, a, (short) ao) == -expected, "compare reversed");
        compareCases++;
        check(Scalar256.compare(a, (short) ao, a, (short) ao) == 0, "compare self");
        compareCases++;
        check(Arrays.equals(a, oldA) && Arrays.equals(b, oldB), "compare preserves buffers");
    }

    private static void binary(byte[] av, byte[] bv, boolean multiply, int layout, int shift)
            throws Exception {
        byte[] a = filled(320), b = filled(320), out = filled(320);
        int ao = 64, bo = 192, oo = 129;
        if (layout == 1) { out = a; oo = ao + shift; }
        if (layout == 2) { out = b; oo = bo + shift; }
        if (layout == 3) { b = a; out = a; bo = ao + 32; oo = ao + 16; }
        if (layout == 4) { b = a; out = a; bo = ao; oo = ao + shift; }
        if (layout == 5) { b = a; }
        if (layout == 6) { b = a; out = a; bo = ao + 11; oo = ao + shift; }
        System.arraycopy(av, 0, a, ao, 32);
        System.arraycopy(bv, 0, b, bo, 32);
        // Snapshot AFTER arranging overlapping inputs: both operands mean their
        // actual entry-time window, not the originally requested byte strings.
        BigInteger x = integer(a, ao), y = integer(b, bo);
        BigInteger expected = (multiply ? x.multiply(y) : x.add(y)).mod(N);
        byte[] oldA = a.clone(), oldB = b.clone(), oldOut = out.clone();
        op(multiply, a, ao, b, bo, out, oo);
        result(out, oo, expected, "binary layout=" + layout + " shift=" + shift);
        unchangedExcept(out, oldOut, oo, "binary output guards");
        if (a != out) check(Arrays.equals(a, oldA), "first input unchanged");
        if (b != out) check(Arrays.equals(b, oldB), "second input unchanged");
    }

    private static void op(boolean multiply, byte[] a, int ao, byte[] b, int bo,
                           byte[] out, int oo) throws Exception {
        if (multiply) {
            scalar.mulMod(a, (short) ao, b, (short) bo, out, (short) oo);
            mulCases++;
        } else {
            scalar.addMod(a, (short) ao, b, (short) bo, out, (short) oo);
            addCases++;
        }
        checkScratch();
    }

    /** Mirrors b*k2, a*sk, e*(a*sk) with third multiply output==second. */
    private static byte[] chain(byte[] a, byte[] b, byte[] e, byte[] k1, byte[] k2,
                                byte[] sk, boolean negateNonce, boolean negateKey)
            throws Exception {
        byte[] nonce = filled(100), keyTerm = filled(100), secret = sk.clone();
        op(true, b, 0, k2, 0, nonce, 19);
        BigInteger nonceExpected = integer(b).multiply(integer(k2)).add(integer(k1)).mod(N);
        op(false, k1, 0, nonce, 19, nonce, 19);
        if (negateNonce) {
            scalar.negate(nonce, (short) 19, nonce, (short) 19);
            negateCases++;
            checkScratch();
            nonceExpected = nonceExpected.negate().mod(N);
        }
        if (negateKey) {
            scalar.negate(secret, (short) 0, secret, (short) 0);
            negateCases++;
            checkScratch();
        }
        op(true, a, 0, secret, 0, keyTerm, 23);
        op(true, e, 0, keyTerm, 23, keyTerm, 23);
        BigInteger keyExpected = integer(a).multiply(integer(sk)).multiply(integer(e)).mod(N);
        if (negateKey) keyExpected = keyExpected.negate().mod(N);
        result(keyTerm, 23, keyExpected, "third multiply aliases second input");
        op(false, nonce, 19, keyTerm, 23, keyTerm, 23);
        result(keyTerm, 23, nonceExpected.add(keyExpected).mod(N), "partial arithmetic chain");
        chains++;
        return Arrays.copyOfRange(keyTerm, 23, 55);
    }

    /** All six valid public sign_verify fixtures, including the infinity case. */
    private static void bip327() throws Exception {
        String[] publicKeys = {
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661"
        };
        byte[] sk = unhex("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671");
        byte[] secnonce = unhex("508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61"
            + "FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703");
        byte[] pubnonce = unhex("0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA"
            + "0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480");
        byte[] aggregateNonce = unhex("028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61"
            + "037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9");
        byte[][] messages = {
            unhex("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"),
            new byte[0],
            unhex("2626262626262626262626262626262626262626262626262626262626262626262626262626")
        };
        int[][] orders = {{0,1,2}, {1,0,2}, {1,2,0}, {0,1}, {0,1,2}, {0,1,2}};
        int[] messageIndices = {0,0,0,0,1,2};
        String[] expected = {
            "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB",
            "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52",
            "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900",
            "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531",
            "D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D",
            "E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C"
        };
        check(Arrays.equals(compressed(CURVE.getG().multiply(integer(sk))), unhex(publicKeys[0])),
            "BIP327 fixture secret/public key match");
        for (int c = 0; c < orders.length; c++) {
            byte[][] keys = new byte[orders[c].length][];
            for (int i = 0; i < keys.length; i++) keys[i] = unhex(publicKeys[orders[c][i]]);
            byte[] listHash = tagged("KeyAgg list", concat(keys));
            byte[][] coeff = new byte[keys.length][];
            ECPoint q = CURVE.getCurve().getInfinity();
            byte[] signerCoefficient = null;
            for (int i = 0; i < keys.length; i++) {
                // All listed keys are distinct: second distinct key is keys[1].
                coeff[i] = Arrays.equals(keys[i], keys[1]) ? bytes(BigInteger.ONE)
                    : normalized(tagged("KeyAgg coefficient", concat(listHash, keys[i])));
                q = q.add(CURVE.getCurve().decodePoint(keys[i]).multiply(integer(coeff[i])));
                if (orders[c][i] == 0) signerCoefficient = coeff[i];
            }

            byte[] message = messages[messageIndices[c]];
            byte[] aggnonce = c == 3 ? new byte[66] : aggregateNonce;
            byte[] b = normalized(tagged("MuSig/noncecoef", concat(aggnonce, xbytes(q), message)));
            ECPoint r = c == 3 ? CURVE.getG()
                : point(aggnonce, 0).add(point(aggnonce, 33).multiply(integer(b)));
            if (r.isInfinity()) r = CURVE.getG();
            byte[] e = normalized(tagged("BIP0340/challenge", concat(xbytes(r), xbytes(q), message)));
            byte[] actual = chain(signerCoefficient, b, e,
                Arrays.copyOfRange(secnonce, 0, 32), Arrays.copyOfRange(secnonce, 32, 64), sk,
                odd(r), odd(q));
            check(Arrays.equals(actual, unhex(expected[c])),
                "BIP327 sign_verify valid[" + c + "] expected=" + expected[c] + " actual=" + hex(actual));
            ECPoint effectiveNonce = point(pubnonce, 0).add(point(pubnonce, 33).multiply(integer(b)));
            if (odd(r)) effectiveNonce = effectiveNonce.negate();
            BigInteger ea = integer(e).multiply(integer(signerCoefficient)).mod(N);
            if (odd(q)) ea = ea.negate().mod(N);
            ECPoint rhs = effectiveNonce.add(CURVE.getCurve().decodePoint(unhex(publicKeys[0])).multiply(ea));
            check(CURVE.getG().multiply(integer(actual)).equals(rhs),
                "BIP327 partial verification valid[" + c + "]");
            bipCases++;
        }
        check(bipCases == 6, "all six official valid sign_verify cases consumed");
    }

    private static byte[] normalized(byte[] value) throws Exception {
        byte[] out = new byte[32];
        scalar.reduce(value, (short) 0, out, (short) 0);
        reduceCases++;
        result(out, 0, integer(value).mod(N), "BIP hash reduction");
        checkScratch();
        return out;
    }

    private static ECPoint point(byte[] encoding, int offset) {
        return CURVE.getCurve().decodePoint(Arrays.copyOfRange(encoding, offset, offset + 33));
    }
    private static byte[] compressed(ECPoint point) {
        byte[] encoded = point.getEncoded();
        if (encoded.length == 33) return encoded;
        if (encoded.length != 65) throw new IllegalArgumentException("not a finite point");
        byte[] out = Arrays.copyOfRange(encoded, 0, 33);
        out[0] = (byte)(2 | (encoded[64] & 1));
        return out;
    }
    private static boolean odd(ECPoint point) { return compressed(point)[0] == 3; }
    private static byte[] xbytes(ECPoint point) {
        return Arrays.copyOfRange(compressed(point), 1, 33);
    }
    private static byte[] tagged(String tag, byte[] message) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] th = sha.digest(tag.getBytes(StandardCharsets.UTF_8));
        sha.update(th);
        sha.update(th);
        return sha.digest(message);
    }

    /** Inspect transient instance arrays only; static modulus/constants are not scratch. */
    private static void discoverScratch() throws Exception {
        for (Field field : Scalar256.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) || !field.getType().isArray()) continue;
            field.setAccessible(true);
            Object value = field.get(scalar);
            if (value != null && JCSystem.isTransient(value) != JCSystem.NOT_A_TRANSIENT_OBJECT) {
                check(value.getClass().getComponentType().isPrimitive(), "primitive scratch " + field.getName());
                scratch.add(value);
            }
        }
        check(!scratch.isEmpty(), "constructor allocates discoverable transient scratch");
        checkScratch();
    }
    private static void checkScratch() {
        for (Object value : scratch) {
            for (int i = 0; i < Array.getLength(value); i++) {
                Object element = Array.get(value, i);
                boolean zero = element instanceof Boolean ? !((Boolean) element).booleanValue()
                    : element instanceof Character ? ((Character) element).charValue() == 0
                    : ((Number) element).longValue() == 0;
                check(zero, "transient scratch erased at index " + i);
            }
            scratchChecks++;
        }
    }
    private static void result(byte[] out, int offset, BigInteger expected, String label) {
        BigInteger actual = integer(out, offset);
        check(actual.compareTo(N) < 0, label + " canonical output");
        check(actual.equals(expected), label + " expected=" + expected.toString(16)
            + " actual=" + actual.toString(16));
    }
    private static void unchangedExcept(byte[] actual, byte[] before, int offset, String label) {
        for (int i = 0; i < actual.length; i++) {
            if (i < offset || i >= offset + 32) check(actual[i] == before[i], label + " index=" + i);
        }
    }
    private static byte[] filled(int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) out[i] = (byte) (0xA5 ^ (i * 73));
        return out;
    }
    private static int[] range(int from, int to) {
        int[] out = new int[to - from + 1];
        for (int i = 0; i < out.length; i++) out[i] = from + i;
        return out;
    }
    private static BigInteger integer(byte[] value) { return new BigInteger(1, value); }
    private static BigInteger integer(byte[] value, int offset) {
        return integer(Arrays.copyOfRange(value, offset, offset + 32));
    }
    private static byte[] bytes(BigInteger value) {
        if (value.signum() < 0 || value.bitLength() > 256) throw new IllegalArgumentException("not uint256");
        byte[] encoded = value.toByteArray(), out = new byte[32];
        int count = Math.min(encoded.length, 32);
        System.arraycopy(encoded, encoded.length - count, out, 32 - count, count);
        return out;
    }
    private static byte[] unhex(String text) {
        if ((text.length() & 1) != 0) throw new IllegalArgumentException("odd hex");
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(text.charAt(i * 2), 16), lo = Character.digit(text.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("invalid hex");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte value : bytes) out.append(String.format("%02X", value & 255));
        return out.toString();
    }
    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) length += part.length;
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }
    private static void check(boolean condition, String label) {
        assertions++;
        if (!condition) throw new AssertionError(label);
    }
}
