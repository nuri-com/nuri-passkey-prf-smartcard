import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.bouncycastle.asn1.sec.SECNamedCurves;
import com.licel.jcardsim.bouncycastle.asn1.x9.X9ECParameters;
import com.licel.jcardsim.bouncycastle.math.ec.ECPoint;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import nuri.musig2.NuriMuSig2v019;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * jCardSim regression test for audit finding A1 (MuSig2 nonce lifetime).
 *
 * Pre-fix applet (v1.11): noncesReady/finalized were persistent booleans while
 * nonceK1/nonceK2 were CLEAR_ON_RESET. A power cycle between GET_NONCES and
 * FINALIZE left noncesReady == true with zero nonces, so FINALIZE answered
 * 9000 with s_i = e*a_i*sk and the host could compute sk = s_i / (e*a_i).
 *
 * Post-fix applet (v1.12): the flags live in CLEAR_ON_RESET transient memory
 * and FINALIZE refuses all-zero nonces. After a reset FINALIZE must fail with
 * an error status word and must never return a 32-byte s value.
 *
 * Simulator only. This is not a hardware test.
 */
public final class NonceLifetimeTest {
    private static final String APPLET_AID = "4E5552494D554701";
    private static final int SW_OK = 0x9000;
    private static final int SW_NONCES_NOT_READY = 0x6984;
    private static final int SW_ALREADY_FINALIZED = 0x6985;
    private static final int SW_INVALID_NONCE = 0x6988;

    private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256k1");
    private static final BigInteger N = CURVE.getN();

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        testHappyPathStillSigns();
        testFinalizeAfterPowerCycleIsRefused();
        testFinalizeAfterPowerCycleWithFreshNoncesIsFine();
        testReplayAfterFinalizeIsRefused();
        testHostScalarNormalizationAndParity();
        testZeroNonceDefenseInDepth();
        if (failures != 0) {
            System.err.println("MUSIG2_JCARDSIM_NONCE_LIFETIME_FAILED failures=" + failures);
            System.exit(1);
        }
        System.out.println("MUSIG2_JCARDSIM_NONCE_LIFETIME_OK");
    }

    // ---- scenarios ---------------------------------------------------------

    /** Sanity: version is 1.13 and a normal GET_NONCES -> FINALIZE round verifies. */
    private static void testHappyPathStillSigns() {
        Simulator sim = freshCard();
        byte[] version = ok(sim, apdu(0x01, null));
        check("version byte is 1.14", version[0] == 0x01 && version[1] == 0x0E,
              "got " + hex(version));

        byte[] pubkey = ok(sim, apdu(0x04, null));
        check("KEYGEN returns 33-byte compressed pubkey", pubkey.length == 33, hex(pubkey));

        byte[] nonces = ok(sim, apdu(0x40, null));
        check("GET_NONCES returns 70 bytes", nonces.length == 70, hex(nonces));

        byte[] a = randomScalar();
        byte[] b = randomScalar();
        byte[] e = randomScalar();
        byte[] s = ok(sim, apdu(0x41, concat(a, b, new byte[] {0x00}, e)));
        check("FINALIZE returns 32-byte partial", s.length == 32, hex(s));

        // s_i * G == (K1 + b*K2) + e*a_i*P
        ECPoint k1 = CURVE.getCurve().decodePoint(Arrays.copyOfRange(nonces, 0, 33));
        ECPoint k2 = CURVE.getCurve().decodePoint(Arrays.copyOfRange(nonces, 33, 66));
        ECPoint p = CURVE.getCurve().decodePoint(pubkey);
        ECPoint lhs = CURVE.getG().multiply(new BigInteger(1, s));
        ECPoint rhs = k1.add(k2.multiply(new BigInteger(1, b)))
            .add(p.multiply(new BigInteger(1, e).multiply(new BigInteger(1, a)).mod(N)));
        check("partial signature verifies: s*G == R_i + e*a_i*P", lhs.equals(rhs),
              "lhs=" + hex(lhs.getEncoded()) + " rhs=" + hex(rhs.getEncoded()));
    }

    /** The A1 regression: reset between GET_NONCES and FINALIZE. */
    private static void testFinalizeAfterPowerCycleIsRefused() {
        Simulator sim = freshCard();
        byte[] pubkey = ok(sim, apdu(0x04, null));
        ok(sim, apdu(0x40, null));

        // Power cycle: jCardSim reset() zeroes CLEAR_ON_RESET transient memory
        // and deselects. Re-select the applet as a reader would after ATR.
        sim.reset();
        check("applet re-selectable after reset", sim.selectApplet(aid()), "");
        ok(sim, apdu(0x20, new byte[] {49,50,51,52}));
        boolean[] flags = (boolean[])appletField("sessionFlags");
        check("reset clears both nonce session flags independently", !flags[0] && !flags[1], "");

        byte[] a = randomScalar();
        byte[] b = randomScalar();
        byte[] e = randomScalar();
        Response r = tx(sim, apdu(0x41, concat(a, b, new byte[] {0x00}, e)));
        check("FINALIZE after power cycle is refused (SW != 9000)", r.sw != SW_OK,
              "sw=" + Integer.toHexString(r.sw) + " data=" + hex(r.data));
        check("FINALIZE after power cycle answers 6984 or 6988",
              r.sw == SW_NONCES_NOT_READY || r.sw == SW_INVALID_NONCE,
              "sw=" + Integer.toHexString(r.sw));
        check("FINALIZE after power cycle leaks no bytes", r.data.length == 0, hex(r.data));

        // Pre-fix exploit check: if a 32-byte s had come back, sk = s/(e*a) mod n
        // would reproduce the card pubkey. Prove that this derivation does NOT
        // yield the pubkey from anything the card returned.
        if (r.data.length == 32) {
            BigInteger ea = new BigInteger(1, e).multiply(new BigInteger(1, a)).mod(N);
            BigInteger sk = new BigInteger(1, r.data).multiply(ea.modInverse(N)).mod(N);
            byte[] derived = CURVE.getG().multiply(sk).getEncoded();
            check("private key NOT recoverable from FINALIZE output",
                  !Arrays.equals(compress(derived), pubkey), "sk leaked: " + sk.toString(16));
        }
    }

    /** After a reset the card must still sign once fresh nonces are generated. */
    private static void testFinalizeAfterPowerCycleWithFreshNoncesIsFine() {
        Simulator sim = freshCard();
        ok(sim, apdu(0x04, null));
        ok(sim, apdu(0x40, null));
        sim.reset();
        sim.selectApplet(aid());
        ok(sim, apdu(0x20, new byte[] {49,50,51,52}));
        byte[] nonces = ok(sim, apdu(0x40, null));
        check("fresh GET_NONCES after reset works", nonces.length == 70, hex(nonces));
        byte[] s = ok(sim, apdu(0x41, concat(randomScalar(), randomScalar(), new byte[] {0x01}, randomScalar())));
        check("FINALIZE with fresh nonces after reset works", s.length == 32, hex(s));
    }

    /** Existing invariant: a second FINALIZE on the same nonces is refused. */
    private static void testReplayAfterFinalizeIsRefused() {
        Simulator sim = freshCard();
        ok(sim, apdu(0x04, null));
        ok(sim, apdu(0x40, null));
        byte[] payload = concat(randomScalar(), randomScalar(), new byte[] {0x00}, randomScalar());
        ok(sim, apdu(0x41, payload));
        Response r = tx(sim, apdu(0x41, payload));
        check("replayed FINALIZE is refused", r.sw != SW_OK && r.data.length == 0,
              "sw=" + Integer.toHexString(r.sw));
        check("replayed FINALIZE answers 6984/6985/6988",
              r.sw == SW_NONCES_NOT_READY || r.sw == SW_ALREADY_FINALIZED || r.sw == SW_INVALID_NONCE,
              "sw=" + Integer.toHexString(r.sw));
    }

    /** Noncanonical host a,b,e retain modulo semantics through the APDU path. */
    private static void testHostScalarNormalizationAndParity() {
        Simulator sim = freshCard();
        byte[] pubkey = ok(sim, apdu(0x04, null));
        BigInteger[] values = {BigInteger.ZERO, BigInteger.ONE, N.subtract(BigInteger.ONE),
            N, N.add(BigInteger.ONE), BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)};
        for (int parity = 0; parity < 2; parity++) {
            for (int i = 0; i < values.length; i++) {
                byte[] a = scalarBytes(values[i]);
                byte[] b = scalarBytes(values[(i + 2) % values.length]);
                byte[] e = scalarBytes(values[(i + 4) % values.length]);
                byte[] nonces = ok(sim, apdu(0x40, null));
                byte[] s = ok(sim, apdu(0x41, concat(a, b, new byte[] {(byte)parity}, e)));
                ECPoint k1 = CURVE.getCurve().decodePoint(Arrays.copyOfRange(nonces, 0, 33));
                ECPoint k2 = CURVE.getCurve().decodePoint(Arrays.copyOfRange(nonces, 33, 66));
                ECPoint r = k1.add(k2.multiply(new BigInteger(1, b).mod(N)));
                if (parity == 1) r = r.negate();
                ECPoint p = CURVE.getCurve().decodePoint(pubkey);
                BigInteger ea = new BigInteger(1, e).multiply(new BigInteger(1, a)).mod(N);
                check("noncanonical APDU partial verifies parity=" + parity + " vector=" + i,
                    s.length == 32 && new BigInteger(1, s).compareTo(N) < 0
                        && CURVE.getG().multiply(new BigInteger(1, s)).equals(r.add(p.multiply(ea))),
                    "partial=" + hex(s));
            }
        }
    }

    /** Harness-only fault: leave flags ready but zero either secret nonce. */
    private static void testZeroNonceDefenseInDepth() throws Exception {
        for (String fieldName : new String[] {"nonceK1", "nonceK2"}) {
            Simulator sim = freshCard();
            ok(sim, apdu(0x04, null));
            ok(sim, apdu(0x40, null));
            Arrays.fill((byte[])appletField(fieldName), (byte)0);
            Response r = tx(sim, apdu(0x41,
                concat(randomScalar(), randomScalar(), new byte[] {0}, randomScalar())));
            check("zero " + fieldName + " with ready flags rejected without output",
                r.sw == SW_INVALID_NONCE && r.data.length == 0,
                "sw=" + Integer.toHexString(r.sw) + " data=" + hex(r.data));
            ok(sim, apdu(0x20, new byte[] {49,50,51,52}));
            r = tx(sim, apdu(0x41,
                concat(randomScalar(), randomScalar(), new byte[] {0}, randomScalar())));
            check("zero nonce refusal invalidates session", r.sw == SW_NONCES_NOT_READY,
                "sw=" + Integer.toHexString(r.sw));
        }
    }

    private static Object appletField(String name) {
        try {
            Object applet = com.licel.jcardsim.base.SimulatorSystem.instance().lookupApplet(aid()).getApplet();
            java.lang.reflect.Field field = NuriMuSig2v019.class.getDeclaredField(name);
            field.setAccessible(true);
            return field.get(applet);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("simulator field access: " + name, e);
        }
    }

    private static byte[] scalarBytes(BigInteger value) {
        byte[] raw = value.toByteArray(), out = new byte[32];
        int copy = Math.min(32, raw.length);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    // ---- helpers -----------------------------------------------------------

    private static final class Response {
        final byte[] data;
        final int sw;
        Response(byte[] raw) {
            this.data = Arrays.copyOfRange(raw, 0, raw.length - 2);
            this.sw = ((raw[raw.length - 2] & 0xFF) << 8) | (raw[raw.length - 1] & 0xFF);
        }
    }

    private static AID aid() {
        return AIDUtil.create(APPLET_AID);
    }

    private static Simulator freshCard() {
        Simulator sim = new Simulator();
        sim.installApplet(aid(), NuriMuSig2v019.class);

        if (!sim.selectApplet(aid())) {
            throw new IllegalStateException("applet select failed");
        }
        ok(sim, apdu(0x21, new byte[] {49,50,51,52}));
        ok(sim, apdu(0x20, new byte[] {49,50,51,52}));
        return sim;
    }


    private static byte[] apdu(int ins, byte[] data) {
        if (data == null || data.length == 0) {
            return new byte[] {0x00, (byte) ins, 0x00, 0x00, 0x00};
        }
        byte[] out = new byte[5 + data.length + 1];
        out[0] = 0x00;
        out[1] = (byte) ins;
        out[4] = (byte) data.length;
        System.arraycopy(data, 0, out, 5, data.length);
        out[out.length - 1] = 0x20; // Le
        return out;
    }

    private static Response tx(Simulator sim, byte[] apdu) {
        // Existing scalar/nonce fixtures exercise the 1.14 frame using valid
        // public points; transcript verification remains the host's boundary.
        if ((apdu[1] & 255) == 0x41 && (apdu[4] & 255) == 97) {
            byte[] old = Arrays.copyOfRange(apdu, 5, 102);
            ECPoint r = old[64] == 1 ? CURVE.getG().negate() : CURVE.getG();
            apdu = apdu(0x41, concat(old, ((byte[])appletField("nonceSession")).clone(),
                r.getEncoded(), CURVE.getG().getEncoded()));
        }
        return new Response(sim.transmitCommand(apdu));
    }

    private static byte[] ok(Simulator sim, byte[] apdu) {
        Response r = tx(sim, apdu);
        if (r.sw != SW_OK) {
            throw new IllegalStateException("APDU " + hex(apdu) + " failed sw=" + Integer.toHexString(r.sw));
        }
        return r.data;
    }

    private static byte[] randomScalar() {
        SecureRandom rng = new SecureRandom();
        BigInteger v;
        do {
            v = new BigInteger(256, rng).mod(N);
        } while (v.signum() == 0);
        byte[] out = new byte[32];
        byte[] raw = v.toByteArray();
        int copy = Math.min(32, raw.length);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    private static byte[] compress(byte[] uncompressed65) {
        byte[] out = new byte[33];
        out[0] = (byte) ((uncompressed65[64] & 1) == 0 ? 0x02 : 0x03);
        System.arraycopy(uncompressed65, 1, out, 1, 32);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) len += p.length;
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    private static void check(String name, boolean cond, String detail) {
        if (cond) {
            System.out.println("ok   " + name);
        } else {
            failures++;
            System.out.println("FAIL " + name + " :: " + detail);
        }
    }
}
