package test.totp;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.nuri.oath.NuriOathTotp;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * jCardSim tests for card/totp/NuriOathTotp.java. Plain main(), no JUnit.
 *
 * Runs every check twice: once with the native HMAC engine (jCardSim supports
 * ALG_HMAC_SHA1) and once with the install parameter that forces the software
 * RFC 2104 fallback, which is the path a JCOP4 J3R180 / SECORA will take.
 *
 * Vectors: RFC 6238 Appendix B, SHA-1 secret "12345678901234567890", 8 digits.
 */
public final class NuriOathTotpSimTest {

    private static final String AID_HEX = "4E555249544F5450";
    private static final byte[] SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PIN = "1234".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] WRONG_PIN = "9999".getBytes(StandardCharsets.US_ASCII);

    private static final long[] TIMES = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
    private static final String[] CODES = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        for (boolean forceSoftware : new boolean[] {false, true}) {
            String label = forceSoftware ? "software" : "native";
            CardSimulator sim = install(forceSoftware);

            // STATUS before PUT: not provisioned, engine as requested, 5 tries.
            ResponseAPDU st = send(sim, 0x03, new byte[0]);
            check(label + " status sw", 0x9000, st.getSW());
            check(label + " status.provisioned", 0, st.getData()[0]);
            check(label + " status.engine", forceSoftware ? 1 : 0, st.getData()[1]);
            check(label + " status.tries", 5, st.getData()[2]);

            // CALC before PUT -> 6985.
            check(label + " calc before put", 0x6985, send(sim, 0x02, counter(59L)).getSW());

            // Bad PUT shapes -> 6700.
            check(label + " put pin too short", 0x6700, send(sim, 0x01, putData("123".getBytes(), SECRET)).getSW());
            check(label + " put empty secret", 0x6700, send(sim, 0x01, putData(PIN, new byte[0])).getSW());
            check(label + " put secret 65", 0x6700, send(sim, 0x01, putData(PIN, new byte[65])).getSW());
            check(label + " put empty body", 0x6700, send(sim, 0x01, new byte[0]).getSW());
            check(label + " still unprovisioned", 0, send(sim, 0x03, new byte[0]).getData()[0]);

            // First PUT: sets PIN + secret, no PIN known yet.
            check(label + " first put", 0x9000, send(sim, 0x01, putData(PIN, SECRET)).getSW());
            check(label + " status.provisioned after put", 1, send(sim, 0x03, new byte[0]).getData()[0]);

            // RFC 6238 vectors over the public wire format (8-byte counter -> 20-byte HMAC).
            for (int i = 0; i < TIMES.length; i++) {
                ResponseAPDU r = send(sim, 0x02, counter(TIMES[i]));
                check(label + " calc sw T=" + TIMES[i], 0x9000, r.getSW());
                check(label + " hmac len T=" + TIMES[i], 20, r.getData().length);
                String code = truncate(r.getData(), 8);
                check(label + " code T=" + TIMES[i], CODES[i], code);
            }

            // CALC with wrong length -> 6700.
            check(label + " calc len 7", 0x6700, send(sim, 0x02, new byte[7]).getSW());

            // Re-PUT without the right PIN: rejected, secret untouched, tries counted down.
            byte[] other = "ABCDEFGHIJKLMNOPQRST".getBytes(StandardCharsets.US_ASCII);
            check(label + " reput wrong pin", 0x63C4, send(sim, 0x01, putData(WRONG_PIN, other)).getSW());
            check(label + " tries after 1 wrong", 4, send(sim, 0x03, new byte[0]).getData()[2]);
            check(label + " secret unchanged after wrong pin", CODES[0], truncate(send(sim, 0x02, counter(59L)).getData(), 8));

            // Correct PIN: secret replaced, tries reset.
            check(label + " reput right pin", 0x9000, send(sim, 0x01, putData(PIN, other)).getSW());
            check(label + " tries reset", 5, send(sim, 0x03, new byte[0]).getData()[2]);
            String expectOther = truncate(hostHmacSha1(other, counter(59L)), 8);
            check(label + " new secret active", expectOther, truncate(send(sim, 0x02, counter(59L)).getData(), 8));
            check(label + " new secret differs", true, !expectOther.equals(CODES[0]));

            // PIN cannot be changed by re-PUT with a new PIN value: the old PIN must still gate.
            check(label + " reput with new pin value needs old pin", 0x63C4,
                send(sim, 0x01, putData(WRONG_PIN, SECRET)).getSW());
            check(label + " restore secret", 0x9000, send(sim, 0x01, putData(PIN, SECRET)).getSW());

            // Exhaust tries -> 6983, then PUT blocked even with the right PIN, CALC still works.
            int[] expectSw = {0x63C4, 0x63C3, 0x63C2, 0x63C1, 0x6983};
            for (int i = 0; i < expectSw.length; i++) {
                check(label + " wrong pin #" + (i + 1), expectSw[i], send(sim, 0x01, putData(WRONG_PIN, other)).getSW());
            }
            check(label + " blocked right pin", 0x6983, send(sim, 0x01, putData(PIN, other)).getSW());
            check(label + " calc still works when blocked", CODES[0], truncate(send(sim, 0x02, counter(59L)).getData(), 8));
            check(label + " status.tries blocked", 0, send(sim, 0x03, new byte[0]).getData()[2]);

            // Unknown INS -> 6D00.
            check(label + " unknown ins", 0x6D00, send(sim, 0x7F, new byte[0]).getSW());

            // Reset (power cycle): secret and PIN state persist, transient scratch does not matter.
            sim.reset();
            select(sim);
            check(label + " after reset provisioned", 1, send(sim, 0x03, new byte[0]).getData()[0]);
            check(label + " after reset code", CODES[1], truncate(send(sim, 0x02, counter(1111111109L)).getData(), 8));
        }

        if (failures != 0) {
            System.out.println("TOTP_JCARDSIM_FAILED failures=" + failures);
            System.exit(1);
        }
        System.out.println("TOTP_JCARDSIM_OK native+software RFC6238 vectors=" + TIMES.length);
    }

    private static CardSimulator install(boolean forceSoftware) {
        CardSimulator sim = new CardSimulator();
        AID aid = AIDUtil.create(AID_HEX);
        byte[] aidBytes = hex(AID_HEX);
        // GP install data: [Li][AID][Lc][control][La][app data]
        byte[] app = forceSoftware ? new byte[] {0x01} : new byte[0];
        ByteBuffer b = ByteBuffer.allocate(1 + aidBytes.length + 1 + 1 + app.length);
        b.put((byte) aidBytes.length).put(aidBytes).put((byte) 0).put((byte) app.length).put(app);
        byte[] params = b.array();
        sim.installApplet(aid, NuriOathTotp.class, params, (short) 0, (byte) params.length);
        select(sim);
        return sim;
    }

    private static void select(CardSimulator sim) {
        ResponseAPDU r = sim.transmitCommand(new CommandAPDU(AIDUtil.select(AID_HEX)));
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("SELECT failed: " + Integer.toHexString(r.getSW()));
        }
    }

    private static ResponseAPDU send(CardSimulator sim, int ins, byte[] data) {
        return sim.transmitCommand(new CommandAPDU(0x00, ins, 0x00, 0x00, data, 256));
    }

    private static byte[] putData(byte[] pin, byte[] secret) {
        byte[] out = new byte[1 + pin.length + secret.length];
        out[0] = (byte) pin.length;
        System.arraycopy(pin, 0, out, 1, pin.length);
        System.arraycopy(secret, 0, out, 1 + pin.length, secret.length);
        return out;
    }

    private static byte[] counter(long unixTime) {
        return ByteBuffer.allocate(8).putLong(unixTime / 30).array();
    }

    /** RFC 4226 dynamic truncation, host side (same as scripts/card-totp.py truncate()). */
    private static String truncate(byte[] digest, int digits) {
        int o = digest[digest.length - 1] & 0x0F;
        long code = ((digest[o] & 0x7FL) << 24) | ((digest[o + 1] & 0xFFL) << 16)
            | ((digest[o + 2] & 0xFFL) << 8) | (digest[o + 3] & 0xFFL);
        long mod = (long) Math.pow(10, digits);
        return String.format("%0" + digits + "d", code % mod);
    }

    private static byte[] hostHmacSha1(byte[] key, byte[] msg) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
        mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"));
        return mac.doFinal(msg);
    }

    private static byte[] hex(String s) {
        byte[] raw = new BigInteger("10" + s, 16).toByteArray();
        byte[] out = new byte[s.length() / 2];
        System.arraycopy(raw, raw.length - out.length, out, 0, out.length);
        return out;
    }

    private static void check(String name, Object expected, Object actual) {
        if (expected instanceof Integer && actual instanceof Byte) {
            actual = Integer.valueOf(((Byte) actual).intValue() & 0xFF);
        }
        boolean ok = expected.equals(actual);
        String exp = expected instanceof Integer ? Integer.toHexString((Integer) expected) : String.valueOf(expected);
        String act = actual instanceof Integer ? Integer.toHexString((Integer) actual) : String.valueOf(actual);
        System.out.println((ok ? "ok   " : "FAIL ") + name + " expected=" + exp + " actual=" + act);
        if (!ok) {
            failures++;
        }
    }
}
