// SPDX-License-Identifier: MIT
package test.vault;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.nuri.vault.NuriVault;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/** Real applet in jCardSim. Constants from RFC 4231 section 4 (not applet code). */
public final class NuriVaultSimTest {
    public static final String AID = "4E555249564C5401";
    private static final byte[] PIN = ascii("123456");
    private static int checks;
    private static int vectors;

    public static void main(String[] args) throws Exception {
        CardSimulator sim = install();
        bytes("blank status", hex("01000510"), ok(sim, 1, new byte[0]));
        for (int ins : new int[] {0x20, 0x30, 0x31, 0x40, 0x41, 0x50}) {
            sw("first use must set PIN " + ins, 0x6985, send(sim, ins, new byte[0]));
        }
        sw("init PIN too short", 0x6700, send(sim, 0x10, ascii("123")));
        sw("init PIN too long", 0x6700, send(sim, 0x10, new byte[17]));
        ok(sim, 0x10, PIN);
        sw("cannot replace PIN", 0x6985, send(sim, 0x10, ascii("654321")));
        for (int ins : new int[] {0x30, 0x31, 0x40, 0x41, 0x50}) {
            sw("setup is not VERIFY " + ins, 0x6982, send(sim, ins, new byte[0]));
        }
        verify(sim);
        bytes("empty page0", new byte[0], ok(sim, 0x31, new byte[0]));
        bytes("empty page1", new byte[0], okPage(sim, 1));
        sw("wrong CLA", 0x6E00, tx(sim, 0, 1, 0, 0, new byte[0]));
        sw("logical channel not accepted", 0x6E00, tx(sim, 0x81, 1, 0, 0, new byte[0]));
        sw("chaining not accepted", 0x6E00, tx(sim, 0x90, 1, 0, 0, new byte[0]));
        sw("P1", 0x6A86, tx(sim, 0x80, 1, 1, 0, new byte[0]));
        sw("P2", 0x6A86, tx(sim, 0x80, 1, 0, 1, new byte[0]));
        sw("page2", 0x6A86, tx(sim, 0x80, 0x31, 2, 0, new byte[0]));
        sw("unknown instruction", 0x6D00, send(sim, 0x7F, new byte[0]));
        sw("status trailing data", 0x6700, send(sim, 1, new byte[1]));
        sw("list trailing data", 0x6700, send(sim, 0x31, new byte[1]));
        sw("invalid class", 0x6A80, send(sim, 0x30, put(3, ascii("A"), ascii("K"))));
        sw("PUT name zero", 0x6700, send(sim, 0x30, put(1, new byte[0], ascii("KEY"))));
        sw("PUT name 17", 0x6700, send(sim, 0x30, put(1, new byte[17], ascii("K"))));
        sw("PUT empty key", 0x6700, send(sim, 0x30, put(1, ascii("A"), new byte[0])));
        sw("PUT key65", 0x6700, send(sim, 0x30, put(1, ascii("A"), new byte[65])));
        for (int ins : new int[] {0x40, 0x41, 0x50}) {
            sw("missing " + ins, 0x6A88, send(sim, ins, named(ascii("ABSENT"), new byte[0])));
            sw("name empty " + ins, 0x6700, send(sim, ins, new byte[0]));
            sw("name zero " + ins, 0x6700, send(sim, ins, new byte[] {0}));
            sw("name truncated " + ins, 0x6700, send(sim, ins, new byte[] {2, 1}));
            sw("name too long " + ins, 0x6700, send(sim, ins, named(new byte[17], new byte[0])));
        }
        vector(sim, "RFC1", repeat(0x0B, 20), ascii("Hi There"),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        vector(sim, "RFC2", ascii("Jefe"), ascii("what do ya want for nothing?"),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        vector(sim, "RFC3", repeat(0xAA, 20), repeat(0xDD, 50),
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        byte[] key25 = new byte[25];
        for (int i = 0; i < key25.length; i++) key25[i] = (byte) (i + 1);
        vector(sim, "RFC4", key25, repeat(0xCD, 50),
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
        byte[] truncName = ascii("RFC5");
        ok(sim, 0x30, put(1, truncName, repeat(0x0C, 20)));
        byte[] truncated = ok(sim, 0x40, named(truncName, ascii("Test With Truncation")));
        bytes("RFC4231 case5 truncated", hex("a3b6167473100ee06e0c796c2955552b"), Arrays.copyOf(truncated, 16));
        vectors++;
        // RFC cases 6/7 have 131-byte keys, outside the explicit 64-byte import limit.
        sw("RFC long key refused not silently truncated", 0x6700,
                send(sim, 0x30, put(1, ascii("LONG"), repeat(0xAA, 131))));
        byte[] boundaryName = ascii("1234567890ABCDEF");
        byte[] boundaryKey = repeat(0xF1, 64);
        ok(sim, 0x30, put(1, boundaryName, boundaryKey));
        for (int length : new int[] {0, 1, 63, 64, 65, 238}) {
            byte[] message = repeat(length, length);
            bytes("JCE boundary " + length, hostHmac(boundaryKey, message), ok(sim, 0x40, named(boundaryName, message)));
        }
        byte[] bearerName = ascii("TOKEN");
        byte[] bearer = ascii("fixture-bearer-never-a-credential");
        ok(sim, 0x30, put(2, bearerName, bearer));
        bytes("bearer reveal", bearer, ok(sim, 0x41, named(bearerName, new byte[0])));
        sw("bearer cannot HMAC", 0x6985, send(sim, 0x40, named(bearerName, ascii("m"))));
        sw("reveal trailing data", 0x6700, send(sim, 0x41, named(bearerName, new byte[1])));
        sw("delete trailing data", 0x6700, send(sim, 0x50, named(bearerName, new byte[1])));
        sw("class immutable on duplicate", 0x6985, send(sim, 0x30, put(2, ascii("RFC1"), bearer)));
        sw("HMAC never revealable", 0x6985, send(sim, 0x41, named(ascii("RFC1"), new byte[0])));
        // A failed VERIFY invalidates an already-authenticated session.
        sw("wrong PIN", 0x63C4, send(sim, 0x20, ascii("654321")));
        for (int ins : new int[] {0x30, 0x31, 0x40, 0x41, 0x50}) {
            sw("wrong VERIFY revokes auth " + ins, 0x6982, send(sim, ins, new byte[0]));
        }
        bytes("tries4", hex("01010410"), ok(sim, 1, new byte[0]));
        verify(sim);
        bytes("tries restored on success", hex("01010510"), ok(sim, 1, new byte[0]));
        select(sim); // select even the same AID must require new authentication.
        sw("reselect logs out", 0x6982, send(sim, 0x41, named(bearerName, new byte[0])));
        verify(sim);
        sim.reset();
        select(sim);
        sw("reset logs out", 0x6982, send(sim, 0x40, named(ascii("RFC1"), ascii("Hi There"))));
        verify(sim);
        bytes("persistent bearer", bearer, ok(sim, 0x41, named(bearerName, new byte[0])));
        bytes("persistent HMAC", hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                ok(sim, 0x40, named(ascii("RFC1"), ascii("Hi There"))));
        ok(sim, 0x50, named(bearerName, new byte[0]));
        sw("delete missing afterwards", 0x6A88, send(sim, 0x41, named(bearerName, new byte[0])));
        ok(sim, 0x30, put(1, bearerName, ascii("new-class-after-explicit-delete")));
        sw("reused slot class not old bearer", 0x6985, send(sim, 0x41, named(bearerName, new byte[0])));

        // Fresh store: exactly 16 full-length names; both LIST pages are 144 bytes.
        CardSimulator full = install();
        ok(full, 0x10, PIN);
        verify(full);
        for (int i = 0; i < 16; i++) {
            byte[] name = ascii(String.format("SLOT%012d", i));
            ok(full, 0x30, put((i & 1) + 1, name, repeat(i + 1, 64)));
        }
        for (int page = 0; page < 2; page++) {
            byte[] list = okPage(full, page);
            equal("full page length", 144, list.length);
            for (int i = 0; i < 8; i++) {
                int id = page * 8 + i;
                equal("list kind", (id & 1) + 1, list[i * 18] & 0xFF);
                equal("list name length", 16, list[i * 18 + 1] & 0xFF);
                bytes("list exact name", ascii(String.format("SLOT%012d", id)), Arrays.copyOfRange(list, i * 18 + 2, (i + 1) * 18));
            }
        }
        sw("full store", 0x6A84, send(full, 0x30, put(2, ascii("OVERFLOW"), bearer)));
        sw("duplicate in full store", 0x6985, send(full, 0x30, put(2, ascii("SLOT000000000000"), bearer)));
        ok(full, 0x50, named(ascii("SLOT000000000008"), new byte[0]));
        equal("hole in page1", 126, okPage(full, 1).length);
        ok(full, 0x30, put(2, ascii("REUSED"), bearer));
        bytes("slot reuse exact secret", bearer, ok(full, 0x41, named(ascii("REUSED"), new byte[0])));
        // Exhaustion persists through reset. Every secret operation stops, including HMAC.
        int[] errors = {0x63C4, 0x63C3, 0x63C2, 0x63C1, 0x6983};
        for (int error : errors) sw("five wrong attempts", error, send(full, 0x20, ascii("999999")));
        sw("blocked correct PIN", 0x6983, send(full, 0x20, PIN));
        for (int ins : new int[] {0x30, 0x31, 0x40, 0x41, 0x50}) {
            sw("blocked operation " + ins, 0x6983, send(full, ins, new byte[0]));
        }
        full.reset();
        select(full);
        bytes("blocked persists", hex("01010010"), ok(full, 1, new byte[0]));
        sw("blocked after reset", 0x6983, send(full, 0x20, PIN));
        sw("no reset command", 0x6D00, send(full, 0x7F, PIN));
        System.out.println("VAULT_JCARDSIM_OK checks=" + checks + " RFC4231_vectors=" + vectors + " engine=software-sha256");
    }

    public static CardSimulator install() {
        CardSimulator sim = new CardSimulator();
        sim.installApplet(AIDUtil.create(AID), NuriVault.class);
        select(sim);
        return sim;
    }

    public static void select(CardSimulator sim) {
        sw("SELECT", 0x9000, sim.transmitCommand(new CommandAPDU(AIDUtil.select(AID))));
    }

    private static void vector(CardSimulator sim, String name, byte[] key, byte[] message, String expected) {
        ok(sim, 0x30, put(1, ascii(name), key));
        bytes(name, hex(expected), ok(sim, 0x40, named(ascii(name), message)));
        sw(name + " export forbidden", 0x6985, send(sim, 0x41, named(ascii(name), new byte[0])));
        vectors++;
    }

    private static void verify(CardSimulator sim) { ok(sim, 0x20, PIN); }
    private static byte[] okPage(CardSimulator sim, int page) {
        ResponseAPDU r = tx(sim, 0x80, 0x31, page, 0, new byte[0]);
        sw("LIST page=" + page, 0x9000, r);
        return r.getData();
    }
    private static ResponseAPDU send(CardSimulator sim, int ins, byte[] data) { return tx(sim, 0x80, ins, 0, 0, data); }
    private static ResponseAPDU tx(CardSimulator sim, int cla, int ins, int p1, int p2, byte[] data) {
        return sim.transmitCommand(new CommandAPDU(cla, ins, p1, p2, data, 256));
    }
    private static byte[] ok(CardSimulator sim, int ins, byte[] data) {
        ResponseAPDU r = send(sim, ins, data);
        sw("INS=" + ins, 0x9000, r);
        return r.getData();
    }
    private static void sw(String label, int expected, ResponseAPDU response) {
        equal(label, expected, response.getSW());
        if (expected != 0x9000) equal(label + " no data leaked", 0, response.getData().length);
    }
    private static void equal(String label, int expected, int actual) {
        checks++;
        if (expected != actual) throw new AssertionError(label + " expected=" + Integer.toHexString(expected) + " actual=" + Integer.toHexString(actual));
    }
    private static void bytes(String label, byte[] expected, byte[] actual) {
        checks++;
        if (!Arrays.equals(expected, actual)) throw new AssertionError(label + " byte mismatch");
    }
    private static byte[] put(int kind, byte[] name, byte[] secret) {
        byte[] out = new byte[2 + name.length + secret.length];
        out[0] = (byte) kind; out[1] = (byte) name.length;
        System.arraycopy(name, 0, out, 2, name.length);
        System.arraycopy(secret, 0, out, 2 + name.length, secret.length);
        return out;
    }
    private static byte[] named(byte[] name, byte[] msg) {
        byte[] out = new byte[1 + name.length + msg.length]; out[0] = (byte) name.length;
        System.arraycopy(name, 0, out, 1, name.length);
        System.arraycopy(msg, 0, out, 1 + name.length, msg.length);
        return out;
    }
    private static byte[] hostHmac(byte[] key, byte[] message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(message);
    }
    public static byte[] ascii(String s) { return s.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] repeat(int b, int count) { byte[] out = new byte[count]; Arrays.fill(out, (byte) b); return out; }
    public static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
