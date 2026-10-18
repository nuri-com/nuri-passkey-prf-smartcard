package com.nuri.eth2.test;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.nuri.eth2.NuriEthSignerV2;

import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * jCardSim driver for NuriEthSignerV2. Pure simulator: never opens a reader.
 *
 * Exercises every SW path of the applet and writes the signatures it collected to
 * the JSON file given as argv[0]; scripts/test-eth2-sim.sh then verifies them with
 * python-ecdsa (verify, low-S, recovery of v against the returned pubkey).
 *
 * Exit code 0 = all SW assertions passed. Any failure prints FAIL and exits 1.
 */
public final class Eth2SimTest {

    static final String AID_V2 = "4E5552494554483201";
    static final String AID_V1 = "4E55524945544801";
    static final byte[] PIN = "1234".getBytes();
    static final byte[] PIN2 = "987654".getBytes();
    static final byte[] PUK = "0123456789ABCDEF".getBytes();

    static CardSimulator sim;
    static int checks = 0;

    public static void main(String[] args) throws Exception {
        String out = args.length > 0 ? args[0] : "eth2-sim-signatures.json";
        int nSign = args.length > 1 ? Integer.parseInt(args[1]) : 20;
        boolean withV1 = args.length > 2 && args[2].equals("with-v1");

        sim = new CardSimulator();
        AID aidV2 = AIDUtil.create(AID_V2);
        sim.installApplet(aidV2, NuriEthSignerV2.class);
        if (withV1) {
            @SuppressWarnings("unchecked")
            Class<? extends javacard.framework.Applet> v1 =
                (Class<? extends javacard.framework.Applet>) Class.forName("com.nuri.eth.NuriEcdsaSigner");
            sim.installApplet(AIDUtil.create(AID_V1), v1);
        }

        // 1. select + version + caps -------------------------------------------------
        select();
        ResponseAPDU r = tx(0x80, 0x01, 0, 0, null);
        expectSW(r, 0x9000, "GET_VERSION");
        byte[] ver = r.getData();
        check(ver.length == 9, "version length 9, got " + ver.length);
        check(ver[0] == 2 && ver[1] == 0 && ver[2] == 0, "version 2.0.0");
        check(new String(ver, 3, 4).equals("ETH2"), "tag ETH2");
        check(ver[7] == 0, "state blank");
        check(ver[8] == 5, "5 PIN tries while unset");

        r = tx(0x80, 0x05, 0, 0, null);
        expectSW(r, 0x9000, "GET_CAPS");
        int caps = r.getData()[0] & 0xFF;
        check((caps & 0x01) != 0, "caps: native ECDSA");
        check((caps & 0x18) == 0, "caps: no PIN, not keyed");
        System.out.println("caps=0x" + Integer.toHexString(caps));

        // 2. negatives before keygen -----------------------------------------------
        expectSW(tx(0x80, 0x04, 0, 0, random(32)), 0x6986, "SIGN before keygen");
        expectSW(tx(0x80, 0x02, 0, 0, null), 0x6986, "GET_PUBKEY before keygen");
        expectSW(tx(0x00, 0x01, 0, 0, null), 0x6E00, "wrong CLA");
        expectSW(tx(0x80, 0x7F, 0, 0, null), 0x6D00, "unknown INS");
        expectSW(tx(0x80, 0x20, 0, 0, PIN), 0x6985, "VERIFY while no PIN set");

        // 3. keygen (PIN unset -> allowed), one-shot ---------------------------------
        r = tx(0x80, 0x03, 0, 0, null);
        expectSW(r, 0x9000, "KEYGEN");
        byte[] pub = r.getData();
        check(pub.length == 65 && pub[0] == 0x04, "KEYGEN returns uncompressed pubkey");
        expectSW(tx(0x80, 0x03, 0, 0, null), 0x6989, "second KEYGEN -> 6989");

        r = tx(0x80, 0x02, 0, 0, null);
        expectSW(r, 0x9000, "GET_PUBKEY P1=00");
        check(java.util.Arrays.equals(r.getData(), pub), "GET_PUBKEY uncompressed == keygen output");
        r = tx(0x80, 0x02, 1, 0, null);
        expectSW(r, 0x9000, "GET_PUBKEY P1=01");
        byte[] cpub = r.getData();
        check(cpub.length == 33 && (cpub[0] == 0x02 || cpub[0] == 0x03), "compressed pubkey 33 B");
        check(cpub[0] == (((pub[64] & 1) == 0) ? 0x02 : 0x03), "compressed prefix matches y parity");
        for (int i = 0; i < 32; i++) check(cpub[1 + i] == pub[1 + i], "compressed x == uncompressed x");
        expectSW(tx(0x80, 0x02, 2, 0, null), 0x6A86, "GET_PUBKEY bad P1");

        r = tx(0x80, 0x05, 0, 0, null);
        caps = r.getData()[0] & 0xFF;
        check((caps & 0x10) != 0, "caps: keyed");
        System.out.println("keygen path: " + (((caps & 0x02) != 0) ? "KeyPair.genKeyPair" : "rng+setS+ECDH fallback"));

        // 4. sign N random hashes with no PIN set --------------------------------------
        List<String> sigs = new ArrayList<>();
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < nSign; i++) {
            byte[] h = new byte[32];
            rnd.nextBytes(h);
            r = tx(0x80, 0x04, 0, 0, h);
            expectSW(r, 0x9000, "SIGN #" + i);
            byte[] d = r.getData();
            check(d.length == 129, "SIGN response 129 B, got " + d.length);
            byte[] rpub = new byte[65];
            System.arraycopy(d, 64, rpub, 0, 65);
            check(java.util.Arrays.equals(rpub, pub), "SIGN echoes the pubkey");
            sigs.add("{\"hash\":\"" + hex(h) + "\",\"r\":\"" + hex(d, 0, 32) + "\",\"s\":\"" + hex(d, 32, 32) + "\",\"pub\":\"" + hex(rpub) + "\",\"phase\":\"nopin\"}");
        }
        expectSW(tx(0x80, 0x04, 0, 0, random(31)), 0x6700, "SIGN Lc=31");
        expectSW(tx(0x80, 0x04, 0, 0, random(33)), 0x6700, "SIGN Lc=33");

        // 5. SET_PIN -> gated -----------------------------------------------------------
        expectSW(tx(0x80, 0x21, 0, 0, lv(new byte[]{1,2,3})), 0x6700, "SET_PIN too short");
        expectSW(tx(0x80, 0x21, 0, 0, cat(lv(PIN), lv("short".getBytes()))), 0x6A80, "SET_PIN PUK must be 16 B");
        expectSW(tx(0x80, 0x21, 0, 0, cat(lv(PIN), lv(PUK))), 0x9000, "SET_PIN + PUK");
        expectSW(tx(0x80, 0x21, 0, 0, lv(PIN)), 0x6985, "second SET_PIN -> 6985");
        r = tx(0x80, 0x01, 0, 0, null);
        check(r.getData()[7] == 0x03, "state keyed+pin");
        r = tx(0x80, 0x04, 0, 0, random(32));
        expectSW(r, 0x9000, "SIGN right after SET_PIN (session validated)");

        // deselect clears validation: re-SELECT, then SIGN must be 6982
        select();
        expectSW(tx(0x80, 0x04, 0, 0, random(32)), 0x6982, "SIGN after re-SELECT without VERIFY");
        expectSW(tx(0x80, 0x03, 0, 0, null), 0x6989, "KEYGEN still 6989 (keyed check first)");

        // wrong PIN decrements
        expectSW(tx(0x80, 0x20, 0, 0, "0000".getBytes()), 0x63C4, "wrong PIN #1 -> 63C4");
        expectSW(tx(0x80, 0x20, 0, 0, "0000".getBytes()), 0x63C3, "wrong PIN #2 -> 63C3");
        r = tx(0x80, 0x01, 0, 0, null);
        check(r.getData()[8] == 3, "GET_VERSION reports 3 tries left");
        expectSW(tx(0x80, 0x20, 0, 0, PIN), 0x9000, "correct PIN resets tries");
        r = tx(0x80, 0x01, 0, 0, null);
        check(r.getData()[8] == 5, "tries back to 5");

        // sign with PIN validated
        for (int i = 0; i < 5; i++) {
            byte[] h = new byte[32];
            rnd.nextBytes(h);
            r = tx(0x80, 0x04, 0, 0, h);
            expectSW(r, 0x9000, "SIGN (pin) #" + i);
            byte[] d = r.getData();
            sigs.add("{\"hash\":\"" + hex(h) + "\",\"r\":\"" + hex(d, 0, 32) + "\",\"s\":\"" + hex(d, 32, 32) + "\",\"pub\":\"" + hex(d, 64, 65) + "\",\"phase\":\"pin\"}");
        }

        // simulator reset (power cycle) also clears validation
        sim.reset();
        select();
        expectSW(tx(0x80, 0x04, 0, 0, random(32)), 0x6982, "SIGN after reset without VERIFY");

        // CHANGE_PIN
        expectSW(tx(0x80, 0x22, 0, 0, cat(lv("0000".getBytes()), lv(PIN2))), 0x63C4, "CHANGE_PIN wrong old -> 63C4");
        expectSW(tx(0x80, 0x22, 0, 0, cat(lv(PIN), lv(PIN2))), 0x9000, "CHANGE_PIN");
        expectSW(tx(0x80, 0x04, 0, 0, random(32)), 0x9000, "SIGN after CHANGE_PIN (validated)");
        select();
        expectSW(tx(0x80, 0x20, 0, 0, PIN), 0x63C4, "old PIN no longer valid");
        expectSW(tx(0x80, 0x20, 0, 0, PIN2), 0x9000, "new PIN valid");

        // block: 5 wrong -> 6983, then even the right PIN is 6983
        select();
        int[] expect = {0x63C4, 0x63C3, 0x63C2, 0x63C1, 0x6983};
        for (int i = 0; i < 5; i++) {
            expectSW(tx(0x80, 0x20, 0, 0, "9999".getBytes()), expect[i], "wrong PIN block step " + (i + 1));
        }
        expectSW(tx(0x80, 0x20, 0, 0, PIN2), 0x6983, "correct PIN while blocked -> 6983");
        expectSW(tx(0x80, 0x04, 0, 0, random(32)), 0x6982, "SIGN while blocked -> 6982");
        r = tx(0x80, 0x01, 0, 0, null);
        check(r.getData()[8] == 0, "0 tries left");

        // UNBLOCK with PUK
        expectSW(tx(0x80, 0x23, 0, 0, cat("XXXXXXXXXXXXXXXX".getBytes(), lv(PIN))), 0x63C2, "UNBLOCK wrong PUK -> 63C2");
        expectSW(tx(0x80, 0x23, 0, 0, cat(PUK, lv(PIN))), 0x9000, "UNBLOCK with PUK");
        expectSW(tx(0x80, 0x04, 0, 0, random(32)), 0x6982, "UNBLOCK does not validate");
        expectSW(tx(0x80, 0x20, 0, 0, PIN), 0x9000, "VERIFY after unblock");
        r = tx(0x80, 0x04, 0, 0, random(32));
        expectSW(r, 0x9000, "SIGN after unblock");
        {
            byte[] d = r.getData();
            sigs.add("{\"hash\":\"" + "" + "\",\"r\":\"" + hex(d, 0, 32) + "\",\"s\":\"" + hex(d, 32, 32) + "\",\"pub\":\"" + hex(d, 64, 65) + "\",\"phase\":\"skip\"}");
        }

        // 6. coexistence with v1 in the same simulator ------------------------------------
        if (withV1) {
            check(sim.selectApplet(AIDUtil.create(AID_V1)), "SELECT v1");
            r = tx(0x80, 0x01, 0, 0, null);
            expectSW(r, 0x9000, "v1 GET_VERSION");
            check(new String(r.getData(), 3, 4).equals("ETH1"), "v1 tag ETH1");
            select();
            r = tx(0x80, 0x01, 0, 0, null);
            check(new String(r.getData(), 3, 4).equals("ETH2"), "v2 still ETH2 after v1 round-trip");
            check(r.getData()[7] == 0x03, "v2 state survived");
        }

        // write signatures ----------------------------------------------------------------
        StringBuilder sb = new StringBuilder("[\n");
        boolean first = true;
        for (String s : sigs) {
            if (s.contains("\"phase\":\"skip\"")) continue;
            if (!first) sb.append(",\n");
            sb.append(s);
            first = false;
        }
        sb.append("\n]\n");
        try (FileWriter w = new FileWriter(out)) {
            w.write(sb.toString());
        }
        System.out.println("ETH2_SIM_SW_OK checks=" + checks + " signatures=" + (sigs.size() - 1) + " -> " + out);
    }

    // --- helpers --------------------------------------------------------------------------

    static void select() {
        check(sim.selectApplet(AIDUtil.create(AID_V2)), "SELECT v2");
    }

    static ResponseAPDU tx(int cla, int ins, int p1, int p2, byte[] data) {
        CommandAPDU c = data == null ? new CommandAPDU(cla, ins, p1, p2, 256) : new CommandAPDU(cla, ins, p1, p2, data, 256);
        return sim.transmitCommand(c);
    }

    static void expectSW(ResponseAPDU r, int sw, String what) {
        check(r.getSW() == sw, what + ": expected SW " + Integer.toHexString(sw) + " got " + Integer.toHexString(r.getSW()));
        System.out.println("ok   " + what + " -> " + Integer.toHexString(r.getSW()).toUpperCase());
    }

    static void check(boolean cond, String what) {
        checks++;
        if (!cond) {
            System.out.println("FAIL " + what);
            System.exit(1);
        }
    }

    static byte[] random(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    static byte[] lv(byte[] v) {
        byte[] o = new byte[v.length + 1];
        o[0] = (byte) v.length;
        System.arraycopy(v, 0, o, 1, v.length);
        return o;
    }

    static byte[] cat(byte[] a, byte[] b) {
        byte[] o = new byte[a.length + b.length];
        System.arraycopy(a, 0, o, 0, a.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    static String hex(byte[] b) { return hex(b, 0, b.length); }

    static String hex(byte[] b, int off, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = off; i < off + len; i++) sb.append(String.format("%02x", b[i] & 0xFF));
        return sb.toString();
    }
}
