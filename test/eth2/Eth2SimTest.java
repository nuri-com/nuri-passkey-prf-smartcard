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
    static InspectRuntime runtime;
    static int checks = 0;

    static final class InspectRuntime extends com.licel.jcardsim.base.SimulatorRuntime {
        javacard.framework.Applet applet() { return getApplet(AIDUtil.create(AID_V2)); }
    }

    static void newSimulator() {
        runtime = new InspectRuntime();
        sim = new CardSimulator(runtime);
    }

    public static void main(String[] args) throws Exception {
        String out = args.length > 0 ? args[0] : "eth2-sim-signatures.json";
        int nSign = args.length > 1 ? Integer.parseInt(args[1]) : 20;
        boolean withV1 = args.length > 2 && args[2].equals("with-v1");

        mandatoryAndAttestationTests();
        newSimulator();
        AID aidV2 = AIDUtil.create(AID_V2);
        byte[] demo = installData(new byte[]{1, 0});
        sim.installApplet(aidV2, NuriEthSignerV2.class, demo, (short)0, (byte)demo.length);
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
        check(ver[0] == 2 && ver[1] == 1 && ver[2] == 0, "version 2.1.0");
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
        expectSW(r, 0x6982, "SET_PIN does not authorize SIGN, even in demo mode");
        expectSW(tx(0x80, 0x20, 0, 0, PIN), 0x9000, "explicit VERIFY after SET_PIN");
        expectSW(tx(0x80, 0x04, 0, 0, random(32)), 0x9000, "SIGN after explicit VERIFY");

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
        r = tx(0x80, 0x01, 0, 0, null);
        check(r.getData()[8] == 4, "wrong-old decrement persisted at 4 (try state is non-transactional)");
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

        // UNBLOCK with PUK. The PIN was at 0 tries; the PUK try counter is 3.
        expectSW(tx(0x80, 0x23, 0, 0, cat("XXXXXXXXXXXXXXXX".getBytes(), lv(PIN))), 0x63C2, "UNBLOCK wrong PUK -> 63C2");
        expectSW(tx(0x80, 0x23, 0, 0, cat("YYYYYYYYYYYYYYYY".getBytes(), lv(PIN))), 0x63C1, "UNBLOCK wrong PUK #2 -> 63C1 (PUK decrement persists)");
        expectSW(tx(0x80, 0x23, 0, 0, cat(PUK, lv(PIN))), 0x9000, "UNBLOCK with PUK");
        // A single wrong PIN now returns 63C4 (not 6983): observable proof that
        // UNBLOCK's OwnerPIN.update reset the blocked PIN's try counter to the
        // limit without any resetAndUnblock() call.
        expectSW(tx(0x80, 0x20, 0, 0, "0000".getBytes()), 0x63C4, "wrong PIN after UNBLOCK -> 63C4 (update reset the counter)");
        expectSW(tx(0x80, 0x04, 0, 0, random(32)), 0x6982, "UNBLOCK does not validate");
        expectSW(tx(0x80, 0x20, 0, 0, PIN), 0x9000, "VERIFY after unblock");
        expectSW(tx(0x80, 0x23, 0, 0, cat("XXXXXXXXXXXXXXXX".getBytes(), lv(PIN))), 0x63C2, "PUK counter back at 3 (successful PUK check reset it)");
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

    // --- mandatory policy, strict GP install and attestation integration -------------------

    static void mandatoryAndAttestationTests() throws Exception {
        // No install parameters and an empty GP application field both fail closed.
        for (byte[] params : new byte[][]{new byte[0], installData(new byte[0])}) {
            install(params);
            check(tx(0x80, 1, 0, 0, null).getData()[7] == 4, "blank mandatory state bit");
            check((tx(0x80, 5, 0, 0, null).getData()[0] & 0x40) != 0, "mandatory capability");
            expectSW(tx(0x80, 3, 0, 0, null), 0x6982, "mandatory KEYGEN before SET_PIN");
            expectSW(tx(0x80, 4, 0, 0, random(32)), 0x6982, "mandatory SIGN before SET_PIN");
            byte[] blank = attestation(null, 1, new byte[0]);
            expectSW(tx(0x80, 0x74, 0, 0, null), 0x6986, "no binding before keygen");
            expectSW(tx(0x80, 0x21, 0, 0, cat(lv(PIN), lv(PUK))), 0x9000, "mandatory SET_PIN");
            attestation(null, 3, new byte[0]);
            expectSW(tx(0x80, 3, 0, 0, null), 0x6982, "SET_PIN does not authorize KEYGEN");
            expectSW(tx(0x80, 4, 0, 0, random(32)), 0x6982, "SET_PIN does not authorize SIGN");
            expectSW(tx(0x80, 0x20, 0, 0, PIN), 0x9000, "mandatory VERIFY");
            ResponseAPDU key = tx(0x80, 3, 0, 0, null);
            expectSW(key, 0x9000, "mandatory KEYGEN after VERIFY");
            byte[] pub = tx(0x80, 2, 1, 0, null).getData();
            check(pub.length == 33, "attested key is compressed33");
            byte[] binding = tx(0x80, 0x74, 0, 0, null).getData();
            verifyP256(blank, cat("NHWV1".getBytes("US-ASCII"), cat(aidBytes(), pub)), binding);
            byte[] keyedInfo = attestation(pub, 7, binding);
            check(java.util.Arrays.equals(blank, keyedInfo), "attestation identity unchanged by keygen");
            expectSW(tx(0x80, 4, 0, 0, random(32)), 0x9000, "mandatory SIGN after VERIFY");
            for (int ins : new int[]{1, 2, 3, 4, 5, 0x20, 0x21, 0x22, 0x23, 0x70, 0x71, 0x72, 0x73, 0x74}) {
                expectSW(tx(0x80, ins, 2, 0, null), 0x6A86, "P1 rejected INS=" + ins);
                expectSW(tx(0x80, ins, 0, 1, null), 0x6A86, "P2 rejected INS=" + ins);
                expectSW(tx(0x81, ins, 0, 0, null), 0x6E00, "logical channel rejected INS=" + ins);
            }
            for (int ins : new int[]{0x70, 0x71, 0x73, 0x74})
                expectSW(tx(0x80, ins, 1, 0, null), 0x6A86, "attestation P1=1 rejected");
            expectSW(tx(0x80, 0x72, 1, 0, null), 0x6700, "attestation tail requires challenge32");
            select();
            expectSW(tx(0x80, 4, 0, 0, random(32)), 0x6982, "mandatory reselect locks SIGN");
            attestation(pub, 3, binding);
            int[] wrong = {0x63C4, 0x63C3, 0x63C2, 0x63C1, 0x6983};
            for (int sw : wrong) expectSW(tx(0x80, 0x20, 0, 0, "0000".getBytes()), sw, "mandatory wrong PIN");
            attestation(pub, 11, binding);
            expectSW(tx(0x80, 4, 0, 0, random(32)), 0x6982, "mandatory blocked SIGN");
            expectSW(tx(0x80, 0x23, 0, 0, cat(PUK, lv(PIN2))), 0x9000, "mandatory PUK unblock");
            attestation(pub, 3, binding);
            expectSW(tx(0x80, 4, 0, 0, random(32)), 0x6982, "mandatory unblock not validated");
            expectSW(tx(0x80, 0x20, 0, 0, PIN2), 0x9000, "mandatory VERIFY after unblock");
            expectSW(tx(0x80, 4, 0, 0, random(32)), 0x9000, "mandatory sign after unblock VERIFY");

            // CA certificate lifecycle is independent from the spending key and PIN.
            expectSW(tx(0x80, 0x73, 0, 0, null), 0x6985, "cannot seal without cert");
            java.security.KeyPairGenerator ca = java.security.KeyPairGenerator.getInstance("EC");
            ca.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
            signer.initSign(ca.generateKeyPair().getPrivate());
            signer.update(cat("NURI-ATT-V1".getBytes("US-ASCII"),
                    cat(java.util.Arrays.copyOfRange(blank, 1, 17), cat(aidBytes(), attPub(blank)))));
            byte[] cert = signer.sign();
            expectSW(tx(0x80, 0x71, 0, 0, cert), 0x9000, "STORE_ATTESTATION_CERT");
            expectSW(tx(0x80, 0x71, 0, 0, cert), 0x6985, "cert write once");
            expectSW(tx(0x80, 0x73, 0, 0, null), 0x9000, "SEAL_ATTESTATION");
            sim.reset(); select();
            expectSW(tx(0x80, 4, 0, 0, random(32)), 0x6982, "mandatory reset locks SIGN");
            expectSW(tx(0x80, 3, 0, 0, null), 0x6989, "one-shot after reset");
            check(java.util.Arrays.equals(pub, tx(0x80, 2, 1, 0, null).getData()), "pub survives reset");
            check(java.util.Arrays.equals(binding, tx(0x80, 0x74, 0, 0, null).getData()), "binding survives reset");
            byte[] info = tx(0x80, 0x70, 0, 0, null).getData();
            int sealOff = 18 + (info[17] & 255) + 65;
            check(info[sealOff] == 1, "seal survives reset");
            check(java.util.Arrays.equals(cert, java.util.Arrays.copyOfRange(info, sealOff + 2, info.length)), "cert survives reset");
            attestation(pub, 3, binding);
            expectSW(tx(0x80, 0x71, 0, 0, cert), 0x6985, "sealed cert cannot overwrite");
        }
        // A personalized install still requires VERIFY, including nonzero GP offsets.
        byte[] params = installData(cat(new byte[]{0}, lv(PIN)));
        newSimulator();
        byte[] padded = cat(new byte[]{99, 98}, cat(params, new byte[]{97}));
        sim.installApplet(AIDUtil.create(AID_V2), NuriEthSignerV2.class, padded, (short)2, (byte)params.length);
        select();
        expectSW(tx(0x80, 3, 0, 0, null), 0x6982, "personalized install not validated");
        attestation(null, 3, new byte[0]);
        expectSW(tx(0x80, 0x20, 0, 0, PIN), 0x9000, "personalized PIN verifies");
        expectSW(tx(0x80, 3, 0, 0, null), 0x9000, "personalized KEYGEN");

        // Strict lengths: no raw app-data fallback, unknown modes, trailing bytes,
        // truncated fields, zero/short/oversized mandatory PIN, or alternate AID.
        for (byte[] bad : new byte[][]{
                {1, 0}, {0}, {0, 0}, {0, 0, 2, 1}, {0, 0, 0, 1},
                {0, 0, 3, 1, 0, 0}, {0, 0, 2, 2, 0}, {0, 0, 2, 0, 0},
                {0, 0, 3, 1, 1, 42}, {0, 4, 1}, {0, 0, (byte)255},
                installData(cat(new byte[]{0}, lv(new byte[3]))),
                installData(cat(new byte[]{0}, lv(new byte[17]))),
                cat(lv(new byte[]{1,2,3,4,5}), new byte[]{0,0})}) {
            boolean rejected = false;
            try { install(bad); } catch (RuntimeException expected) { rejected = true; }
            check(rejected, "malformed install rejected: " + hex(bad));
        }
        // Explicit GP control bytes are skipped, not mistaken for app data.
        byte[] control = cat(lv(aidBytes()), cat(lv(new byte[]{1, 2}), lv(new byte[]{1, 0})));
        install(control);
        attestation(null, 0, new byte[0]);
        expectSW(tx(0x80, 3, 0, 0, null), 0x9000, "only explicit demo can keygen unconfigured");
        expectSW(tx(0x80, 4, 0, 0, random(32)), 0x9000, "explicit demo SIGN");
    }

    static void install(byte[] params) {
        newSimulator();
        sim.installApplet(AIDUtil.create(AID_V2), NuriEthSignerV2.class, params, (short)0, (byte)params.length);
        select();
    }

    static byte[] aidBytes() { return new byte[]{0x4e,0x55,0x52,0x49,0x45,0x54,0x48,0x32,1}; }
    static byte[] installData(byte[] app) { return cat(lv(aidBytes()), cat(new byte[]{0}, lv(app))); }

    /** Parse and independently verify full-message P-256 signatures. */
    static byte[] attestation(byte[] pub, int pinState, byte[] binding) throws Exception {
        byte[] challenge = random(32);
        ResponseAPDU r = tx(0x80, 0x70, 0, 0, null);
        expectSW(r, 0x9000, "GET_ATTESTATION_INFO");
        byte[] info = r.getData();
        check(info[0] == 1 && info[17] == 9, "info version and AID length");
        check(java.util.Arrays.equals(aidBytes(), java.util.Arrays.copyOfRange(info, 18, 27)), "canonical attestation AID");
        check(info.length == 94 + (info[93] & 255), "info exact length");
        byte[] response = readAttestation(challenge);
        check(java.util.Arrays.equals(info, java.util.Arrays.copyOf(response, info.length)), "response starts with INFO");
        int p = info.length;
        int n = response[p++] & 255;
        byte[] signingPub = pub == null ? new byte[0] : pub;
        check(n == signingPub.length, "committed signing pub length");
        check(java.util.Arrays.equals(signingPub, java.util.Arrays.copyOfRange(response, p, p + n)), "committed signing pub bytes");
        p += n;
        check((response[p++] & 255) == pinState, "attested PIN bitfield=" + pinState);
        int sigLen = response[p++] & 255;
        byte[] sig = java.util.Arrays.copyOfRange(response, p, p + sigLen);
        p += sigLen;
        verifyP256(info, cat("NURI-ATT-RESP-V1".getBytes("US-ASCII"), cat(challenge, cat(signingPub, new byte[]{(byte)pinState}))), sig);
        int bindingLen = response[p++] & 255;
        check(bindingLen == binding.length, "binding length");
        check(java.util.Arrays.equals(binding, java.util.Arrays.copyOfRange(response, p, p + bindingLen)), "same committed binding in response");
        check(p + bindingLen == response.length, "response exact length");
        expectSW(tx(0x80, 0x72, 0, 0, random(31)), 0x6700, "challenge length strict");
        return info;
    }

    /** Keep logical evidence unchanged while each physical APDU stays short. */
    static byte[] readAttestation(byte[] challenge) {
        ResponseAPDU info = tx(0x80, 0x72, 0, 0, challenge);
        expectSW(info, 0x9000, "GET_ATTESTATION INFO page");
        check(info.getData().length > 0 && info.getData().length <= 256, "INFO page fits short Le");
        ResponseAPDU tail = tx(0x80, 0x72, 1, 0, challenge);
        expectSW(tail, 0x9000, "GET_ATTESTATION signed tail page");
        check(tail.getData().length > 0 && tail.getData().length <= 256, "tail page fits short Le");
        return cat(info.getData(), tail.getData());
    }

    static byte[] attPub(byte[] info) { return java.util.Arrays.copyOfRange(info, 18 + (info[17] & 255), 83 + (info[17] & 255)); }

    static void verifyP256(byte[] info, byte[] message, byte[] sig) throws Exception {
        byte[] spkiPrefix = {0x30,0x59,0x30,0x13,0x06,0x07,0x2a,(byte)0x86,0x48,(byte)0xce,0x3d,0x02,0x01,
            0x06,0x08,0x2a,(byte)0x86,0x48,(byte)0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0};
        java.security.PublicKey key = java.security.KeyFactory.getInstance("EC").generatePublic(
            new java.security.spec.X509EncodedKeySpec(cat(spkiPrefix, attPub(info))));
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(key); verifier.update(message);
        check(verifier.verify(sig), "independent P256 SHA256withECDSA verification");
        byte[] changed = message.clone(); changed[changed.length - 1] ^= 1;
        verifier.initVerify(key); verifier.update(changed);
        check(!verifier.verify(sig), "altered attestation message rejected");
    }

    // --- helpers --------------------------------------------------------------------------

    static void select() {
        check(sim.selectApplet(AIDUtil.create(AID_V2)), "SELECT v2");
    }

    static ResponseAPDU tx(int cla, int ins, int p1, int p2, byte[] data) {
        CommandAPDU c = data == null ? new CommandAPDU(cla, ins, p1, p2, 256) : new CommandAPDU(cla, ins, p1, p2, data, 256);
        if (!AIDUtil.create(AID_V2).equals(runtime.getAID())) return sim.transmitCommand(c);
        try {
            // Seed the applet work buffer: even header/PIN failures must erase it.
            java.lang.reflect.Field scratchField = NuriEthSignerV2.class.getDeclaredField("scratch");
            scratchField.setAccessible(true);
            byte[] scratch = (byte[])scratchField.get(runtime.applet());
            java.util.Arrays.fill(scratch, (byte)0x5a);
            ResponseAPDU response = sim.transmitCommand(c);
            boolean zero = true;
            for (byte b : scratch) zero &= b == 0;
            check(zero, "applet scratch erased after INS=" + ins);
            java.lang.reflect.Field helperField = NuriEthSignerV2.class.getDeclaredField("attestation");
            helperField.setAccessible(true);
            Object helper = helperField.get(runtime.applet());
            for (java.lang.reflect.Field f : helper.getClass().getDeclaredFields()) {
                f.setAccessible(true);
                Object value = f.get(helper);
                if (value instanceof byte[] && javacard.framework.JCSystem.isTransient(value) != 0) {
                    zero = true;
                    for (byte b : (byte[])value) zero &= b == 0;
                    check(zero, "helper transient byte scratch erased: " + f.getName());
                }
            }
            check(runtime.getTransactionDepth() == 0, "no command leaves a transaction open");
            return response;
        } catch (ReflectiveOperationException error) {
            throw new AssertionError(error);
        }
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
