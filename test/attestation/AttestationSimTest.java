// SPDX-License-Identifier: MIT
package com.nuri.attestation.test;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.nuri.eth2.NuriEthSignerV2;
import com.nuri.vault.NuriVault;
import nuri.musig2.NuriMuSig2v019;
import javacard.framework.Applet;
import javacard.framework.JCSystem;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Actual applet classes, real simulator APDUs, and independent JCA verification.
 * Reflection is restricted to seeding/inspecting scratch; never reads a scalar.
 * The ephemeral CA private key never leaves this JVM. Exported fixtures are public.
 */
public final class AttestationSimTest {
    private static final byte[] PIN = ascii("123456");
    private static final byte[] PUK = ascii("0123456789ABCDEF");
    private static final SecureRandom RNG = new SecureRandom();
    private static final Set<String> IDS = new HashSet<>(), IDENTITIES = new HashSet<>();
    private static int checks, commands, wipes, javaSignatures;
    private static final byte[] SPKI_PREFIX = unhex("3059301306072a8648ce3d020106082a8648ce3d030107034200");

    private static final class Spec {
        final String name;
        final byte[] aid;
        final Class<? extends Applet> appletClass;
        final int cla, keygen, getPub, getPubP1, setPin;
        Spec(String n, String a, Class<? extends Applet> c, int cl, int kg, int gp, int p1, int sp) {
            name = n; aid = unhex(a); appletClass = c; cla = cl;
            keygen = kg; getPub = gp; getPubP1 = p1; setPin = sp;
        }
        boolean vault() { return name.equals("vault"); }
    }
    private static final Spec[] SPECS = {
        new Spec("eth2", "4E5552494554483201", NuriEthSignerV2.class, 0x80, 3, 2, 1, 0x21),
        new Spec("musig2", "4E5552494D554701", NuriMuSig2v019.class, 0, 4, 3, 0, 0x21),
        new Spec("vault", "4E555249564C5401", NuriVault.class, 0x80, 3, 2, 0, 0x10)
    };

    private static final class InspectRuntime extends SimulatorRuntime {
        Applet applet(Spec s) { return getApplet(AIDUtil.create(s.aid)); }
    }
    private static final class Session {
        final Spec spec;
        final InspectRuntime runtime = new InspectRuntime();
        final CardSimulator sim = new CardSimulator(runtime);
        final List<Object> scratch = new ArrayList<>();
        Session(Spec s) throws Exception {
            spec = s;
            sim.installApplet(AIDUtil.create(s.aid), s.appletClass);
            select();
            Applet a = runtime.applet(s);
            check(a != null && a.getClass() == s.appletClass, "actual applet class " + s.name);
            scratchArrays(a);
            Object helper = field(a, "attestation");
            scratchArrays(helper);
            if (s.name.equals("musig2")) scratchArrays(field(a, "scalar"));
            check(scratch.size() >= 5, "found applet and helper scratch " + s.name);
        }
        void scratchArrays(Object owner) throws Exception {
            for (Field f : owner.getClass().getDeclaredFields()) {
                if (Modifier.isStatic(f.getModifiers())) continue;
                f.setAccessible(true);
                Object value = f.get(owner);
                if ((value instanceof byte[] || value instanceof short[]) &&
                        JCSystem.isTransient(value) == JCSystem.CLEAR_ON_DESELECT) scratch.add(value);
            }
        }
        void select() { check(sim.selectApplet(AIDUtil.create(spec.aid)), "SELECT " + spec.name); }
        ResponseAPDU tx(int ins, int p1, int p2, byte[] data) throws Exception {
            return txCla(spec.cla, ins, p1, p2, data);
        }
        ResponseAPDU txCla(int cla, int ins, int p1, int p2, byte[] data) throws Exception {
            // Dirty every scratch array before success AND rejection paths, including
            // helper pendingLength. Session nonce/counter state is intentionally excluded.
            for (Object a : scratch) {
                if (a instanceof byte[]) Arrays.fill((byte[])a, (byte)0x5a);
                else Arrays.fill((short[])a, (short)0x5a5a);
            }
            CommandAPDU cmd = data == null || data.length == 0
                ? new CommandAPDU(cla, ins, p1, p2, 256)
                : new CommandAPDU(cla, ins, p1, p2, data, 256);
            check(cmd.getNe() == 256 && cmd.getNc() <= 255, "short command and Le256");
            if (data != null && data.length > 0)
                check(cmd.getBytes()[4] != 0 && cmd.getBytes().length == data.length + 6, "not an extended APDU");
            ResponseAPDU r = sim.transmitCommand(cmd);
            commands++;
            check(r.getData().length <= 256, "physical response fits short Le INS=" + ins);
            if (r.getSW() != 0x9000) check(r.getData().length == 0, "errors expose no scalar/data");
            for (Object a : scratch) {
                if (a instanceof byte[]) for (byte b : (byte[])a) check(b == 0, "byte scratch cleared INS=" + ins);
                else for (short v : (short[])a) check(v == 0, "pending short scratch cleared INS=" + ins);
                wipes++;
            }
            check(runtime.getTransactionDepth() == 0, "no open transaction after command");
            return r;
        }
        byte[] ok(int ins, byte[] data) throws Exception { return ok(ins, 0, data); }
        byte[] ok(int ins, int p1, byte[] data) throws Exception {
            ResponseAPDU r = tx(ins, p1, 0, data); sw(r, 0x9000, spec.name + " INS=" + ins); return r.getData();
        }
        byte[] info() throws Exception { return ok(0x70, null); }
        void verifyPin() throws Exception { ok(0x20, PIN); }
        byte[] moneyPub() throws Exception { return ok(spec.getPub, spec.getPubP1, null); }
        Evidence evidence(byte[] pub, int pinState, byte[] binding, KeyPair ca) throws Exception {
            byte[] challenge = random(32);
            byte[] infoPage = ok(0x72, 0, challenge);
            byte[] tailPage = ok(0x72, 1, challenge);
            check(infoPage.length <= 170 && tailPage.length <= 214, "bounded short pages");
            check(Arrays.equals(infoPage, info()), "GET72 page0 is exactly INFO");
            Info info = new Info(infoPage, spec);
            Cursor c = new Cursor(tailPage);
            byte[] currentPub = c.take(c.u8());
            int state = c.u8();
            byte[] sig = c.take(c.u8()), bound = c.take(c.u8());
            c.end(); // Exact schema: no trailing scalar/debug bytes.
            check(Arrays.equals(pub, currentPub), "current signing public key bound " + spec.name);
            check(state == pinState, "signed PIN state expected=" + pinState + " actual=" + state);
            check(Arrays.equals(binding, bound), "published NHWV1 bytes unchanged");
            byte[] message = cat(ascii("NURI-ATT-RESP-V1"), challenge, pub, new byte[]{(byte)state});
            verified(info.identity, sig, message, "response");
            byte[] wrongChallenge = challenge.clone(); wrongChallenge[0] ^= 1;
            rejected(info.identity, sig, cat(ascii("NURI-ATT-RESP-V1"), wrongChallenge, pub, new byte[]{(byte)state}), "wrong challenge");
            byte[] wrongPub = pub.length == 0 ? new byte[]{4} : pub.clone(); wrongPub[0] ^= 1;
            rejected(info.identity, sig, cat(ascii("NURI-ATT-RESP-V1"), challenge, wrongPub, new byte[]{(byte)state}), "wrong current money pub");
            rejected(info.identity, sig, cat(ascii("NURI-ATT-RESP-V1"), challenge, pub, new byte[]{(byte)(state ^ 4)}), "wrong PIN state");
            if (binding.length != 0) {
                verified(info.identity, bound, cat(ascii("NHWV1"), spec.aid, pub), "NHWV1");
                rejected(info.identity, bound, cat(ascii("NHWV1"), spec.aid, wrongPub), "wrong binding pub");
            }
            if (info.cert.length != 0) {
                check(ca != null, "pinned CA available");
                verified(ca.getPublic(), info.cert, info.caMessage(), "CA certificate");
                byte[] wrong = info.caMessage(); wrong[10] ^= 1;
                rejected(ca.getPublic(), info.cert, wrong, "wrong CA card identity");
                rejected(info.identity, info.cert, info.caMessage(), "identity cannot impersonate CA");
            }
            return new Evidence(challenge, infoPage, tailPage);
        }
    }

    private static final class Cursor {
        final byte[] bytes;
        int p;
        Cursor(byte[] b) { bytes = b; }
        int u8() { return take(1)[0] & 255; }
        byte[] take(int n) {
            check(n >= 0 && p + n <= bytes.length, "no truncated public evidence");
            byte[] r = Arrays.copyOfRange(bytes, p, p + n); p += n; return r;
        }
        void end() { check(p == bytes.length, "exact public evidence length; no scalar/debug extension"); }
    }
    private static final class Info {
        final byte[] cardId, aid, pub, cert;
        final PublicKey identity;
        final int sealed;
        Info(byte[] raw, Spec spec) throws Exception {
            Cursor c = new Cursor(raw);
            check(c.u8() == 1, "INFO version 1");
            cardId = c.take(16); aid = c.take(c.u8()); pub = c.take(65);
            sealed = c.u8(); cert = c.take(c.u8()); c.end();
            check(Arrays.equals(aid, spec.aid), "canonical applet AID");
            check(sealed <= 1 && (sealed == 0 || cert.length != 0), "valid seal state");
            check(pub[0] == 4, "identity SEC1 uncompressed65");
            identity = p256(pub);
            check(((ECPublicKey)identity).getParams().getCurve().getField().getFieldSize() == 256, "native P256 identity");
        }
        byte[] caMessage() { return cat(ascii("NURI-ATT-V1"), cardId, aid, pub); }
    }
    private static final class Evidence {
        final byte[] challenge, info, tail;
        Evidence(byte[] c, byte[] i, byte[] t) { challenge = c; info = i; tail = t; }
        String json(Spec s, byte[] pub, byte[] cert, byte[] binding) {
            return "{" + member("applet", s.name) + "," + member("aid", hex(s.aid)) + "," +
                member("challenge", hex(challenge)) + "," + member("signing_pub", hex(pub)) + "," +
                member("certificate", hex(cert)) + "," + member("info_page", hex(info)) + "," +
                member("tail_page", hex(tail)) + "," + member("response", hex(cat(info, tail))) + "," +
                member("binding", hex(binding)) + "}";
        }
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 1, "fixture output directory argument required");
        // jCardSim 3.0.5.11 defaults to an UNSEEDED deterministic RandomDataImpl.
        // Enable its actual SecureRandom-backed mode, not an applet RNG mock.
        check(System.getProperty("com.licel.jcardsim.randomdata.seed") == null, "fixed simulator RNG seed forbidden for install uniqueness");
        System.setProperty("com.licel.jcardsim.randomdata.secure", "1");
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ca = gen.generateKeyPair(); // throwaway: NEVER serialize/getEncoded private key
        byte[] caPub = sec1((ECPublicKey)ca.getPublic());
        List<String> fixtures = new ArrayList<>();
        for (Spec spec : SPECS) fixtures.add(run(spec, ca));
        check(fixtures.size() == 3 && IDS.size() == 6 && IDENTITIES.size() == 6, "all3, six independent installs");
        Path dir = Path.of(args[0]); Files.createDirectories(dir);
        Path output = dir.resolve("fixtures.json");
        Files.writeString(output, "{\"ca_pub\":\"" + hex(caPub) + "\",\"fixtures\":[\n" + String.join(",\n", fixtures) + "\n]}\n");
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rw-------"));
        System.out.println("ATTESTATION_JAVA_SIM_OK applets=3 installs=6 checks=" + checks +
            " apdus=" + commands + " scratch_wipes=" + wipes + " signatures=" + javaSignatures);
        System.out.println("ATTESTATION_PUBLIC_FIXTURES=" + output.toAbsolutePath());
    }

    private static String run(Spec s, KeyPair ca) throws Exception {
        int before = commands;
        // A new simulator installs the actual class again, proving uniqueness per install.
        Session first = new Session(s);
        Info original = new Info(first.info(), s); unique(original);
        Session x = new Session(s);
        byte[] blank = x.info(); Info info = new Info(blank, s); unique(info);
        check(!Arrays.equals(original.cardId, info.cardId) && !Arrays.equals(original.pub, info.pub), "new install unique " + s.name);
        check(info.sealed == 0 && info.cert.length == 0, "blank personalization");
        x.evidence(new byte[0], 1, new byte[0], null);
        sw(x.tx(0x74, 0, 0, null), 0x6986, "no binding before keygen");
        sw(x.tx(0x73, 0, 0, null), 0x6985, "cannot seal absent certificate");
        check(Arrays.equals(blank, x.info()), "failed seal does not alter INFO");
        sw(x.tx(0x71, 0, 0, random(7)), 0x6700, "cert minimum8");
        sw(x.tx(0x71, 0, 0, random(73)), 0x6700, "cert maximum72");
        sw(x.tx(0x71, 0, 0, new byte[8]), 0x6A80, "certificate DER tag");
        for (int ins = 0x70; ins <= 0x74; ins++) {
            sw(x.tx(ins, 2, 0, null), 0x6A86, "bad page");
            sw(x.tx(ins, 0, 1, null), 0x6A86, "bad P2");
            sw(x.txCla(s.cla ^ 1, ins, 0, 0, null), 0x6E00, "logical channel forbidden");
            if (ins != 0x72) sw(x.tx(ins, 1, 0, null), 0x6A86, "tail page reserved for GET72");
        }
        for (int page = 0; page < 2; page++) for (int len : new int[]{0, 31, 33})
            sw(x.tx(0x72, page, 0, random(len)), 0x6700, "challenge exact32 page=" + page);
        for (int ins : new int[]{0x70, 0x73, 0x74})
            sw(x.tx(ins, 0, 0, new byte[]{1}), 0x6700, "empty request required");
        // Removed legacy debug/export entrypoints and unused attestation command space.
        for (int ins : new int[]{0x06, 0x08, 0x75, 0x7f, 0xff}) {
            sw(x.tx(ins, 0, 0, null), 0x6D00, "no debug/scalar command");
            sw(x.tx(ins, 0, 0, random(32)), 0x6D00, "no scalar import command");
        }
        if (s.name.equals("musig2")) sw(x.tx(2, 0, 0, random(32)), 0x6D00, "legacy seed import removed");
        check(Arrays.equals(blank, x.info()), "all rejected commands leave identity intact");
        sw(x.tx(s.keygen, 0, 0, null), s.vault() ? 0x6985 : 0x6982, "KEYGEN requires PIN setup");
        byte[] setup = s.name.equals("eth2") ? cat(lv(PIN), lv(PUK)) : PIN;
        x.ok(s.setPin, setup);
        x.evidence(new byte[0], 3, new byte[0], null);
        sw(x.tx(s.keygen, 0, 0, null), 0x6982, "SET_PIN alone does not authorize KEYGEN");
        x.verifyPin();
        sw(x.tx(s.getPub, s.getPubP1, 0, null), 0x6986, "no published key before KEYGEN");
        x.verifyPin();
        if (s.vault()) importedHmacIsNotBinding(x);
        x.verifyPin();
        byte[] generated = x.ok(s.keygen, null);
        byte[] pub = x.moneyPub();
        check(pub.length == (s.vault() ? 65 : 33), "canonical current public length");
        if (s.vault()) { p256(pub); check(pub[0] == 4, "vault KEYGEN03 creates P256 binding key"); }
        else check(pub[0] == 2 || pub[0] == 3, "compressed secp256k1 prefix");
        if (s.name.equals("eth2")) {
            check(generated.length == 65 && generated[0] == 4, "ETH KEYGEN uncompressed65");
            check(Arrays.equals(pub, compress(generated)), "ETH attests exact KEYGEN money key");
        } else check(Arrays.equals(generated, pub), "KEYGEN publishes exact attested key");
        byte[] binding = x.ok(0x74, null);
        verified(info.identity, binding, cat(ascii("NHWV1"), s.aid, pub), "one-shot KEYGEN NHWV1");
        x.evidence(pub, 7, binding, null);
        x.verifyPin();
        sw(x.tx(s.keygen, 0, 0, null), 0x6989, "KEYGEN one-shot");
        x.verifyPin();
        check(Arrays.equals(pub, x.moneyPub()) && Arrays.equals(binding, x.ok(0x74, null)), "refused keygen preserves money key and binding");
        // Force a maximum-length real DER CA cert, exercising unsigned total lengths.
        byte[] certificate = certificate72(ca, info.caMessage());
        verified(ca.getPublic(), certificate, info.caMessage(), "independent P256 CA cert");
        x.ok(0x71, certificate);
        byte[] stored = x.info();
        Info personalized = new Info(stored, s);
        check(Arrays.equals(certificate, personalized.cert) && personalized.sealed == 0, "cert exact readback before seal");
        byte[] replacement = sign(ca, info.caMessage());
        sw(x.tx(0x71, 0, 0, replacement), 0x6985, "write once before seal");
        check(Arrays.equals(stored, x.info()), "overwrite cannot change unsealed cert");
        x.ok(0x73, null);
        byte[] sealedInfo = x.info();
        check(new Info(sealedInfo, s).sealed == 1, "seal readback");
        sw(x.tx(0x71, 0, 0, replacement), 0x6985, "prior seal forbids cert overwrite");
        sw(x.tx(0x73, 0, 0, null), 0x6985, "seal irreversible, second seal refused");
        check(Arrays.equals(sealedInfo, x.info()), "refused store/seal cannot alter sealed bytes");
        x.verifyPin();
        Evidence evidence = x.evidence(pub, 7, binding, ca);
        check(evidence.info.length + evidence.tail.length > 256, "logical evidence really exceeds one short page");
        x.select();
        x.evidence(pub, 3, binding, ca);
        x.sim.reset(); x.select();
        check(Arrays.equals(sealedInfo, x.info()), "identity/cert/seal persist reset");
        check(Arrays.equals(binding, x.ok(0x74, null)), "NHWV1 persists reset, readable while locked");
        x.evidence(pub, 3, binding, ca);
        x.verifyPin();
        check(Arrays.equals(pub, x.moneyPub()), "money pub persists reset");
        sw(x.tx(s.keygen, 0, 0, null), 0x6989, "KEYGEN one-shot after reset");
        x.select();
        for (int tries = 4; tries >= 0; tries--)
            sw(x.tx(0x20, 0, 0, ascii("000000")), tries == 0 ? 0x6983 : 0x63c0 + tries, "PIN block path");
        x.evidence(pub, 11, binding, ca);
        check(Arrays.equals(sealedInfo, x.info()), "blocked PIN cannot clear identity/cert/seal");
        System.out.println("ATTESTATION_APPLET_OK applet=" + s.name + " apdus=" + (commands - before) +
            " info_page=" + evidence.info.length + " tail_page=" + evidence.tail.length +
            " logical_bytes=" + (evidence.info.length + evidence.tail.length));
        return evidence.json(s, pub, certificate, binding);
    }

    private static void importedHmacIsNotBinding(Session x) throws Exception {
        byte[] secret = ascii("test-only-imported-HMAC-not-a-binding-key");
        x.ok(0x30, cat(new byte[]{1, 1, 'h'}, secret));
        sw(x.tx(0x74, 0, 0, null), 0x6986, "imported HMAC creates no asymmetric binding");
        x.evidence(new byte[0], 7, new byte[0], null);
        byte[] challenge = random(32);
        byte[] actual = x.ok(0x40, cat(new byte[]{1, 'h'}, challenge));
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
        check(Arrays.equals(actual, mac.doFinal(challenge)), "vault imported HMAC remains a separate slot function");
        sw(x.tx(0x41, 0, 0, new byte[]{1, 'h'}), 0x6985, "HMAC scalar/secret never REVEALs");
    }

    private static void unique(Info i) {
        check(IDS.add(hex(i.cardId)), "install cardId unique across applets");
        check(IDENTITIES.add(hex(i.pub)), "install attestation identity unique across applets");
    }
    private static PublicKey p256(byte[] pub) throws Exception {
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(cat(SPKI_PREFIX, pub)));
    }
    private static byte[] sign(KeyPair ca, byte[] message) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(ca.getPrivate()); signer.update(message); return signer.sign();
    }
    private static byte[] certificate72(KeyPair ca, byte[] message) throws Exception {
        for (int i = 0; i < 512; i++) { byte[] cert = sign(ca, message); if (cert.length == 72) return cert; }
        throw new AssertionError("could not generate maximum-length real DER certificate");
    }
    private static boolean verifies(PublicKey key, byte[] sig, byte[] message) throws Exception {
        check(sig.length >= 8 && sig.length <= 72 && sig[0] == 0x30, "native DER ECDSA signature");
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(key); verifier.update(message); return verifier.verify(sig);
    }
    private static void verified(PublicKey key, byte[] sig, byte[] msg, String label) throws Exception {
        check(verifies(key, sig, msg), "independent Java signature " + label); javaSignatures++;
    }
    private static void rejected(PublicKey key, byte[] sig, byte[] msg, String label) throws Exception {
        check(!verifies(key, sig, msg), "negative Java signature " + label);
    }
    private static Object field(Object owner, String name) throws Exception {
        Field f = owner.getClass().getDeclaredField(name); f.setAccessible(true); return f.get(owner);
    }
    private static void sw(ResponseAPDU r, int expected, String label) {
        check(r.getSW() == expected, label + " expected=" + Integer.toHexString(expected) + " actual=" + Integer.toHexString(r.getSW()));
    }
    private static void check(boolean yes, String message) {
        checks++;
        if (!yes) throw new AssertionError("ATTESTATION_FAIL " + message);
    }
    private static byte[] sec1(ECPublicKey key) {
        byte[] out = new byte[65]; out[0] = 4;
        byte[] x = key.getW().getAffineX().toByteArray(), y = key.getW().getAffineY().toByteArray();
        System.arraycopy(x, Math.max(0, x.length - 32), out, 33 - Math.min(32, x.length), Math.min(32, x.length));
        System.arraycopy(y, Math.max(0, y.length - 32), out, 65 - Math.min(32, y.length), Math.min(32, y.length));
        return out;
    }
    private static byte[] compress(byte[] pub) { byte[] out = Arrays.copyOfRange(pub, 0, 33); out[0] = (byte)(2 | (pub[64] & 1)); return out; }
    private static byte[] random(int n) { byte[] b = new byte[n]; RNG.nextBytes(b); return b; }
    private static byte[] ascii(String s) { return s.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] lv(byte[] b) { return cat(new byte[]{(byte)b.length}, b); }
    private static byte[] cat(byte[]... parts) {
        int n = 0; for (byte[] a : parts) n += a.length;
        byte[] b = new byte[n]; int p = 0;
        for (byte[] a : parts) { System.arraycopy(a, 0, b, p, a.length); p += a.length; } return b;
    }
    private static String member(String k, String v) { return "\"" + k + "\":\"" + v + "\""; }
    private static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte v : b) s.append(String.format("%02x", v & 255)); return s.toString(); }
    private static byte[] unhex(String s) { byte[] b = new byte[s.length()/2]; for (int i = 0; i < b.length; i++) b[i] = (byte)Integer.parseInt(s.substring(2*i, 2*i+2),16); return b; }
}
