package test.piv;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.nuri.piv.NuriPivApplet;

import javacard.framework.AID;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

public final class NuriPivSimTest {

    private static final String PIV_AID_HEX = "A000000308000010000100";
    private static final byte[] DEFAULT_ADMIN_KEY = hex("010203040506070801020304050607080102030405060708");

    private static byte[] hex(String s) {
        int n = s.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static void check(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError("FAIL: " + msg);
        }
    }

    private static byte[] txAll(CardSimulator sim, byte[] apdu, int expectSw) throws Exception {
        ResponseAPDU r = sim.transmitCommand(new CommandAPDU(apdu));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(r.getData());
        int sw = r.getSW();
        while ((sw & 0xFF00) == 0x6100) {
            int le = sw & 0xFF;
            r = sim.transmitCommand(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le == 0 ? 256 : le));
            out.write(r.getData());
            sw = r.getSW();
        }
        check(sw == expectSw, String.format("SW got %04X expected %04X", sw, expectSw));
        return out.toByteArray();
    }

    private static byte[] des3(int mode, byte[] key, byte[] block) throws Exception {
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(mode, new SecretKeySpec(key, "DESede"));
        return c.doFinal(block);
    }

    private static ECPublicKey parseUncompressedP256(byte[] w) throws Exception {
        check(w.length == 65 && w[0] == 0x04, "65B uncompressed P-256 point");
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(w, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(w, 33, 65));
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
    }

    private static byte[] encodeUncompressedP256(ECPublicKey pub) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        byte[] x = pub.getW().getAffineX().toByteArray();
        byte[] y = pub.getW().getAffineY().toByteArray();
        copyRightAligned(x, out, 1, 32);
        copyRightAligned(y, out, 33, 32);
        return out;
    }

    private static void copyRightAligned(byte[] src, byte[] dst, int dstOff, int width) {
        int sOff = src.length > width ? src.length - width : 0;
        int len = Math.min(src.length, width);
        System.arraycopy(src, sOff, dst, dstOff + (width - len), len);
    }

    public static void main(String[] args) throws Exception {
        CardSimulator sim = new CardSimulator();
        AID aid = AIDUtil.create(PIV_AID_HEX);
        sim.installApplet(aid, NuriPivApplet.class);

        // 1. SELECT returns APT (61 39 ...)
        byte[] sel = txAll(sim, hex("00A404000B" + PIV_AID_HEX), 0x9000);
        check(sel.length == 59 && sel[0] == 0x61 && sel[1] == 0x39, "APT TLV format");

        // 2. Version, Serial, Discovery (7E), CHUID (5FC102), CCC (5FC107)
        byte[] ver = txAll(sim, hex("00FD000000"), 0x9000);
        check(Arrays.equals(ver, new byte[]{5, 4, 0}), "GET_VER 5.4.0");
        byte[] ser = txAll(sim, hex("00F8000000"), 0x9000);
        check(ser.length == 4, "GET_SERIAL 4B");
        byte[] disc = txAll(sim, hex("00CB3FFF035C017E"), 0x9000);
        check(disc[0] == 0x7E && disc.length == 20, "Discovery 7E");
        byte[] chuid = txAll(sim, hex("00CB3FFF055C035FC102"), 0x9000);
        check(chuid.length == 61 && chuid[0] == 0x53 && chuid[1] == 0x3B, "CHUID 53 3B");
        byte[] ccc = txAll(sim, hex("00CB3FFF055C035FC107"), 0x9000);
        check(ccc.length == 52 && ccc[0] == 0x53 && ccc[1] == 0x32, "CCC 53 32");

        // 3. Unauthenticated GEN_ASYM & PUT_DATA rejected (6982)
        txAll(sim, hex("0047009A05AC03800111"), 0x6982);
        txAll(sim, hex("00DB3FFF085C035FC1055301AA"), 0x6982);

        // 4. 3DES mutual admin auth (9B)
        byte[] step1 = txAll(sim, hex("0087039B047C028000"), 0x9000);
        check(step1.length == 12 && step1[0] == 0x7C && step1[2] == (byte) 0x80, "Admin witness");
        byte[] wit = des3(Cipher.DECRYPT_MODE, DEFAULT_ADMIN_KEY, Arrays.copyOfRange(step1, 4, 12));
        byte[] hchal = hex("1122334455667788");
        ByteArrayOutputStream m2 = new ByteArrayOutputStream();
        m2.write(hex("0087039B167C148008"));
        m2.write(wit);
        m2.write(hex("8108"));
        m2.write(hchal);
        byte[] step2 = txAll(sim, m2.toByteArray(), 0x9000);
        check(Arrays.equals(Arrays.copyOfRange(step2, 4, 12), des3(Cipher.ENCRYPT_MODE, DEFAULT_ADMIN_KEY, hchal)),
                "Card mutual challenge response");

        // 5. Generate ECCP256 in 9A and 9D
        byte[] g9a = txAll(sim, hex("0047009A05AC03800111"), 0x9000);
        check(g9a.length == 70 && g9a[0] == 0x7F && g9a[1] == 0x49, "GEN_ASYM 9A");
        ECPublicKey pub9a = parseUncompressedP256(Arrays.copyOfRange(g9a, 5, 70));

        byte[] g9d = txAll(sim, hex("0047009D05AC03800111"), 0x9000);
        ECPublicKey pub9d = parseUncompressedP256(Arrays.copyOfRange(g9d, 5, 70));

        // 6. Chained PUT DATA (600B dummy cert) + GET DATA with 61xx response chaining
        byte[] fakeCert = new byte[600];
        for (int i = 0; i < fakeCert.length; i++) fakeCert[i] = (byte) (i * 31 + 7);
        ByteArrayOutputStream putBody = new ByteArrayOutputStream();
        putBody.write(hex("5C035FC1055382"));
        putBody.write((fakeCert.length >> 8) & 0xFF);
        putBody.write(fakeCert.length & 0xFF);
        putBody.write(fakeCert);
        byte[] fullPut = putBody.toByteArray();
        for (int off = 0; off < fullPut.length; off += 200) {
            int len = Math.min(200, fullPut.length - off);
            boolean more = (off + len) < fullPut.length;
            ByteArrayOutputStream cmd = new ByteArrayOutputStream();
            cmd.write(more ? 0x10 : 0x00);
            cmd.write(hex("DB3FFF"));
            cmd.write(len);
            cmd.write(fullPut, off, len);
            txAll(sim, cmd.toByteArray(), 0x9000);
        }
        byte[] readBack = txAll(sim, hex("00CB3FFF055C035FC105"), 0x9000);
        check(Arrays.equals(readBack, Arrays.copyOfRange(fullPut, 5, fullPut.length)),
                "Chained PUT/GET 600B cert exact match");

        // 7. Sign before PIN fails with 6982
        byte[] msg = "nuri-piv-sim-test".getBytes("UTF-8");
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(msg);
        ByteArrayOutputStream signApdu = new ByteArrayOutputStream();
        signApdu.write(hex("0087119A267C2482008120"));
        signApdu.write(digest);
        txAll(sim, signApdu.toByteArray(), 0x6982);

        // 8. Wrong PIN decrements tries (63C4), right PIN succeeds (9000)
        txAll(sim, hex("00200080"), 0x63C5);
        txAll(sim, hex("0020008008303030303030FFFF"), 0x63C4);
        txAll(sim, hex("0020008008313233343536FFFF"), 0x9000);

        // 9. ECDSA 9A signPreComputedHash + Java verification
        byte[] sigResp = txAll(sim, signApdu.toByteArray(), 0x9000);
        check(sigResp[0] == 0x7C && sigResp[2] == (byte) 0x82, "7C 82 sig wrapper");
        byte[] derSig = Arrays.copyOfRange(sigResp, 4, 4 + (sigResp[3] & 0xFF));
        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(pub9a);
        v.update(msg);
        check(v.verify(derSig), "ECDSA P-256 9A signature valid");

        // 10. ECDH 9D shared secret match
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair eph = kpg.generateKeyPair();
        byte[] ephW = encodeUncompressedP256((ECPublicKey) eph.getPublic());
        ByteArrayOutputStream dhApdu = new ByteArrayOutputStream();
        dhApdu.write(hex("0087119D477C4582008541"));
        dhApdu.write(ephW);
        byte[] dhResp = txAll(sim, dhApdu.toByteArray(), 0x9000);
        check(dhResp.length == 36 && dhResp[0] == 0x7C && dhResp[2] == (byte) 0x82 && dhResp[3] == 0x20, "7C 82 20 ECDH");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(eph.getPrivate());
        ka.doPhase((PublicKey) pub9d, true);
        check(Arrays.equals(Arrays.copyOfRange(dhResp, 4, 36), ka.generateSecret()), "ECDH P-256 9D shared secret match");

        // 11. PIN logout (P1=FF) locks 9A again
        txAll(sim, hex("0020FF80"), 0x9000);
        txAll(sim, signApdu.toByteArray(), 0x6982);

        System.out.println("NURI_PIV_SIM_TEST_OK (11 checks passed)");
    }
}
