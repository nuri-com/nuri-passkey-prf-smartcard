package com.nuri.eth2;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.Signature;

/**
 * NuriEthSignerV2 — secp256k1 ECDSA signer for Ethereum/EVM, native engine.
 *
 * v2 replaces the v1 software ECDSA (Satochip bignum + branchy modInverse,
 * audit finding A4) with the card OS Signature.ALG_ECDSA_SHA_256 engine and
 * signPreComputedHash (JC 3.0.4 API) on an ECPrivateKey carrying secp256k1
 * domain parameters. There is no bignum code in this package at all.
 *
 * Access control (audit A5): an optional OwnerPIN (5 tries, 4..16 bytes).
 * While no PIN is set the applet signs freely (same behaviour as v1). Once
 * SET_PIN has run, SIGN / KEYGEN / CHANGE_PIN require VERIFY_PIN in the
 * current session; deselect() resets the validation. An optional 16-byte PUK
 * (3 tries) can unblock the PIN.
 *
 * Output of SIGN is r(32) || s(32, low-S) || pubkey(65, uncompressed). The
 * recovery id v is NOT computed on-card: the host recovers it by trying
 * yParity 0/1 against the returned pubkey (what Keycard does).
 *
 * Package AID 4E55524945544832 ("NURIETH2"), applet AID 4E5552494554483201.
 * Installs next to v1 (package 4E555249455448). Never touches FIDO2.
 */
public class NuriEthSignerV2 extends Applet {

    private static final byte[] APPLET_VERSION = {(byte)0x02, (byte)0x00, (byte)0x00};

    private static final byte CLA_NURI = (byte)0x80;

    private static final byte INS_GET_VERSION = (byte)0x01;
    private static final byte INS_GET_PUBKEY  = (byte)0x02;
    private static final byte INS_KEYGEN      = (byte)0x03;
    private static final byte INS_SIGN        = (byte)0x04;
    private static final byte INS_GET_CAPS    = (byte)0x05;
    private static final byte INS_VERIFY_PIN  = (byte)0x20;
    private static final byte INS_SET_PIN     = (byte)0x21;
    private static final byte INS_CHANGE_PIN  = (byte)0x22;
    private static final byte INS_UNBLOCK_PIN = (byte)0x23;

    private static final short SW_PIN_BLOCKED          = (short)0x6983;
    private static final short SW_NOT_INITIALIZED      = (short)0x6986;
    private static final short SW_SIGN_FAILED          = (short)0x6988;
    private static final short SW_KEY_ALREADY_GENERATED = (short)0x6989;
    private static final short SW_PIN_TRIES_BASE       = (short)0x63C0;

    private static final byte PIN_TRIES = (byte)5;
    private static final byte PIN_MIN   = (byte)4;
    private static final byte PIN_MAX   = (byte)16;
    private static final byte PUK_TRIES = (byte)3;
    private static final byte PUK_LEN   = (byte)16;

    private static final short LENGTH_EC_FP_256 = (short)256;
    // KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY is a JC 3.0.5 constant; inlined so
    // the 3.0.4 converter accepts it (same trick as v1 / Satochip).
    private static final byte ALG_EC_SVDP_DH_PLAIN_XY = (byte)0x06;

    // caps bitfield (GET_CAPS)
    private static final byte CAP_ECDSA_NATIVE = (byte)0x01;
    private static final byte CAP_GENKEYPAIR   = (byte)0x02;
    private static final byte CAP_PLAIN_XY     = (byte)0x04;
    private static final byte CAP_PIN_SET      = (byte)0x08;
    private static final byte CAP_KEYED        = (byte)0x10;
    private static final byte CAP_PUK_SET      = (byte)0x20;

    // secp256k1: P(32) | A(32) | B(32) | N(32) | G(65 uncompressed)
    private static final byte[] SECP256K1 = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE, (byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6, (byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C, (byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41,
        (byte)0x04,
        (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E, (byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
        (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95, (byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
        (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB, (byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
        (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B, (byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
        (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77, (byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
        (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC, (byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
        (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48, (byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
        (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F, (byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
    };
    private static final short OFF_P = 0;
    private static final short OFF_A = 32;
    private static final short OFF_B = 64;
    private static final short OFF_N = 96;
    private static final short OFF_G = 128;

    // n/2 (floor) — the low-S threshold.
    private static final byte[] HALF_N = {
        (byte)0x7F,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0x5D,(byte)0x57,(byte)0x6E,(byte)0x73, (byte)0x57,(byte)0xA4,(byte)0x50,(byte)0x1D,
        (byte)0xDF,(byte)0xE9,(byte)0x2F,(byte)0x46, (byte)0x68,(byte)0x1B,(byte)0x20,(byte)0xA0
    };

    // --- persistent state --------------------------------------------------
    private final ECPrivateKey priv;
    private final ECPublicKey pub;
    private final KeyPair kp;
    private final Signature ecdsa;
    private final KeyAgreement ecdh;      // may be null (no PLAIN_XY on this OS)
    private final RandomData rng;
    private final OwnerPIN pin;
    private final OwnerPIN puk;
    private final byte[] pubCache;        // 65 bytes, set at KEYGEN
    private final byte[] flags;           // [0]=keyed [1]=pinSet [2]=pukSet [3]=genKeyPairPath
    private static final byte F_KEYED = 0;
    private static final byte F_PIN_SET = 1;
    private static final byte F_PUK_SET = 2;
    private static final byte F_GENKEYPAIR = 3;

    // --- transient ---------------------------------------------------------
    private final byte[] scratch;         // 160 bytes CLEAR_ON_DESELECT
    private static final short SCR_LEN  = 160;
    private static final short SCR_HASH = 0;    // 32
    private static final short SCR_DER  = 32;   // DER <= 72 bytes -> 32..104
    private static final short SCR_TMP  = 112;  // 32

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NuriEthSignerV2().register();
    }

    protected NuriEthSignerV2() {
        priv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
        pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, LENGTH_EC_FP_256, false);
        setCurve(priv);
        setCurve(pub);
        kp = new KeyPair(pub, priv);

        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        KeyAgreement ka = null;
        try {
            ka = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
        } catch (CryptoException e) {
            ka = null;
        }
        ecdh = ka;

        pin = new OwnerPIN(PIN_TRIES, PIN_MAX);
        puk = new OwnerPIN(PUK_TRIES, PUK_LEN);
        pubCache = new byte[65];
        flags = new byte[4];
        scratch = JCSystem.makeTransientByteArray(SCR_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    private static void setCurve(javacard.security.ECKey key) {
        key.setFieldFP(SECP256K1, OFF_P, (short)32);
        key.setA(SECP256K1, OFF_A, (short)32);
        key.setB(SECP256K1, OFF_B, (short)32);
        key.setR(SECP256K1, OFF_N, (short)32);
        key.setG(SECP256K1, OFF_G, (short)65);
        key.setK((short)1);
    }

    public boolean select() {
        return true;
    }

    public void deselect() {
        pin.reset();
        puk.reset();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != CLA_NURI) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_GET_VERSION: getVersion(apdu); break;
            case INS_GET_CAPS:    getCaps(apdu); break;
            case INS_GET_PUBKEY:  getPublicKey(apdu); break;
            case INS_KEYGEN:      keygen(apdu); break;
            case INS_SIGN:        sign(apdu); break;
            case INS_VERIFY_PIN:  verifyPin(apdu); break;
            case INS_SET_PIN:     setPin(apdu); break;
            case INS_CHANGE_PIN:  changePin(apdu); break;
            case INS_UNBLOCK_PIN: unblockPin(apdu); break;
            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // --- gates -------------------------------------------------------------

    /** PIN optional: no PIN set = open; PIN set = must be validated this session. */
    private void requirePin() {
        if (flags[F_PIN_SET] != 0 && !pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void requireKeyed() {
        if (flags[F_KEYED] == 0) ISOException.throwIt(SW_NOT_INITIALIZED);
    }

    // --- info --------------------------------------------------------------

    /** 02 00 00 'E' 'T' 'H' '2' state triesLeft  (state: b0 keyed, b1 pinSet). */
    private void getVersion(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(APPLET_VERSION, (short)0, buffer, (short)0, (short)3);
        buffer[3] = (byte)0x45; // 'E'
        buffer[4] = (byte)0x54; // 'T'
        buffer[5] = (byte)0x48; // 'H'
        buffer[6] = (byte)0x32; // '2'
        buffer[7] = (byte)((flags[F_KEYED] != 0 ? 0x01 : 0x00) | (flags[F_PIN_SET] != 0 ? 0x02 : 0x00));
        buffer[8] = flags[F_PIN_SET] != 0 ? pin.getTriesRemaining() : PIN_TRIES;
        apdu.setOutgoingAndSend((short)0, (short)9);
    }

    private void getCaps(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte caps = CAP_ECDSA_NATIVE;
        if (flags[F_GENKEYPAIR] != 0) caps |= CAP_GENKEYPAIR;
        if (ecdh != null) caps |= CAP_PLAIN_XY;
        if (flags[F_PIN_SET] != 0) caps |= CAP_PIN_SET;
        if (flags[F_KEYED] != 0) caps |= CAP_KEYED;
        if (flags[F_PUK_SET] != 0) caps |= CAP_PUK_SET;
        buffer[0] = caps;
        apdu.setOutgoingAndSend((short)0, (short)1);
    }

    /** P1=00 uncompressed 65 B (default, what the host expects); P1=01 compressed 33 B. */
    private void getPublicKey(APDU apdu) {
        requireKeyed();
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        if (p1 == (byte)0x01) {
            buffer[0] = (byte)(((pubCache[64] & 0x01) == 0) ? 0x02 : 0x03);
            Util.arrayCopyNonAtomic(pubCache, (short)1, buffer, (short)1, (short)32);
            apdu.setOutgoingAndSend((short)0, (short)33);
        } else if (p1 == (byte)0x00) {
            Util.arrayCopyNonAtomic(pubCache, (short)0, buffer, (short)0, (short)65);
            apdu.setOutgoingAndSend((short)0, (short)65);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    // --- key ---------------------------------------------------------------

    /**
     * One-shot on-card key generation (6989 once keyed). Primary path: KeyPair.genKeyPair()
     * on the secp256k1-parameterised pair. Fallback (batches whose genKeyPair rejects
     * custom domain params): 32 random bytes, rejected if 0 or >= n (compare, never
     * reduce), setS, pubkey = d*G via ALG_EC_SVDP_DH_PLAIN_XY. The pubkey cache and the
     * keyed flag are committed in one transaction (audit A11).
     */
    private void keygen(APDU apdu) {
        if (flags[F_KEYED] != 0) ISOException.throwIt(SW_KEY_ALREADY_GENERATED);
        requirePin();
        byte[] buffer = apdu.getBuffer();

        boolean generated = false;
        try {
            kp.genKeyPair();
            short wLen = pub.getW(scratch, (short)0);
            if (wLen == 65 && scratch[0] == (byte)0x04) {
                generated = true;
            }
        } catch (CryptoException e) {
            generated = false;
        }

        if (!generated) {
            if (ecdh == null) ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            do {
                rng.generateData(scratch, SCR_TMP, (short)32);
            } while (isZero(scratch, SCR_TMP) || !lessThan(scratch, SCR_TMP, SECP256K1, OFF_N));
            priv.setS(scratch, SCR_TMP, (short)32);
            Util.arrayFillNonAtomic(scratch, SCR_TMP, (short)32, (byte)0);
            ecdh.init(priv);
            short outLen = ecdh.generateSecret(SECP256K1, OFF_G, (short)65, scratch, (short)0);
            if (outLen != 65 || scratch[0] != (byte)0x04) {
                priv.clearKey();
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
        }

        JCSystem.beginTransaction();
        Util.arrayCopy(scratch, (short)0, pubCache, (short)0, (short)65);
        flags[F_GENKEYPAIR] = generated ? (byte)1 : (byte)0;
        flags[F_KEYED] = (byte)1;
        JCSystem.commitTransaction();

        Util.arrayCopyNonAtomic(pubCache, (short)0, buffer, (short)0, (short)65);
        Util.arrayFillNonAtomic(scratch, (short)0, SCR_LEN, (byte)0);
        apdu.setOutgoingAndSend((short)0, (short)65);
    }

    // --- sign --------------------------------------------------------------

    /** Lc=32 hash -> r(32) || s(32, low-S) || pubkey(65). */
    private void sign(APDU apdu) {
        requireKeyed();
        requirePin();
        byte[] buffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen != 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, scratch, SCR_HASH, (short)32);

        ecdsa.init(priv, Signature.MODE_SIGN);
        short derLen = ecdsa.signPreComputedHash(scratch, SCR_HASH, (short)32, scratch, SCR_DER);

        // DER SEQUENCE { INTEGER r, INTEGER s } -> fixed 32-byte r, s at buffer[0..64]
        derToRS(scratch, SCR_DER, derLen, buffer, (short)0);

        // low-S (EIP-2): s = n - s if s > n/2, constant-time select.
        subtractFromN(buffer, (short)32, scratch, SCR_TMP);
        byte mask = greaterThanMask(buffer, (short)32, HALF_N, (short)0);
        ctSelect(buffer, (short)32, scratch, SCR_TMP, mask);

        Util.arrayCopyNonAtomic(pubCache, (short)0, buffer, (short)64, (short)65);
        Util.arrayFillNonAtomic(scratch, (short)0, SCR_LEN, (byte)0);
        apdu.setOutgoingAndSend((short)0, (short)129);
    }

    /** Parse a DER ECDSA signature with r,s < 2^256 into two left-padded 32-byte integers. */
    private static void derToRS(byte[] der, short off, short len, byte[] out, short outOff) {
        if (len < 8 || der[off] != (byte)0x30) ISOException.throwIt(SW_SIGN_FAILED);
        short p = (short)(off + 2);
        short seqLen = (short)(der[(short)(off + 1)] & 0xFF);
        if (seqLen >= 0x80 || (short)(seqLen + 2) != len) ISOException.throwIt(SW_SIGN_FAILED);
        Util.arrayFillNonAtomic(out, outOff, (short)64, (byte)0);
        for (short i = 0; i < 2; i++) {
            if (der[p] != (byte)0x02) ISOException.throwIt(SW_SIGN_FAILED);
            short l = (short)(der[(short)(p + 1)] & 0xFF);
            p += 2;
            short start = p;
            // strip leading zero bytes (DER sign padding)
            while (l > 0 && der[start] == 0) { start++; l--; }
            if (l > 32 || l == 0) ISOException.throwIt(SW_SIGN_FAILED);
            Util.arrayCopyNonAtomic(der, start, out, (short)(outOff + (i == 0 ? 0 : 32) + 32 - l), l);
            p = (short)(start + l);
        }
        if (p != (short)(off + len)) ISOException.throwIt(SW_SIGN_FAILED);
    }

    /** out = n - a (32-byte big-endian), no data-dependent branches. */
    private static void subtractFromN(byte[] a, short aOff, byte[] out, short outOff) {
        short borrow = 0;
        for (short i = 31; i >= 0; i--) {
            short d = (short)((short)(SECP256K1[(short)(OFF_N + i)] & 0xFF) - (short)(a[(short)(aOff + i)] & 0xFF) - borrow);
            borrow = (short)((d >> 15) & 1);   // d < 0 ?
            out[(short)(outOff + i)] = (byte)d;
        }
    }

    /** 0xFF if a > b (unsigned 32-byte big-endian), else 0x00; no data-dependent branches. */
    private static byte greaterThanMask(byte[] a, short aOff, byte[] b, short bOff) {
        short gt = 0;   // 1 once a > b decided
        short lt = 0;   // 1 once a < b decided
        for (short i = 0; i < 32; i++) {
            short ai = (short)(a[(short)(aOff + i)] & 0xFF);
            short bi = (short)(b[(short)(bOff + i)] & 0xFF);
            short aGt = (short)(((short)(bi - ai) >> 15) & 1);   // ai > bi
            short aLt = (short)(((short)(ai - bi) >> 15) & 1);   // ai < bi
            short undecided = (short)(1 ^ (gt | lt));
            gt |= (short)(undecided & aGt);
            lt |= (short)(undecided & aLt);
        }
        return (byte)(0 - gt);   // 0x00 or 0xFF
    }

    /** dst = mask ? src : dst, byte-wise. */
    private static void ctSelect(byte[] dst, short dOff, byte[] src, short sOff, byte mask) {
        for (short i = 0; i < 32; i++) {
            byte d = dst[(short)(dOff + i)];
            byte s = src[(short)(sOff + i)];
            dst[(short)(dOff + i)] = (byte)(d ^ (mask & (d ^ s)));
        }
    }

    private static boolean isZero(byte[] a, short off) {
        byte acc = 0;
        for (short i = 0; i < 32; i++) acc |= a[(short)(off + i)];
        return acc == 0;
    }

    private static boolean lessThan(byte[] a, short aOff, byte[] b, short bOff) {
        return greaterThanMask(b, bOff, a, aOff) != 0;
    }

    // --- PIN ---------------------------------------------------------------

    /** Data: PIN (4..16). 9000 / 63Cx tries left / 6983 blocked / 6985 no PIN set. */
    private void verifyPin(APDU apdu) {
        if (flags[F_PIN_SET] == 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        checkPinLen(len);
        if (pin.getTriesRemaining() == 0) ISOException.throwIt(SW_PIN_BLOCKED);
        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, (byte)len)) {
            byte left = pin.getTriesRemaining();
            if (left == 0) ISOException.throwIt(SW_PIN_BLOCKED);
            ISOException.throwIt((short)(SW_PIN_TRIES_BASE | left));
        }
    }

    /**
     * Data: Lp PIN [Lk PUK]. Once only (6985 if a PIN is already set). PUK optional,
     * must be exactly 16 bytes when present. Validates the new PIN for this session.
     */
    private void setPin(APDU apdu) {
        if (flags[F_PIN_SET] != 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len < 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short pOff = (short)(ISO7816.OFFSET_CDATA + 1);
        short pLen = (short)(buffer[ISO7816.OFFSET_CDATA] & 0xFF);
        checkPinLen(pLen);
        short rest = (short)(len - 1 - pLen);
        short kLen = 0;
        short kOff = 0;
        if (rest < 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (rest > 0) {
            kOff = (short)(pOff + pLen + 1);
            kLen = (short)(buffer[(short)(pOff + pLen)] & 0xFF);
            if (kLen != 0 && kLen != PUK_LEN) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            if ((short)(rest - 1) != kLen) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // OwnerPIN.update is atomic by itself; the flags flip together afterwards so a
        // tear can never leave PIN_SET=1 with a half-written PIN.
        pin.update(buffer, pOff, (byte)pLen);
        if (kLen != 0) puk.update(buffer, kOff, (byte)kLen);
        JCSystem.beginTransaction();
        flags[F_PUK_SET] = (kLen != 0) ? (byte)1 : (byte)0;
        flags[F_PIN_SET] = (byte)1;
        JCSystem.commitTransaction();
        pin.check(buffer, pOff, (byte)pLen);   // validate this session
    }

    /** Data: Lo oldPIN Ln newPIN. Requires PIN (checks old inline, decrements on mismatch). */
    private void changePin(APDU apdu) {
        if (flags[F_PIN_SET] == 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len < 2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short oLen = (short)(buffer[ISO7816.OFFSET_CDATA] & 0xFF);
        short oOff = (short)(ISO7816.OFFSET_CDATA + 1);
        checkPinLen(oLen);
        if ((short)(oOff + oLen) >= (short)(ISO7816.OFFSET_CDATA + len)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short nLen = (short)(buffer[(short)(oOff + oLen)] & 0xFF);
        short nOff = (short)(oOff + oLen + 1);
        checkPinLen(nLen);
        if ((short)(nOff + nLen) != (short)(ISO7816.OFFSET_CDATA + len)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (pin.getTriesRemaining() == 0) ISOException.throwIt(SW_PIN_BLOCKED);
        if (!pin.check(buffer, oOff, (byte)oLen)) {
            byte left = pin.getTriesRemaining();
            if (left == 0) ISOException.throwIt(SW_PIN_BLOCKED);
            ISOException.throwIt((short)(SW_PIN_TRIES_BASE | left));
        }
        pin.update(buffer, nOff, (byte)nLen);
        pin.check(buffer, nOff, (byte)nLen);
    }

    /** Data: PUK(16) Ln newPIN. Requires a PUK to have been set. Resets PIN tries. */
    private void unblockPin(APDU apdu) {
        if (flags[F_PUK_SET] == 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len < (short)(PUK_LEN + 2)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short nLen = (short)(buffer[(short)(ISO7816.OFFSET_CDATA + PUK_LEN)] & 0xFF);
        short nOff = (short)(ISO7816.OFFSET_CDATA + PUK_LEN + 1);
        checkPinLen(nLen);
        if ((short)(nOff + nLen) != (short)(ISO7816.OFFSET_CDATA + len)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (puk.getTriesRemaining() == 0) ISOException.throwIt(SW_PIN_BLOCKED);
        if (!puk.check(buffer, ISO7816.OFFSET_CDATA, PUK_LEN)) {
            byte left = puk.getTriesRemaining();
            if (left == 0) ISOException.throwIt(SW_PIN_BLOCKED);
            ISOException.throwIt((short)(SW_PIN_TRIES_BASE | left));
        }
        pin.resetAndUnblock();
        pin.update(buffer, nOff, (byte)nLen);
        puk.reset();
    }

    private static void checkPinLen(short len) {
        if (len < PIN_MIN || len > PIN_MAX) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
}
