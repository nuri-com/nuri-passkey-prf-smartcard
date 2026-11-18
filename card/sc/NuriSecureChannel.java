// SPDX-License-Identifier: MIT
package com.nuri.sc;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * NURI-SC v1 application-layer secure channel (Java Card 3.0.4 Classic).
 *
 * Handshake (OPEN):
 *   host_eph(65) -> card generates fresh P-256 ephemeral pair, computes
 *   z_ee = ECDH(card_eph_priv, host_eph) and z_se = ECDH(identity_priv, host_eph),
 *   signs T = "NURI-SC-V1" || aid_len(1) || AID || host_eph(65) || card_eph(65)
 *   with identity_priv (ALG_ECDSA_SHA_256, DER), derives directional keys via
 *   RFC 5869 HKDF-SHA256(salt = SHA256(T), ikm = z_ee || z_se).
 *
 * Transport (WRAP):
 *   Encrypt-then-MAC: AES-128-CBC-NOPAD with ISO/IEC 9797-1 Method 2 padding
 *   (0x80 0x00...) + RFC 2104 HMAC-SHA256-128 over MessageDigest.ALG_SHA_256.
 *   MAC input: "NURI-SC-V1" || dir(1) || session_id(8) || counter32(4) || iv16 || ct.
 *   Constant-time 16-byte XOR-OR tag verification before decryption.
 *   Session keys and counters live strictly in CLEAR_ON_DESELECT RAM.
 */
public final class NuriSecureChannel {
    public static final byte INS_OPEN  = (byte) 0x10;
    public static final byte INS_WRAP  = (byte) 0x11;
    public static final byte INS_CLOSE = (byte) 0x12;

    public static final byte DIR_C2D = (byte) 0x01;
    public static final byte DIR_D2C = (byte) 0x02;

    public static final short SW_SC_ERROR = (short) 0x6988;

    private static final byte ALG_EC_SVDP_DH_PLAIN    = (byte) 0x03;
    private static final byte ALG_EC_SVDP_DH_PLAIN_XY = (byte) 0x06;

    private static final byte[] PROTOCOL = {
        'N','U','R','I','-','S','C','-','V','1'
    };
    private static final byte[] HKDF_INFO_1 = {
        'n','u','r','i','-','s','c','-','v','1','/','k','e','y','s', (byte) 0x01
    };
    private static final byte[] HKDF_INFO_2 = {
        'n','u','r','i','-','s','c','-','v','1','/','k','e','y','s', (byte) 0x02
    };
    private static final byte[] HKDF_INFO_3 = {
        'n','u','r','i','-','s','c','-','v','1','/','k','e','y','s', (byte) 0x03
    };
    private static final byte[] HKDF_INFO_4 = {
        'n','u','r','i','-','s','c','-','v','1','/','k','e','y','s', (byte) 0x04
    };

    // NIST P-256: p(32), a(32), b(32), n(32), G(65 uncompressed).
    private static final byte[] P256 = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFC,
        (byte)0x5A,(byte)0xC6,(byte)0x35,(byte)0xD8,(byte)0xAA,(byte)0x3A,(byte)0x93,(byte)0xE7,
        (byte)0xB3,(byte)0xEB,(byte)0xBD,(byte)0x55,(byte)0x76,(byte)0x98,(byte)0x86,(byte)0xBC,
        (byte)0x65,(byte)0x1D,(byte)0x06,(byte)0xB0,(byte)0xCC,(byte)0x53,(byte)0xB0,(byte)0xF6,
        (byte)0x3B,(byte)0xCE,(byte)0x3C,(byte)0x3E,(byte)0x27,(byte)0xD2,(byte)0x60,(byte)0x4B,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xBC,(byte)0xE6,(byte)0xFA,(byte)0xAD,(byte)0xA7,(byte)0x17,(byte)0x9E,(byte)0x84,
        (byte)0xF3,(byte)0xB9,(byte)0xCA,(byte)0xC2,(byte)0xFC,(byte)0x63,(byte)0x25,(byte)0x51,
        (byte)0x04,(byte)0x6B,(byte)0x17,(byte)0xD1,(byte)0xF2,(byte)0xE1,(byte)0x2C,(byte)0x42,
        (byte)0x47,(byte)0xF8,(byte)0xBC,(byte)0xE6,(byte)0xE5,(byte)0x63,(byte)0xA4,(byte)0x40,
        (byte)0xF2,(byte)0x77,(byte)0x03,(byte)0x7D,(byte)0x81,(byte)0x2D,(byte)0xEB,(byte)0x33,
        (byte)0xA0,(byte)0xF4,(byte)0xA1,(byte)0x39,(byte)0x45,(byte)0xD8,(byte)0x98,(byte)0xC2,
        (byte)0x96,(byte)0x4F,(byte)0xE3,(byte)0x42,(byte)0xE2,(byte)0xFE,(byte)0x1A,(byte)0x7F,
        (byte)0x9B,(byte)0x8E,(byte)0xE7,(byte)0xEB,(byte)0x4A,(byte)0x7C,(byte)0x0F,(byte)0x9E,
        (byte)0x16,(byte)0x2B,(byte)0xCE,(byte)0x33,(byte)0x57,(byte)0x6B,(byte)0x31,(byte)0x5E,
        (byte)0xCE,(byte)0xCB,(byte)0xB6,(byte)0x40,(byte)0x68,(byte)0x37,(byte)0xBF,(byte)0x51,
        (byte)0xF5
    };

    // State offsets in transient session[] (113 bytes total):
    // [0] openFlag (0/1)
    // [1..8] session_id (8)
    // [9..40] m_c2d (32)
    // [41..72] m_d2c (32)
    // [73..76] rxCounter (4, big-endian unsigned)
    // [77..80] txCounter (4, big-endian unsigned)
    // [81..112] prk (32)
    private static final short S_OPEN = (short) 0;
    private static final short S_SID  = (short) 1;
    private static final short S_MC2D = (short) 9;
    private static final short S_MD2C = (short) 41;
    private static final short S_RX   = (short) 73;
    private static final short S_TX   = (short) 77;
    private static final short S_PRK  = (short) 81;
    private static final short S_LEN  = (short) 113;

    private final byte[] aid;
    private final ECPrivateKey identityPriv;
    private final ECPublicKey ephPub;
    private final ECPrivateKey ephPriv;
    private final KeyPair ephPair;
    private final KeyAgreement ecdh;
    private final boolean ecdhPlainXy;
    private final Signature signer;
    private final MessageDigest sha;
    private final Cipher aesCbc;
    private final AESKey keyC2d;
    private final AESKey keyD2c;
    private final RandomData rng;

    private final byte[] session;
    private final byte[] work;   // 260B transient scratch (transcript, ciphertext, reply)
    private final byte[] pad;    // 64B HMAC ipad/opad scratch
    private final byte[] inner;  // 65B HMAC inner digest / ECDH raw output

    public NuriSecureChannel(byte[] appletAid, ECPrivateKey identityPrivateKey) {
        aid = new byte[(short) appletAid.length];
        Util.arrayCopyNonAtomic(appletAid, (short) 0, aid, (short) 0, (short) appletAid.length);
        identityPriv = identityPrivateKey;

        ephPriv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false);
        ephPub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) 256, false);
        setP256(ephPriv);
        setP256(ephPub);
        ephPair = new KeyPair(ephPub, ephPriv);

        KeyAgreement ka = null;
        boolean xy = false;
        try {
            ka = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN, false);
        } catch (CryptoException e) {
            ka = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
            xy = true;
        }
        ecdh = ka;
        ecdhPlainXy = xy;

        signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        AESKey kc;
        AESKey kd;
        try {
            kc = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
            kd = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
        } catch (CryptoException e) {
            kc = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            kd = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        }
        keyC2d = kc;
        keyD2c = kd;
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        session = JCSystem.makeTransientByteArray(S_LEN, JCSystem.CLEAR_ON_DESELECT);
        work = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
        pad = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        inner = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
    }

    public static void setP256(ECKey key) {
        key.setFieldFP(P256, (short) 0, (short) 32);
        key.setA(P256, (short) 32, (short) 32);
        key.setB(P256, (short) 64, (short) 32);
        key.setR(P256, (short) 96, (short) 32);
        key.setG(P256, (short) 128, (short) 65);
        key.setK((short) 1);
    }

    public boolean isOpen() {
        return session[S_OPEN] == (byte) 1;
    }

    public byte ecdhMode() {
        return ecdhPlainXy ? ALG_EC_SVDP_DH_PLAIN_XY : ALG_EC_SVDP_DH_PLAIN;
    }

    public void reset() {
        Util.arrayFillNonAtomic(session, (short) 0, S_LEN, (byte) 0);
        Util.arrayFillNonAtomic(work, (short) 0, (short) work.length, (byte) 0);
        Util.arrayFillNonAtomic(pad, (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(inner, (short) 0, (short) 65, (byte) 0);
        if (keyC2d.isInitialized()) keyC2d.clearKey();
        if (keyD2c.isInitialized()) keyD2c.clearKey();
        if (ephPriv.isInitialized()) ephPriv.clearKey();
    }

    /** Receive exact or bounded APDU body into dst[0..len). */
    public static short receiveBody(APDU apdu, byte[] dst, short maxLen) {
        short got = apdu.setIncomingAndReceive();
        short len = apdu.getIncomingLength();
        if (len < 0 || len > maxLen) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short copied = 0;
        short off = apdu.getOffsetCdata();
        byte[] buf = apdu.getBuffer();
        while (got > 0) {
            if ((short) (copied + got) > len) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            Util.arrayCopyNonAtomic(buf, off, dst, copied, got);
            copied = (short) (copied + got);
            if (copied == len) break;
            got = apdu.receiveBytes((short) 0);
            off = 0;
        }
        if (copied != len) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return len;
    }

    /** Compute 32-byte X coordinate of ECDH(priv, peer65) into out[outOff..outOff+32). */
    private void computeEcdhX(ECPrivateKey priv, byte[] peer, short peerOff, byte[] out, short outOff) {
        Util.arrayFillNonAtomic(inner, (short) 0, (short) 65, (byte) 0);
        ecdh.init(priv);
        short n;
        try {
            n = ecdh.generateSecret(peer, peerOff, (short) 65, inner, (short) 0);
        } catch (CryptoException e) {
            reset();
            ISOException.throwIt(SW_SC_ERROR);
            return;
        }
        if (ecdhPlainXy) {
            if (n != 65 || inner[0] != (byte) 0x04) {
                reset();
                ISOException.throwIt(SW_SC_ERROR);
            }
            Util.arrayCopyNonAtomic(inner, (short) 1, out, outOff, (short) 32);
        } else {
            if (n < 1 || n > 32) {
                reset();
                ISOException.throwIt(SW_SC_ERROR);
            }
            Util.arrayFillNonAtomic(out, outOff, (short) 32, (byte) 0);
            Util.arrayCopyNonAtomic(inner, (short) 0, out, (short) (outOff + (short) (32 - n)), n);
        }
        Util.arrayFillNonAtomic(inner, (short) 0, (short) 65, (byte) 0);
    }

    /** Clean-room RFC 2104 HMAC-SHA256 using only MessageDigest.ALG_SHA_256 (keyLen <= 64). */
    public void hmacSha256(
        byte[] key, short keyOff, short keyLen,
        byte[] m1, short m1Off, short m1Len,
        byte[] m2, short m2Off, short m2Len,
        byte[] m3, short m3Off, short m3Len,
        byte[] out, short outOff
    ) {
        Util.arrayFillNonAtomic(pad, (short) 0, (short) 64, (byte) 0);
        Util.arrayCopyNonAtomic(key, keyOff, pad, (short) 0, keyLen);
        for (short i = 0; i < 64; i++) pad[i] ^= (byte) 0x36;
        sha.reset();
        sha.update(pad, (short) 0, (short) 64);
        if (m1Len > 0) sha.update(m1, m1Off, m1Len);
        if (m2Len > 0) sha.update(m2, m2Off, m2Len);
        if (m3Len > 0) sha.update(m3, m3Off, m3Len);
        sha.doFinal(pad, (short) 0, (short) 0, inner, (short) 0);

        for (short i = 0; i < 64; i++) pad[i] ^= (byte) (0x36 ^ 0x5C);
        sha.reset();
        sha.update(pad, (short) 0, (short) 64);
        sha.doFinal(inner, (short) 0, (short) 32, out, outOff);

        Util.arrayFillNonAtomic(pad, (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(inner, (short) 0, (short) 32, (byte) 0);
    }

    /**
     * Handle INS_OPEN (CLA 80 INS 10 P1 01 P2 00, Lc=65 host_eph).
     * Response: card_eph(65) || session_id(8) || sig_len(1) || sig_der(sig_len).
     */
    public void open(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_P1] != (byte) 0x01 || buf[ISO7816.OFFSET_P2] != (byte) 0x00) {
            reset();
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        reset();
        short len = receiveBody(apdu, work, (short) 65);
        if (len != 65 || work[0] != (byte) 0x04) {
            reset();
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short hostOff = (short) (11 + aid.length);
        Util.arrayCopyNonAtomic(work, (short) 0, work, hostOff, (short) 65);
        Util.arrayCopyNonAtomic(PROTOCOL, (short) 0, work, (short) 0, (short) 10);
        work[10] = (byte) aid.length;
        Util.arrayCopyNonAtomic(aid, (short) 0, work, (short) 11, (short) aid.length);

        setP256(ephPriv);
        setP256(ephPub);
        ephPair.genKeyPair();
        short cardOff = (short) (hostOff + 65);
        if (ephPub.getW(work, cardOff) != 65 || work[cardOff] != (byte) 0x04) {
            reset();
            ISOException.throwIt(SW_SC_ERROR);
        }
        short tLen = (short) (cardOff + 65);

        computeEcdhX(ephPriv, work, hostOff, work, tLen);
        ephPriv.clearKey();
        computeEcdhX(identityPriv, work, hostOff, work, (short) (tLen + 32));

        sha.reset();
        sha.doFinal(work, (short) 0, tLen, session, S_MC2D);

        hmacSha256(
            session, S_MC2D, (short) 32,
            work, tLen, (short) 64,
            work, (short) 0, (short) 0,
            work, (short) 0, (short) 0,
            session, S_PRK
        );
        Util.arrayFillNonAtomic(work, tLen, (short) 64, (byte) 0);

        signer.init(identityPriv, Signature.MODE_SIGN);
        short sigLen = signer.sign(work, (short) 0, tLen, work, tLen);
        if (sigLen < 8 || sigLen > 73) {
            reset();
            ISOException.throwIt(SW_SC_ERROR);
        }

        // HKDF-Expand from PRK (104 bytes total across 4 blocks of 32B).
        // Copy card_eph(65) -> work[0..65) and sig -> work[74..74+sigLen) first;
        // transcript has already been hashed and signed, and work[160..224) stays free.
        Util.arrayCopyNonAtomic(work, cardOff, work, (short) 0, (short) 65);
        Util.arrayCopyNonAtomic(work, tLen, work, (short) 74, sigLen);
        work[73] = (byte) sigLen;
        short replyLen = (short) (74 + sigLen);

        hmacSha256(
            session, S_PRK, (short) 32,
            HKDF_INFO_1, (short) 0, (short) HKDF_INFO_1.length,
            work, (short) 0, (short) 0,
            work, (short) 0, (short) 0,
            work, (short) 160
        );
        keyC2d.setKey(work, (short) 160);
        keyD2c.setKey(work, (short) 176);

        hmacSha256(
            session, S_PRK, (short) 32,
            work, (short) 160, (short) 32,
            HKDF_INFO_2, (short) 0, (short) HKDF_INFO_2.length,
            work, (short) 0, (short) 0,
            session, S_MC2D
        );
        hmacSha256(
            session, S_PRK, (short) 32,
            session, S_MC2D, (short) 32,
            HKDF_INFO_3, (short) 0, (short) HKDF_INFO_3.length,
            work, (short) 0, (short) 0,
            session, S_MD2C
        );
        hmacSha256(
            session, S_PRK, (short) 32,
            session, S_MD2C, (short) 32,
            HKDF_INFO_4, (short) 0, (short) HKDF_INFO_4.length,
            work, (short) 0, (short) 0,
            work, (short) 160
        );
        Util.arrayCopyNonAtomic(work, (short) 160, session, S_SID, (short) 8);
        Util.arrayCopyNonAtomic(session, S_SID, work, (short) 65, (short) 8);

        Util.arrayFillNonAtomic(session, S_RX, (short) 40, (byte) 0);
        Util.arrayFillNonAtomic(work, (short) 160, (short) 64, (byte) 0);
        session[S_OPEN] = (byte) 1;

        apdu.setOutgoing();
        apdu.setOutgoingLength(replyLen);
        apdu.sendBytesLong(work, (short) 0, replyLen);
        Util.arrayFillNonAtomic(work, (short) 0, replyLen, (byte) 0);
    }

    /** Increment big-endian 32-bit unsigned counter at session[off..off+4); reject overflow. */
    private void incrementCounter(short off) {
        if (session[off] == (byte) 0xFF && session[(short) (off + 1)] == (byte) 0xFF
                && session[(short) (off + 2)] == (byte) 0xFF && session[(short) (off + 3)] == (byte) 0xFF) {
            reset();
            ISOException.throwIt(SW_SC_ERROR);
        }
        for (short i = (short) (off + 3); i >= off; i--) {
            short v = (short) ((session[i] & 0xFF) + 1);
            session[i] = (byte) v;
            if ((v & 0x100) == 0) break;
        }
    }

    /**
     * Unwrap an incoming WRAP APDU into plainOut[0..plainLen).
     * Frame body: iv16 || ct(16..208, multiple of 16) || tag16.
     */
    public short unwrapCommand(APDU apdu, byte[] plainOut) {
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_P1] != DIR_C2D || buf[ISO7816.OFFSET_P2] != (byte) 0x00) {
            reset();
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (!isOpen()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short len = receiveBody(apdu, work, (short) 240);
        short ctLen = (short) (len - 32);
        if (len < 48 || (ctLen & (short) 0x0F) != 0) {
            reset();
            ISOException.throwIt(SW_SC_ERROR);
        }

        incrementCounter(S_RX);

        Util.arrayCopyNonAtomic(PROTOCOL, (short) 0, plainOut, (short) 0, (short) 10);
        plainOut[10] = DIR_C2D;
        Util.arrayCopyNonAtomic(session, S_SID, plainOut, (short) 11, (short) 8);
        Util.arrayCopyNonAtomic(session, S_RX, plainOut, (short) 19, (short) 4);

        short tagOff = (short) (16 + ctLen);
        hmacSha256(
            session, S_MC2D, (short) 32,
            plainOut, (short) 0, (short) 23,
            work, (short) 0, tagOff,
            work, (short) 0, (short) 0,
            plainOut, (short) 24
        );

        byte diff = 0;
        for (short i = 0; i < 16; i++) {
            diff |= (byte) (plainOut[(short) (24 + i)] ^ work[(short) (tagOff + i)]);
        }
        if (diff != 0) {
            Util.arrayFillNonAtomic(plainOut, (short) 0, (short) 56, (byte) 0);
            reset();
            ISOException.throwIt(SW_SC_ERROR);
        }

        aesCbc.init(keyC2d, Cipher.MODE_DECRYPT, work, (short) 0, (short) 16);
        short decLen = aesCbc.doFinal(work, (short) 16, ctLen, plainOut, (short) 0);
        if (decLen != ctLen) {
            reset();
            ISOException.throwIt(SW_SC_ERROR);
        }

        short padPos = -1;
        short badPad = 0;
        for (short i = (short) (ctLen - 1); i >= 0; i--) {
            byte b = plainOut[i];
            if (padPos < 0) {
                if (b == (byte) 0x80) {
                    padPos = i;
                } else if (b != (byte) 0x00) {
                    badPad = 1;
                }
            }
        }
        if (badPad != 0 || padPos < 4) {
            Util.arrayFillNonAtomic(plainOut, (short) 0, ctLen, (byte) 0);
            reset();
            ISOException.throwIt(SW_SC_ERROR);
        }
        return padPos;
    }

    /**
     * Encrypt and authenticate inner response plain[0..plainLen) || sw1 || sw2,
     * and send iv16 || ct || tag16 as the WRAP APDU response.
     */
    public void sendWrappedResponse(APDU apdu, byte[] plain, short plainLen, short sw) {
        if (!isOpen() || plainLen < 0 || plainLen > 205) {
            reset();
            ISOException.throwIt(SW_SC_ERROR);
        }
        incrementCounter(S_TX);

        short pos = plainLen;
        plain[pos++] = (byte) ((sw >> 8) & 0xFF);
        plain[pos++] = (byte) (sw & 0xFF);
        plain[pos++] = (byte) 0x80;
        while ((pos & (short) 0x0F) != 0) {
            plain[pos++] = (byte) 0x00;
        }
        short ctLen = pos;

        rng.generateData(work, (short) 0, (short) 16);
        aesCbc.init(keyD2c, Cipher.MODE_ENCRYPT, work, (short) 0, (short) 16);
        aesCbc.doFinal(plain, (short) 0, ctLen, work, (short) 16);
        Util.arrayFillNonAtomic(plain, (short) 0, ctLen, (byte) 0);

        Util.arrayCopyNonAtomic(PROTOCOL, (short) 0, plain, (short) 0, (short) 10);
        plain[10] = DIR_D2C;
        Util.arrayCopyNonAtomic(session, S_SID, plain, (short) 11, (short) 8);
        Util.arrayCopyNonAtomic(session, S_TX, plain, (short) 19, (short) 4);

        short tagOff = (short) (16 + ctLen);
        hmacSha256(
            session, S_MD2C, (short) 32,
            plain, (short) 0, (short) 23,
            work, (short) 0, tagOff,
            work, (short) 0, (short) 0,
            plain, (short) 24
        );
        Util.arrayCopyNonAtomic(plain, (short) 24, work, tagOff, (short) 16);
        Util.arrayFillNonAtomic(plain, (short) 0, (short) 56, (byte) 0);

        short outLen = (short) (tagOff + 16);
        apdu.setOutgoing();
        apdu.setOutgoingLength(outLen);
        apdu.sendBytesLong(work, (short) 0, outLen);
        Util.arrayFillNonAtomic(work, (short) 0, outLen, (byte) 0);
    }
}
