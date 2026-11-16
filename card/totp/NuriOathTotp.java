package com.nuri.oath;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.HMACKey;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * Minimal on-card OATH-TOTP.
 *
 * The card has no clock, so the host sends the 8-byte time counter
 * (floor(unixtime/period)). The card only does the one secret-dependent
 * step: HMAC-SHA1(secret, counter). The TOTP truncation is public math and
 * is done on the host. The shared secret never leaves the card.
 *
 * HMAC engine: the constructor tries the native TYPE_HMAC / ALG_HMAC_SHA1
 * pair (works on the Feitian card in use today). JCAlgTest reports both as
 * unsupported on NXP JCOP4 J3R180/J3R200 and Infineon SECORA, so when the
 * native engine throws CryptoException the applet falls back to RFC 2104
 * HMAC-SHA1 built on MessageDigest.ALG_SHA (supported on every profile) with
 * the secret kept in a persistent byte array. Both engines give the same bytes.
 *
 * INS_PUT    (0x01): data = [pinLen][pin 4..16 bytes][secret 1..64 bytes]
 *                    The first PUT chooses the admin PIN and stores the secret.
 *                    Every later PUT must present that PIN (5 tries; after
 *                    that PUT is blocked until the applet is reinstalled,
 *                    CALC keeps working). 63Cx = wrong PIN, x tries left.
 *                    6983 = blocked. 6700 = bad lengths.
 * INS_CALC   (0x02): data = 8-byte big-endian counter -> 20-byte HMAC-SHA1
 *                    (wire format unchanged; holding the card = reading codes)
 * INS_STATUS (0x03): -> [provisioned 0/1][engine 0=native 1=software][PIN tries left]
 *
 * Install parameter (GP application-specific data, first byte) 0x01 forces
 * the software engine. The jCardSim tests use it to exercise the fallback on
 * a simulator that has native HMAC.
 *
 * AID: 4E 55 52 49 54 4F 54 50  ("NURITOTP")
 */
public class NuriOathTotp extends Applet {

    private static final byte INS_PUT    = (byte) 0x01;
    private static final byte INS_CALC   = (byte) 0x02;
    private static final byte INS_STATUS = (byte) 0x03;

    private static final short HMAC_BLOCK = (short) 64;   // SHA-1 block; secrets <= 64 need no pre-hash
    private static final short SECRET_MAX = HMAC_BLOCK;
    private static final short SHA1_LEN   = (short) 20;
    private static final short PIN_MIN    = (short) 4;
    private static final short PIN_MAX    = (short) 16;
    private static final byte  PIN_TRIES  = (byte) 5;

    private static final byte PARAM_FORCE_SOFTWARE = (byte) 0x01;

    private static final short SW_PIN_BLOCKED = (short) 0x6983;
    private static final short SW_PIN_WRONG   = (short) 0x63C0;  // low nibble = tries left

    // Native engine; both null when unsupported or forced off.
    private HMACKey key;
    private Signature hmac;

    // Software engine.
    private MessageDigest sha;
    private final byte[] secret;      // persistent, SECRET_MAX bytes
    private short secretLen;
    private byte[] block;             // transient 64: K ^ ipad, then K ^ opad
    private byte[] inner;             // transient 20: inner hash

    private final OwnerPIN pin;
    private boolean provisioned = false;

    private NuriOathTotp(boolean forceSoftware) {
        pin = new OwnerPIN(PIN_TRIES, (byte) PIN_MAX);
        secret = new byte[SECRET_MAX];
        secretLen = 0;

        if (!forceSoftware) {
            try {
                key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) (HMAC_BLOCK * 8), false);
                hmac = Signature.getInstance(Signature.ALG_HMAC_SHA1, false);
            } catch (CryptoException e) {
                key = null;
                hmac = null;
            }
        }
        if (hmac == null) {
            sha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            block = JCSystem.makeTransientByteArray(HMAC_BLOCK, JCSystem.CLEAR_ON_DESELECT);
            inner = JCSystem.makeTransientByteArray(SHA1_LEN, JCSystem.CLEAR_ON_DESELECT);
        }
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NuriOathTotp(forceSoftwareParam(bArray, bOffset, bLength)).register();
    }

    /** GP install data is [Li][instance AID][Lc][control][La][app data]; app data byte 0 == 0x01 forces software HMAC. */
    private static boolean forceSoftwareParam(byte[] bArray, short bOffset, byte bLength) {
        short len = (short) (bLength & 0xFF);
        if (bArray == null || len < 3) {
            return false;
        }
        short end = (short) (bOffset + len);
        short p = bOffset;
        short li = (short) (bArray[p] & 0xFF);
        p = (short) (p + 1 + li);
        if (p >= end) {
            return false;
        }
        short lc = (short) (bArray[p] & 0xFF);
        p = (short) (p + 1 + lc);
        if (p >= end) {
            return false;
        }
        short la = (short) (bArray[p] & 0xFF);
        p = (short) (p + 1);
        if (la < 1 || p >= end) {
            return false;
        }
        return bArray[p] == PARAM_FORCE_SOFTWARE;
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_PUT:
                put(buf, len);
                break;

            case INS_CALC:
                if (!provisioned) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                if (len != 8) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                short n;
                if (hmac != null) {
                    hmac.init(key, Signature.MODE_SIGN);
                    n = hmac.sign(buf, ISO7816.OFFSET_CDATA, len, buf, (short) 0);
                } else {
                    n = softHmacSha1(buf, ISO7816.OFFSET_CDATA, len, buf, (short) 0);
                }
                apdu.setOutgoingAndSend((short) 0, n);
                break;

            case INS_STATUS:
                buf[0] = provisioned ? (byte) 1 : (byte) 0;
                buf[1] = (hmac != null) ? (byte) 0 : (byte) 1;
                buf[2] = pin.getTriesRemaining();
                apdu.setOutgoingAndSend((short) 0, (short) 3);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void put(byte[] buf, short len) {
        if (len < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short pinLen = (short) (buf[ISO7816.OFFSET_CDATA] & 0xFF);
        short pinOff = (short) (ISO7816.OFFSET_CDATA + 1);
        short secOff = (short) (pinOff + pinLen);
        short secLen = (short) (len - 1 - pinLen);
        if (pinLen < PIN_MIN || pinLen > PIN_MAX || secLen < 1 || secLen > SECRET_MAX) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (provisioned) {
            if (pin.getTriesRemaining() == 0) {
                ISOException.throwIt(SW_PIN_BLOCKED);
            }
            if (!pin.check(buf, pinOff, (byte) pinLen)) {
                byte left = pin.getTriesRemaining();
                ISOException.throwIt(left == 0 ? SW_PIN_BLOCKED : (short) (SW_PIN_WRONG | left));
            }
        }

        // PIN, secret and flag land together or not at all (card pulled mid-PUT).
        JCSystem.beginTransaction();
        if (!provisioned) {
            pin.update(buf, pinOff, (byte) pinLen);
        }
        if (hmac != null) {
            key.setKey(buf, secOff, secLen);
        } else {
            Util.arrayCopy(buf, secOff, secret, (short) 0, secLen);
            for (short i = secLen; i < SECRET_MAX; i++) {
                secret[i] = 0;
            }
            secretLen = secLen;
        }
        provisioned = true;
        JCSystem.commitTransaction();
        pin.reset();
    }

    /** RFC 2104: SHA1((K ^ opad) || SHA1((K ^ ipad) || msg)), K zero-padded to 64 bytes. */
    private short softHmacSha1(byte[] msg, short msgOff, short msgLen, byte[] out, short outOff) {
        Util.arrayFillNonAtomic(block, (short) 0, HMAC_BLOCK, (byte) 0x36);
        for (short i = 0; i < secretLen; i++) {
            block[i] = (byte) (block[i] ^ secret[i]);
        }
        sha.reset();
        sha.update(block, (short) 0, HMAC_BLOCK);
        sha.doFinal(msg, msgOff, msgLen, inner, (short) 0);

        Util.arrayFillNonAtomic(block, (short) 0, HMAC_BLOCK, (byte) 0x5C);
        for (short i = 0; i < secretLen; i++) {
            block[i] = (byte) (block[i] ^ secret[i]);
        }
        sha.reset();
        sha.update(block, (short) 0, HMAC_BLOCK);
        sha.doFinal(inner, (short) 0, SHA1_LEN, out, outOff);

        Util.arrayFillNonAtomic(block, (short) 0, HMAC_BLOCK, (byte) 0);
        Util.arrayFillNonAtomic(inner, (short) 0, SHA1_LEN, (byte) 0);
        return SHA1_LEN;
    }
}
