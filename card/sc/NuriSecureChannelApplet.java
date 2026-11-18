// SPDX-License-Identifier: MIT
package com.nuri.sc;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/**
 * NURI-SC v1 reference & hardware-verification applet (AID 4E55524953433031).
 *
 * Enforces SC_REQUIRED: all PIN-bearing and secret-bearing commands
 * (SET_PIN, VERIFY_PIN, PUT_SECRET, HMAC_SHA256, PING) are rejected with
 * 0x6985 outside INS_WRAP and succeed only inside an authenticated NURI-SC v1
 * encrypted tunnel. Inner ISOException status words (e.g. 63Cx wrong PIN) are
 * returned encrypted inside the D2C frame so status words never leak on the
 * reader/PC/SC wire. Any outer MAC, padding, or counter failure wipes the
 * session and resets OwnerPIN validation immediately.
 */
public final class NuriSecureChannelApplet extends Applet {
    public static final byte[] APPLET_AID = {
        (byte) 0x4E, (byte) 0x55, (byte) 0x52, (byte) 0x49,
        (byte) 0x53, (byte) 0x43, (byte) 0x30, (byte) 0x31
    };

    // Outer plaintext discovery / session lifecycle (CLA 0x80)
    public static final byte INS_STATUS     = (byte) 0x01;
    public static final byte INS_GET_PUBKEY = (byte) 0x02;

    // Inner encrypted-only commands (rejected with 0x6985 in plaintext)
    public static final byte INS_SET_PIN    = (byte) 0x20;
    public static final byte INS_VERIFY_PIN = (byte) 0x21;
    public static final byte INS_PUT_SECRET = (byte) 0x30;
    public static final byte INS_HMAC       = (byte) 0x40;
    public static final byte INS_PING       = (byte) 0x50;

    private static final short SW_PIN_BLOCKED = (short) 0x6983;
    private static final short SW_MISSING     = (short) 0x6A88;
    private static final short SECRET_MAX     = (short) 64;

    private final ECPrivateKey identityPriv;
    private final ECPublicKey identityPub;
    private final byte[] identityPubBytes;
    private final NuriSecureChannel sc;
    private final OwnerPIN pin;
    private boolean pinSet;
    private final byte[] secret;
    private short secretLen;

    private final byte[] innerBuf;  // >= 240B transient buffer for unwrapped C2D APDU
    private final byte[] replyBuf;  // >= 224B transient buffer for inner D2C response

    private NuriSecureChannelApplet() {
        identityPriv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false);
        identityPub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) 256, false);
        NuriSecureChannel.setP256(identityPriv);
        NuriSecureChannel.setP256(identityPub);
        new KeyPair(identityPub, identityPriv).genKeyPair();
        identityPubBytes = new byte[65];
        if (identityPub.getW(identityPubBytes, (short) 0) != 65 || identityPubBytes[0] != (byte) 0x04) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        sc = new NuriSecureChannel(APPLET_AID, identityPriv);
        pin = new OwnerPIN((byte) 5, (byte) 16);
        secret = new byte[SECRET_MAX];

        innerBuf = JCSystem.makeTransientByteArray((short) 240, JCSystem.CLEAR_ON_DESELECT);
        replyBuf = JCSystem.makeTransientByteArray((short) 224, JCSystem.CLEAR_ON_DESELECT);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NuriSecureChannelApplet().register(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
    }

    public boolean select() {
        wipeTransient();
        return true;
    }

    public void deselect() {
        wipeTransient();
    }

    private void wipeTransient() {
        pin.reset();
        sc.reset();
        Util.arrayFillNonAtomic(innerBuf, (short) 0, (short) innerBuf.length, (byte) 0);
        Util.arrayFillNonAtomic(replyBuf, (short) 0, (short) replyBuf.length, (byte) 0);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        byte cla = buf[ISO7816.OFFSET_CLA];
        if (cla != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        byte ins = buf[ISO7816.OFFSET_INS];

        switch (ins) {
            case INS_STATUS:
                outerStatus(apdu, buf);
                return;
            case INS_GET_PUBKEY:
                outerGetPubkey(apdu, buf);
                return;
            case NuriSecureChannel.INS_OPEN:
                pin.reset();
                sc.open(apdu);
                return;
            case NuriSecureChannel.INS_CLOSE:
                if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
                    wipeTransient();
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
                if (NuriSecureChannel.receiveBody(apdu, innerBuf, (short) 0) != 0) {
                    wipeTransient();
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                wipeTransient();
                return;
            case NuriSecureChannel.INS_WRAP:
                handleWrap(apdu);
                return;
            case INS_SET_PIN:
            case INS_VERIFY_PIN:
            case INS_PUT_SECRET:
            case INS_HMAC:
            case INS_PING:
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void outerStatus(APDU apdu, byte[] buf) {
        if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (NuriSecureChannel.receiveBody(apdu, innerBuf, (short) 0) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        replyBuf[0] = (byte) 0x01;
        replyBuf[1] = sc.ecdhMode();
        replyBuf[2] = sc.isOpen() ? (byte) 1 : (byte) 0;
        replyBuf[3] = pinSet ? (byte) 1 : (byte) 0;
        replyBuf[4] = pin.getTriesRemaining();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 5);
        apdu.sendBytesLong(replyBuf, (short) 0, (short) 5);
    }

    private void outerGetPubkey(APDU apdu, byte[] buf) {
        if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (NuriSecureChannel.receiveBody(apdu, innerBuf, (short) 0) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 65);
        apdu.sendBytesLong(identityPubBytes, (short) 0, (short) 65);
    }

    private void handleWrap(APDU apdu) {
        short plainLen;
        try {
            plainLen = sc.unwrapCommand(apdu, innerBuf);
        } catch (ISOException e) {
            if (!sc.isOpen()) {
                pin.reset();
            }
            throw e;
        }

        short respLen = 0;
        short innerSw = ISO7816.SW_NO_ERROR;
        try {
            respLen = dispatchInner(innerBuf, plainLen, replyBuf);
        } catch (ISOException e) {
            respLen = 0;
            innerSw = e.getReason();
        } finally {
            Util.arrayFillNonAtomic(innerBuf, (short) 0, (short) innerBuf.length, (byte) 0);
        }

        sc.sendWrappedResponse(apdu, replyBuf, respLen, innerSw);
    }

    /**
     * Parse canonical short inner APDU from cmd[0..cmdLen):
     *   - 4 bytes: CLA INS P1 P2 (Lc=0)
     *   - 5+Lc bytes: CLA INS P1 P2 Lc Data[Lc]
     */
    private short dispatchInner(byte[] cmd, short cmdLen, byte[] out) {
        if (cmdLen < 4) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte cla = cmd[0];
        byte ins = cmd[1];
        byte p1 = cmd[2];
        byte p2 = cmd[3];
        if (cla != (byte) 0x80) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (p1 != 0 || p2 != 0) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short dataOff = 5;
        short lc = 0;
        if (cmdLen == 4) {
            lc = 0;
        } else {
            lc = (short) (cmd[4] & 0xFF);
            if (cmdLen != (short) (5 + lc)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }

        switch (ins) {
            case INS_PING:
                if (lc > 180) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (lc > 0) Util.arrayCopyNonAtomic(cmd, dataOff, out, (short) 0, lc);
                return lc;

            case INS_SET_PIN:
                if (pinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                if (lc < 4 || lc > 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                JCSystem.beginTransaction();
                pin.update(cmd, dataOff, (byte) lc);
                pinSet = true;
                JCSystem.commitTransaction();
                pin.reset();
                return 0;

            case INS_VERIFY_PIN:
                if (!pinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                if (pin.getTriesRemaining() == 0) ISOException.throwIt(SW_PIN_BLOCKED);
                if (lc < 4 || lc > 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (!pin.check(cmd, dataOff, (byte) lc)) {
                    short rem = pin.getTriesRemaining();
                    ISOException.throwIt(rem == 0 ? SW_PIN_BLOCKED : (short) (0x63C0 | rem));
                }
                return 0;

            case INS_PUT_SECRET:
                requirePin();
                if (lc < 1 || lc > SECRET_MAX) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                JCSystem.beginTransaction();
                Util.arrayFillNonAtomic(secret, (short) 0, SECRET_MAX, (byte) 0);
                Util.arrayCopy(cmd, dataOff, secret, (short) 0, lc);
                secretLen = lc;
                JCSystem.commitTransaction();
                return 0;

            case INS_HMAC:
                requirePin();
                if (secretLen == 0) ISOException.throwIt(SW_MISSING);
                sc.hmacSha256(
                    secret, (short) 0, secretLen,
                    cmd, dataOff, lc,
                    cmd, (short) 0, (short) 0,
                    cmd, (short) 0, (short) 0,
                    out, (short) 0
                );
                return 32;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return 0;
        }
    }

    private void requirePin() {
        if (!pinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (pin.getTriesRemaining() == 0) ISOException.throwIt(SW_PIN_BLOCKED);
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
}
