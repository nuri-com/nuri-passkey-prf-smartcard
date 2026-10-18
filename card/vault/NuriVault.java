// SPDX-License-Identifier: MIT
package com.nuri.vault;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/** PIN-gated, 16-slot vault. Clean-room RFC 2104 HMAC-SHA256 using only SHA256.
 * No secret export exists for HMAC slots. Bearer REVEAL deliberately exports.
 * No native TYPE_HMAC dependency, install switches, debug or reset commands.
 */
public final class NuriVault extends Applet {
    private static final byte STATUS = (byte) 0x01;
    private static final byte SET_PIN = (byte) 0x10;
    private static final byte VERIFY = (byte) 0x20;
    private static final byte PUT = (byte) 0x30;
    private static final byte LIST = (byte) 0x31;
    private static final byte HMAC = (byte) 0x40;
    private static final byte REVEAL = (byte) 0x41;
    private static final byte DELETE = (byte) 0x50;
    private static final byte HMAC_KIND = (byte) 1;
    private static final byte BEARER_KIND = (byte) 2;
    private static final short BLOCKED = (short) 0x6983;
    private static final short MISSING = (short) 0x6A88;
    private static final short SLOTS = (short) 16;
    private static final short NAME_MAX = (short) 16;
    private static final short SECRET_MAX = (short) 64;

    private final OwnerPIN pin;
    private boolean pinSet;
    private final byte[] kinds;
    private final byte[] nameLengths;
    private final byte[] secretLengths;
    private final byte[] names;
    private final byte[] secrets;
    private final MessageDigest sha;
    private final byte[] request;
    private final byte[] reply;
    private final byte[] pad;
    private final byte[] inner;

    private NuriVault() {
        pin = new OwnerPIN((byte) 5, (byte) 16);
        kinds = new byte[SLOTS];
        nameLengths = new byte[SLOTS];
        secretLengths = new byte[SLOTS];
        names = new byte[(short) (SLOTS * NAME_MAX)];
        secrets = new byte[(short) (SLOTS * SECRET_MAX)];
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        request = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_DESELECT);
        reply = JCSystem.makeTransientByteArray((short) 144, JCSystem.CLEAR_ON_DESELECT);
        pad = JCSystem.makeTransientByteArray(SECRET_MAX, JCSystem.CLEAR_ON_DESELECT);
        inner = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
    }

    public static void install(byte[] data, short offset, byte length) {
        new NuriVault().register();
    }

    public boolean select() {
        pin.reset();
        clearScratch();
        return true;
    }

    public void deselect() {
        pin.reset();
        clearScratch();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        try {
            if (buffer[ISO7816.OFFSET_CLA] != (byte) 0x80) {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }
            byte ins = buffer[ISO7816.OFFSET_INS];
            short page = (short) (buffer[ISO7816.OFFSET_P1] & 0xFF);
            if (buffer[ISO7816.OFFSET_P2] != 0 || (ins == LIST ? page > 1 : page != 0)) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            short length = receive(apdu);
            short n = 0;
            switch (ins) {
                case STATUS:
                    exact(length, (short) 0);
                    reply[0] = 1;
                    reply[1] = pinSet ? (byte) 1 : (byte) 0;
                    reply[2] = pin.getTriesRemaining();
                    reply[3] = (byte) SLOTS;
                    n = 4;
                    break;
                case SET_PIN:
                    if (pinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    pinLength(length);
                    JCSystem.beginTransaction();
                    pin.update(request, (short) 0, (byte) length);
                    pinSet = true;
                    JCSystem.commitTransaction();
                    pin.reset(); // Initial setup is NOT authentication.
                    break;
                case VERIFY:
                    initialized();
                    pinLength(length);
                    if (!pin.check(request, (short) 0, (byte) length)) {
                        byte left = pin.getTriesRemaining();
                        ISOException.throwIt(left == 0 ? BLOCKED : (short) (0x63C0 | left));
                    }
                    break;
                case PUT:
                    authorized();
                    put(length);
                    break;
                case LIST:
                    authorized();
                    exact(length, (short) 0);
                    n = list(page);
                    break;
                case HMAC:
                case REVEAL:
                case DELETE:
                    authorized();
                    short nameLength = requestName(length);
                    if (ins != HMAC) exact(length, (short) (1 + nameLength));
                    short slot = find((short) 1, nameLength);
                    if (slot < 0) ISOException.throwIt(MISSING);
                    if (ins == HMAC) {
                        if (kinds[slot] != HMAC_KIND) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                        hmac(slot, (short) (1 + nameLength), (short) (length - 1 - nameLength));
                        n = 32;
                    } else if (ins == REVEAL) {
                        if (kinds[slot] != BEARER_KIND) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                        n = (short) (secretLengths[slot] & 0xFF);
                        Util.arrayCopyNonAtomic(secrets, (short) (slot * SECRET_MAX), reply, (short) 0, n);
                    } else {
                        delete(slot);
                    }
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
            if (n != 0) {
                apdu.setOutgoing();
                apdu.setOutgoingLength(n);
                apdu.sendBytesLong(reply, (short) 0, n);
            }
        } finally {
            if (JCSystem.getTransactionDepth() != 0) JCSystem.abortTransaction();
            clearScratch();
            // Incoming PINs/PUT values and outgoing bearer copies must not linger.
            Util.arrayFillNonAtomic(buffer, (short) 0, (short) buffer.length, (byte) 0);
        }
    }

    /** Receive the COMPLETE short command, including readers with small APDU buffers. */
    private short receive(APDU apdu) {
        short got = apdu.setIncomingAndReceive();
        short length = apdu.getIncomingLength();
        if (length < 0 || length > 255) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short offset = apdu.getOffsetCdata();
        short copied = 0;
        while (got > 0) {
            if ((short) (copied + got) > length) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            Util.arrayCopyNonAtomic(apdu.getBuffer(), offset, request, copied, got);
            copied = (short) (copied + got);
            if (copied == length) break;
            got = apdu.receiveBytes((short) 0);
            offset = 0;
        }
        exact(copied, length);
        return length;
    }

    private void initialized() {
        if (!pinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (pin.getTriesRemaining() == 0) ISOException.throwIt(BLOCKED);
    }

    private void authorized() {
        initialized();
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    private static void exact(short actual, short expected) {
        if (actual != expected) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    private static void pinLength(short length) {
        if (length < 4 || length > 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    private short requestName(short length) {
        if (length < 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short n = (short) (request[0] & 0xFF);
        if (n < 1 || n > NAME_MAX || length < (short) (n + 1)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return n;
    }

    private short find(short offset, short length) {
        for (short slot = 0; slot < SLOTS; slot++) {
            if (kinds[slot] != 0 && nameLengths[slot] == (byte) length &&
                    Util.arrayCompare(request, offset, names, (short) (slot * NAME_MAX), length) == 0) return slot;
        }
        return (short) -1;
    }

    private void put(short length) {
        if (length < 4) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte kind = request[0];
        if (kind != HMAC_KIND && kind != BEARER_KIND) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        short nl = (short) (request[1] & 0xFF);
        short sl = (short) (length - 2 - nl);
        if (nl < 1 || nl > NAME_MAX || sl < 1 || sl > SECRET_MAX) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (find((short) 2, nl) >= 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short slot;
        for (slot = 0; slot < SLOTS; slot++) if (kinds[slot] == 0) break;
        if (slot == SLOTS) ISOException.throwIt(ISO7816.SW_FILE_FULL);
        JCSystem.beginTransaction();
        Util.arrayCopy(request, (short) 2, names, (short) (slot * NAME_MAX), nl);
        Util.arrayCopy(request, (short) (2 + nl), secrets, (short) (slot * SECRET_MAX), sl);
        nameLengths[slot] = (byte) nl;
        secretLengths[slot] = (byte) sl;
        kinds[slot] = kind; // Publish name/class/value together, never change class in place.
        JCSystem.commitTransaction();
    }

    private short list(short page) {
        short n = 0;
        for (short slot = (short) (page * 8); slot < (short) ((page + 1) * 8); slot++) {
            if (kinds[slot] == 0) continue;
            reply[n++] = kinds[slot];
            short length = (short) (nameLengths[slot] & 0xFF);
            reply[n++] = (byte) length;
            Util.arrayCopyNonAtomic(names, (short) (slot * NAME_MAX), reply, n, length);
            n = (short) (n + length);
        }
        return n;
    }

    private void delete(short slot) {
        JCSystem.beginTransaction();
        for (short i = 0; i < SECRET_MAX; i++) secrets[(short) (slot * SECRET_MAX + i)] = 0;
        for (short i = 0; i < NAME_MAX; i++) names[(short) (slot * NAME_MAX + i)] = 0;
        secretLengths[slot] = 0;
        nameLengths[slot] = 0;
        kinds[slot] = 0;
        JCSystem.commitTransaction();
    }

    /** RFC 2104: SHA256((K xor opad) || SHA256((K xor ipad) || message)).
     * Imported keys are 1..64 bytes, so RFC 2104's long-key reduction is unneeded.
     */
    private void hmac(short slot, short offset, short length) {
        short kl = (short) (secretLengths[slot] & 0xFF);
        short ko = (short) (slot * SECRET_MAX);
        Util.arrayFillNonAtomic(pad, (short) 0, SECRET_MAX, (byte) 0x36);
        for (short i = 0; i < kl; i++) pad[i] ^= secrets[(short) (ko + i)];
        sha.reset();
        sha.update(pad, (short) 0, SECRET_MAX);
        sha.doFinal(request, offset, length, inner, (short) 0);
        Util.arrayFillNonAtomic(pad, (short) 0, SECRET_MAX, (byte) 0x5C);
        for (short i = 0; i < kl; i++) pad[i] ^= secrets[(short) (ko + i)];
        sha.update(pad, (short) 0, SECRET_MAX);
        sha.doFinal(inner, (short) 0, (short) 32, reply, (short) 0);
    }

    private void clearScratch() {
        sha.reset();
        Util.arrayFillNonAtomic(request, (short) 0, (short) request.length, (byte) 0);
        Util.arrayFillNonAtomic(reply, (short) 0, (short) reply.length, (byte) 0);
        Util.arrayFillNonAtomic(pad, (short) 0, (short) pad.length, (byte) 0);
        Util.arrayFillNonAtomic(inner, (short) 0, (short) inner.length, (byte) 0);
    }
}
