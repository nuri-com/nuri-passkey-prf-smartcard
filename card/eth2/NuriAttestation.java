// SPDX-License-Identifier: MIT
// Canonical clean-room source. Generate package-local copies with generate-attestation.py.
package com.nuri.eth2;

import javacard.framework.*;
import javacard.security.*;

/** Per-applet native P-256 identity. No scalar import, readback, reset or debug API. */
final class NuriAttestation {
    private static final byte[] CERT_DOMAIN = {'N','U','R','I','-','A','T','T','-','V','1'};
    private static final byte[] RESP_DOMAIN = {'N','U','R','I','-','A','T','T','-','R','E','S','P','-','V','1'};
    private static final byte[] BIND_DOMAIN = {'N','H','W','V','1'};
    private static final byte[] P256 = {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xfc,(byte)0x5a,(byte)0xc6,(byte)0x35,(byte)0xd8,(byte)0xaa,(byte)0x3a,(byte)0x93,(byte)0xe7,(byte)0xb3,(byte)0xeb,(byte)0xbd,(byte)0x55,(byte)0x76,(byte)0x98,(byte)0x86,(byte)0xbc,(byte)0x65,(byte)0x1d,(byte)0x06,(byte)0xb0,(byte)0xcc,(byte)0x53,(byte)0xb0,(byte)0xf6,(byte)0x3b,(byte)0xce,(byte)0x3c,(byte)0x3e,(byte)0x27,(byte)0xd2,(byte)0x60,(byte)0x4b,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xbc,(byte)0xe6,(byte)0xfa,(byte)0xad,(byte)0xa7,(byte)0x17,(byte)0x9e,(byte)0x84,(byte)0xf3,(byte)0xb9,(byte)0xca,(byte)0xc2,(byte)0xfc,(byte)0x63,(byte)0x25,(byte)0x51,(byte)0x04,(byte)0x6b,(byte)0x17,(byte)0xd1,(byte)0xf2,(byte)0xe1,(byte)0x2c,(byte)0x42,(byte)0x47,(byte)0xf8,(byte)0xbc,(byte)0xe6,(byte)0xe5,(byte)0x63,(byte)0xa4,(byte)0x40,(byte)0xf2,(byte)0x77,(byte)0x03,(byte)0x7d,(byte)0x81,(byte)0x2d,(byte)0xeb,(byte)0x33,(byte)0xa0,(byte)0xf4,(byte)0xa1,(byte)0x39,(byte)0x45,(byte)0xd8,(byte)0x98,(byte)0xc2,(byte)0x96,(byte)0x4f,(byte)0xe3,(byte)0x42,(byte)0xe2,(byte)0xfe,(byte)0x1a,(byte)0x7f,(byte)0x9b,(byte)0x8e,(byte)0xe7,(byte)0xeb,(byte)0x4a,(byte)0x7c,(byte)0x0f,(byte)0x9e,(byte)0x16,(byte)0x2b,(byte)0xce,(byte)0x33,(byte)0x57,(byte)0x6b,(byte)0x31,(byte)0x5e,(byte)0xce,(byte)0xcb,(byte)0xb6,(byte)0x40,(byte)0x68,(byte)0x37,(byte)0xbf,(byte)0x51,(byte)0xf5};
    private final ECPrivateKey identity;
    private final ECPublicKey identityPublic;
    private final Signature signer;
    private final byte[] aid;
    private final byte[] cardId;
    private final byte[] publicKey;
    private final byte[] cert;
    private final byte[] binding;
    private short certLength;
    private short bindingLength;
    private boolean sealed;
    private final byte[] message;
    private final byte[] signature;
    private final byte[] reply;
    private final short[] pendingLength;

    NuriAttestation(byte[] appletAid) {
        aid = new byte[(short)appletAid.length];
        Util.arrayCopyNonAtomic(appletAid, (short)0, aid, (short)0, (short)aid.length);
        cardId = new byte[16];
        RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(cardId, (short)0, (short)16);
        identity = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)256, false);
        identityPublic = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)256, false);
        curve(identity); curve(identityPublic);
        new KeyPair(identityPublic, identity).genKeyPair();
        publicKey = new byte[65];
        if (identityPublic.getW(publicKey, (short)0) != 65 || publicKey[0] != 4)
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        cert = new byte[72]; binding = new byte[72];
        message = JCSystem.makeTransientByteArray((short)160, JCSystem.CLEAR_ON_DESELECT);
        signature = JCSystem.makeTransientByteArray((short)72, JCSystem.CLEAR_ON_DESELECT);
        reply = JCSystem.makeTransientByteArray((short)512, JCSystem.CLEAR_ON_DESELECT);
        pendingLength = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
    }

    static void curve(ECKey key) {
        key.setFieldFP(P256, (short)0, (short)32);
        key.setA(P256, (short)32, (short)32);
        key.setB(P256, (short)64, (short)32);
        key.setR(P256, (short)96, (short)32);
        key.setG(P256, (short)128, (short)65);
        key.setK((short)1);
    }

    boolean handles(byte ins) { return ins >= (byte)0x70 && ins <= (byte)0x74; }

    private short sign(short length) {
        signer.init(identity, Signature.MODE_SIGN);
        short n = signer.sign(message, (short)0, length, signature, (short)0);
        if (n < 8 || n > 72) ISOException.throwIt((short)0x6988);
        return n;
    }

    /** Complete all crypto before the caller publishes a signing key. */
    void prepareBinding(byte[] pub, short off, short length) {
        if (length != 33 && length != 65) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short p = append(message, (short)0, BIND_DOMAIN, (short)0, (short)BIND_DOMAIN.length);
        p = append(message, p, aid, (short)0, (short)aid.length);
        p = append(message, p, pub, off, length);
        pendingLength[0] = sign(p);
        Util.arrayFillNonAtomic(message, (short)0, (short)message.length, (byte)0);
    }

    /** Must share the caller's transaction with its key cache and keyed flag. */
    void commitBinding() {
        if (JCSystem.getTransactionDepth() == 0 || pendingLength[0] == 0)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        Util.arrayCopy(signature, (short)0, binding, (short)0, pendingLength[0]);
        bindingLength = pendingLength[0];
    }

    private short receive(APDU apdu, short expected) {
        short got = apdu.setIncomingAndReceive();
        short len = apdu.getIncomingLength();
        if (len != expected) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short copied = 0;
        short off = apdu.getOffsetCdata();
        while (got > 0) {
            if ((short)(copied + got) > len) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            Util.arrayCopyNonAtomic(apdu.getBuffer(), off, message, copied, got);
            copied = (short)(copied + got);
            if (copied == len) break;
            got = apdu.receiveBytes((short)0); off = 0;
        }
        if (copied != len) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return len;
    }

    void process(APDU apdu, byte[] signingPub, short off, short length, byte pinState) {
        byte[] buf = apdu.getBuffer();
        byte ins = buf[ISO7816.OFFSET_INS];
        byte page = buf[ISO7816.OFFSET_P1];
        if (buf[ISO7816.OFFSET_P2] != 0 ||
                (page != 0 && !(ins == (byte)0x72 && page == 1)))
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        short n = 0;
        switch (ins) {
            case (byte)0x70:
                receive(apdu, (short)0); n = info(); break;
            case (byte)0x71:
                if (sealed || certLength != 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                short certLen = receiveCertificate(apdu);
                if (certLen < 8 || certLen > 72 || message[0] != (byte)0x30)
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                JCSystem.beginTransaction();
                Util.arrayCopy(message, (short)0, cert, (short)0, certLen);
                certLength = certLen;
                JCSystem.commitTransaction();
                break;
            case (byte)0x72:
                receive(apdu, (short)32);
                if (page == 0) { n = info(); break; }
                // Preserve challenge while prefixing its domain.
                Util.arrayCopyNonAtomic(message, (short)0, reply, (short)0, (short)32);
                short p = append(message, (short)0, RESP_DOMAIN, (short)0, (short)RESP_DOMAIN.length);
                p = append(message, p, reply, (short)0, (short)32);
                p = append(message, p, signingPub, off, length);
                message[p++] = pinState;
                short sigLen = sign(p);
                n = 0;
                reply[n++] = (byte)length;
                n = append(reply, n, signingPub, off, length);
                reply[n++] = pinState;
                reply[n++] = (byte)sigLen;
                n = append(reply, n, signature, (short)0, sigLen);
                reply[n++] = (byte)bindingLength;
                n = append(reply, n, binding, (short)0, bindingLength);
                break;
            case (byte)0x73:
                receive(apdu, (short)0);
                if (sealed || certLength == 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                JCSystem.beginTransaction(); sealed = true; JCSystem.commitTransaction();
                break;
            case (byte)0x74:
                receive(apdu, (short)0);
                if (length == 0 || bindingLength == 0) ISOException.throwIt((short)0x6986);
                n = append(reply, (short)0, binding, (short)0, bindingLength);
                break;
            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        if (n != 0) {
            apdu.setOutgoing(); apdu.setOutgoingLength(n);
            apdu.sendBytesLong(reply, (short)0, n);
        }
    }

    private short receiveCertificate(APDU apdu) {
        short got = apdu.setIncomingAndReceive();
        short len = apdu.getIncomingLength();
        if (len < 8 || len > 72) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short copied = 0;
        short off = apdu.getOffsetCdata();
        while (got > 0) {
            if ((short)(copied + got) > len) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            Util.arrayCopyNonAtomic(apdu.getBuffer(), off, message, copied, got);
            copied = (short)(copied + got);
            if (copied == len) break;
            got = apdu.receiveBytes((short)0); off = 0;
        }
        if (copied != len) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return len;
    }

    private short info() {
        short p = 0;
        reply[p++] = 1;
        p = append(reply, p, cardId, (short)0, (short)16);
        reply[p++] = (byte)aid.length;
        p = append(reply, p, aid, (short)0, (short)aid.length);
        p = append(reply, p, publicKey, (short)0, (short)65);
        reply[p++] = sealed ? (byte)1 : (byte)0;
        reply[p++] = (byte)certLength;
        return append(reply, p, cert, (short)0, certLength);
    }

    private static short append(byte[] out, short pos, byte[] data, short off, short len) {
        if (len != 0) Util.arrayCopyNonAtomic(data, off, out, pos, len);
        return (short)(pos + len);
    }

    void clearScratch() {
        Util.arrayFillNonAtomic(message, (short)0, (short)message.length, (byte)0);
        Util.arrayFillNonAtomic(signature, (short)0, (short)signature.length, (byte)0);
        Util.arrayFillNonAtomic(reply, (short)0, (short)reply.length, (byte)0);
        pendingLength[0] = 0;
    }
}
