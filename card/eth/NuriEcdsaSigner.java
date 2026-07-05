package com.nuri.eth;

import javacard.framework.*;
import javacard.security.*;

/**
 * NuriEcdsaSigner — secp256k1 ECDSA signing for Ethereum/EVM.
 *
 * Uses Satochip's Biginteger class for RSA-accelerated modular arithmetic
 * (same as the MuSig2 applet). The private key is generated on-card and
 * never leaves the secure element.
 *
 * ECDSA: r = (k·G).x mod n
 *        s = k⁻¹(z + r·d) mod n
 *        v = parity(k·G.y)  (0 or 1)
 *
 * INS_GET_VERSION (0x01): returns version + build tag
 * INS_GET_PUBKEY   (0x02): returns 33-byte compressed pubkey
 * INS_KEYGEN       (0x03): generates a new key on-card, returns pubkey
 * INS_SIGN         (0x04): signs a 32-byte hash → r(32) || s(32) || v(1)
 *
 * AID: 4E 55 52 49 45 54 48 01  ("NURIETH1")
 */
public class NuriEcdsaSigner extends Applet {

    // 1.1: fixed modInverse (endianness, halving carry, termination — 1.0 hung on every SIGN)
    private static final byte[] APPLET_VERSION = {(byte)0x01, (byte)0x01};

    private static final byte INS_GET_VERSION = (byte)0x01;
    private static final byte INS_GET_PUBKEY  = (byte)0x02;
    private static final byte INS_KEYGEN      = (byte)0x03;
    private static final byte INS_SIGN        = (byte)0x04;

    private static final short SW_NOT_INITIALIZED = (short)0x6986;
    private static final short SW_SIGN_FAILED     = (short)0x6988;

    private static final short LENGTH_EC_FP_256 = (short)256;
    private static final byte ALG_EC_SVDP_DH_PLAIN_XY = (byte)0x06;

    // secp256k1 parameters
    public static final byte[] SECP256K1 = {
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
    private static final short OFF_N = 96;
    private static final short OFF_G = 128;

    // State
    private ECPrivateKey privKey;
    private ECPrivateKey nonceKey;
    private KeyAgreement keyAgreement;
    private RandomData rng;

    // Buffers
    private byte[] ecdhOut;       // 65 bytes
    private byte[] scratchA;      // 32 bytes (z)
    private byte[] scratchB;      // 32 bytes (k)
    private byte[] scratchC;      // 32 bytes (temp)
    private byte[] rStore;        // 32 bytes (r, saved)
    private byte[] mulWorkspace;  // 96 bytes (for BigIntegerWrapper.mulMod)

    // Extended GCD workspace for modInverse
    private byte[] gcdU;
    private byte[] gcdV;
    private byte[] gcdX1;
    private byte[] gcdX2;
    private byte[] gcdTemp;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NuriEcdsaSigner().register();
    }

    protected NuriEcdsaSigner() {
        privKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
        nonceKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);

        privKey.setFieldFP(SECP256K1, OFF_P, (short)32);
        privKey.setA(SECP256K1, (short)32, (short)32);
        privKey.setB(SECP256K1, (short)64, (short)32);
        privKey.setR(SECP256K1, OFF_N, (short)32);
        privKey.setG(SECP256K1, OFF_G, (short)65);

        nonceKey.setFieldFP(SECP256K1, OFF_P, (short)32);
        nonceKey.setA(SECP256K1, (short)32, (short)32);
        nonceKey.setB(SECP256K1, (short)64, (short)32);
        nonceKey.setR(SECP256K1, OFF_N, (short)32);
        nonceKey.setG(SECP256K1, OFF_G, (short)65);

        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        try {
            keyAgreement = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
        } catch (CryptoException e) {
            try {
                keyAgreement = KeyAgreement.getInstance((byte)0x03, false);
            } catch (CryptoException e2) {
                keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
            }
        }

        ecdhOut = JCSystem.makeTransientByteArray((short)65, JCSystem.CLEAR_ON_DESELECT);
        scratchA = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scratchB = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scratchC = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        rStore = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        mulWorkspace = JCSystem.makeTransientByteArray((short)96, JCSystem.CLEAR_ON_DESELECT);

        gcdU = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        gcdV = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        gcdX1 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        gcdX2 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        gcdTemp = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);

        Biginteger.init();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_GET_VERSION: getVersion(apdu); break;
            case INS_GET_PUBKEY:  getPublicKey(apdu); break;
            case INS_KEYGEN:      keygen(apdu); break;
            case INS_SIGN:        sign(apdu); break;
            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void getVersion(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopy(APPLET_VERSION, (short)0, buffer, (short)0, (short)2);
        buffer[2] = (byte)0x01;
        buffer[3] = (byte)0x45; // 'E'
        buffer[4] = (byte)0x54; // 'T'
        buffer[5] = (byte)0x48; // 'H'
        buffer[6] = (byte)0x31; // '1'
        apdu.setOutgoingAndSend((short)0, (short)7);
    }

    private void keygen(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        do {
            rng.generateData(scratchA, (short)0, (short)32);
            BigIntegerMod.reduce(scratchA, (short)0, scratchA, (short)0);
        } while (isZero(scratchA, (short)0));

        privKey.setS(scratchA, (short)0, (short)32);

        keyAgreement.init(privKey);
        short outLen = keyAgreement.generateSecret(SECP256K1, OFF_G, (short)65, ecdhOut, (short)0);
        compressPubkey(ecdhOut, outLen, buffer, (short)0);

        Util.arrayFillNonAtomic(scratchA, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(ecdhOut, (short)0, (short)65, (byte)0);
        apdu.setOutgoingAndSend((short)0, (short)33);
    }

    private void getPublicKey(APDU apdu) {
        if (!privKey.isInitialized()) ISOException.throwIt(SW_NOT_INITIALIZED);
        byte[] buffer = apdu.getBuffer();
        keyAgreement.init(privKey);
        short outLen = keyAgreement.generateSecret(SECP256K1, OFF_G, (short)65, ecdhOut, (short)0);
        compressPubkey(ecdhOut, outLen, buffer, (short)0);
        apdu.setOutgoingAndSend((short)0, (short)33);
    }

    private void sign(APDU apdu) {
        if (!privKey.isInitialized()) ISOException.throwIt(SW_NOT_INITIALIZED);
        byte[] buffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen != 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // z = hash mod n → scratchA
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, scratchA, (short)0, (short)32);
        BigIntegerMod.reduce(scratchA, (short)0, scratchA, (short)0);

        // Generate random nonce k → scratchB
        do {
            rng.generateData(scratchB, (short)0, (short)32);
            BigIntegerMod.reduce(scratchB, (short)0, scratchB, (short)0);
        } while (isZero(scratchB, (short)0));

        // R = k·G
        nonceKey.setS(scratchB, (short)0, (short)32);
        keyAgreement.init(nonceKey);
        short outLen = keyAgreement.generateSecret(SECP256K1, OFF_G, (short)65, ecdhOut, (short)0);

        // r = R.x mod n → rStore
        if (outLen == 65 && ecdhOut[0] == 0x04) {
            Util.arrayCopy(ecdhOut, (short)1, rStore, (short)0, (short)32);
        } else if (outLen == 32) {
            Util.arrayCopy(ecdhOut, (short)0, rStore, (short)0, (short)32);
        } else {
            ISOException.throwIt(SW_SIGN_FAILED);
        }
        BigIntegerMod.reduce(rStore, (short)0, rStore, (short)0);

        byte v = 0;
        if (outLen == 65 && ecdhOut[0] == 0x04) {
            v = (byte)(ecdhOut[64] & 0x01);
        }

        // s = k⁻¹(z + r·d) mod n
        // 1. r·d mod n → scratchC (d = private key)
        privKey.getS(ecdhOut, (short)0);
        BigIntegerWrapper.mulMod(rStore, (short)0, ecdhOut, (short)0, scratchC, (short)0, mulWorkspace, (short)0, (short)32);

        // 2. z + (r·d) mod n → scratchC
        BigIntegerWrapper.addMod(scratchA, (short)0, scratchC, (short)0, scratchC, (short)0, (short)32);

        // 3. k⁻¹ mod n → scratchA
        modInverse(scratchB, (short)0, scratchA, (short)0);

        // 4. s = k⁻¹ · (z + r·d) mod n → scratchB
        BigIntegerWrapper.mulMod(scratchA, (short)0, scratchC, (short)0, scratchB, (short)0, mulWorkspace, (short)0, (short)32);

        // Low-s normalization (EIP-2)
        if (isHighS(scratchB, (short)0)) {
            BigIntegerWrapper.negateMod(scratchB, (short)0, scratchB, (short)0, (short)32);
            v = (byte)(v ^ 1);
        }

        // Output: r(32) || s(32) || v(1)
        Util.arrayCopy(rStore, (short)0, buffer, (short)0, (short)32);
        Util.arrayCopy(scratchB, (short)0, buffer, (short)32, (short)32);
        buffer[(short)64] = v;

        // Clear sensitive data
        Util.arrayFillNonAtomic(scratchA, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(scratchB, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(scratchC, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(ecdhOut, (short)0, (short)65, (byte)0);
        Util.arrayFillNonAtomic(rStore, (short)0, (short)32, (byte)0);

        apdu.setOutgoingAndSend((short)0, (short)65);
    }

    /**
     * Modular inverse via binary extended GCD (HAC 14.61 shape).
     * result = a⁻¹ mod n
     *
     * Invariants: x1·a ≡ u (mod n), x2·a ≡ v (mod n). gcd(a,n)=1 (n prime),
     * so the loop ends with u==1 (inverse in x1) or v==1 (inverse in x2) —
     * u and v never reach 0, which the previous version did (u==v==1 →
     * u-=v → u=0 → "while u even" spun forever on zero and muted the card).
     */
    private void modInverse(byte[] a, short aOff, byte[] result, short rOff) {
        // u = a mod n, v = n, x1 = 1, x2 = 0
        BigIntegerMod.reduce(a, aOff, gcdU, (short)0);
        Util.arrayCopy(BigIntegerMod.SECP256K1_N, (short)0, gcdV, (short)0, (short)32);
        Util.arrayFillNonAtomic(gcdX1, (short)0, (short)32, (byte)0);
        gcdX1[(short)31] = 0x01;
        Util.arrayFillNonAtomic(gcdX2, (short)0, (short)32, (byte)0);

        short iterations = 0;
        while (!isOne(gcdU, (short)0) && !isOne(gcdV, (short)0)) {
            // Mute-proofing: answer 6988 instead of hanging if this ever cycles
            if (++iterations > (short)3000) ISOException.throwIt(SW_SIGN_FAILED);

            while (isEven(gcdU, (short)0)) {
                shiftRight1(gcdU, (short)0);
                halveMod(gcdX1, (short)0);
            }
            while (isEven(gcdV, (short)0)) {
                shiftRight1(gcdV, (short)0);
                halveMod(gcdX2, (short)0);
            }

            // if u >= v: u -= v, x1 -= x2  (else the mirror image)
            if (Biginteger.lessThan(gcdU, (short)0, gcdV, (short)0, (short)32) == false) {
                Biginteger.subtract(gcdU, (short)0, gcdV, (short)0, (short)32);
                BigIntegerWrapper.subMod(gcdX1, (short)0, gcdX2, (short)0, gcdX1, (short)0, (short)32);
            } else {
                Biginteger.subtract(gcdV, (short)0, gcdU, (short)0, (short)32);
                BigIntegerWrapper.subMod(gcdX2, (short)0, gcdX1, (short)0, gcdX2, (short)0, (short)32);
            }
        }

        Util.arrayCopy(isOne(gcdU, (short)0) ? gcdX1 : gcdX2, (short)0, result, rOff, (short)32);
        // x1/x2 may sit in [n, 2^256) after halveMod; bring into [0, n)
        BigIntegerMod.reduce(result, rOff, result, rOff);

        Util.arrayFillNonAtomic(gcdU, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(gcdV, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(gcdX1, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(gcdX2, (short)0, (short)32, (byte)0);
    }

    private void shiftRight1(byte[] buf, short off) {
        short carry = 0;
        for (short i = (short)0; i < (short)32; i++) {
            short val = (short)(buf[(short)(off + i)] & 0xFF);
            short nextCarry = (short)(val & 1);
            buf[(short)(off + i)] = (byte)((val >> 1) | (carry << 7));
            carry = nextCarry;
        }
    }

    // Buffers are big-endian: the parity bit lives in the LAST byte.
    // (The previous version tested buf[off] — the MSB — so every even/odd
    // decision in the GCD was made on the wrong end of the number.)
    private boolean isEven(byte[] buf, short off) {
        return (buf[(short)(off + 31)] & 0x01) == 0;
    }

    private boolean isOne(byte[] buf, short off) {
        if (buf[(short)(off + 31)] != 0x01) return false;
        for (short i = 0; i < (short)31; i++) {
            if (buf[(short)(off + i)] != 0) return false;
        }
        return true;
    }

    /**
     * x = x/2 mod n. Odd x → (x + n) / 2 as a 257-bit INTEGER: the carry out
     * of the 32-byte add must be shifted back in as the top bit. (The previous
     * version did addMod(x, n) — which is (x+n) mod n = x, a no-op — before
     * halving, so odd values were halved without the +n.)
     */
    private void halveMod(byte[] x, short off) {
        if (isEven(x, off)) {
            shiftRight1(x, off);
            return;
        }
        boolean carry = Biginteger.add_carry(x, off, BigIntegerMod.SECP256K1_N, (short)0, (short)32);
        shiftRight1(x, off);
        if (carry) x[off] |= (byte)0x80;
    }

    private boolean isZero(byte[] buf, short off) {
        for (short i = 0; i < (short)32; i++) {
            if (buf[(short)(off + i)] != 0) return false;
        }
        return true;
    }

    // n/2 for secp256k1 (for low-s check)
    private static final byte[] HALF_N = {
        (byte)0x7F,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x7F,
        (byte)0x5D,(byte)0x57,(byte)0x6E,(byte)0x73, (byte)0x57,(byte)0xA4,(byte)0x50,(byte)0x1D,
        (byte)0xDF,(byte)0xE9,(byte)0x2F,(byte)0x46, (byte)0x68,(byte)0x1B,(byte)0x20,(byte)0xA0
    };

    private boolean isHighS(byte[] s, short sOff) {
        for (short i = 0; i < (short)32; i++) {
            short sv = (short)(s[(short)(sOff + i)] & 0xFF);
            short hv = (short)(HALF_N[i] & 0xFF);
            if (sv > hv) return true;
            if (sv < hv) return false;
        }
        return false;
    }

    private void compressPubkey(byte[] point, short pointLen, byte[] out, short outOff) {
        if (pointLen == 65 && point[0] == 0x04) {
            out[outOff] = (byte)((point[64] & 0x01) == 0 ? 0x02 : 0x03);
            Util.arrayCopy(point, (short)1, out, (short)(outOff + 1), (short)32);
        } else if (pointLen == 32) {
            out[outOff] = (byte)0x02;
            Util.arrayCopy(point, (short)0, out, (short)(outOff + 1), (short)32);
        } else {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }
}