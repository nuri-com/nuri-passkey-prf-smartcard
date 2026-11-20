package com.nuri.piv;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Clean-room NIST SP 800-73-4 PIV applet (ECC P-256) for Java Card 3.0.4 Classic.
 *
 * Compact footprint (~6 KB CAP) designed to coexist alongside FIDO2, MuSig2,
 * ETH2, Vault, TOTP, and NURI-SC on constrained smartcards while providing full
 * native macOS CryptoTokenKit (pivtoken / sc_auth / sudo / Keychain), OpenSC,
 * and yubico-piv-tool compatibility over contact (T=0/T=1) and contactless NFC.
 *
 * License: MIT.
 */
public final class NuriPivApplet extends Applet {

    private static final byte[] PIV_AID = {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08,
        (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x00
    };

    private static final byte[] APT_RESPONSE = {
        (byte) 0x61, (byte) 0x39,
        // AID (4F)
        (byte) 0x4F, (byte) 0x0B,
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08,
        (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x00,
        // Coexistent Tag Allocation Authority (79 -> 4F RID)
        (byte) 0x79, (byte) 0x07,
        (byte) 0x4F, (byte) 0x05,
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08,
        // Application label (50): "Nuri PIV"
        (byte) 0x50, (byte) 0x08,
        'N', 'u', 'r', 'i', ' ', 'P', 'I', 'V',
        // Application URI (5F50): "nuri.com/piv"
        (byte) 0x5F, (byte) 0x50, (byte) 0x0C,
        'n', 'u', 'r', 'i', '.', 'c', 'o', 'm', '/', 'p', 'i', 'v',
        // Cryptographic algorithms supported (AC): 3DES (03) + ECCP256 (11)
        (byte) 0xAC, (byte) 0x08,
        (byte) 0x80, (byte) 0x01, (byte) 0x03,
        (byte) 0x80, (byte) 0x01, (byte) 0x11,
        (byte) 0x06, (byte) 0x00
    };

    private static final byte[] DISCOVERY_OBJ = {
        (byte) 0x7E, (byte) 0x12,
        (byte) 0x4F, (byte) 0x0B,
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08,
        (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x00,
        (byte) 0x5F, (byte) 0x2F, (byte) 0x02, (byte) 0x40, (byte) 0x00
    };

    private static final byte[] DEFAULT_ADMIN_KEY = {
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8
    };
    private static final byte[] DEFAULT_PIN = {
        '1', '2', '3', '4', '5', '6', (byte) 0xFF, (byte) 0xFF
    };
    private static final byte[] DEFAULT_PUK = {
        '1', '2', '3', '4', '5', '6', '7', '8'
    };
    private static final byte[] CARD_ID_PREFIX = {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x16,
        (byte) 0xFF, (byte) 0x02
    };
    private static final byte[] EXPIRY = {
        '2', '0', '5', '0', '0', '1', '0', '1'
    };
    private static final byte[] YK_VERSION = { 5, 4, 0 };

    // NIST P-256 (secp256r1) curve parameters
    private static final byte[] P256_P = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };
    private static final byte[] P256_A = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
    };
    private static final byte[] P256_B = {
        (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
        (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
        (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
        (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B
    };
    private static final byte[] P256_G = {
        (byte) 0x04,
        (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47,
        (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2,
        (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0,
        (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96,
        (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B,
        (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16,
        (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE,
        (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5
    };
    private static final byte[] P256_R = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
        (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51
    };

    // Standard PIV INS codes
    private static final byte INS_VERIFY       = (byte) 0x20;
    private static final byte INS_CHANGE_PIN   = (byte) 0x24;
    private static final byte INS_RESET_PIN    = (byte) 0x2C;
    private static final byte INS_GEN_ASYM     = (byte) 0x47;
    private static final byte INS_GEN_AUTH     = (byte) 0x87;
    private static final byte INS_GET_RESPONSE = (byte) 0xC0;
    private static final byte INS_GET_DATA     = (byte) 0xCB;
    private static final byte INS_PUT_DATA     = (byte) 0xDB;

    // Yubico PIV compatibility INS codes
    private static final byte INS_GET_SERIAL   = (byte) 0xF8;
    private static final byte INS_RESET        = (byte) 0xFB;
    private static final byte INS_GET_VER      = (byte) 0xFD;
    private static final byte INS_SET_MGMT     = (byte) 0xFF;

    // PIV algorithms
    private static final byte ALG_DEFAULT  = (byte) 0x00;
    private static final byte ALG_3DES     = (byte) 0x03;
    private static final byte ALG_ECCP256  = (byte) 0x11;

    // Key slots: 0=9A, 1=9C, 2=9D, 3=9E
    private static final byte NUM_KEYS = 4;

    // Stored data objects:
    // 0=CHUID(5FC102), 1=CCC(5FC107), 2=CERT_9A(5FC105), 3=CERT_9C(5FC10A),
    // 4=CERT_9D(5FC10B), 5=CERT_9E(5FC101), 6=KEYHIST(5FC10C), 7=SECOBJ(5FC106), 8=PIVMAN(5FFF00)
    private static final byte FILE_CHUID   = 0;
    private static final byte FILE_CCC     = 1;
    private static final byte FILE_CERT_9A = 2;
    private static final byte FILE_CERT_9C = 3;
    private static final byte FILE_CERT_9D = 4;
    private static final byte FILE_CERT_9E = 5;
    private static final byte FILE_KEYHIST = 6;
    private static final byte FILE_SECOBJ  = 7;
    private static final byte FILE_PIVMAN  = 8;
    private static final byte NUM_FILES    = 9;

    private static final short MAX_RX_LEN   = 1280;
    private static final short TX_CHUNK_MAX = 240;

    private static final byte ALG_EC_SVDP_DH_PLAIN    = (byte) 0x03;
    private static final byte ALG_EC_SVDP_DH_PLAIN_XY = (byte) 0x06;

    // Persistent state
    private final OwnerPIN pivPin;
    private final OwnerPIN pukPin;
    private final DESKey adminKey;
    private final KeyPair[] keyPairs;
    private final Object[] files;       // byte[] per file (full 53 <ber-len> <val>)
    private final short[] fileLens;
    private final byte[] serial;
    private final byte[] rxBuf;         // Persistent command-chaining staging buffer

    // Crypto engines
    private final RandomData rng;
    private final Cipher desCipher;
    private final Signature ecdsa;
    private final KeyAgreement ecdh;
    private final boolean ecdhXY;

    // Transient RAM state (CLEAR_ON_DESELECT)
    private final byte[] flags;         // [0]=adminAuthed, [1]=adminChalValid, [2]=rxIns
    private final short[] state;        // [0]=rxLen, [1]=txOff, [2]=txRem
    private final Object[] txRef;       // [0]=active outgoing byte[]
    private final byte[] adminChal;     // 8B
    private final byte[] scratch;       // 160B (hashes, DER sigs, ECDH, 3DES blocks, short responses)

    private static final byte FL_ADMIN_AUTH = 0;
    private static final byte FL_CHAL_VALID = 1;
    private static final byte FL_RX_INS     = 2;

    private static final byte ST_RX_LEN = 0;
    private static final byte ST_TX_OFF = 1;
    private static final byte ST_TX_REM = 2;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NuriPivApplet().register();
    }

    private NuriPivApplet() {
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        desCipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        KeyAgreement ka = null;
        boolean xy = false;
        try {
            ka = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN, false);
        } catch (CryptoException e) {
            ka = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
            xy = true;
        }
        ecdh = ka;
        ecdhXY = xy;

        pivPin = new OwnerPIN((byte) 5, (byte) 8);
        pivPin.update(DEFAULT_PIN, (short) 0, (byte) 8);
        pukPin = new OwnerPIN((byte) 3, (byte) 8);
        pukPin.update(DEFAULT_PUK, (short) 0, (byte) 8);

        adminKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
        adminKey.setKey(DEFAULT_ADMIN_KEY, (short) 0);

        keyPairs = new KeyPair[NUM_KEYS];
        files = new Object[NUM_FILES];
        fileLens = new short[NUM_FILES];
        serial = new byte[4];
        rng.generateData(serial, (short) 0, (short) 4);
        serial[0] |= (byte) 0x80;

        rxBuf = new byte[MAX_RX_LEN];

        flags = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);
        state = JCSystem.makeTransientShortArray((short) 3, JCSystem.CLEAR_ON_DESELECT);
        txRef = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        adminChal = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        scratch = JCSystem.makeTransientByteArray((short) 160, JCSystem.CLEAR_ON_DESELECT);

        initDefaultObjects();
    }

    private void initDefaultObjects() {
        // CHUID (5FC102): 53 3B | 30 19 <25B zero FASC-N> | 34 10 <16B GUID> | 35 08 <8B expiry> | 3E 00 | FE 00
        byte[] chuid = new byte[61];
        short o = 0;
        chuid[o++] = (byte) 0x53;
        chuid[o++] = (byte) 0x3B;
        chuid[o++] = (byte) 0x30;
        chuid[o++] = (byte) 0x19;
        o += 25;
        chuid[o++] = (byte) 0x34;
        chuid[o++] = (byte) 0x10;
        rng.generateData(chuid, o, (short) 16);
        o += 16;
        chuid[o++] = (byte) 0x35;
        chuid[o++] = (byte) 0x08;
        Util.arrayCopyNonAtomic(EXPIRY, (short) 0, chuid, o, (short) 8);
        o += 8;
        chuid[o++] = (byte) 0x3E;
        chuid[o++] = (byte) 0x00;
        chuid[o++] = (byte) 0xFE;
        chuid[o++] = (byte) 0x00;
        files[FILE_CHUID] = chuid;
        fileLens[FILE_CHUID] = o;

        // CCC (5FC107): 53 32 | F0 15 <7B prefix + 14B rand> | F1 01 21 | F2 01 21 | F3 00 | F4 00 | F5 01 10 | F6 00 | F7 00 | FA 00 | FB 00 | FC 00 | FD 00 | FE 00
        byte[] ccc = new byte[52];
        o = 0;
        ccc[o++] = (byte) 0x53;
        ccc[o++] = (byte) 0x32;
        ccc[o++] = (byte) 0xF0;
        ccc[o++] = (byte) 0x15;
        Util.arrayCopyNonAtomic(CARD_ID_PREFIX, (short) 0, ccc, o, (short) 7);
        o += 7;
        rng.generateData(ccc, o, (short) 14);
        o += 14;
        ccc[o++] = (byte) 0xF1; ccc[o++] = 1; ccc[o++] = (byte) 0x21;
        ccc[o++] = (byte) 0xF2; ccc[o++] = 1; ccc[o++] = (byte) 0x21;
        ccc[o++] = (byte) 0xF3; ccc[o++] = 0;
        ccc[o++] = (byte) 0xF4; ccc[o++] = 0;
        ccc[o++] = (byte) 0xF5; ccc[o++] = 1; ccc[o++] = (byte) 0x10;
        ccc[o++] = (byte) 0xF6; ccc[o++] = 0;
        ccc[o++] = (byte) 0xF7; ccc[o++] = 0;
        ccc[o++] = (byte) 0xFA; ccc[o++] = 0;
        ccc[o++] = (byte) 0xFB; ccc[o++] = 0;
        ccc[o++] = (byte) 0xFC; ccc[o++] = 0;
        ccc[o++] = (byte) 0xFD; ccc[o++] = 0;
        ccc[o++] = (byte) 0xFE; ccc[o++] = 0;
        files[FILE_CCC] = ccc;
        fileLens[FILE_CCC] = o;

        // Key History (5FC10C): 53 08 C1 01 00 C2 01 00 FE 00
        byte[] kh = {
            (byte) 0x53, (byte) 0x08,
            (byte) 0xC1, (byte) 0x01, (byte) 0x00,
            (byte) 0xC2, (byte) 0x01, (byte) 0x00,
            (byte) 0xFE, (byte) 0x00
        };
        files[FILE_KEYHIST] = kh;
        fileLens[FILE_KEYHIST] = (short) kh.length;
    }

    public void deselect() {
        pivPin.reset();
        pukPin.reset();
        clearSession();
    }

    private void clearSession() {
        Util.arrayFillNonAtomic(flags, (short) 0, (short) flags.length, (byte) 0);
        Util.arrayFillNonAtomic(adminChal, (short) 0, (short) adminChal.length, (byte) 0);
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) scratch.length, (byte) 0);
        state[ST_RX_LEN] = 0;
        state[ST_TX_OFF] = 0;
        state[ST_TX_REM] = 0;
        txRef[0] = null;
    }

    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];

        if (selectingApplet()) {
            state[ST_RX_LEN] = 0;
            startOutgoing(apdu, APT_RESPONSE, (short) 0, (short) APT_RESPONSE.length);
            return;
        }

        if ((cla & (byte) 0x80) != 0) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (ins == INS_GET_RESPONSE) {
            continueOutgoing(apdu);
            return;
        }

        // Any non-GET_RESPONSE resets pending outgoing stream
        state[ST_TX_REM] = 0;
        txRef[0] = null;

        // Case 1/2 commands that carry no incoming data (avoid setIncomingAndReceive on Case 1/2)
        if (ins == INS_GET_VER) {
            state[ST_RX_LEN] = 0;
            startOutgoing(apdu, YK_VERSION, (short) 0, (short) YK_VERSION.length);
            return;
        }
        if (ins == INS_GET_SERIAL) {
            state[ST_RX_LEN] = 0;
            startOutgoing(apdu, serial, (short) 0, (short) serial.length);
            return;
        }
        if (ins == INS_RESET) {
            state[ST_RX_LEN] = 0;
            processReset(buf);
            return;
        }
        if (ins == INS_VERIFY && buf[ISO7816.OFFSET_LC] == 0) {
            state[ST_RX_LEN] = 0;
            processVerify(buf, buf, ISO7816.OFFSET_CDATA, (short) 0);
            return;
        }

        boolean chained = (cla & (byte) 0x10) != 0;
        if (chained) {
            short lc = receiveAll(apdu);
            if (state[ST_RX_LEN] == 0) {
                flags[FL_RX_INS] = ins;
            } else if (flags[FL_RX_INS] != ins) {
                state[ST_RX_LEN] = 0;
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            if ((short) (state[ST_RX_LEN] + lc) > MAX_RX_LEN) {
                state[ST_RX_LEN] = 0;
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, rxBuf, state[ST_RX_LEN], lc);
            state[ST_RX_LEN] = (short) (state[ST_RX_LEN] + lc);
            return;
        }

        byte[] inBuf;
        short inOff;
        short inLen;
        if (state[ST_RX_LEN] > 0) {
            if (flags[FL_RX_INS] != ins) {
                state[ST_RX_LEN] = 0;
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            short lc = receiveAll(apdu);
            if ((short) (state[ST_RX_LEN] + lc) > MAX_RX_LEN) {
                state[ST_RX_LEN] = 0;
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, rxBuf, state[ST_RX_LEN], lc);
            inLen = (short) (state[ST_RX_LEN] + lc);
            state[ST_RX_LEN] = 0;
            inBuf = rxBuf;
            inOff = 0;
        } else {
            inLen = receiveAll(apdu);
            inBuf = buf;
            inOff = ISO7816.OFFSET_CDATA;
        }

        switch (ins) {
            case INS_VERIFY:
                processVerify(buf, inBuf, inOff, inLen);
                break;
            case INS_CHANGE_PIN:
                processChangePin(buf, inBuf, inOff, inLen);
                break;
            case INS_RESET_PIN:
                processResetPin(buf, inBuf, inOff, inLen);
                break;
            case INS_GET_DATA:
                processGetData(apdu, buf, inBuf, inOff, inLen);
                break;
            case INS_PUT_DATA:
                processPutData(buf, inBuf, inOff, inLen);
                break;
            case INS_GEN_ASYM:
                processGenAsym(apdu, buf, inBuf, inOff, inLen);
                break;
            case INS_GEN_AUTH:
                processGenAuth(apdu, buf, inBuf, inOff, inLen);
                break;
            case INS_GET_VER:
                startOutgoing(apdu, YK_VERSION, (short) 0, (short) YK_VERSION.length);
                break;
            case INS_GET_SERIAL:
                startOutgoing(apdu, serial, (short) 0, (short) serial.length);
                break;
            case INS_SET_MGMT:
                processSetMgmt(buf, inBuf, inOff, inLen);
                break;
            case INS_RESET:
                processReset(buf);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private short receiveAll(APDU apdu) {
        short read = apdu.setIncomingAndReceive();
        short total = apdu.getIncomingLength();
        if (total == 0) {
            return 0;
        }
        short off = read;
        while (off < total) {
            short n = apdu.receiveBytes(off);
            if (n <= 0) {
                break;
            }
            off += n;
        }
        return total;
    }

    private void startOutgoing(APDU apdu, byte[] data, short off, short len) {
        txRef[0] = data;
        state[ST_TX_OFF] = off;
        state[ST_TX_REM] = len;
        continueOutgoing(apdu);
    }

    private void continueOutgoing(APDU apdu) {
        byte[] data = (byte[]) txRef[0];
        short rem = state[ST_TX_REM];
        if (data == null || rem <= 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short le = apdu.setOutgoing();
        short chunk = rem;
        if (le > 0 && chunk > le) {
            chunk = le;
        }
        if (chunk > TX_CHUNK_MAX) {
            chunk = TX_CHUNK_MAX;
        }
        short off = state[ST_TX_OFF];
        short left = (short) (rem - chunk);
        state[ST_TX_OFF] = (short) (off + chunk);
        state[ST_TX_REM] = left;
        if (left == 0) {
            txRef[0] = null;
        }

        apdu.setOutgoingLength(chunk);
        apdu.sendBytesLong(data, off, chunk);

        if (left > 0) {
            short next = left > (short) 0xFF ? (short) 0x00 : left;
            ISOException.throwIt((short) (ISO7816.SW_BYTES_REMAINING_00 | (next & (short) 0x00FF)));
        }
    }

    private void processVerify(byte[] apduBuf, byte[] inBuf, short inOff, short inLen) {
        byte p1 = apduBuf[ISO7816.OFFSET_P1];
        byte p2 = apduBuf[ISO7816.OFFSET_P2];
        if (p2 != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (p1 == (byte) 0xFF) {
            if (inLen != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            pivPin.reset();
            return;
        }
        if (p1 != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (inLen == 0) {
            if (pivPin.isValidated()) {
                return;
            }
            ISOException.throwIt((short) (0x63C0 | (pivPin.getTriesRemaining() & 0x0F)));
        }
        if (inLen != 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (pivPin.getTriesRemaining() == 0) {
            ISOException.throwIt((short) 0x6983);
        }
        if (!pivPin.check(inBuf, inOff, (byte) 8)) {
            byte left = pivPin.getTriesRemaining();
            ISOException.throwIt(left == 0 ? (short) 0x6983 : (short) (0x63C0 | (left & 0x0F)));
        }
    }

    private void processChangePin(byte[] apduBuf, byte[] inBuf, short inOff, short inLen) {
        if (apduBuf[ISO7816.OFFSET_P1] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        byte p2 = apduBuf[ISO7816.OFFSET_P2];
        OwnerPIN target = (p2 == (byte) 0x80) ? pivPin : (p2 == (byte) 0x81) ? pukPin : null;
        if (target == null) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (inLen != 16) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (target.getTriesRemaining() == 0) {
            ISOException.throwIt((short) 0x6983);
        }
        if (!target.check(inBuf, inOff, (byte) 8)) {
            byte left = target.getTriesRemaining();
            ISOException.throwIt(left == 0 ? (short) 0x6983 : (short) (0x63C0 | (left & 0x0F)));
        }
        target.update(inBuf, (short) (inOff + 8), (byte) 8);
        if (target == pukPin) {
            pukPin.reset();
        }
    }

    private void processResetPin(byte[] apduBuf, byte[] inBuf, short inOff, short inLen) {
        if (apduBuf[ISO7816.OFFSET_P1] != 0 || apduBuf[ISO7816.OFFSET_P2] != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (inLen != 16) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (pukPin.getTriesRemaining() == 0) {
            ISOException.throwIt((short) 0x6983);
        }
        if (!pukPin.check(inBuf, inOff, (byte) 8)) {
            byte left = pukPin.getTriesRemaining();
            ISOException.throwIt(left == 0 ? (short) 0x6983 : (short) (0x63C0 | (left & 0x0F)));
        }
        pivPin.update(inBuf, (short) (inOff + 8), (byte) 8);
        pivPin.resetAndUnblock();
        pukPin.reset();
    }

    private byte mapTagToFile(byte[] buf, short off, short len) {
        if (len == 3 && buf[off] == (byte) 0x5F) {
            byte b1 = buf[(short) (off + 1)];
            byte b2 = buf[(short) (off + 2)];
            if (b1 == (byte) 0xC1) {
                switch (b2) {
                    case (byte) 0x02: return FILE_CHUID;
                    case (byte) 0x07: return FILE_CCC;
                    case (byte) 0x05: return FILE_CERT_9A;
                    case (byte) 0x0A: return FILE_CERT_9C;
                    case (byte) 0x0B: return FILE_CERT_9D;
                    case (byte) 0x01: return FILE_CERT_9E;
                    case (byte) 0x0C: return FILE_KEYHIST;
                    case (byte) 0x06: return FILE_SECOBJ;
                    default: return (byte) -1;
                }
            }
            if (b1 == (byte) 0xFF && b2 == (byte) 0x00) {
                return FILE_PIVMAN;
            }
        }
        return (byte) -1;
    }

    private void processGetData(APDU apdu, byte[] apduBuf, byte[] inBuf, short inOff, short inLen) {
        if (apduBuf[ISO7816.OFFSET_P1] != (byte) 0x3F || apduBuf[ISO7816.OFFSET_P2] != (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (inLen < 3 || inBuf[inOff] != (byte) 0x5C) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short tLen = (short) (inBuf[(short) (inOff + 1)] & 0xFF);
        if ((short) (2 + tLen) > inLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (tLen == 1 && inBuf[(short) (inOff + 2)] == (byte) 0x7E) {
            startOutgoing(apdu, DISCOVERY_OBJ, (short) 0, (short) DISCOVERY_OBJ.length);
            return;
        }
        byte idx = mapTagToFile(inBuf, (short) (inOff + 2), tLen);
        if (idx < 0 || files[idx] == null || fileLens[idx] == 0) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        startOutgoing(apdu, (byte[]) files[idx], (short) 0, fileLens[idx]);
    }

    private void processPutData(byte[] apduBuf, byte[] inBuf, short inOff, short inLen) {
        if (apduBuf[ISO7816.OFFSET_P1] != (byte) 0x3F || apduBuf[ISO7816.OFFSET_P2] != (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (flags[FL_ADMIN_AUTH] == 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (inLen < 6 || inBuf[inOff] != (byte) 0x5C) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short tLen = (short) (inBuf[(short) (inOff + 1)] & 0xFF);
        short dataPos = (short) (inOff + 2 + tLen);
        if (dataPos >= (short) (inOff + inLen) || inBuf[dataPos] != (byte) 0x53) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte idx = mapTagToFile(inBuf, (short) (inOff + 2), tLen);
        if (idx < 0) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        short objLen = (short) (inOff + inLen - dataPos);
        byte[] existing = (byte[]) files[idx];
        if (existing == null || existing.length < objLen) {
            existing = new byte[objLen];
            files[idx] = existing;
        }
        Util.arrayCopyNonAtomic(inBuf, dataPos, existing, (short) 0, objLen);
        fileLens[idx] = objLen;
    }

    private byte mapSlotToKeyIndex(byte slot) {
        switch (slot) {
            case (byte) 0x9A: return 0;
            case (byte) 0x9C: return 1;
            case (byte) 0x9D: return 2;
            case (byte) 0x9E: return 3;
            default: return (byte) -1;
        }
    }

    private void processGenAsym(APDU apdu, byte[] apduBuf, byte[] inBuf, short inOff, short inLen) {
        if (apduBuf[ISO7816.OFFSET_P1] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (flags[FL_ADMIN_AUTH] == 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte kidx = mapSlotToKeyIndex(apduBuf[ISO7816.OFFSET_P2]);
        if (kidx < 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        // Parse AC <len> ... 80 01 <alg> ...
        if (inLen < 5 || inBuf[inOff] != (byte) 0xAC) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short pos = (short) (inOff + 2);
        short end = (short) (inOff + inLen);
        byte alg = 0;
        while ((short) (pos + 2) <= end) {
            byte tag = inBuf[pos++];
            short l = (short) (inBuf[pos++] & 0xFF);
            if ((short) (pos + l) > end) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            if (tag == (byte) 0x80 && l == 1) {
                alg = inBuf[pos];
            }
            pos += l;
        }
        if (alg != ALG_ECCP256) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        KeyPair kp = keyPairs[kidx];
        if (kp == null) {
            kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            setP256Params((ECPublicKey) kp.getPublic(), (ECPrivateKey) kp.getPrivate());
            keyPairs[kidx] = kp;
        }
        kp.genKeyPair();

        // Response: 7F 49 43 86 41 <65B uncompressed W>
        short o = 0;
        scratch[o++] = (byte) 0x7F;
        scratch[o++] = (byte) 0x49;
        scratch[o++] = (byte) 0x43;
        scratch[o++] = (byte) 0x86;
        scratch[o++] = (byte) 0x41;
        short wLen = ((ECPublicKey) kp.getPublic()).getW(scratch, o);
        if (wLen != 65) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        o += wLen;
        startOutgoing(apdu, scratch, (short) 0, o);
    }

    private void processGenAuth(APDU apdu, byte[] apduBuf, byte[] inBuf, short inOff, short inLen) {
        byte alg = apduBuf[ISO7816.OFFSET_P1];
        byte slot = apduBuf[ISO7816.OFFSET_P2];

        if (slot == (byte) 0x9B) {
            if (alg != ALG_DEFAULT && alg != ALG_3DES) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            processAdminAuth(apdu, inBuf, inOff, inLen);
            return;
        }

        byte kidx = mapSlotToKeyIndex(slot);
        if (kidx < 0 || alg != ALG_ECCP256) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (slot != (byte) 0x9E && !pivPin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        KeyPair kp = keyPairs[kidx];
        if (kp == null) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Parse 7C <ber-len> { 82 00, 81 <hash> | 85 <peer_pubkey> }
        short p = parse7CStart(inBuf, inOff, inLen);
        short end = (short) (inOff + inLen);
        short chalOff = -1;
        short chalLen = 0;
        short expOff = -1;
        short expLen = 0;
        boolean wantResp = false;

        while (p < end) {
            byte tag = inBuf[p++];
            short l = readBerLen(inBuf, p, end);
            p = skipBerLen(inBuf, p, end);
            if ((short) (p + l) > end) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            if (tag == (byte) 0x82 && l == 0) {
                wantResp = true;
            } else if (tag == (byte) 0x81) {
                chalOff = p;
                chalLen = l;
            } else if (tag == (byte) 0x85) {
                expOff = p;
                expLen = l;
            } else {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            p += l;
        }
        if (!wantResp) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (chalOff >= 0 && chalLen > 0) {
            // ECDSA P-256 signPreComputedHash
            Util.arrayFillNonAtomic(scratch, (short) 0, (short) 32, (byte) 0);
            if (chalLen <= 32) {
                Util.arrayCopyNonAtomic(inBuf, chalOff, scratch, (short) (32 - chalLen), chalLen);
            } else {
                Util.arrayCopyNonAtomic(inBuf, chalOff, scratch, (short) 0, (short) 32);
            }
            ecdsa.init(kp.getPrivate(), Signature.MODE_SIGN);
            short sigLen = ecdsa.signPreComputedHash(scratch, (short) 0, (short) 32, scratch, (short) 36);
            scratch[32] = (byte) 0x7C;
            scratch[33] = (byte) (sigLen + 2);
            scratch[34] = (byte) 0x82;
            scratch[35] = (byte) sigLen;
            startOutgoing(apdu, scratch, (short) 32, (short) (sigLen + 4));
            return;
        }

        if (expOff >= 0 && expLen == 65 && inBuf[expOff] == (byte) 0x04) {
            // ECDH P-256
            ecdh.init(kp.getPrivate());
            short outLen = ecdh.generateSecret(inBuf, expOff, expLen, scratch, (short) 64);
            Util.arrayFillNonAtomic(scratch, (short) 4, (short) 32, (byte) 0);
            if (ecdhXY) {
                if (outLen < 33) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                Util.arrayCopyNonAtomic(scratch, (short) 65, scratch, (short) 4, (short) 32);
            } else {
                if (outLen <= 0 || outLen > 32) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                Util.arrayCopyNonAtomic(scratch, (short) 64, scratch, (short) (4 + 32 - outLen), outLen);
            }
            scratch[0] = (byte) 0x7C;
            scratch[1] = (byte) 0x22;
            scratch[2] = (byte) 0x82;
            scratch[3] = (byte) 0x20;
            startOutgoing(apdu, scratch, (short) 0, (short) 36);
            return;
        }

        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    private void processAdminAuth(APDU apdu, byte[] inBuf, short inOff, short inLen) {
        short p = parse7CStart(inBuf, inOff, inLen);
        short end = (short) (inOff + inLen);
        short witOff = -1, witLen = 0;
        short chalOff = -1, chalLen = 0;
        short respOff = -1, respLen = 0;
        byte wanted = 0;

        while (p < end) {
            byte tag = inBuf[p++];
            short l = readBerLen(inBuf, p, end);
            p = skipBerLen(inBuf, p, end);
            if ((short) (p + l) > end) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            if (l == 0) {
                wanted = tag;
            } else if (tag == (byte) 0x80) {
                witOff = p; witLen = l;
            } else if (tag == (byte) 0x81) {
                chalOff = p; chalLen = l;
            } else if (tag == (byte) 0x82) {
                respOff = p; respLen = l;
            } else {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            p += l;
        }

        // Case 1: Request witness (7C 02 80 00) -> mutual auth step 1 (yubico-piv-tool)
        if (wanted == (byte) 0x80 && witOff < 0 && chalOff < 0 && respOff < 0) {
            flags[FL_ADMIN_AUTH] = 0;
            rng.generateData(adminChal, (short) 0, (short) 8);
            flags[FL_CHAL_VALID] = 1;
            scratch[0] = (byte) 0x7C;
            scratch[1] = (byte) 0x0A;
            scratch[2] = (byte) 0x80;
            scratch[3] = (byte) 0x08;
            desBlock(Cipher.MODE_ENCRYPT, adminChal, (short) 0, scratch, (short) 4);
            startOutgoing(apdu, scratch, (short) 0, (short) 12);
            return;
        }

        // Case 2: Verify witness (80 08 <chal>) + optional host challenge (81 08 <hostChal>)
        if (witOff >= 0 && witLen == 8) {
            boolean ok = flags[FL_CHAL_VALID] != 0 && ctEquals8(adminChal, (short) 0, inBuf, witOff);
            flags[FL_CHAL_VALID] = 0;
            Util.arrayFillNonAtomic(adminChal, (short) 0, (short) 8, (byte) 0);
            if (!ok) {
                flags[FL_ADMIN_AUTH] = 0;
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            flags[FL_ADMIN_AUTH] = 1;
            if (chalOff >= 0 && chalLen == 8) {
                scratch[0] = (byte) 0x7C;
                scratch[1] = (byte) 0x0A;
                scratch[2] = (byte) 0x82;
                scratch[3] = (byte) 0x08;
                desBlock(Cipher.MODE_ENCRYPT, inBuf, chalOff, scratch, (short) 4);
                startOutgoing(apdu, scratch, (short) 0, (short) 12);
            }
            return;
        }

        // Case 3: Single-auth request challenge (7C 02 81 00)
        if (wanted == (byte) 0x81 && witOff < 0 && chalOff < 0 && respOff < 0) {
            flags[FL_ADMIN_AUTH] = 0;
            rng.generateData(adminChal, (short) 0, (short) 8);
            flags[FL_CHAL_VALID] = 1;
            scratch[0] = (byte) 0x7C;
            scratch[1] = (byte) 0x0A;
            scratch[2] = (byte) 0x81;
            scratch[3] = (byte) 0x08;
            Util.arrayCopyNonAtomic(adminChal, (short) 0, scratch, (short) 4, (short) 8);
            startOutgoing(apdu, scratch, (short) 0, (short) 12);
            return;
        }

        // Case 4: Single-auth verify response (7C 0A 82 08 <enc(chal)>)
        if (respOff >= 0 && respLen == 8) {
            desBlock(Cipher.MODE_ENCRYPT, adminChal, (short) 0, scratch, (short) 0);
            boolean ok = flags[FL_CHAL_VALID] != 0 && ctEquals8(scratch, (short) 0, inBuf, respOff);
            flags[FL_CHAL_VALID] = 0;
            Util.arrayFillNonAtomic(adminChal, (short) 0, (short) 8, (byte) 0);
            if (!ok) {
                flags[FL_ADMIN_AUTH] = 0;
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            flags[FL_ADMIN_AUTH] = 1;
            return;
        }

        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    private void processSetMgmt(byte[] apduBuf, byte[] inBuf, short inOff, short inLen) {
        if (flags[FL_ADMIN_AUTH] == 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (apduBuf[ISO7816.OFFSET_P1] != (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        byte p2 = apduBuf[ISO7816.OFFSET_P2];
        if (p2 != (byte) 0xFF && p2 != (byte) 0xFE) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (inLen != 27 || inBuf[inOff] != ALG_3DES
                || inBuf[(short) (inOff + 1)] != (byte) 0x9B
                || inBuf[(short) (inOff + 2)] != 24) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        adminKey.setKey(inBuf, (short) (inOff + 3));
    }

    private void processReset(byte[] apduBuf) {
        if (apduBuf[ISO7816.OFFSET_P1] != 0 || apduBuf[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (pivPin.getTriesRemaining() > 0 || pukPin.getTriesRemaining() > 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        pivPin.update(DEFAULT_PIN, (short) 0, (byte) 8);
        pivPin.resetAndUnblock();
        pukPin.update(DEFAULT_PUK, (short) 0, (byte) 8);
        pukPin.resetAndUnblock();
        adminKey.setKey(DEFAULT_ADMIN_KEY, (short) 0);
        for (byte i = 0; i < NUM_KEYS; i++) {
            if (keyPairs[i] != null) {
                keyPairs[i].getPrivate().clearKey();
                keyPairs[i].getPublic().clearKey();
            }
        }
        for (byte i = 0; i < NUM_FILES; i++) {
            fileLens[i] = 0;
        }
        initDefaultObjects();
        clearSession();
    }

    private void desBlock(byte mode, byte[] in, short inOff, byte[] out, short outOff) {
        Util.arrayFillNonAtomic(scratch, (short) 152, (short) 8, (byte) 0);
        desCipher.init(adminKey, mode, scratch, (short) 152, (short) 8);
        desCipher.doFinal(in, inOff, (short) 8, out, outOff);
    }

    private static boolean ctEquals8(byte[] a, short aOff, byte[] b, short bOff) {
        byte diff = 0;
        for (short i = 0; i < 8; i++) {
            diff |= (byte) (a[(short) (aOff + i)] ^ b[(short) (bOff + i)]);
        }
        return diff == 0;
    }

    private static short parse7CStart(byte[] buf, short off, short len) {
        if (len < 2 || buf[off] != (byte) 0x7C) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short end = (short) (off + len);
        short vLen = readBerLen(buf, (short) (off + 1), end);
        short p = skipBerLen(buf, (short) (off + 1), end);
        if ((short) (p + vLen) != end) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        return p;
    }

    private static short readBerLen(byte[] buf, short off, short end) {
        if (off >= end) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short b = (short) (buf[off] & 0xFF);
        if (b < 0x80) {
            return b;
        }
        if (b == 0x81) {
            if ((short) (off + 1) >= end) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            return (short) (buf[(short) (off + 1)] & 0xFF);
        }
        if (b == 0x82) {
            if ((short) (off + 2) >= end) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            short v = Util.getShort(buf, (short) (off + 1));
            if (v < 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            return v;
        }
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return 0;
    }

    private static short skipBerLen(byte[] buf, short off, short end) {
        short b = (short) (buf[off] & 0xFF);
        if (b < 0x80) {
            return (short) (off + 1);
        }
        if (b == 0x81) {
            return (short) (off + 2);
        }
        if (b == 0x82) {
            return (short) (off + 3);
        }
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return end;
    }

    private static void setP256Params(ECPublicKey pub, ECPrivateKey priv) {
        pub.setFieldFP(P256_P, (short) 0, (short) P256_P.length);
        pub.setA(P256_A, (short) 0, (short) P256_A.length);
        pub.setB(P256_B, (short) 0, (short) P256_B.length);
        pub.setG(P256_G, (short) 0, (short) P256_G.length);
        pub.setR(P256_R, (short) 0, (short) P256_R.length);
        pub.setK((short) 1);

        priv.setFieldFP(P256_P, (short) 0, (short) P256_P.length);
        priv.setA(P256_A, (short) 0, (short) P256_A.length);
        priv.setB(P256_B, (short) 0, (short) P256_B.length);
        priv.setG(P256_G, (short) 0, (short) P256_G.length);
        priv.setR(P256_R, (short) 0, (short) P256_R.length);
        priv.setK((short) 1);
    }
}
