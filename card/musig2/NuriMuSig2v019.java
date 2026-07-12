package nuri.musig2;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * NuriMuSig2 v0.19 - FIXED 96-byte buffer handling
 *
 * Fixes from v0.18:
 * - Use full 96-byte buffer for mod() like Satochip
 * - Copy result from offset+64 for 96-byte buffer
 *
 * Author: Claude & Emin
 * Date: 2025-08-31
 */
public class NuriMuSig2v019 extends Applet {

    // Version 1.9 - Fixed 96-byte buffer
    private static final byte[] APPLET_VERSION = {(byte)0x01, (byte)0x0A};

    // Commands
    private static final byte INS_GET_VERSION = (byte)0x01;
    private static final byte INS_INIT = (byte)0x02;
    private static final byte INS_GET_PUBKEY = (byte)0x03;
    private static final byte INS_KEYGEN = (byte)0x04;
    private static final byte INS_GET_NONCES = (byte)0x40;
    private static final byte INS_FINALIZE = (byte)0x41;

    // Status codes
    private static final short SW_NONCES_NOT_READY = (short)0x6984;
    private static final short SW_ALREADY_FINALIZED = (short)0x6985;
    private static final short SW_NOT_INITIALIZED = (short)0x6986;
    private static final short SW_INVALID_SEED = (short)0x6987;
    private static final short SW_INVALID_NONCE = (short)0x6988;

    // Algorithm constants
    private final static byte ALG_EC_SVDP_DH_PLAIN_XY = (byte)0x06;
    private final static short LENGTH_EC_FP_256 = (short)256;

    // secp256k1 parameters
    public final static byte[] SECP256K1 = {
        // P (field prime) - offset 0
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE, (byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F,
        // a - offset 32
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        // b - offset 64
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07,
        // N (order) - offset 96
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6, (byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C, (byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41,
        // G (generator point, uncompressed) - offset 128
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

    // Offsets
    public final static short OFFSET_SECP256K1_P = 0;
    public final static short OFFSET_SECP256K1_N = 96;
    public final static short OFFSET_SECP256K1_G = 128;

    // State
    private ECPrivateKey masterKey;
    private ECPrivateKey tempPrivKey;
    private KeyAgreement keyAgreement;
    private MessageDigest sha256;
    private RandomData rng;

    // Nonce storage (CLEAR_ON_RESET to survive deselect)
    private byte[] nonceK1;      // 32 bytes secret k1
    private byte[] nonceK2;      // 32 bytes secret k2
    private byte[] pubK1;        // 33 bytes compressed K1 = k1·G
    private byte[] pubK2;        // 33 bytes compressed K2 = k2·G
    private boolean noncesReady;
    private boolean finalized;

    // Pre-allocated buffers
    private byte[] tempBuffer;   // 65 bytes for ECDH output
    private byte[] scratch32_1;  // 32 bytes
    private byte[] scratch32_2;  // 32 bytes
    private byte[] scratch32_3;  // 32 bytes
    private byte[] scratch32_4;  // 32 bytes
    private byte[] scratch32_5;  // 32 bytes
    private byte[] mulWorkspace; // 96 bytes for Satochip multiplication

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NuriMuSig2v019().register();
    }

    protected NuriMuSig2v019() {
        // Initialize keys
        masterKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
        tempPrivKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);

        // Set EC parameters
        masterKey.setFieldFP(SECP256K1, OFFSET_SECP256K1_P, (short)32);
        masterKey.setA(SECP256K1, (short)32, (short)32);
        masterKey.setB(SECP256K1, (short)64, (short)32);
        masterKey.setR(SECP256K1, OFFSET_SECP256K1_N, (short)32);
        masterKey.setG(SECP256K1, OFFSET_SECP256K1_G, (short)65);

        tempPrivKey.setFieldFP(SECP256K1, OFFSET_SECP256K1_P, (short)32);
        tempPrivKey.setA(SECP256K1, (short)32, (short)32);
        tempPrivKey.setB(SECP256K1, (short)64, (short)32);
        tempPrivKey.setR(SECP256K1, OFFSET_SECP256K1_N, (short)32);
        tempPrivKey.setG(SECP256K1, OFFSET_SECP256K1_G, (short)65);

        // Initialize crypto
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        // Try to get the best KeyAgreement algorithm
        try {
            keyAgreement = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
        } catch (CryptoException e) {
            try {
                keyAgreement = KeyAgreement.getInstance((byte)0x03, false);
            } catch (CryptoException e2) {
                keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
            }
        }

        // Allocate nonce storage (CLEAR_ON_RESET to survive deselect)
        nonceK1 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_RESET);
        nonceK2 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_RESET);
        pubK1 = JCSystem.makeTransientByteArray((short)33, JCSystem.CLEAR_ON_RESET);
        pubK2 = JCSystem.makeTransientByteArray((short)33, JCSystem.CLEAR_ON_RESET);

        // Allocate scratch buffers
        tempBuffer = JCSystem.makeTransientByteArray((short)65, JCSystem.CLEAR_ON_DESELECT);
        scratch32_1 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scratch32_2 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scratch32_3 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scratch32_4 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scratch32_5 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        mulWorkspace = JCSystem.makeTransientByteArray((short)96, JCSystem.CLEAR_ON_DESELECT);

        // Initialize Satochip BigInteger
        BigIntegerWrapper.init();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
            case INS_GET_VERSION:
                getVersion(apdu);
                break;
            case INS_INIT:
                initialize(apdu);
                break;
            case INS_GET_PUBKEY:
                getPublicKey(apdu);
                break;
            case INS_KEYGEN:
                keygen(apdu);
                break;
            case INS_GET_NONCES:
                getNonces(apdu);
                break;
            case INS_FINALIZE:
                doFinalize(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void getVersion(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopy(APPLET_VERSION, (short)0, buffer, (short)0, (short)2);
        buffer[2] = (byte)0x03;  // Capabilities: sign + on-card keygen
        // Build tag: "KGEN" - v20 with on-card key generation
        buffer[3] = (byte)0x4B;  // 'K'
        buffer[4] = (byte)0x47;  // 'G'
        buffer[5] = (byte)0x45;  // 'E'
        buffer[6] = (byte)0x4E;  // 'N'
        apdu.setOutgoingAndSend((short)0, (short)7);
    }

    private void initialize(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (dataLen != 32) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Derive master key from seed
        sha256.reset();
        sha256.update(buffer, ISO7816.OFFSET_CDATA, (short)32);
        sha256.doFinal(tempBuffer, (short)0, (short)0, scratch32_1, (short)0);

        // Reduce modulo n
        BigIntegerMod.reduce(scratch32_1, (short)0, scratch32_1, (short)0);

        // Check for zero
        if (isZero(scratch32_1, (short)0, (short)32)) {
            ISOException.throwIt(SW_INVALID_SEED);
        }

        // Set as private key
        masterKey.setS(scratch32_1, (short)0, (short)32);

        // Clear state
        noncesReady = false;
        finalized = false;

        // Clear scratch
        Util.arrayFillNonAtomic(scratch32_1, (short)0, (short)32, (byte)0);
    }

    private void keygen(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Generate a non-zero secp256k1 scalar fully on-card.
        do {
            rng.generateData(scratch32_1, (short)0, (short)32);
            BigIntegerMod.reduce(scratch32_1, (short)0, scratch32_1, (short)0);
        } while (isZero(scratch32_1, (short)0, (short)32));

        masterKey.setS(scratch32_1, (short)0, (short)32);

        // Compute public key so we can normalize the x-only key to even Y.
        keyAgreement.init(masterKey);
        short outLen = keyAgreement.generateSecret(
            SECP256K1, OFFSET_SECP256K1_G, (short)65,
            tempBuffer, (short)0
        );

        if (outLen == 65 && tempBuffer[0] == 0x04 && ((tempBuffer[64] & 0x01) != 0)) {
            // BIP340 uses x-only even-Y keys. If generated key has odd Y,
            // replace sk with n-sk so the public point becomes even-Y.
            Util.arrayCopy(scratch32_1, (short)0, scratch32_2, (short)0, (short)32);
            BigIntegerWrapper.negateMod(
                scratch32_2, (short)0,
                scratch32_1, (short)0,
                (short)32
            );
            masterKey.setS(scratch32_1, (short)0, (short)32);
            keyAgreement.init(masterKey);
            outLen = keyAgreement.generateSecret(
                SECP256K1, OFFSET_SECP256K1_G, (short)65,
                tempBuffer, (short)0
            );
        }

        // Clear one-shot nonce/session state when replacing the long-term key.
        noncesReady = false;
        finalized = false;

        // Return compressed card public key. No private key material leaves card.
        if (outLen == 65 && tempBuffer[0] == 0x04) {
            buffer[0] = (byte)((tempBuffer[64] & 0x01) == 0 ? 0x02 : 0x03);
            Util.arrayCopy(tempBuffer, (short)1, buffer, (short)1, (short)32);
        } else if (outLen == 32) {
            buffer[0] = (byte)0x02;
            Util.arrayCopy(tempBuffer, (short)0, buffer, (short)1, (short)32);
        } else {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        Util.arrayFillNonAtomic(scratch32_1, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(scratch32_2, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)65, (byte)0);
        apdu.setOutgoingAndSend((short)0, (short)33);
    }

    private void getPublicKey(APDU apdu) {
        if (!masterKey.isInitialized()) {
            ISOException.throwIt(SW_NOT_INITIALIZED);
        }

        byte[] buffer = apdu.getBuffer();

        // Compute public key
        keyAgreement.init(masterKey);
        short outLen = keyAgreement.generateSecret(
            SECP256K1, OFFSET_SECP256K1_G, (short)65,
            tempBuffer, (short)0
        );

        // Compress point
        if (outLen == 65 && tempBuffer[0] == 0x04) {
            buffer[0] = (byte)((tempBuffer[64] & 0x01) == 0 ? 0x02 : 0x03);
            Util.arrayCopy(tempBuffer, (short)1, buffer, (short)1, (short)32);
        } else if (outLen == 32) {
            buffer[0] = (byte)0x02;
            Util.arrayCopy(tempBuffer, (short)0, buffer, (short)1, (short)32);
        } else {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        apdu.setOutgoingAndSend((short)0, (short)33);
    }

    private void getNonces(APDU apdu) {
        if (!masterKey.isInitialized()) {
            ISOException.throwIt(SW_NOT_INITIALIZED);
        }

        // Generate fresh nonces k1 and k2
        do {
            rng.generateData(nonceK1, (short)0, (short)32);
            BigIntegerMod.reduce(nonceK1, (short)0, nonceK1, (short)0);
        } while (isZero(nonceK1, (short)0, (short)32));

        do {
            rng.generateData(nonceK2, (short)0, (short)32);
            BigIntegerMod.reduce(nonceK2, (short)0, nonceK2, (short)0);
        } while (isZero(nonceK2, (short)0, (short)32));

        // Compute K1 = k1·G
        tempPrivKey.setS(nonceK1, (short)0, (short)32);
        keyAgreement.init(tempPrivKey);
        short outLen = keyAgreement.generateSecret(
            SECP256K1, OFFSET_SECP256K1_G, (short)65,
            tempBuffer, (short)0
        );

        // Compress K1
        if (outLen == 65 && tempBuffer[0] == 0x04) {
            pubK1[0] = (byte)((tempBuffer[64] & 0x01) == 0 ? 0x02 : 0x03);
            Util.arrayCopy(tempBuffer, (short)1, pubK1, (short)1, (short)32);
        } else if (outLen == 32) {
            pubK1[0] = (byte)0x02;
            Util.arrayCopy(tempBuffer, (short)0, pubK1, (short)1, (short)32);
        }

        // Compute K2 = k2·G
        tempPrivKey.setS(nonceK2, (short)0, (short)32);
        keyAgreement.init(tempPrivKey);
        outLen = keyAgreement.generateSecret(
            SECP256K1, OFFSET_SECP256K1_G, (short)65,
            tempBuffer, (short)0
        );

        // Compress K2
        if (outLen == 65 && tempBuffer[0] == 0x04) {
            pubK2[0] = (byte)((tempBuffer[64] & 0x01) == 0 ? 0x02 : 0x03);
            Util.arrayCopy(tempBuffer, (short)1, pubK2, (short)1, (short)32);
        } else if (outLen == 32) {
            pubK2[0] = (byte)0x02;
            Util.arrayCopy(tempBuffer, (short)0, pubK2, (short)1, (short)32);
        }

        // Mark nonces as ready
        noncesReady = true;
        finalized = false;

        // Return K1 || K2
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopy(pubK1, (short)0, buffer, (short)0, (short)33);
        Util.arrayCopy(pubK2, (short)0, buffer, (short)33, (short)33);
        apdu.setOutgoingAndSend((short)0, (short)66);
    }

    private void doFinalize(APDU apdu) {
        if (!noncesReady) {
            ISOException.throwIt(SW_NONCES_NOT_READY);
        }

        if (finalized) {
            ISOException.throwIt(SW_ALREADY_FINALIZED);
        }

        byte[] buffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // Must receive exactly 97 bytes: a_i(32) | b(32) | parity(1) | e(32)
        if (dataLen != 97) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Parse APDU data
        // a_i: buffer[OFFSET_CDATA + 0..31]
        // b:   buffer[OFFSET_CDATA + 32..63]
        // parity: buffer[OFFSET_CDATA + 64]
        // e:   buffer[OFFSET_CDATA + 65..96]

        short offset = ISO7816.OFFSET_CDATA;

        // Copy a_i to scratch32_1
        Util.arrayCopy(buffer, offset, scratch32_1, (short)0, (short)32);
        offset += 32;

        // Copy b to scratch32_2
        Util.arrayCopy(buffer, offset, scratch32_2, (short)0, (short)32);
        offset += 32;

        // Get parity
        byte parity = buffer[offset];
        offset += 1;

        // Copy e to scratch32_3
        Util.arrayCopy(buffer, offset, scratch32_3, (short)0, (short)32);

        // === COMPUTE s_i = r_i + e·a_i·sk (mod n) ===

        // Step 1: Compute r_i = k1 + b·k2 (mod n)
        // First: scratch32_4 = b * k2 (mod n)
        BigIntegerWrapper.mulMod(
            scratch32_2, (short)0,    // b
            nonceK2, (short)0,         // k2
            scratch32_4, (short)0,     // result: b*k2
            mulWorkspace, (short)0,    // workspace
            (short)32                  // length
        );

        // Then: scratch32_5 = k1 + b*k2 (mod n)
        BigIntegerWrapper.addMod(
            nonceK1, (short)0,         // k1
            scratch32_4, (short)0,     // b*k2
            scratch32_5, (short)0,     // result: r_i
            (short)32                  // length
        );

        // Step 2: Apply parity negation if needed
        if (parity == 1) {
            // r_i = -r_i (mod n)
            // Use scratch32_4 as temp to avoid aliasing
            Util.arrayCopy(scratch32_5, (short)0, scratch32_4, (short)0, (short)32);
            BigIntegerWrapper.negateMod(
                scratch32_4, (short)0,
                scratch32_5, (short)0,
                (short)32
            );
        }

        // Step 3: Compute e·a_i·sk (mod n)
        // Get private key
        masterKey.getS(tempBuffer, (short)0);

        // First: scratch32_4 = a_i * sk (mod n)
        BigIntegerWrapper.mulMod(
            scratch32_1, (short)0,     // a_i
            tempBuffer, (short)0,      // sk
            scratch32_4, (short)0,     // result: a_i*sk
            mulWorkspace, (short)0,
            (short)32
        );

        // Then: scratch32_4 = e * (a_i*sk) (mod n)
        BigIntegerWrapper.mulMod(
            scratch32_3, (short)0,     // e
            scratch32_4, (short)0,     // a_i*sk
            scratch32_4, (short)0,     // result: e*a_i*sk (reuse buffer)
            mulWorkspace, (short)0,
            (short)32
        );

        // Step 4: s_i = r_i + e·a_i·sk (mod n)
        BigIntegerWrapper.addMod(
            scratch32_5, (short)0,     // r_i
            scratch32_4, (short)0,     // e*a_i*sk
            buffer, (short)0,          // result: s_i (directly to output buffer)
            (short)32
        );

        // Clear sensitive data
        Util.arrayFillNonAtomic(nonceK1, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(nonceK2, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)65, (byte)0);
        Util.arrayFillNonAtomic(scratch32_1, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(scratch32_2, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(scratch32_3, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(scratch32_4, (short)0, (short)32, (byte)0);
        Util.arrayFillNonAtomic(scratch32_5, (short)0, (short)32, (byte)0);

        // Mark as finalized
        finalized = true;
        noncesReady = false;

        // Return s_i (32 bytes)
        apdu.setOutgoingAndSend((short)0, (short)32);
    }

    /**
     * Check if buffer is all zeros
     */
    private boolean isZero(byte[] buf, short off, short len) {
        for (short i = 0; i < len; i++) {
            if (buf[(short)(off + i)] != 0) {
                return false;
            }
        }
        return true;
    }
}