package nuri.musig2;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * NuriMuSig2 v1.14 - PIN, session binding and blinded double computation.
 * Scalar256 normalizes all host scalars and supports aliased outputs.
 *
 * Hardening v1.11 (Coldcard Mk3 entropy advisory, 2026-07):
 * - INS_INIT (host seed import) REMOVED. Key material can only be born
 *   on-card via ALG_SECURE_RANDOM; no host bytes ever become the master key.
 * - KEYGEN is one-shot: a card with a key answers 6989. No silent re-key.
 *
 * Hardening v1.12 (audit finding A1, nonce lifetime, 2026-10):
 * - noncesReady/finalized were persistent booleans while nonceK1/nonceK2 are
 *   CLEAR_ON_RESET. After a power cycle between GET_NONCES and FINALIZE the
 *   nonces were zero but noncesReady stayed true, so FINALIZE returned
 *   s_i = 0 + e*a_i*sk and the host could solve for sk. The two session flags
 *   now live in the same CLEAR_ON_RESET transient memory as the nonces, and
 *   FINALIZE additionally refuses (6988) when either secret nonce is all-zero.
 *
 * Author: Claude & Emin
 * Date: 2025-08-31
 */
public class NuriMuSig2v019 extends Applet {

    // Version 1.14: incompatible nonce/finalize frames; see docs/musig2-pin-and-hardening.md
    private static final byte[] APPLET_VERSION = {(byte)0x01, (byte)0x0E};

    // Commands
    private static final byte INS_GET_VERSION = (byte)0x01;
    private static final byte INS_GET_PUBKEY = (byte)0x03;
    private static final byte INS_KEYGEN = (byte)0x04;
    private static final byte INS_GET_NONCES = (byte)0x40;
    private static final byte INS_FINALIZE = (byte)0x41;
    private static final byte INS_VERIFY = (byte)0x20;
    private static final byte INS_SET_PIN = (byte)0x21;
    private static final byte INS_PIN_STATUS = (byte)0x22;

    // Status codes
    private static final short SW_NONCES_NOT_READY = (short)0x6984;
    private static final short SW_ALREADY_FINALIZED = (short)0x6985;
    private static final short SW_NOT_INITIALIZED = (short)0x6986;
    private static final short SW_INVALID_NONCE = (short)0x6988;
    private static final short SW_KEY_ALREADY_GENERATED = (short)0x6989;

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
    private byte[] masterPublicKey; // persistent committed public cache; no sk oracle on reads
    private ECPrivateKey tempPrivKey;
    private KeyAgreement keyAgreement;
    private MessageDigest sha256;
    private RandomData rng;

    // Nonce storage: reset-transient, explicitly burned on deselect
    private byte[] nonceK1;      // 32 bytes secret k1
    private byte[] nonceK2;      // 32 bytes secret k2
    private byte[] pubK1;        // 33 bytes compressed K1 = k1·G
    private byte[] pubK2;        // 33 bytes compressed K2 = k2·G
    // Session flags MUST have the same lifetime as the nonces above, so they
    // are a CLEAR_ON_RESET transient boolean array, never persistent fields.
    private boolean[] sessionFlags; // [FLAG_NONCES_READY], [FLAG_FINALIZED]
    private static final short FLAG_NONCES_READY = (short)0;
    private static final short FLAG_FINALIZED = (short)1;
    // Persistent (EEPROM): once true, KEYGEN is locked forever.
    private boolean keyGenerated;
    private OwnerPIN pin;
    private boolean pinRequired;
    private boolean pinSet;
    private byte[] sessionCounter; // reset-transient, random seed on selection
    private byte[] nonceSession;   // exact counter snapshot for latest nonce pair
    private byte[] blind;
    private byte[] maskedKey;
    private byte[] checkResult;
    private byte[] result;

    // Pre-allocated buffers
    private byte[] tempBuffer;   // 65 bytes for ECDH output
    private byte[] scratch32_1;  // 32 bytes
    private byte[] scratch32_2;  // 32 bytes
    private byte[] scratch32_3;  // 32 bytes
    private byte[] scratch32_4;  // 32 bytes
    private byte[] scratch32_5;  // 32 bytes
    private Scalar256 scalar;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        NuriMuSig2v019 applet = new NuriMuSig2v019();
        applet.personalize(bArray, bOffset, (short)(bLength & 0xff));
        applet.register();
    }

    protected NuriMuSig2v019() {
        // Initialize keys
        masterPublicKey = new byte[33];
        masterKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
        // Prefer transient EC key storage; explicit clearKey on every APDU exit
        // also covers cards which expose only persistent EC private key objects.
        try {
            tempPrivKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, LENGTH_EC_FP_256, false);
        } catch (CryptoException unavailable) {
            tempPrivKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
        }

        // Set EC parameters
        masterKey.setFieldFP(SECP256K1, OFFSET_SECP256K1_P, (short)32);
        masterKey.setA(SECP256K1, (short)32, (short)32);
        masterKey.setB(SECP256K1, (short)64, (short)32);
        masterKey.setR(SECP256K1, OFFSET_SECP256K1_N, (short)32);
        masterKey.setG(SECP256K1, OFFSET_SECP256K1_G, (short)65);
        masterKey.setK((short)1);

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

        // Allocate reset-transient nonces/flags; deselect explicitly burns them
        nonceK1 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_RESET);
        nonceK2 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_RESET);
        pubK1 = JCSystem.makeTransientByteArray((short)33, JCSystem.CLEAR_ON_RESET);
        pubK2 = JCSystem.makeTransientByteArray((short)33, JCSystem.CLEAR_ON_RESET);
        sessionFlags = JCSystem.makeTransientBooleanArray((short)2, JCSystem.CLEAR_ON_RESET);

        // Allocate scratch buffers
        tempBuffer = JCSystem.makeTransientByteArray((short)65, JCSystem.CLEAR_ON_DESELECT);
        scratch32_1 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scratch32_2 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scratch32_3 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scratch32_4 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scratch32_5 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        scalar = new Scalar256();
        pin = new OwnerPIN((byte)5, (byte)12);
        pinRequired = true;
        pinSet = false;
        sessionCounter = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);
        nonceSession = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);
        blind = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        maskedKey = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        checkResult = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        result = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
    }

    /** Strict GP install layout: Li|AID|Lc|control|La|application data.
     * Empty app data means mandatory PIN, not yet personalized. Application data:
     * 00|len|PIN = mandatory PIN (len 4..12); 01|00 = explicit public demo.
     */
    private void personalize(byte[] data, short off, short len) {
        if (len == 0) return;
        short end = (short)(off + len);
        for (short field = 0; field < 2; field++) {
            if (off >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            short count = (short)(data[off++] & 0xff);
            off = (short)(off + count);
            if (off > end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (off >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        short appLen = (short)(data[off++] & 0xff);
        if ((short)(off + appLen) != end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        if (appLen == 0) return;
        if (appLen < 2) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        byte mode = data[off++];
        short pinLen = (short)(data[off++] & 0xff);
        if ((short)(pinLen + 2) != appLen) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        if (mode == 1 && pinLen == 0) {
            pinRequired = false;
        } else if (mode == 0) {
            validPin(data, off, pinLen);
            pin.update(data, off, (byte)pinLen);
            pinSet = true;
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    public boolean select() {
        pin.reset();
        burnNonces();
        clearScratch();
        rng.generateData(sessionCounter, (short)0, (short)4);
        return true;
    }

    public void deselect() {
        pin.reset();
        burnNonces();
        clearScratch();
        wipe(sessionCounter);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        try {
            // Basic logical channel only: no cross-channel shared validation.
            if (buffer[ISO7816.OFFSET_CLA] != 0) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0)
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            switch (buffer[ISO7816.OFFSET_INS]) {
                case INS_GET_VERSION: getVersion(apdu); break;
                case INS_GET_PUBKEY: getPublicKey(apdu); break;
                case INS_KEYGEN: requirePin(); keygen(apdu); break;
                case INS_VERIFY: verify(apdu); break;
                case INS_SET_PIN: setPin(apdu); break;
                case INS_PIN_STATUS: pinStatus(apdu); break;
                case INS_GET_NONCES: requirePin(); getNonces(apdu); break;
                case INS_FINALIZE: requirePin(); doFinalize(apdu); break;
                default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (RuntimeException error) {
            // Includes malformed frames, crypto/RNG/transport failures and PIN errors.
            // No terminal error leaves a usable old nonce session or authorization.
            if (JCSystem.getTransactionDepth() != 0) JCSystem.abortTransaction();
            burnNonces();
            pin.reset();
            throw error;
        } finally {
            finishCommand(buffer, ins == INS_VERIFY || ins == INS_SET_PIN);
        }
    }

    private void finishCommand(byte[] buffer, boolean eraseInput) {
        try {
            clearScratch();
        } catch (RuntimeException cleanupError) {
            burnNonces();
            pin.reset();
            throw cleanupError;
        } finally {
            // Never alter a successful outgoing APDU buffer after send. Only
            // VERIFY/SET_PIN carry secrets and neither sends response data.
            if (eraseInput) Util.arrayFillNonAtomic(buffer, (short)0, (short)buffer.length, (byte)0);
        }
    }

    private void requirePin() {
        if ((pinRequired || pinSet) && (!pinSet || !pin.isValidated()))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    private void validPin(byte[] data, short off, short len) {
        if (len < 4 || len > 12) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        for (short i = 0; i < len; i++) {
            byte digit = data[(short)(off + i)];
            if (digit < (byte)'0' || digit > (byte)'9') ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    private short receive(APDU apdu, short expected) {
        short got = apdu.setIncomingAndReceive();
        short length = apdu.getIncomingLength();
        if (length != expected) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        while (got < length) {
            short part = apdu.receiveBytes((short)(ISO7816.OFFSET_CDATA + got));
            if (part <= 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            got = (short)(got + part);
        }
        if (got != length) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return got;
    }

    private void verify(APDU apdu) {
        if (!pinSet) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        short got = apdu.setIncomingAndReceive();
        short length = apdu.getIncomingLength();
        if (got != length || length > 12) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (pin.getTriesRemaining() == 0) ISOException.throwIt((short)0x6983);
        if (!pin.check(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (byte)length)) {
            byte tries = pin.getTriesRemaining();
            if (tries == 0) ISOException.throwIt((short)0x6983);
            ISOException.throwIt((short)(0x63C0 | tries));
        }
    }

    private void setPin(APDU apdu) {
        if (pinSet || keyGenerated) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short got = apdu.setIncomingAndReceive();
        if (got != apdu.getIncomingLength()) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        validPin(apdu.getBuffer(), ISO7816.OFFSET_CDATA, got);
        JCSystem.beginTransaction();
        pin.update(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (byte)got);
        pinSet = true;
        JCSystem.commitTransaction();
        // SET_PIN does not authorize signing. VERIFY is a separate operation.
        pin.reset();
        burnNonces();
    }

    private void pinStatus(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = pinRequired ? (byte)1 : (byte)0;
        buffer[1] = pinSet ? (byte)1 : (byte)0;
        buffer[2] = pin.getTriesRemaining();
        apdu.setOutgoingAndSend((short)0, (short)3);
    }

    private void getVersion(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(APPLET_VERSION, (short)0, buffer, (short)0, (short)2);
        buffer[2] = (byte)(3 | (pinRequired ? 4 : 0) | (pinSet ? 8 : 0));
        buffer[3] = (byte)'P'; buffer[4] = (byte)'I'; buffer[5] = (byte)'N'; buffer[6] = (byte)'2';
        apdu.setOutgoingAndSend((short)0, (short)7);
    }

    private void configureTemp() {
        tempPrivKey.setFieldFP(SECP256K1, (short)0, (short)32);
        tempPrivKey.setA(SECP256K1, (short)32, (short)32);
        tempPrivKey.setB(SECP256K1, (short)64, (short)32);
        tempPrivKey.setR(SECP256K1, (short)96, (short)32);
        tempPrivKey.setG(SECP256K1, (short)128, (short)65);
        tempPrivKey.setK((short)1);
    }

    private void randomScalar(byte[] out) {
        do {
            rng.generateData(out, (short)0, (short)32);
            scalar.reduce(out, (short)0, out, (short)0);
        } while (Scalar256.isZero(out, (short)0));
    }

    private void publicFromScalar(byte[] secret, byte[] out) {
        configureTemp();
        tempPrivKey.setS(secret, (short)0, (short)32);
        keyAgreement.init(tempPrivKey);
        short length = keyAgreement.generateSecret(SECP256K1, OFFSET_SECP256K1_G,
            (short)65, out, (short)0);
        // X-only and hashed ECDH cannot tell Y parity. Never invent an even Y.
        if (length != 65 || out[0] != 4) ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        tempPrivKey.clearKey();
    }

    private void compress(byte[] point, byte[] out, short off) {
        out[off] = (byte)(2 | (point[64] & 1));
        Util.arrayCopyNonAtomic(point, (short)1, out, (short)(off + 1), (short)32);
    }

    private void keygen(APDU apdu) {
        if (keyGenerated) ISOException.throwIt(SW_KEY_ALREADY_GENERATED);
        burnNonces();
        randomScalar(scratch32_1);
        publicFromScalar(scratch32_1, tempBuffer);
        if ((tempBuffer[64] & 1) != 0) {
            scalar.negate(scratch32_1, (short)0, scratch32_1, (short)0);
            publicFromScalar(scratch32_1, tempBuffer);
        }
        if ((tempBuffer[64] & 1) != 0) ISOException.throwIt(SW_INVALID_NONCE);
        // Candidate math completes using the temporary key first. Some key
        // providers do not roll back key-object writes, so write the scalar
        // BEFORE atomically publishing the cached public key and keyed flag.
        // An interrupted uncommitted scalar is never advertised or usable.
        compress(tempBuffer, apdu.getBuffer(), (short)0);
        JCSystem.beginTransaction();
        masterKey.setS(scratch32_1, (short)0, (short)32);
        Util.arrayCopy(apdu.getBuffer(), (short)0, masterPublicKey, (short)0, (short)33);
        keyGenerated = true;
        JCSystem.commitTransaction();
        apdu.setOutgoingAndSend((short)0, (short)33);
    }

    private void getPublicKey(APDU apdu) {
        if (!keyGenerated) ISOException.throwIt(SW_NOT_INITIALIZED);
        // Public reads must never repeat an unblinded master-secret EC product.
        Util.arrayCopyNonAtomic(masterPublicKey, (short)0, apdu.getBuffer(), (short)0, (short)33);
        apdu.setOutgoingAndSend((short)0, (short)33);
    }

    private void nextSession() {
        short carry = 1;
        for (short i = 3; i >= 0; i--) {
            short digit = (short)((sessionCounter[i] & 0xff) + carry);
            sessionCounter[i] = (byte)digit;
            carry = (short)(digit >> 8);
        }
        if (carry != 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        Util.arrayCopyNonAtomic(sessionCounter, (short)0, nonceSession, (short)0, (short)4);
    }

    private void getNonces(APDU apdu) {
        burnNonces(); // invalidate BEFORE RNG or engine calls can fail
        if (!keyGenerated || !masterKey.isInitialized()) ISOException.throwIt(SW_NOT_INITIALIZED);
        receive(apdu, (short)0);
        nextSession();
        randomScalar(nonceK1);
        randomScalar(nonceK2);
        publicFromScalar(nonceK1, tempBuffer);
        compress(tempBuffer, pubK1, (short)0);
        publicFromScalar(nonceK2, tempBuffer);
        compress(tempBuffer, pubK2, (short)0);
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(pubK1, (short)0, buffer, (short)0, (short)33);
        Util.arrayCopyNonAtomic(pubK2, (short)0, buffer, (short)33, (short)33);
        Util.arrayCopyNonAtomic(nonceSession, (short)0, buffer, (short)66, (short)4);
        sessionFlags[FLAG_FINALIZED] = false;
        sessionFlags[FLAG_NONCES_READY] = true;
        apdu.setOutgoingAndSend((short)0, (short)70);
    }

    /** Constant-iteration equality for both scalars and session tokens. */
    private boolean equalCT(byte[] a, short ao, byte[] b, short bo, short len) {
        short different = 0;
        for (short i = 0; i < len; i++) different |= (short)(a[(short)(ao + i)] ^ b[(short)(bo + i)]);
        return different == 0;
    }

    /** Uncompressed SEC1 only; bounds plus the card EC engine at scalar one.
     * No secret is ever multiplied by an unvalidated external point. secp256k1
     * has cofactor one, so a valid finite curve point is in the required group.
     * Fail closed if native full-XY multiplication is unavailable.
     */
    private void validatePoint(byte[] data, short off) {
        if (data[off] != 4
            || Scalar256.compare(data, (short)(off + 1), SECP256K1, (short)0) >= 0
            || Scalar256.compare(data, (short)(off + 33), SECP256K1, (short)0) >= 0)
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        // Some native engines accept an off-curve point when multiplying by
        // one (observed in jCardSim). Check y^2 = x^3 + 7 ourselves as well.
        scalar.fieldMultiply(data, (short)(off + 1), data, (short)(off + 1), scratch32_4, (short)0);
        scalar.fieldMultiply(scratch32_4, (short)0, data, (short)(off + 1), scratch32_4, (short)0);
        wipe(scratch32_5);
        scratch32_5[31] = 7;
        scalar.fieldAdd(scratch32_4, (short)0, scratch32_5, (short)0, scratch32_4, (short)0);
        scalar.fieldMultiply(data, (short)(off + 33), data, (short)(off + 33), scratch32_5, (short)0);
        if (!equalCT(scratch32_4, (short)0, scratch32_5, (short)0, (short)32))
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        configureTemp();
        wipe(scratch32_4);
        scratch32_4[31] = 1;
        tempPrivKey.setS(scratch32_4, (short)0, (short)32);
        keyAgreement.init(tempPrivKey);
        short length;
        try {
            length = keyAgreement.generateSecret(data, off, (short)65, tempBuffer, (short)0);
        } catch (CryptoException invalid) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        if (length != 65 || !equalCT(data, off, tempBuffer, (short)0, (short)65))
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        tempPrivKey.clearKey();
    }

    /** c*x = c*(x+r) - c*r mod n, with a fresh independent random r.
     * The only secret operand entering multiplication is randomized; unmasking
     * occurs after both fixed-iteration products. Blinds never leave transient
     * memory. This is first-order software hardening, not a physical evaluation.
     */
    private void blindedMultiply(byte[] coefficient, byte[] secret, byte[] out) {
        randomScalar(blind);
        scalar.addMod(secret, (short)0, blind, (short)0, maskedKey, (short)0);
        scalar.mulMod(coefficient, (short)0, maskedKey, (short)0, out, (short)0);
        scalar.mulMod(coefficient, (short)0, blind, (short)0, maskedKey, (short)0);
        scalar.negate(maskedKey, (short)0, maskedKey, (short)0);
        scalar.addMod(out, (short)0, maskedKey, (short)0, out, (short)0);
        wipe(blind);
        wipe(maskedKey);
    }

    private void computePartial(byte parity, byte[] out) {
        // Independent recomputation includes the coefficient and nonce products.
        scalar.mulMod(scratch32_1, (short)0, scratch32_3, (short)0, scratch32_4, (short)0);
        if (masterKey.getS(tempBuffer, (short)0) != 32) ISOException.throwIt(SW_INVALID_NONCE);
        blindedMultiply(scratch32_4, tempBuffer, out);
        blindedMultiply(scratch32_2, nonceK2, scratch32_5);
        scalar.addMod(nonceK1, (short)0, scratch32_5, (short)0, scratch32_5, (short)0);
        if (parity == 1) scalar.negate(scratch32_5, (short)0, scratch32_5, (short)0);
        scalar.addMod(out, (short)0, scratch32_5, (short)0, out, (short)0);
    }

    private void doFinalize(APDU apdu) {
        if (!sessionFlags[FLAG_NONCES_READY]) ISOException.throwIt(SW_NONCES_NOT_READY);
        if (sessionFlags[FLAG_FINALIZED]) ISOException.throwIt(SW_ALREADY_FINALIZED);
        // Burn authorization-to-finalize before ANY parsing/math, including errors.
        sessionFlags[FLAG_NONCES_READY] = false;
        sessionFlags[FLAG_FINALIZED] = true;
        if (Scalar256.isZero(nonceK1, (short)0) | Scalar256.isZero(nonceK2, (short)0))
            ISOException.throwIt(SW_INVALID_NONCE);
        receive(apdu, (short)231);
        byte[] buffer = apdu.getBuffer();
        short off = ISO7816.OFFSET_CDATA;
        byte parity = buffer[(short)(off + 64)];
        if (parity != 0 && parity != 1) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        if (!equalCT(buffer, (short)(off + 97), nonceSession, (short)0, (short)4)
            || !equalCT(nonceSession, (short)0, sessionCounter, (short)0, (short)4))
            ISOException.throwIt(SW_NONCES_NOT_READY);
        validatePoint(buffer, (short)(off + 101));
        validatePoint(buffer, (short)(off + 166));
        if ((buffer[(short)(off + 165)] & 1) != parity) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        Util.arrayCopyNonAtomic(buffer, off, scratch32_1, (short)0, (short)32);
        Util.arrayCopyNonAtomic(buffer, (short)(off + 32), scratch32_2, (short)0, (short)32);
        Util.arrayCopyNonAtomic(buffer, (short)(off + 65), scratch32_3, (short)0, (short)32);
        computePartial(parity, result);
        computePartial(parity, checkResult);
        if (!equalCT(result, (short)0, checkResult, (short)0, (short)32))
            ISOException.throwIt(SW_INVALID_NONCE);
        Util.arrayCopyNonAtomic(result, (short)0, buffer, (short)0, (short)32);
        // Erase before attempting delivery: even an output transport exception
        // cannot permit a second partial with this nonce pair.
        burnNonces();
        clearScratch();
        apdu.setOutgoingAndSend((short)0, (short)32);
    }

    private void wipe(byte[] data) {
        Util.arrayFillNonAtomic(data, (short)0, (short)data.length, (byte)0);
    }

    private void burnNonces() {
        sessionFlags[FLAG_NONCES_READY] = false;
        sessionFlags[FLAG_FINALIZED] = false;
        wipe(nonceK1); wipe(nonceK2); wipe(pubK1); wipe(pubK2); wipe(nonceSession);
    }

    private void clearScratch() {
        // clearKey first is deliberately not used: a key-provider error must not
        // prevent the byte-array cleanup in the finally block.
        try { tempPrivKey.clearKey(); }
        finally {
            wipe(tempBuffer); wipe(scratch32_1); wipe(scratch32_2); wipe(scratch32_3);
            wipe(scratch32_4); wipe(scratch32_5); wipe(blind); wipe(maskedKey);
            wipe(result); wipe(checkResult); scalar.clear();
        }
    }
}
