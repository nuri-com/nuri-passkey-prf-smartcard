package com.nuri.uv;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Shareable;

/** On-card PIN/fingerprint policy. Sessions end at card reset or explicit logout. */
public final class NuriUvApplet extends Applet implements NuriUserVerification {
    private static final byte[] AID = {0x4E, 0x55, 0x52, 0x49, 0x41, 0x55, 0x54, 0x48, 0x01};
    private static final byte[] CLIENT_AID = {0x4E, 0x55, 0x52, 0x49, 0x41, 0x55, 0x54, 0x48, 0x02};

    private static final byte INS_VERIFY_PIN = 0x20;
    private static final byte INS_VERIFY_FINGER = 0x2A;
    private static final byte INS_STATUS = 0x07;
    private static final byte INS_SET_PIN = 0x31;
    private static final byte INS_SET_POLICY = 0x38;
    private static final byte INS_ENROLL = 0x34;
    private static final byte INS_LOGOUT = 0x35;

    private static final byte PIN_TRIES = 5;
    private static final byte FINGER_TRIES = 3;
    private static final short SESSION_PIN = 0;
    private static final short SESSION_FINGER = 1;

    private final OwnerPIN pin;
    private final BiometricMatcher matcher;
    private final boolean[] session;
    private boolean pinSet;
    private byte policy;
    private byte fingerTries;
    private byte authorizedBitmap;

    public static void install(byte[] data, short offset, byte length) {
        new NuriUvApplet().register(AID, (short)0, (byte)AID.length);
    }

    private NuriUvApplet() {
        pin = new OwnerPIN(PIN_TRIES, (byte)12);
        matcher = MatcherFactory.create();
        session = JCSystem.makeTransientBooleanArray((short)2, JCSystem.CLEAR_ON_RESET);
        policy = POLICY_PIN;
        fingerTries = FINGER_TRIES;
    }

    public boolean select() {
        return true; // CLEAR_ON_RESET sessions intentionally survive applet switching.
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != 0) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (buffer[ISO7816.OFFSET_P2] != 0) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_STATUS: status(apdu); break;
            case INS_SET_PIN: setPin(apdu); break;
            case INS_VERIFY_PIN: verifyPinApdu(apdu); break;
            case INS_VERIFY_FINGER:
                short result = verifyFingerprintInternal();
                if (result != (short)0x9000) ISOException.throwIt(result);
                break;
            case INS_SET_POLICY: setPolicy(apdu.getBuffer()[ISO7816.OFFSET_P1]); break;
            case INS_ENROLL: enroll(apdu); break;
            case INS_LOGOUT: logout(); break;
            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private short receive(APDU apdu) {
        short got = apdu.setIncomingAndReceive();
        short length = apdu.getIncomingLength();
        if (got != length) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return length;
    }

    private void setPin(APDU apdu) {
        if (pinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        byte initialPolicy = apdu.getBuffer()[ISO7816.OFFSET_P1];
        if (initialPolicy < POLICY_PIN || initialPolicy > POLICY_PIN_AND_FINGER)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        short length = receive(apdu);
        validateDigits(apdu.getBuffer(), ISO7816.OFFSET_CDATA, length);
        pin.update(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (byte)length);
        policy = initialPolicy;
        pinSet = true;
        authorizedBitmap = MatcherFactory.initialBitmap();
        logout();
    }

    private static void validateDigits(byte[] data, short offset, short length) {
        if (length < 4 || length > 12) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        for (short i = 0; i < length; i++) {
            byte value = data[(short)(offset + i)];
            if (value < (byte)'0' || value > (byte)'9') ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    private void verifyPinApdu(APDU apdu) {
        short length = receive(apdu);
        if (!pinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (pin.getTriesRemaining() == 0) ISOException.throwIt((short)0x6983);
        session[SESSION_PIN] = false;
        if (!pin.check(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (byte)length)) {
            byte left = pin.getTriesRemaining();
            ISOException.throwIt(left == 0 ? (short)0x6983 : (short)(0x63C0 | left));
        }
        session[SESSION_PIN] = true;
        fingerTries = FINGER_TRIES;
    }

    private short verifyFingerprintInternal() {
        session[SESSION_FINGER] = false;
        if (authorizedBitmap == 0) return 0x6A88;
        if (fingerTries == 0) return 0x6983;
        fingerTries--; // Persistent before the blocking sensor call: power loss fails closed.
        short result = matcher.match();
        if (result == BiometricMatcher.MATCH_OK) {
            fingerTries = FINGER_TRIES;
            session[SESSION_FINGER] = true;
            return (short)0x9000;
        }
        if (result == BiometricMatcher.MATCH_TIMEOUT) {
            fingerTries++;
            return 0x63E9;
        }
        if (result == BiometricMatcher.MATCH_FAILED) {
            return fingerTries == 0 ? (short)0x6983 : (short)(0x63C0 | fingerTries);
        }
        return 0x63E1;
    }

    private void setPolicy(byte next) {
        if (next < POLICY_PIN || next > POLICY_PIN_AND_FINGER)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        requireAuthorizedInternal();
        if (next != POLICY_PIN && authorizedBitmap == 0)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        policy = next;
        logout(); // Re-authenticate under the new policy; no implicit downgrade session.
    }

    private void enroll(APDU apdu) {
        requirePinSession();

        byte touch = apdu.getBuffer()[ISO7816.OFFSET_P1];
        byte maximum = matcher.enrollmentTouches();
        if (touch <= 0 || touch > maximum) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        short current = matcher.enrollStep(touch);
        if (current < 0) ISOException.throwIt((short)(0x63E0 | (-current & 0x0F)));
        byte[] buffer = apdu.getBuffer();
        buffer[0] = (byte)current;
        buffer[1] = maximum;
        buffer[2] = matcher.templateBitmap();
        if (current == maximum) {
            if (buffer[2] == 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            authorizedBitmap = buffer[2];
            fingerTries = FINGER_TRIES;
        }
        apdu.setOutgoingAndSend((short)0, (short)3);
    }

    private void status(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = policy;
        buffer[1] = sessionStatusInternal();
        apdu.setOutgoingAndSend((short)0, (short)2);
    }

    private void requirePinSession() {
        if (!session[SESSION_PIN]) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    private boolean fingerSessionValid() {
        if (!session[SESSION_FINGER]) return false;
        return authorizedBitmap != 0;
    }

    private boolean authorized() {
        if (!pinSet) return false;
        switch (policy) {
            case POLICY_PIN: return session[SESSION_PIN];
            case POLICY_PIN_OR_FINGER: return session[SESSION_PIN] || fingerSessionValid();
            case POLICY_PIN_AND_FINGER: return session[SESSION_PIN] && fingerSessionValid();
            default: return false;
        }
    }

    private void requireAuthorizedInternal() {
        if (!authorized()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    private byte sessionStatusInternal() {
        return (byte)((session[SESSION_PIN] ? 1 : 0) | (fingerSessionValid() ? 2 : 0) | (authorized() ? 4 : 0));
    }

    public Shareable getShareableInterfaceObject(AID clientAid, byte parameter) {
        return clientAid.equals(CLIENT_AID, (short)0, (byte)CLIENT_AID.length) ? this : null;
    }

    public void requireAuthorized() {
        requireAuthorizedInternal();
    }

    public boolean verifyPin(byte[] apduBuffer, short offset, byte length) {
        if (!pinSet || pin.getTriesRemaining() == 0) return false;
        session[SESSION_PIN] = false;
        if (!pin.check(apduBuffer, offset, length)) return false;
        session[SESSION_PIN] = true;
        fingerTries = FINGER_TRIES;
        return true;
    }

    public short verifyFingerprint() {
        return verifyFingerprintInternal();
    }

    public byte getPolicy() {
        return policy;
    }

    public byte sessionStatus() {
        return sessionStatusInternal();
    }

    public void logout() {
        session[SESSION_PIN] = false;
        session[SESSION_FINGER] = false;
        pin.reset();
    }
}
