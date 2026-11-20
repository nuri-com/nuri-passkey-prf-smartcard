package com.nuri.uv;

import javacard.framework.Shareable;

/** On-card authorization shared by Nuri signer applets. */
public interface NuriUserVerification extends Shareable {
    byte POLICY_PIN = 0;
    byte POLICY_PIN_OR_FINGER = 1;
    byte POLICY_PIN_AND_FINGER = 2;

    /** Throws 6982 unless the configured on-card policy is currently satisfied. */
    void requireAuthorized();
    /** Verify a PIN from the global APDU buffer; returns false without leaking tries. */
    boolean verifyPin(byte[] apduBuffer, short offset, byte length);
    /** Run on-card fingerprint matching and set the fingerprint session flag on pass. */
    short verifyFingerprint();
    byte getPolicy();
    /** Bit 0 PIN satisfied, bit 1 finger satisfied, bit 2 full policy satisfied. */
    byte sessionStatus();
    void logout();
}
